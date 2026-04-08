from flask import Flask, render_template, request, redirect
from flask import session
from utils.encryption import encrypt_file, decrypt_file
from utils.signature import sign_data, verify_signature
from datetime import datetime, timedelta

from flask import send_file

import sqlite3
import bcrypt
import os

app = Flask(__name__)

app.secret_key = "supersecretkey"
# -------------------------
# DATABASE SETUP
# -------------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        email TEXT,
        password TEXT,
        failed_attempts INTEGER DEFAULT 0,
        lock_until TEXT
    )
    """)
    conn.commit()
    conn.close()

init_db()


# -------------------------
# ROUTES
# -------------------------

@app.route("/")
def home():
    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password, failed_attempts, lock_until FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        if user:
            stored_password, failed_attempts, lock_until = user

            #  CHECK IF ACCOUNT IS LOCKED
            if lock_until:
                lock_time = datetime.fromisoformat(lock_until)
                now = datetime.now()

                if now < lock_time:
                    remaining_time = lock_time - now
                    seconds = int(remaining_time.total_seconds())

                    mins = seconds // 60
                    secs = seconds % 60

                    conn.close()
                    return f"Account locked! Try again in {mins} min {secs} sec"

            #  CHECK PASSWORD
            if bcrypt.checkpw(password.encode("utf-8"), stored_password):

                # RESET ATTEMPTS AFTER SUCCESS
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE username = ?",
                    (username,)
                )

                conn.commit()
                conn.close()

                session["user"] = username
                return redirect("/dashboard")

            else:
                #  WRONG PASSWORD
                failed_attempts += 1

                if failed_attempts >= 3:
                    lock_time = datetime.now() + timedelta(seconds=30)

                    cursor.execute(
                        "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
                        (failed_attempts, lock_time.isoformat(), username)
                    )

                    conn.commit()
                    conn.close()

                    return "Too many failed attempts! Account locked for 30 seconds."

                else:
                    cursor.execute(
                        "UPDATE users SET failed_attempts = ? WHERE username = ?",
                        (failed_attempts, username)
                    )

                    conn.commit()
                    conn.close()

                    return f"Invalid password! Attempts left: {3 - failed_attempts}"

        conn.close()
        return "User not found"

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename FROM files WHERE username = ?",
        (session["user"],)
    )
    files = cursor.fetchall()

    conn.close()

    return render_template("dashboard.html", files=files)

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        return redirect("/login")

    if request.method == "POST":
        file = request.files["file"]
        file_password = request.form["file_password"]

        hashed_file_password = bcrypt.hashpw(file_password.encode("utf-8"), bcrypt.gensalt())
        
        if file:
            filename = file.filename
            file_data = file.read()

            #  Set expiry (example: 2 minutes)
            expiry_time = datetime.now() + timedelta(minutes=1)
            expiry_bytes = expiry_time.isoformat().encode()

            # store length of expiry (fixed 4 bytes)
            expiry_length = len(expiry_bytes).to_bytes(4, 'big')

            #  SIGN DATA
            signature = sign_data(file_data)
            signature_length = len(signature).to_bytes(4, 'big')

            #  COMBINE EVERYTHING
            combined_data = (
                expiry_length +
                expiry_bytes +
                signature_length +
                signature +
                file_data
            )

            #  STEP 3: ENCRYPT
            encrypted_data = encrypt_file(combined_data)

            #  SAVE FILE
            stored_name = filename + ".enc"
            filepath = os.path.join("uploads", stored_name)

            with open(filepath, "wb") as f:
                f.write(encrypted_data)

            #  SAVE TO DATABASE
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO files (username, filename, filepath, file_password) VALUES (?, ?, ?, ?)",
                (session["user"], stored_name, filepath, hashed_file_password)
            )

            conn.commit()
            conn.close()

            return redirect("/dashboard?msg=upload_success")

    return render_template("upload.html")

@app.route("/download/<filename>", methods=["GET", "POST"])
def download(filename):
    if "user" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filepath, file_password FROM files WHERE filename = ? AND username = ?",
        (filename, session["user"])
    )
    file = cursor.fetchone()
    conn.close()

    if not file:
        return "File not found"

    filepath, stored_password = file

    # STEP 1: Ask password first
    if request.method == "GET":
        error = request.args.get("error")
        return render_template("file_password.html", filename=filename, error=error)

    # STEP 2: Verify password
    entered_password = request.form["password"]

    try:
    # convert stored password safely to bytes
        if isinstance(stored_password, memoryview):
            stored_password = stored_password.tobytes()
        elif isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        if not bcrypt.checkpw(entered_password.encode("utf-8"), stored_password):
            return redirect(f"/download/{filename}?error=wrong_password")

    except Exception as e:
        print("ERROR DURING PASSWORD CHECK:", e)
        return redirect(f"/download/{filename}?error=wrong_password")

    # STEP 3: Continue decryption

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data)

    # ---- EXPIRY CHECK ----
    expiry_length = int.from_bytes(decrypted_data[:4], 'big')
    expiry_bytes = decrypted_data[4:4+expiry_length]
    expiry_time = datetime.fromisoformat(expiry_bytes.decode())

    current_index = 4 + expiry_length

    if datetime.now() > expiry_time:
        return " File expired"

    # ---- SIGNATURE ----
    signature_length = int.from_bytes(decrypted_data[current_index:current_index+4], 'big')
    current_index += 4

    signature = decrypted_data[current_index:current_index+signature_length]
    current_index += signature_length

    original_data = decrypted_data[current_index:]

    if not verify_signature(original_data, signature):
        return " File tampered!"

    # ---- SEND FILE ----
    temp_path = os.path.join("uploads", "temp_" + filename.replace(".enc", ""))

    with open(temp_path, "wb") as f:
        f.write(original_data)

    return send_file(temp_path, as_attachment=True)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

if __name__ == "__main__":
    app.run(debug=True)