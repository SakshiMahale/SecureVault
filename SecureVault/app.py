from flask import Flask, render_template, request, redirect
from flask import session
from utils.encryption import encrypt_file, decrypt_file
from utils.signature import sign_data, verify_signature

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
        password TEXT
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

        cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        conn.close()

        if user:
            stored_password = user[0]

            if bcrypt.checkpw(password.encode("utf-8"), stored_password):
                session["user"] = username   # ADD THIS LINE
                return redirect("/dashboard")
            else:
                return "Invalid password"

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

        if file:
            filename = file.filename
            file_data = file.read()

            # 🔐 STEP 1: SIGN ORIGINAL DATA
            signature = sign_data(file_data)

            # 🔐 STEP 2: STORE signature + data
            signature_length = len(signature).to_bytes(4, 'big')
            combined_data = signature_length + signature + file_data

            # 🔐 STEP 3: ENCRYPT
            encrypted_data = encrypt_file(combined_data)

            # 📁 SAVE FILE
            stored_name = filename + ".enc"
            filepath = os.path.join("uploads", stored_name)

            with open(filepath, "wb") as f:
                f.write(encrypted_data)

            # 💾 SAVE TO DATABASE
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO files (username, filename, filepath) VALUES (?, ?, ?)",
                (session["user"], stored_name, filepath)
            )

            conn.commit()
            conn.close()

            return "File uploaded successfully!"

    return render_template("upload.html")

@app.route("/download/<filename>")
def download(filename):
    if "user" not in session:
        return redirect("/login")

    filepath = os.path.join("uploads", filename)

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    decrypted_data = decrypt_file(encrypted_data)

    # STEP 1: Extract signature (first 256 bytes for RSA 2048)
    signature_length = int.from_bytes(decrypted_data[:4], 'big')

    signature = decrypted_data[4:4+signature_length]
    original_data = decrypted_data[4+signature_length:]
    
    print("Decrypted length:", len(decrypted_data))

    # STEP 2: Verify signature
    if not verify_signature(original_data, signature):
        return "Signature verification failed! File tampered."

    # STEP 3: continue normally

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