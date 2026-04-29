from flask import Flask, render_template, request, redirect, session, send_file
from utils.encryption import generate_aes_key, encrypt_file_data, decrypt_file_data
from utils.signature import sign_data, verify_signature
from utils.ecc_crypto import generate_ecc_keys, ecc_encrypt_aes_key, ecc_decrypt_aes_key
from utils.elgamal_crypto import generate_elgamal_keys, elgamal_encrypt_aes_key, elgamal_decrypt_aes_key
from utils.rsa_crypto import generate_rsa_keys, rsa_encrypt_key, rsa_decrypt_key
from datetime import datetime, timedelta

import sqlite3
import bcrypt
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"


# -------------------------
# DEBUG LOGGER
# -------------------------
def debug_log(message):
    print(f"[DEBUG] {message}")


# -------------------------
# DATABASE SETUP
# -------------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT,
        password BLOB,
        failed_attempts INTEGER DEFAULT 0,
        lock_until TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        filename TEXT,
        filepath TEXT,
        file_password BLOB,
        crypto_mode TEXT,
        enc_aes_key BLOB,
        ecc_ephemeral_pub BLOB,
        file_nonce BLOB,
        wrap_nonce BLOB,
        uploaded_at TEXT
    )
    """)

    conn.commit()
    conn.close()
    debug_log("Database initialized successfully")


init_db()
generate_ecc_keys()
generate_elgamal_keys()
generate_rsa_keys()
debug_log("ECC, ElGamal, and RSA keys initialized")


# -------------------------
# ROUTES
# -------------------------
@app.route("/")
def home():
    return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]

        debug_log(f"Registration attempt for username: {username}")

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        debug_log("User password hashed using bcrypt")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            debug_log(f"Registration failed: username '{username}' already exists")
            return "Username already exists"

        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, hashed_password)
        )

        conn.commit()
        conn.close()

        debug_log(f"User '{username}' registered successfully")
        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        debug_log(f"Login attempt for username: {username}")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT password, failed_attempts, lock_until FROM users WHERE username = ?",
            (username,)
        )
        user = cursor.fetchone()

        if user:
            stored_password, failed_attempts, lock_until = user

            if lock_until:
                lock_time = datetime.fromisoformat(lock_until)
                now = datetime.now()

                if now < lock_time:
                    remaining_time = lock_time - now
                    seconds = int(remaining_time.total_seconds())
                    mins = seconds // 60
                    secs = seconds % 60
                    conn.close()
                    debug_log(f"User '{username}' is locked out for {mins} min {secs} sec")
                    return f"Account locked! Try again in {mins} min {secs} sec"

            if bcrypt.checkpw(password.encode("utf-8"), stored_password):
                cursor.execute(
                    "UPDATE users SET failed_attempts = 0, lock_until = NULL WHERE username = ?",
                    (username,)
                )
                conn.commit()
                conn.close()

                session["user"] = username
                debug_log(f"Login successful for user '{username}'")
                return redirect("/dashboard")

            else:
                failed_attempts += 1
                debug_log(f"Wrong password for '{username}'. Failed attempts: {failed_attempts}")

                if failed_attempts >= 3:
                    lock_time = datetime.now() + timedelta(seconds=30)

                    cursor.execute(
                        "UPDATE users SET failed_attempts = ?, lock_until = ? WHERE username = ?",
                        (failed_attempts, lock_time.isoformat(), username)
                    )

                    conn.commit()
                    conn.close()

                    debug_log(f"User '{username}' locked for 30 seconds due to repeated failed attempts")
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
        debug_log(f"Login failed: user '{username}' not found")
        return "User not found"

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        debug_log("Unauthorized dashboard access attempt")
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT filename, crypto_mode FROM files WHERE username = ?",
        (session["user"],)
    )
    files = cursor.fetchall()

    conn.close()

    debug_log(f"Dashboard loaded for '{session['user']}'. Total files: {len(files)}")
    return render_template("dashboard.html", files=files)


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if "user" not in session:
        debug_log("Unauthorized upload access attempt")
        return redirect("/login")

    if request.method == "POST":
        file = request.files.get("file")
        file_password = request.form.get("file_password")
        crypto_mode = request.form.get("crypto_mode")

        debug_log("UPLOAD STARTED")
        debug_log(f"Selected crypto mode: {crypto_mode}")

        if not file or file.filename == "":
            debug_log("Upload failed: no file selected")
            return "Please select a file"

        if not file_password:
            debug_log("Upload failed: missing file password")
            return "File password is required"

        if crypto_mode not in ["ECC", "ELGAMAL", "RSA"]:
            debug_log("Upload failed: invalid crypto mode")
            return "Invalid encryption mode"

        hashed_file_password = bcrypt.hashpw(file_password.encode("utf-8"), bcrypt.gensalt())
        debug_log("File password hashed using bcrypt")

        filename = file.filename
        file_data = file.read()

        debug_log(f"Original filename: {filename}")
        debug_log(f"Original file size: {len(file_data)} bytes")

        # Digital signature
        signature = sign_data(file_data)
        signature_length = len(signature).to_bytes(4, 'big')

        debug_log("Digital signature created")
        debug_log(f"Signature length: {len(signature)} bytes")

        combined_data = (
            signature_length +
            signature +
            file_data
        )

        debug_log(f"Combined signed payload size: {len(combined_data)} bytes")

        # AES encryption
        aes_key = generate_aes_key()
        debug_log("AES key generated successfully")
        debug_log(f"AES key length: {len(aes_key)} bytes")

        file_nonce, encrypted_data = encrypt_file_data(combined_data, aes_key)
        debug_log("AES encryption completed")
        debug_log(f"File nonce length: {len(file_nonce)} bytes")
        debug_log(f"Encrypted file size: {len(encrypted_data)} bytes")

        ecc_ephemeral_pub = None
        wrap_nonce = None
        enc_aes_key = None

        # Wrap AES key
        if crypto_mode == "ECC":
            enc_aes_key, wrap_nonce, ecc_ephemeral_pub = ecc_encrypt_aes_key(aes_key)
            debug_log("ECC encryption used for AES key")
            debug_log(f"ECC wrapped key size: {len(enc_aes_key)} bytes")
            debug_log(f"ECC wrap nonce size: {len(wrap_nonce)} bytes")
            debug_log(f"ECC ephemeral public key size: {len(ecc_ephemeral_pub)} bytes")

        elif crypto_mode == "ELGAMAL":
            enc_aes_key = elgamal_encrypt_aes_key(aes_key)
            debug_log("ElGamal encryption used for AES key")
            debug_log(f"ElGamal wrapped key size: {len(enc_aes_key)} bytes")

        elif crypto_mode == "RSA":
            enc_aes_key = rsa_encrypt_key(aes_key)
            debug_log("RSA encryption used for AES key")
            debug_log(f"RSA wrapped key size: {len(enc_aes_key)} bytes")

        stored_name = filename + ".enc"
        filepath = os.path.join("uploads", stored_name)

        with open(filepath, "wb") as f:
            f.write(encrypted_data)

        debug_log(f"Encrypted file saved at: {filepath}")

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO files (
                username, filename, filepath, file_password,
                crypto_mode, enc_aes_key, ecc_ephemeral_pub,
                file_nonce, wrap_nonce, uploaded_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["user"],
            stored_name,
            filepath,
            hashed_file_password,
            crypto_mode,
            enc_aes_key,
            ecc_ephemeral_pub,
            file_nonce,
            wrap_nonce,
            datetime.now().isoformat()
        ))

        conn.commit()
        conn.close()

        debug_log(f"File metadata saved to database for user '{session['user']}'")
        debug_log("UPLOAD COMPLETED SUCCESSFULLY")

        return redirect("/dashboard")

    return render_template("upload.html")


@app.route("/download/<filename>", methods=["GET", "POST"])
def download(filename):
    if "user" not in session:
        debug_log("Unauthorized download access attempt")
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT filepath, file_password, crypto_mode, enc_aes_key,
               ecc_ephemeral_pub, file_nonce, wrap_nonce
        FROM files
        WHERE filename = ? AND username = ?
    """, (filename, session["user"]))

    file = cursor.fetchone()
    conn.close()

    if not file:
        debug_log(f"Download failed: file '{filename}' not found for user '{session['user']}'")
        return "File not found"

    filepath, stored_password, crypto_mode, enc_aes_key, ecc_ephemeral_pub, file_nonce, wrap_nonce = file

    if request.method == "GET":
        error = request.args.get("error")

        # Start 30-second access timer
        session["download_expiry_" + filename] = (datetime.now() + timedelta(seconds=30)).isoformat()
        debug_log(f"DOWNLOAD PAGE OPENED for '{filename}'")
        debug_log("30-second file access timer started")

        return render_template("file_password.html", filename=filename, error=error)

    debug_log("DOWNLOAD STARTED")
    debug_log(f"Requested file: {filename}")
    debug_log(f"Stored crypto mode: {crypto_mode}")

    # Expiry check
    download_expiry_key = "download_expiry_" + filename
    download_expiry_value = session.get(download_expiry_key)

    if not download_expiry_value:
        debug_log("Download failed: no download session timer found")
        return render_template("file_password.html", filename=filename, error="expired")

    download_expiry_time = datetime.fromisoformat(download_expiry_value)

    if datetime.now() > download_expiry_time:
        session.pop(download_expiry_key, None)
        debug_log("Download failed: file access session expired")
        return render_template("file_password.html", filename=filename, error="expired")

    entered_password = request.form["password"]

    try:
        if isinstance(stored_password, memoryview):
            stored_password = stored_password.tobytes()
        elif isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        if not bcrypt.checkpw(entered_password.encode("utf-8"), stored_password):
            debug_log("File password verification failed")
            return redirect(f"/download/{filename}?error=wrong_password")

        debug_log("File password verified successfully using bcrypt")

    except Exception as e:
        debug_log(f"ERROR DURING FILE PASSWORD CHECK: {e}")
        return redirect(f"/download/{filename}?error=wrong_password")

    with open(filepath, "rb") as f:
        encrypted_data = f.read()

    debug_log(f"Encrypted file loaded from disk. Size: {len(encrypted_data)} bytes")

    try:
        if crypto_mode == "ECC":
            aes_key = ecc_decrypt_aes_key(enc_aes_key, wrap_nonce, ecc_ephemeral_pub)
            debug_log("ECC decryption used for AES key")

        elif crypto_mode == "ELGAMAL":
            aes_key = elgamal_decrypt_aes_key(enc_aes_key)
            debug_log("ElGamal decryption used for AES key")

        elif crypto_mode == "RSA":
            aes_key = rsa_decrypt_key(enc_aes_key)
            debug_log("RSA decryption used for AES key")

        else:
            debug_log("Download failed: unsupported crypto mode")
            return "Unsupported crypto mode"

        debug_log("AES key recovered successfully")

    except Exception as e:
        debug_log(f"KEY DECRYPT ERROR: {e}")
        return "Unable to recover AES key"

    try:
        decrypted_data = decrypt_file_data(file_nonce, encrypted_data, aes_key)
        debug_log("AES decryption completed")
        debug_log(f"Decrypted payload size: {len(decrypted_data)} bytes")

    except Exception as e:
        debug_log(f"FILE DECRYPT ERROR: {e}")
        return "File decryption failed"

    current_index = 0

    signature_length = int.from_bytes(decrypted_data[current_index:current_index + 4], 'big')
    current_index += 4

    signature = decrypted_data[current_index:current_index + signature_length]
    current_index += signature_length

    original_data = decrypted_data[current_index:]

    debug_log(f"Extracted signature length: {signature_length} bytes")
    debug_log(f"Recovered original file size: {len(original_data)} bytes")

    if verify_signature(original_data, signature):
        debug_log("Digital signature verified successfully")
    else:
        debug_log("Digital signature verification failed")
        return "File tampered!"

    temp_path = os.path.join("uploads", "temp_" + filename.replace(".enc", ""))

    with open(temp_path, "wb") as f:
        f.write(original_data)

    debug_log(f"Temporary decrypted file created at: {temp_path}")

    session.pop(download_expiry_key, None)
    debug_log("Download timer cleared")
    debug_log("DOWNLOAD COMPLETED SUCCESSFULLY")

    return send_file(temp_path, as_attachment=True)


@app.route("/logout")
def logout():
    user = session.get("user")
    session.clear()
    debug_log(f"User '{user}' logged out")
    return redirect("/login")


if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("keys", exist_ok=True)
    debug_log("Uploads and keys directories ensured")
    app.run(debug=True)