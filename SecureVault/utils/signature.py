from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import os

PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"

# STEP 1: Generate keys only once
if not os.path.exists(PRIVATE_KEY_FILE):
    key = RSA.generate(2048)

    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(key.export_key())

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(key.publickey().export_key())

# STEP 2: Load keys
with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = RSA.import_key(f.read())

with open(PUBLIC_KEY_FILE, "rb") as f:
    public_key = RSA.import_key(f.read())


def sign_data(data):
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(data, signature):
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False