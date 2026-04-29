from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

KEY_DIR = "keys"
PRIVATE_KEY = os.path.join(KEY_DIR, "rsa_private.pem")
PUBLIC_KEY = os.path.join(KEY_DIR, "rsa_public.pem")

def generate_rsa_keys():
    if os.path.exists(PRIVATE_KEY):
        return

    key = RSA.generate(2048)

    with open(PRIVATE_KEY, "wb") as f:
        f.write(key.export_key())

    with open(PUBLIC_KEY, "wb") as f:
        f.write(key.publickey().export_key())


def rsa_encrypt_key(aes_key):
    with open(PUBLIC_KEY, "rb") as f:
        pub_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(pub_key)
    return cipher.encrypt(aes_key)


def rsa_decrypt_key(enc_key):
    with open(PRIVATE_KEY, "rb") as f:
        priv_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(priv_key)
    return cipher.decrypt(enc_key)