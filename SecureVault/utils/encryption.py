import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key():
    return os.urandom(32)  # AES-256

def encrypt_file_data(data: bytes, aes_key: bytes):
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce, ciphertext

def decrypt_file_data(nonce: bytes, ciphertext: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)