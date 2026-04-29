import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_pem_private_key,
    load_pem_public_key
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_DIR = "keys"
ECC_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "ecc_private.pem")
ECC_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "ecc_public.pem")

def generate_ecc_keys():
    os.makedirs(KEY_DIR, exist_ok=True)

    if os.path.exists(ECC_PRIVATE_KEY_PATH) and os.path.exists(ECC_PUBLIC_KEY_PATH):
        return

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(ECC_PRIVATE_KEY_PATH, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption()
            )
        )

    with open(ECC_PUBLIC_KEY_PATH, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
        )

def load_ecc_private_key():
    with open(ECC_PRIVATE_KEY_PATH, "rb") as f:
        return load_pem_private_key(f.read(), password=None)

def load_ecc_public_key():
    with open(ECC_PUBLIC_KEY_PATH, "rb") as f:
        return load_pem_public_key(f.read())

def derive_shared_key(private_key, public_key):
    shared_secret = private_key.exchange(ec.ECDH(), public_key)

    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"securevault-ecc-wrap"
    ).derive(shared_secret)

    return derived_key

def ecc_encrypt_aes_key(aes_key: bytes):
    recipient_public_key = load_ecc_public_key()

    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()

    wrap_key = derive_shared_key(ephemeral_private_key, recipient_public_key)

    aesgcm = AESGCM(wrap_key)
    wrap_nonce = os.urandom(12)
    encrypted_aes_key = aesgcm.encrypt(wrap_nonce, aes_key, None)

    ephemeral_pub_bytes = ephemeral_public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    return encrypted_aes_key, wrap_nonce, ephemeral_pub_bytes

def ecc_decrypt_aes_key(encrypted_aes_key: bytes, wrap_nonce: bytes, ephemeral_pub_bytes: bytes):
    recipient_private_key = load_ecc_private_key()
    ephemeral_public_key = load_pem_public_key(ephemeral_pub_bytes)

    wrap_key = derive_shared_key(recipient_private_key, ephemeral_public_key)

    aesgcm = AESGCM(wrap_key)
    aes_key = aesgcm.decrypt(wrap_nonce, encrypted_aes_key, None)

    return aes_key