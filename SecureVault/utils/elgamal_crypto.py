import os
import pickle
from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse, GCD

KEY_DIR = "keys"
ELGAMAL_PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "elgamal_private.pkl")
ELGAMAL_PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "elgamal_public.pkl")


def generate_elgamal_keys():
    os.makedirs(KEY_DIR, exist_ok=True)

    # regenerate only if files do not exist
    if os.path.exists(ELGAMAL_PRIVATE_KEY_PATH) and os.path.exists(ELGAMAL_PUBLIC_KEY_PATH):
        return

    # use larger modulus
    key = ElGamal.generate(1024, Random.new().read)

    with open(ELGAMAL_PRIVATE_KEY_PATH, "wb") as f:
        pickle.dump((int(key.p), int(key.g), int(key.y), int(key.x)), f)

    with open(ELGAMAL_PUBLIC_KEY_PATH, "wb") as f:
        pickle.dump((int(key.p), int(key.g), int(key.y)), f)


def load_elgamal_public_key():
    with open(ELGAMAL_PUBLIC_KEY_PATH, "rb") as f:
        p, g, y = pickle.load(f)
    return ElGamal.construct((int(p), int(g), int(y)))


def load_elgamal_private_key():
    with open(ELGAMAL_PRIVATE_KEY_PATH, "rb") as f:
        p, g, y, x = pickle.load(f)
    return ElGamal.construct((int(p), int(g), int(y), int(x)))


def elgamal_encrypt_aes_key(aes_key: bytes):
    pub = load_elgamal_public_key()

    p = int(pub.p)
    g = int(pub.g)
    y = int(pub.y)

    m = bytes_to_long(aes_key)

    if m >= p:
        raise ValueError("AES key too large for ElGamal modulus")

    while True:
        k = bytes_to_long(Random.get_random_bytes(32))
        k = int(k % (p - 1))
        if 1 < k < p - 1 and GCD(k, p - 1) == 1:
            break

    c1 = pow(g, k, p)
    s = pow(y, k, p)
    c2 = (m * s) % p

    return pickle.dumps((int(c1), int(c2)))


def elgamal_decrypt_aes_key(cipher_blob: bytes):
    priv = load_elgamal_private_key()

    p = int(priv.p)
    x = int(priv.x)

    c1, c2 = pickle.loads(cipher_blob)
    c1 = int(c1)
    c2 = int(c2)

    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p

    aes_key = long_to_bytes(m)
    return aes_key.rjust(32, b'\x00')[-32:]