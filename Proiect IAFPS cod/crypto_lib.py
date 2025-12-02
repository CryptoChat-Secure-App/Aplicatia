# crypto_lib.py – RSA pentru cheie + ChaCha20 pentru mesaje + Argon2 pentru parole

import os
import base64
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

# Argon2 pentru parole
from argon2 import PasswordHasher, exceptions as argon2_exceptions


# Argon2 – parole utilizatori

_ph = PasswordHasher()


def argon2_hash_password(password: str) -> str:
    """Returnează hash Argon2 pentru parolă."""
    return _ph.hash(password)


def argon2_verify_password(stored_hash: str, password: str) -> bool:
    """Verifică parola față de hash Argon2 salvat."""
    try:
        return _ph.verify(stored_hash, password)
    except argon2_exceptions.VerifyMismatchError:
        return False
    except Exception:
        return False


# RSA – pentru protejarea cheii ChaCha20 pe disc

RSA_PRIV_FILE = "chacha_rsa_private.pem"
RSA_PUB_FILE = "chacha_rsa_public.pem"
CHACHA_KEY_FILE = "common_chacha.key"      # cheia brută (32 bytes)
CHACHA_KEY_ENC_FILE = "common_chacha.enc"  # cheia criptată cu RSA (demo, doar concept)


@dataclass
class RSAKeyPair:
    private_key_pem: bytes
    public_key_pem: bytes


def rsa_generate_keypair() -> RSAKeyPair:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return RSAKeyPair(priv_pem, pub_pem)


def rsa_load_private(pem_bytes: bytes):
    return serialization.load_pem_private_key(pem_bytes, password=None)


def rsa_load_public(pem_bytes: bytes):
    return serialization.load_pem_public_key(pem_bytes)


def rsa_encrypt(pub_pem: bytes, plaintext: bytes) -> str:
    """Criptează cu cheie publică RSA și întoarce base64."""
    pub = rsa_load_public(pub_pem)
    ct = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ct).decode("utf-8")


def rsa_decrypt(priv_pem: bytes, token_b64: str) -> bytes:
    """Decriptează base64 cu cheie privată RSA."""
    priv = rsa_load_private(priv_pem)
    ct = base64.b64decode(token_b64)
    pt = priv.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return pt


# Cheia comună ChaCha20 – generare + stocare

def _generate_and_store_new_chacha_key() -> bytes:
    """
    Generăm:
      - keypair RSA (dacă nu există încă)
      - o cheie ChaCha20 random (32 bytes)
      - o salvăm brut în CHACHA_KEY_FILE
      - o salvăm și criptată cu RSA publică în CHACHA_KEY_ENC_FILE (doar demonstrativ)
    """
    # 1) generăm keypair RSA dacă nu există
    if not (os.path.exists(RSA_PRIV_FILE) and os.path.exists(RSA_PUB_FILE)):
        kp = rsa_generate_keypair()
        with open(RSA_PRIV_FILE, "wb") as f:
            f.write(kp.private_key_pem)
        with open(RSA_PUB_FILE, "wb") as f:
            f.write(kp.public_key_pem)

    # 2) generăm cheia ChaCha20 (32 bytes)
    key = secrets.token_bytes(32)

    # 3) salvăm brut (folosit efectiv de server + clienți)
    with open(CHACHA_KEY_FILE, "wb") as f:
        f.write(key)

    # 4) salvăm și criptat (doar ca să demonstrăm folosirea RSA)
    with open(RSA_PUB_FILE, "rb") as f:
        pub_pem = f.read()
    token_b64 = rsa_encrypt(pub_pem, key)
    with open(CHACHA_KEY_ENC_FILE, "w", encoding="utf-8") as f:
        f.write(token_b64)

    return key


def chacha20_load_common_key() -> bytes:
    """
    În practică:
      - serverul și toți clienții trebuie să aibă ACELAȘI fișier common_chacha.key.
      - Persoana 1 îl generează (prima rulare) și apoi îl trimite celorlalți.

    RSA este folosit doar ca să salvăm în plus cheia criptată în common_chacha.enc,
    pentru a demonstra conceptul „cheie protejată cu RSA”.
    """
    if os.path.exists(CHACHA_KEY_FILE):
        with open(CHACHA_KEY_FILE, "rb") as f:
            key = f.read()
        if len(key) != 32:
            raise ValueError("Cheia ChaCha20 din common_chacha.key nu are 32 de bytes.")
        return key

    key = _generate_and_store_new_chacha_key()
    return key


# pentru compatibilitate cu versiunile vechi
def chacha20_load_or_create_common_key() -> bytes:
    return chacha20_load_common_key()


# ChaCha20-Poly1305 – criptarea efectivă a mesajelor

def chacha20_encrypt(key: bytes, plaintext: str) -> str:
    """
    Întoarce base64(nonce || ciphertext+tag).
    """
    aead = ChaCha20Poly1305(key)
    nonce = secrets.token_bytes(12)
    ct = aead.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")


def chacha20_decrypt(key: bytes, token_b64: str) -> str:
    raw = base64.b64decode(token_b64)
    nonce, ct = raw[:12], raw[12:]
    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(nonce, ct, None)
    return pt.decode("utf-8")
