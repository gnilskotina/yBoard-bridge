import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Cipher:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("TUNNEL_KEY должен содержать 32 байта (64 hex-символа)")
        self.aes = AESGCM(key)

    def encrypt(self, plaintext: bytes, aad: bytes | None = None) -> bytes:
        nonce = os.urandom(12)
        return nonce + self.aes.encrypt(nonce, plaintext, aad)

    def decrypt(self, blob: bytes, aad: bytes | None = None) -> bytes:
        if len(blob) < 28:
            raise ValueError("Слишком короткий шифртекст")
        return self.aes.decrypt(blob[:12], blob[12:], aad)
