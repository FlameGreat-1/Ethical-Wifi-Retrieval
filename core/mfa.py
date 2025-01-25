# mfa.py
import pyotp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os

class MFAManager:
    def __init__(self):
        self.secret_key = self.generate_secret_key()

    def generate_secret_key(self):
        return pyotp.random_base32()

    def generate_totp(self):
        totp = pyotp.TOTP(self.secret_key)
        return totp.now()

    def verify_totp(self, token):
        totp = pyotp.TOTP(self.secret_key)
        return totp.verify(token)

    def generate_backup_codes(self, num_codes=5):
        backup_codes = []
        for _ in range(num_codes):
            code = os.urandom(5).hex()
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            hashed_code = kdf.derive(code.encode())
            backup_codes.append((salt, hashed_code))
        return backup_codes

    def verify_backup_code(self, entered_code, stored_salt, stored_hash):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=stored_salt,
            iterations=100000,
            backend=default_backend()
        )
        derived_key = kdf.derive(entered_code.encode())
        return derived_key == stored_hash


