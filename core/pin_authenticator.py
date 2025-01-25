from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import time
import logging

class PinAuthenticator:
    def __init__(self):
        self.salt = os.urandom(16)
        self.pepper = os.environ.get("PIN_PEPPER", "").encode()
        self.logger = logging.getLogger("audit_log")
        self.attempts = 0
        self.lockout_time = 0

    def verify_pin(self, stored_hash: bytes, entered_pin: str) -> bool:
        if self.is_locked_out():
            self.logger.warning("PIN verification attempt during lockout period")
            return False

        try:
            derived_key = self._derive_key(entered_pin)
            if derived_key == stored_hash:
                self.attempts = 0
                return True
            else:
                self.handle_failed_attempt()
                return False
        except Exception as e:
            self.logger.error(f"PIN verification error: {str(e)}")
            self.handle_failed_attempt()
            return False

    def _derive_key(self, pin: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(pin.encode() + self.pepper)

    def handle_failed_attempt(self):
        self.attempts += 1
        if self.attempts >= 5:
            self.lockout_time = time.time() + 300  # 5 minutes lockout
            self.logger.warning("Multiple failed PIN attempts. Device locked out.")
        else:
            self.logger.warning(f"Failed PIN attempt {self.attempts}")

    def is_locked_out(self):
        return time.time() < self.lockout_time
