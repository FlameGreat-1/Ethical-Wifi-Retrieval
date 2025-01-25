import os
import time
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

class BiometricAuth:
    def __init__(self):
        self.logger = logging.getLogger("audit_log")
        self.salt = os.urandom(16)
        self.attempts = 0
        self.lockout_time = 0
        self.max_attempts = 5
        self.lockout_duration = 300  # 5 minutes

    def authenticate(self, platform):
        if self.is_locked_out():
            self.logger.warning("Authentication attempt during lockout period")
            return False

        try:
            result = self._platform_specific_auth(platform)

            if result:
                self.logger.info("User authentication successful")
                self.reset_attempts()
                return True
            else:
                self.handle_failed_attempt()
                return False

        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            self.handle_failed_attempt()
            return False

    def _platform_specific_auth(self, platform):
        if platform == "android":
            from android_native import BiometricPrompt
            return BiometricPrompt().authenticate(
                "Confirm ownership to retrieve Wi-Fi password"
            )
        elif platform == "ios":
            from ios_native import LAContext
            context = LAContext()
            return context.evaluatePolicy(
                "LAPolicyDeviceOwnerAuthentication", 
                localizedReason="Authenticate to access Keychain"
            )
        else:
            raise ValueError("Unsupported platform")

    def handle_failed_attempt(self):
        self.attempts += 1
        if self.attempts >= self.max_attempts:
            self.lockout_time = time.time() + self.lockout_duration
            self.logger.warning("Multiple failed attempts. Device locked out.")
        else:
            self.logger.warning(f"Failed authentication attempt {self.attempts}")

    def is_locked_out(self):
        return time.time() < self.lockout_time

    def reset_attempts(self):
        self.attempts = 0
        self.lockout_time = 0

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def set_lockout_policy(self, max_attempts, lockout_duration):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration

    def get_attempts_remaining(self):
        return max(0, self.max_attempts - self.attempts)

    def get_lockout_time_remaining(self):
        if self.is_locked_out():
            return max(0, self.lockout_time - time.time())
        return 0
