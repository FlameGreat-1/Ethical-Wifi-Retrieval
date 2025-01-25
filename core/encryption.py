from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import logging

class SecureEncryptor:
    def __init__(self, platform):
        self.platform = platform
        self.logger = logging.getLogger("audit_log")
        self.key = self._derive_hardware_key()

    def _derive_hardware_key(self):
        if self.platform == "android":
            from android.security import Keystore
            ks = Keystore.getInstance("AndroidKeyStore")
            ks.load(None)
            entry = ks.getEntry("wifi_key_alias", None)
            return entry.getSecretKey()
        elif self.platform == "ios":
            from CryptoKit import SecureEnclave
            return SecureEnclave.generateKey(
                SecureEnclave.Curve.secp384r1,
                tokenID="com.wifiretriever.wifi_key"
            )
        else:
            raise NotImplementedError("Unsupported platform")

    def encrypt(self, plaintext):
        iv = os.urandom(16)
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def decrypt(self, ciphertext):
        iv = ciphertext[:16]
        tag = ciphertext[16:32]
        data = ciphertext[32:]
        cipher = Cipher(
            algorithms.AES(self.key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(128).unpadder()
        padded_plaintext = decryptor.update(data) + decryptor.finalize()
        return unpadder.update(padded_plaintext) + unpadder.finalize()
