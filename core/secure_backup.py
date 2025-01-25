# secure_backup.py
from cryptography.fernet import Fernet
import json
import os
import base64

class SecureBackup:
    def __init__(self, master_key):
        self.fernet = Fernet(master_key)

    def backup(self, data, filename):
        encrypted_data = self.fernet.encrypt(json.dumps(data).encode())
        with open(filename, 'wb') as f:
            f.write(encrypted_data)

    def restore(self, filename):
        with open(filename, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = self.fernet.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    def generate_recovery_key(self):
        recovery_key = Fernet.generate_key()
        encrypted_master_key = self.fernet.encrypt(self.fernet._key)
        return base64.urlsafe_b64encode(recovery_key + encrypted_master_key).decode()

    def recover_from_key(self, recovery_key_string):
        decoded = base64.urlsafe_b64decode(recovery_key_string.encode())
        recovery_key, encrypted_master_key = decoded[:32], decoded[32:]
        recovery_fernet = Fernet(recovery_key)
        master_key = recovery_fernet.decrypt(encrypted_master_key)
        self.fernet = Fernet(master_key)

