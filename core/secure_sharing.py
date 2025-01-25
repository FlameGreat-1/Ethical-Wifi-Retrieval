# secure_sharing.py
import secrets
import time
from cryptography.fernet import Fernet

class SecureSharing:
    def __init__(self):
        self.shared_passwords = {}

    def generate_temporary_password(self, ssid, original_password, duration):
        temp_password = secrets.token_urlsafe(16)
        expiration_time = time.time() + duration
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted_original = fernet.encrypt(original_password.encode())
        self.shared_passwords[ssid] = {
            'temp_password': temp_password,
            'expiration': expiration_time,
            'encrypted_original': encrypted_original,
            'key': key
        }
        return temp_password

    def retrieve_original_password(self, ssid, temp_password):
        if ssid not in self.shared_passwords:
            raise ValueError("No shared password for this SSID")
        
        shared_info = self.shared_passwords[ssid]
        if time.time() > shared_info['expiration']:
            del self.shared_passwords[ssid]
            raise ValueError("Shared password has expired")
        
        if temp_password != shared_info['temp_password']:
            raise ValueError("Invalid temporary password")
        
        fernet = Fernet(shared_info['key'])
        original_password = fernet.decrypt(shared_info['encrypted_original']).decode()
        del self.shared_passwords[ssid]
        return original_password

