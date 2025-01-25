# secure_logger.py
from cryptography.fernet import Fernet
import hashlib
import json
import time

class SecureLogger:
    def __init__(self, key):
        self.fernet = Fernet(key)
        self.log_chain = []

    def log(self, event):
        timestamp = int(time.time())
        previous_hash = self.log_chain[-1]['hash'] if self.log_chain else '0' * 64
        log_entry = {
            'timestamp': timestamp,
            'event': event,
            'previous_hash': previous_hash
        }
        entry_string = json.dumps(log_entry, sort_keys=True)
        log_entry['hash'] = hashlib.sha256(entry_string.encode()).hexdigest()
        encrypted_entry = self.fernet.encrypt(entry_string.encode())
        self.log_chain.append(log_entry)
        with open('secure_log.bin', 'ab') as f:
            f.write(encrypted_entry + b'\n')

    def verify_integrity(self):
        with open('secure_log.bin', 'rb') as f:
            logs = f.readlines()
        
        reconstructed_chain = []
        for encrypted_log in logs:
            decrypted_log = self.fernet.decrypt(encrypted_log.strip())
            log_entry = json.loads(decrypted_log)
            if reconstructed_chain:
                if log_entry['previous_hash'] != reconstructed_chain[-1]['hash']:
                    return False
            reconstructed_chain.append(log_entry)
        
        return reconstructed_chain == self.log_chain

