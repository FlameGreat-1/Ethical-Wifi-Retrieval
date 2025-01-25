
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import datetime
import json

class AuditLogger:
    def __init__(self):
        self.private_key = self._load_audit_signing_key()
        
    def log(self, event_type, details):
        log_entry = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "event": event_type,
            "details": details,
            "signature": self._sign_log_entry(details)
        }
        with open("audit.log", "a") as f:
            f.write(json.dumps(log_entry) + "\n")
    
    def _sign_log_entry(self, data):
        return self.private_key.sign(
            json.dumps(data).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
