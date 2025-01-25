import requests
import hashlib
import sys
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class KillSwitch:
    def __init__(self):
        self.revocation_list_url = "https://api.wifiretriever.com/revocation-list"
        self.public_key = self._load_compliance_key()

    def _load_compliance_key(self):
        with open("compliance_public_key.pem", "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def _verify_signature(self, data, signature):
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

    def check_revocation(self):
        try:
            response = requests.get(self.revocation_list_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if self._verify_signature(data['list'].encode(), bytes.fromhex(data['signature'])):
                    current_hash = hashlib.sha256(open(__file__, 'rb').read()).hexdigest()
                    if current_hash in data['list']:
                        sys.exit("Software has been revoked. Please contact support.")
                else:
                    raise ValueError("Invalid signature on revocation list")
        except requests.RequestException:
            # Fail-safe: if we can't verify, assume revoked
            sys.exit("Unable to verify software status. Terminating for safety.")
