# zkp.py
import random
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

class ZeroKnowledgeProver:
    def __init__(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def generate_challenge(self):
        return random.randint(0, 1)

    def generate_proof(self, password, challenge):
        if challenge == 0:
            # Prove knowledge of password without revealing it
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(password.encode())
            hashed_password = hash_obj.finalize()
            signature = self.private_key.sign(
                hashed_password,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
               
                hashes.SHA256()
            )
            return signature
        else:
            # Prove knowledge of private key
            message = b"I know the private key"
            signature = self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature

    def verify_proof(self, password, challenge, proof):
        if challenge == 0:
            hash_obj = hashes.Hash(hashes.SHA256())
            hash_obj.update(password.encode())
            hashed_password = hash_obj.finalize()
            try:
                self.public_key.verify(
                    proof,
                    hashed_password,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except:
                return False
        else:
            message = b"I know the private key"
            try:
                self.public_key.verify(
                    proof,
                    message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True
            except:
                return False



