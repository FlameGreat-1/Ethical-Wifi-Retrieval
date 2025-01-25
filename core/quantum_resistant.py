# quantum_resistant.py
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class QuantumResistantCrypto:
    def __init__(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

    def generate_shared_key(self, peer_public_key):
        shared_key = self.private_key.exchange(peer_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        return derived_key

    def encrypt(self, message, shared_key):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message) + encryptor.finalize()
        return (iv, ciphertext, encryptor.tag)

    def decrypt(self, iv, ciphertext, tag, shared_key):
        cipher = Cipher(algorithms.AES(shared_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

