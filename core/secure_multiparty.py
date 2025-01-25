import numpy as np
from Crypto.Protocol.SecretSharing import Shamir
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

class SecureMultipartyComputation:
    def __init__(self, total_parties, threshold):
        self.total_parties = total_parties
        self.threshold = threshold
        self.key_shares = {}

    def generate_key_shares(self, ssid):
        key = get_random_bytes(32)  # 256-bit key
        shares = Shamir.split(self.threshold, self.total_parties, key)
        self.key_shares[ssid] = shares
        return [share.hex() for _, share in shares]

    def reconstruct_key(self, ssid, shares):
        if ssid not in self.key_shares:
            raise ValueError("No shares found for this SSID")
        
        int_shares = [(i, bytes.fromhex(share)) for i, share in shares]
        key = Shamir.combine(int_shares)
        return key

    def encrypt_password(self, ssid, password):
        if ssid not in self.key_shares:
            self.generate_key_shares(ssid)
        
        key = self.reconstruct_key(ssid, [share.hex() for _, share in self.key_shares[ssid]])
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(password.encode(), AES.block_size))
        return encrypted.hex()

    def decrypt_password(self, ssid, encrypted_password, shares):
        key = self.reconstruct_key(ssid, shares)
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(bytes.fromhex(encrypted_password)), AES.block_size)
        return decrypted.decode()

    def generate_partial_retrieval(self, ssid, party_id):
        if ssid not in self.key_shares:
            raise ValueError("No shares found for this SSID")
        
        all_shares = self.key_shares[ssid]
        party_share = next((share for i, share in all_shares if i == party_id), None)
        if party_share is None:
            raise ValueError("Invalid party ID")
        
        return party_share.hex()

    def verify_share(self, ssid, party_id, share):
        if ssid not in self.key_shares:
            raise ValueError("No shares found for this SSID")
        
        all_shares = self.key_shares[ssid]
        expected_share = next((s for i, s in all_shares if i == party_id), None)
        if expected_share is None:
            raise ValueError("Invalid party ID")
        
        return share == expected_share.hex()

