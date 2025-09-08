import os
import base64
import json
from typing import Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self):
        # Generate ephemeral ECDH private key (P-256 curve)
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.session_active = False

    def get_public_key_pem(self) -> str:
        """Get public key in PEM format for transmission"""
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes.decode('utf-8')

    def load_peer_public_key(self, peer_public_key_pem: str) -> bool:
        """Load peer's public key from PEM format"""
        try:
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            return True
        except Exception as e:
            print(f"Error loading peer public key: {e}")
            return False

    def derive_shared_secret(self) -> bool:
        """Derive shared secret using ECDH and generate AES key"""
        try:
            if not hasattr(self, 'peer_public_key'):
                return False
            
            # Perform ECDH key exchange
            shared_key_raw = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
            
            # Derive 256-bit AES key using HKDF
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256 bits
                salt=None,
                info=b'p2p-file-sharing-v1',
                backend=default_backend()
            ).derive(shared_key_raw)
            
            self.session_active = True
            return True
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return False

    def encrypt_data(self, plaintext: bytes, associated_data: bytes = None) -> str:
        """Encrypt data using AES-256-GCM"""
        if not self.session_active or not self.shared_key:
            raise ValueError("No active encryption session")
        
        try:
            # Generate random 96-bit nonce
            nonce = os.urandom(12)
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(self.shared_key)
            
            # Encrypt and authenticate
            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
            
            # Return base64 encoded nonce + ciphertext
            encrypted_data = nonce + ciphertext
            return base64.b64encode(encrypted_data).decode('utf-8')
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt_data(self, encrypted_b64: str, associated_data: bytes = None) -> bytes:
        """Decrypt data using AES-256-GCM"""
        if not self.session_active or not self.shared_key:
            raise ValueError("No active encryption session")
        
        try:
            # Decode base64
            encrypted_data = base64.b64decode(encrypted_b64)
            
            # Extract nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            # Create AES-GCM cipher
            aesgcm = AESGCM(self.shared_key)
            
            # Decrypt and verify
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def encrypt_json(self, data: dict) -> str:
        """Encrypt JSON data"""
        json_bytes = json.dumps(data).encode('utf-8')
        return self.encrypt_data(json_bytes)

    def decrypt_json(self, encrypted_b64: str) -> dict:
        """Decrypt to JSON data"""
        decrypted_bytes = self.decrypt_data(encrypted_b64)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def get_key_fingerprint(self) -> str:
        """Get fingerprint of current session key for verification"""
        if not self.shared_key:
            return None
        
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(self.shared_key)
        fingerprint = digest.finalize()
        return base64.b64encode(fingerprint[:8]).decode('utf-8')  # First 8 bytes

    def destroy_session(self):
        """Securely destroy encryption session"""
        if self.shared_key:
            # Overwrite key memory (basic attempt)
            self.shared_key = b'\x00' * len(self.shared_key)
            self.shared_key = None
        
        self.session_active = False
        print("Encryption session destroyed")

    def __del__(self):
        """Cleanup on object destruction"""
        self.destroy_session()

# Test the crypto functionality
if __name__ == "__main__":
    # Test ECDH key exchange and AES encryption
    print("Testing ECDH + AES-256-GCM encryption...")
    
    # Create two crypto managers (Alice and Bob)
    alice = CryptoManager()
    bob = CryptoManager()
    
    # Exchange public keys
    alice_pub = alice.get_public_key_pem()
    bob_pub = bob.get_public_key_pem()
    
    print(f"Alice public key: {alice_pub[:50]}...")
    print(f"Bob public key: {bob_pub[:50]}...")
    
    # Load each other's public keys
    alice.load_peer_public_key(bob_pub)
    bob.load_peer_public_key(alice_pub)
    
    # Derive shared secrets
    alice_success = alice.derive_shared_secret()
    bob_success = bob.derive_shared_secret()
    
    print(f"Alice key derivation: {'Success' if alice_success else 'Failed'}")
    print(f"Bob key derivation: {'Success' if bob_success else 'Failed'}")
    
    # Verify same key fingerprint (proving same shared secret)
    alice_fp = alice.get_key_fingerprint()
    bob_fp = bob.get_key_fingerprint()
    
    print(f"Alice key fingerprint: {alice_fp}")
    print(f"Bob key fingerprint: {bob_fp}")
    print(f"Key agreement: {'SUCCESS' if alice_fp == bob_fp else 'FAILED'}")
    
    # Test encryption/decryption
    test_data = {"command": "UPLOAD", "filename": "test.txt", "size": 1024}
    print(f"Original data: {test_data}")
    
    # Alice encrypts
    encrypted = alice.encrypt_json(test_data)
    print(f"Encrypted: {encrypted[:50]}...")
    
    # Bob decrypts
    decrypted = bob.decrypt_json(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Cleanup
    alice.destroy_session()
    bob.destroy_session()
    
    print("\n✅ Crypto test completed successfully!")
