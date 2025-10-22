import os
import base64
import json
from typing import Optional
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoManager:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.shared_key = None
        self.session_active = False
        self.exported_key_b64 = None

    def get_public_key_pem(self) -> str:
        public_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return public_bytes.decode('utf-8')

    def load_peer_public_key(self, peer_public_key_pem: str) -> bool:
        try:
            self.peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem.encode('utf-8')
            )
            return True
        except Exception as e:
            print(f"Error loading peer public key: {e}")
            return False

    def derive_shared_secret(self) -> bool:
        try:
            if not hasattr(self, 'peer_public_key') or self.peer_public_key is None:
                return False
            shared_key_raw = self.private_key.exchange(ec.ECDH(), self.peer_public_key)
            self.shared_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # 256-bit AES key
                salt=None,
                info=b'p2p-file-sharing-v1',
            ).derive(shared_key_raw)
            self.exported_key_b64 = base64.b64encode(self.shared_key).decode('utf-8')
            self.session_active = True
            return True
        except Exception as e:
            print(f"Error deriving shared secret: {e}")
            return False

    def get_aes_key_base64(self) -> Optional[str]:
        return self.exported_key_b64 if self.exported_key_b64 else None

    def encrypt_data(self, plaintext: bytes, associated_data: bytes = None) -> dict:
        if not self.session_active or not self.shared_key:
            raise ValueError("No active encryption session")
        try:
            ad = associated_data if associated_data is not None else b""
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.shared_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, ad)
            return {
                "iv": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "key": self.get_aes_key_base64()
            }
        except Exception as e:
            raise ValueError(f"Encryption failed: {e}")

    def decrypt_data(self, encrypted_b64: dict, associated_data: bytes = None) -> bytes:
        if not self.session_active or not self.shared_key:
            raise ValueError("No active encryption session")
        try:
            ad = associated_data if associated_data is not None else b""
            nonce = base64.b64decode(encrypted_b64['iv'])
            ciphertext = base64.b64decode(encrypted_b64['ciphertext'])
            aesgcm = AESGCM(self.shared_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, ad)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

    def encrypt_json(self, data: dict) -> dict:
        json_bytes = json.dumps(data).encode('utf-8')
        return self.encrypt_data(json_bytes)

    def decrypt_json(self, encrypted_b64: dict) -> dict:
        decrypted_bytes = self.decrypt_data(encrypted_b64)
        return json.loads(decrypted_bytes.decode('utf-8'))

    def get_key_fingerprint(self) -> Optional[str]:
        if not self.shared_key:
            return None
        digest = hashes.Hash(hashes.SHA256())
        digest.update(self.shared_key)
        fingerprint = digest.finalize()
        return base64.b64encode(fingerprint[:8]).decode('utf-8')

    def destroy_session(self):
        self.shared_key = None
        self.exported_key_b64 = None
        self.session_active = False
        print("Encryption session destroyed")

    def __del__(self):
        try:
            self.destroy_session()
        except Exception:
            pass
