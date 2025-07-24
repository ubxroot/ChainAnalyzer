# utils/encryption_utils.py
import hashlib
import base64
from cryptography.fernet import Fernet
from typing import str, bytes

class EncryptionUtils:
    """Encryption utilities for sensitive data."""
    
    def __init__(self):
        self.key = None
    
    def generate_key(self) -> bytes:
        """Generate encryption key."""
        self.key = Fernet.generate_key()
        return self.key
    
    def encrypt_data(self, data: str, key: bytes = None) -> str:
        """Encrypt sensitive data."""
        if not key and not self.key:
            key = self.generate_key()
        
        cipher = Fernet(key or self.key)
        encrypted_data = cipher.encrypt(data.encode())
        return base64.b64encode(encrypted_data).decode()
    
    def decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt sensitive data."""
        cipher = Fernet(key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data.decode()
    
    def hash_address(self, address: str) -> str:
        """Hash address for privacy."""
        return hashlib.sha256(address.encode()).hexdigest()
