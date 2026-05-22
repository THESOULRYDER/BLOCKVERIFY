"""
Cryptographic Utilities for BlockVerify
Handles all symmetric robust encryption using AES-256 (via cryptography Fernet engine).
Fernet guarantees that a message encrypted cannot be manipulated or read without the key.
"""

import os
from cryptography.fernet import Fernet

def get_cipher() -> Fernet:
    """Load the master AES configuration key from environment."""
    key = os.environ.get("SECRET_AES_KEY")
    if not key:
        raise EnvironmentError(
            "[FATAL] SECRET_AES_KEY is not set. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\" "
            "then add it to your .env file."
        )
    return Fernet(key)

def encrypt_data(data: bytes) -> bytes:
    """Encrypt binary data using AES key."""
    f = get_cipher()
    return f.encrypt(data)

def decrypt_data(encrypted_data: bytes) -> bytes:
    """Decrypt binary data using AES key."""
    f = get_cipher()
    return f.decrypt(encrypted_data)

def generate_new_key() -> str:
    """Generate a high-entropy URL-safe base64-encoded 32-byte key."""
    return Fernet.generate_key().decode('utf-8')
