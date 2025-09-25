"""
Cryptographic Utilities Module
Provides encryption/decryption and key management functionality.
"""

import hashlib
import secrets
import base64
from typing import Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


class CryptoManager:
    """Handles encryption, decryption, and key management for secure storage."""
    
    def __init__(self, iterations: int = 100000):
        """
        Initialize crypto manager.
        
        Args:
            iterations: Number of PBKDF2 iterations for key derivation
        """
        self.iterations = iterations
        self.key_size = 32  # 256 bits
        self.iv_size = 16   # 128 bits
        self.salt_size = 32 # 256 bits
        
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """
        Derive encryption key from password using PBKDF2.
        
        Args:
            password: Master password
            salt: Cryptographic salt
            
        Returns:
            Derived encryption key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode('utf-8'))
    
    def generate_salt(self) -> bytes:
        """
        Generate a cryptographically secure salt.
        
        Returns:
            Random salt bytes
        """
        return secrets.token_bytes(self.salt_size)
    
    def generate_iv(self) -> bytes:
        """
        Generate a cryptographically secure initialization vector.
        
        Returns:
            Random IV bytes
        """
        return secrets.token_bytes(self.iv_size)
    
    def encrypt(self, data: str, password: str) -> str:
        """
        Encrypt data using AES-256-CBC.
        
        Args:
            data: Data to encrypt
            password: Master password for encryption
            
        Returns:
            Base64 encoded encrypted data with salt and IV
        """
        try:
            # Generate salt and IV
            salt = self.generate_salt()
            iv = self.generate_iv()
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Encrypt data
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # Pad data to block size (PKCS7 padding)
            padded_data = self._pad_data(data.encode('utf-8'))
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine salt + IV + encrypted_data
            combined = salt + iv + encrypted_data
            
            # Return base64 encoded result
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            raise RuntimeError(f"Encryption failed: {e}")
    
    def decrypt(self, encrypted_data: str, password: str) -> str:
        """
        Decrypt data using AES-256-CBC.
        
        Args:
            encrypted_data: Base64 encoded encrypted data
            password: Master password for decryption
            
        Returns:
            Decrypted data string
        """
        try:
            # Decode from base64
            combined = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract salt, IV, and encrypted data
            salt = combined[:self.salt_size]
            iv = combined[self.salt_size:self.salt_size + self.iv_size]
            ciphertext = combined[self.salt_size + self.iv_size:]
            
            # Derive key
            key = self.derive_key(password, salt)
            
            # Decrypt data
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove padding
            data = self._unpad_data(padded_data)
            
            return data.decode('utf-8')
            
        except Exception as e:
            raise RuntimeError(f"Decryption failed: {e}")
    
    def _pad_data(self, data: bytes) -> bytes:
        """
        Apply PKCS7 padding to data.
        
        Args:
            data: Data to pad
            
        Returns:
            Padded data
        """
        block_size = 16  # AES block size
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length]) * padding_length
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """
        Remove PKCS7 padding from data.
        
        Args:
            padded_data: Padded data
            
        Returns:
            Unpadded data
        """
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def hash_password(self, password: str, salt: bytes = None) -> Tuple[str, bytes]:
        """
        Hash a password for storage verification.
        
        Args:
            password: Password to hash
            salt: Optional salt (generates new one if None)
            
        Returns:
            Tuple of (hash_string, salt_bytes)
        """
        if salt is None:
            salt = self.generate_salt()
        
        # Use PBKDF2 for password hashing
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        
        password_hash = kdf.derive(password.encode('utf-8'))
        hash_string = base64.b64encode(salt + password_hash).decode('utf-8')
        
        return hash_string, salt
    
    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Verify a password against a stored hash.
        
        Args:
            password: Password to verify
            stored_hash: Previously stored password hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Decode stored hash
            combined = base64.b64decode(stored_hash.encode('utf-8'))
            salt = combined[:self.salt_size]
            stored_password_hash = combined[self.salt_size:]
            
            # Hash the provided password with the same salt
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.key_size,
                salt=salt,
                iterations=self.iterations,
                backend=default_backend()
            )
            
            password_hash = kdf.derive(password.encode('utf-8'))
            
            # Compare hashes using constant-time comparison
            return secrets.compare_digest(password_hash, stored_password_hash)
            
        except Exception:
            return False
    
    def generate_secure_token(self, length: int = 32) -> str:
        """
        Generate a cryptographically secure random token.
        
        Args:
            length: Token length in bytes
            
        Returns:
            Base64 encoded token
        """
        token_bytes = secrets.token_bytes(length)
        return base64.b64encode(token_bytes).decode('utf-8')
    
    def secure_compare(self, a: str, b: str) -> bool:
        """
        Perform constant-time string comparison.
        
        Args:
            a: First string
            b: Second string
            
        Returns:
            True if strings are equal, False otherwise
        """
        return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    
    def encrypt_file(self, file_path: str, password: str, output_path: str = None):
        """
        Encrypt a file.
        
        Args:
            file_path: Path to file to encrypt
            password: Encryption password
            output_path: Output path (default: original + .enc)
        """
        if output_path is None:
            output_path = file_path + '.enc'
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Convert bytes to string for encryption function
            data_str = base64.b64encode(data).decode('utf-8')
            encrypted_data = self.encrypt(data_str, password)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise RuntimeError(f"File encryption failed: {e}")
    
    def decrypt_file(self, encrypted_file_path: str, password: str, output_path: str = None):
        """
        Decrypt a file.
        
        Args:
            encrypted_file_path: Path to encrypted file
            password: Decryption password
            output_path: Output path (default: removes .enc extension)
        """
        if output_path is None:
            if encrypted_file_path.endswith('.enc'):
                output_path = encrypted_file_path[:-4]
            else:
                output_path = encrypted_file_path + '.decrypted'
        
        try:
            with open(encrypted_file_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            decrypted_str = self.decrypt(encrypted_data, password)
            # Convert back from base64 to original bytes
            data = base64.b64decode(decrypted_str.encode('utf-8'))
            
            with open(output_path, 'wb') as f:
                f.write(data)
                
        except Exception as e:
            raise RuntimeError(f"File decryption failed: {e}")
    
    def get_entropy_estimate(self) -> float:
        """
        Get an estimate of system entropy (for security assessment).
        
        Returns:
            Estimated entropy bits
        """
        try:
            # Generate some random data and analyze it
            sample_data = secrets.token_bytes(1024)
            
            # Calculate Shannon entropy
            byte_counts = [0] * 256
            for byte in sample_data:
                byte_counts[byte] += 1
            
            entropy = 0.0
            data_len = len(sample_data)
            
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy * 8  # Convert to bits
            
        except Exception:
            return 0.0  # Unknown entropy
    
    def wipe_memory(self, sensitive_data: str):
        """
        Attempt to securely wipe sensitive data from memory.
        Note: This is best-effort in Python due to string immutability.
        
        Args:
            sensitive_data: Data to wipe
        """
        # In Python, strings are immutable, so we can't truly wipe them
        # This is more of a placeholder for best practices
        # In a production system, you might use libraries like ctypes
        # to manipulate memory more directly
        pass