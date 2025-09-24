"""
Uniqueness Tracker Module
Tracks password usage and prevents reuse across different accounts.
"""

import hashlib
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import difflib


class UniquenessTracker:
    """Tracks password uniqueness and prevents reuse across accounts."""
    
    def __init__(self, storage):
        """
        Initialize the uniqueness tracker.
        
        Args:
            storage: Storage instance for data persistence
        """
        self.storage = storage
        self.similarity_threshold = 0.7  # 70% similarity threshold
    
    def _hash_password(self, password: str) -> str:
        """
        Create a secure hash of the password for storage.
        
        Args:
            password: Raw password string
            
        Returns:
            SHA-256 hash of the password
        """
        return hashlib.sha256(password.encode('utf-8')).hexdigest()
    
    def _calculate_similarity(self, password1: str, password2: str) -> float:
        """
        Calculate similarity between two passwords.
        
        Args:
            password1: First password
            password2: Second password
            
        Returns:
            Similarity ratio (0.0 to 1.0)
        """
        return difflib.SequenceMatcher(None, password1.lower(), password2.lower()).ratio()
    
    def is_password_unique(self, password: str, account: str) -> bool:
        """
        Check if a password is unique for the given account.
        
        Args:
            password: Password to check
            account: Account name
            
        Returns:
            True if password is unique, False otherwise
        """
        try:
            # Load existing password data
            password_data = self.storage.load_password_data()
            
            # Check exact matches first
            password_hash = self._hash_password(password)
            if password_hash in password_data.get('hashes', {}):
                existing_accounts = password_data['hashes'][password_hash]['accounts']
                if any(acc != account for acc in existing_accounts):
                    return False
            
            # Check similarity against all stored passwords
            stored_passwords = self.storage.get_decrypted_passwords()
            for stored_account, stored_passwords_list in stored_passwords.items():
                if stored_account == account:
                    continue  # Skip same account
                    
                for stored_password in stored_passwords_list:
                    similarity = self._calculate_similarity(password, stored_password)
                    if similarity >= self.similarity_threshold:
                        return False
            
            return True
            
        except Exception as e:
            # Log error and allow password (fail open)
            print(f"Warning: Error checking password uniqueness: {e}")
            return True
    
    def store_password(self, password: str, account: str) -> None:
        """
        Store a password hash and metadata.
        
        Args:
            password: Password to store
            account: Account name
        """
        try:
            password_hash = self._hash_password(password)
            timestamp = datetime.now().isoformat()
            
            # Load existing data
            password_data = self.storage.load_password_data()
            
            # Initialize structure if needed
            if 'hashes' not in password_data:
                password_data['hashes'] = {}
            if 'accounts' not in password_data:
                password_data['accounts'] = {}
            
            # Store hash data
            if password_hash not in password_data['hashes']:
                password_data['hashes'][password_hash] = {
                    'accounts': [],
                    'created': timestamp,
                    'last_used': timestamp
                }
            
            # Add account to hash record
            if account not in password_data['hashes'][password_hash]['accounts']:
                password_data['hashes'][password_hash]['accounts'].append(account)
            
            password_data['hashes'][password_hash]['last_used'] = timestamp
            
            # Store account data
            if account not in password_data['accounts']:
                password_data['accounts'][account] = {
                    'passwords': [],
                    'created': timestamp,
                    'last_updated': timestamp
                }
            
            # Add password hash to account
            if password_hash not in password_data['accounts'][account]['passwords']:
                password_data['accounts'][account]['passwords'].append(password_hash)
            
            password_data['accounts'][account]['last_updated'] = timestamp
            
            # Save updated data
            self.storage.save_password_data(password_data)
            
            # Also store encrypted password for similarity checking
            self.storage.store_encrypted_password(account, password)
            
        except Exception as e:
            raise RuntimeError(f"Failed to store password: {e}")
    
    def get_account_passwords(self, account: str) -> List[str]:
        """
        Get all password hashes for an account.
        
        Args:
            account: Account name
            
        Returns:
            List of password hashes
        """
        try:
            password_data = self.storage.load_password_data()
            
            if account in password_data.get('accounts', {}):
                return password_data['accounts'][account]['passwords']
            
            return []
            
        except Exception:
            return []
    
    def get_password_date(self, password_hash: str) -> str:
        """
        Get the creation date of a password hash.
        
        Args:
            password_hash: Password hash
            
        Returns:
            Creation date string
        """
        try:
            password_data = self.storage.load_password_data()
            
            if password_hash in password_data.get('hashes', {}):
                created = password_data['hashes'][password_hash]['created']
                # Parse and format the date
                dt = datetime.fromisoformat(created)
                return dt.strftime("%Y-%m-%d %H:%M")
            
            return "Unknown"
            
        except Exception:
            return "Unknown"
    
    def remove_password(self, account: str, password: str) -> bool:
        """
        Remove a password from tracking.
        
        Args:
            account: Account name
            password: Password to remove
            
        Returns:
            True if removed successfully, False otherwise
        """
        try:
            password_hash = self._hash_password(password)
            password_data = self.storage.load_password_data()
            
            # Remove from account record
            if (account in password_data.get('accounts', {}) and
                password_hash in password_data['accounts'][account]['passwords']):
                password_data['accounts'][account]['passwords'].remove(password_hash)
                
                # Remove account from hash record
                if password_hash in password_data.get('hashes', {}):
                    if account in password_data['hashes'][password_hash]['accounts']:
                        password_data['hashes'][password_hash]['accounts'].remove(account)
                    
                    # If no accounts use this hash, remove it entirely
                    if not password_data['hashes'][password_hash]['accounts']:
                        del password_data['hashes'][password_hash]
                
                # If account has no passwords, remove it
                if not password_data['accounts'][account]['passwords']:
                    del password_data['accounts'][account]
                
                # Save updated data
                self.storage.save_password_data(password_data)
                return True
            
            return False
            
        except Exception as e:
            print(f"Error removing password: {e}")
            return False
    
    def get_similar_passwords(self, password: str, threshold: float = None) -> List[Tuple[str, str, float]]:
        """
        Find passwords similar to the given one.
        
        Args:
            password: Password to compare against
            threshold: Similarity threshold (default uses instance threshold)
            
        Returns:
            List of tuples (account, similar_password, similarity_score)
        """
        if threshold is None:
            threshold = self.similarity_threshold
        
        similar_passwords = []
        
        try:
            stored_passwords = self.storage.get_decrypted_passwords()
            
            for account, passwords in stored_passwords.items():
                for stored_password in passwords:
                    similarity = self._calculate_similarity(password, stored_password)
                    if similarity >= threshold:
                        similar_passwords.append((account, stored_password, similarity))
            
            # Sort by similarity (highest first)
            similar_passwords.sort(key=lambda x: x[2], reverse=True)
            
        except Exception as e:
            print(f"Error finding similar passwords: {e}")
        
        return similar_passwords
    
    def get_total_count(self) -> int:
        """
        Get total number of passwords being tracked.
        
        Returns:
            Total password count
        """
        try:
            password_data = self.storage.load_password_data()
            return len(password_data.get('hashes', {}))
        except Exception:
            return 0
    
    def get_unique_accounts_count(self) -> int:
        """
        Get number of unique accounts.
        
        Returns:
            Unique account count
        """
        try:
            password_data = self.storage.load_password_data()
            return len(password_data.get('accounts', {}))
        except Exception:
            return 0
    
    def get_average_strength(self) -> float:
        """
        Calculate average password strength (placeholder for now).
        
        Returns:
            Average strength score
        """
        # This would require storing strength scores with passwords
        # For now, return a placeholder value
        return 75.0
    
    def get_reused_passwords(self) -> List[Tuple[str, List[str]]]:
        """
        Get passwords that are reused across multiple accounts.
        
        Returns:
            List of tuples (password_hash, list_of_accounts)
        """
        reused = []
        
        try:
            password_data = self.storage.load_password_data()
            
            for password_hash, data in password_data.get('hashes', {}).items():
                if len(data['accounts']) > 1:
                    reused.append((password_hash, data['accounts']))
        
        except Exception:
            pass
        
        return reused
    
    def generate_security_report(self) -> Dict:
        """
        Generate a comprehensive security report.
        
        Returns:
            Dictionary containing security metrics
        """
        try:
            password_data = self.storage.load_password_data()
            
            total_passwords = len(password_data.get('hashes', {}))
            unique_accounts = len(password_data.get('accounts', {}))
            reused_passwords = self.get_reused_passwords()
            
            report = {
                'total_passwords': total_passwords,
                'unique_accounts': unique_accounts,
                'reused_count': len(reused_passwords),
                'reuse_percentage': (len(reused_passwords) / max(1, total_passwords)) * 100,
                'accounts_per_password': total_passwords / max(1, unique_accounts),
                'security_score': max(0, 100 - (len(reused_passwords) * 10))
            }
            
            return report
            
        except Exception as e:
            return {
                'error': str(e),
                'total_passwords': 0,
                'unique_accounts': 0,
                'reused_count': 0,
                'reuse_percentage': 0,
                'accounts_per_password': 0,
                'security_score': 0
            }