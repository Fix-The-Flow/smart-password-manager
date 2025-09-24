"""
Storage Management Module
Handles encrypted data persistence for all application data.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from .config import Config
from .crypto import CryptoManager


class Storage:
    """Manages encrypted storage of application data."""
    
    def __init__(self, config: Config = None):
        """
        Initialize storage manager.
        
        Args:
            config: Configuration instance (creates new one if None)
        """
        self.config = config if config else Config()
        self.crypto = CryptoManager(
            iterations=self.config.get('security.password_hash_iterations', 100000)
        )
        self._master_password = None
        self._master_password_hash = None
    
    def set_master_password(self, password: str):
        """
        Set and store the master password hash.
        
        Args:
            password: Master password to store
        """
        try:
            # Hash the password for verification
            password_hash, salt = self.crypto.hash_password(password)
            
            # Store the hash
            master_file = self.config.get_data_dir() / 'master.key'
            with open(master_file, 'w', encoding='utf-8') as f:
                f.write(password_hash)
            
            # Keep password in memory for encryption operations
            self._master_password = password
            self._master_password_hash = password_hash
            
        except Exception as e:
            raise RuntimeError(f"Failed to set master password: {e}")
    
    def verify_master_password(self, password: str) -> bool:
        """
        Verify the master password.
        
        Args:
            password: Password to verify
            
        Returns:
            True if password is correct, False otherwise
        """
        try:
            master_file = self.config.get_data_dir() / 'master.key'
            
            if not master_file.exists():
                return False
            
            with open(master_file, 'r', encoding='utf-8') as f:
                stored_hash = f.read().strip()
            
            if self.crypto.verify_password(password, stored_hash):
                self._master_password = password
                self._master_password_hash = stored_hash
                return True
            
            return False
            
        except Exception:
            return False
    
    def master_password_exists(self) -> bool:
        """
        Check if master password is set.
        
        Returns:
            True if master password exists, False otherwise
        """
        master_file = self.config.get_data_dir() / 'master.key'
        return master_file.exists()
    
    def _ensure_master_password(self):
        """Ensure master password is available for operations."""
        if not self._master_password:
            raise RuntimeError("Master password not set. Please authenticate first.")
    
    def _save_encrypted_data(self, data: Dict[str, Any], filename: str):
        """
        Save encrypted data to file.
        
        Args:
            data: Data to encrypt and save
            filename: Target filename
        """
        self._ensure_master_password()
        
        try:
            # Convert to JSON string
            json_data = json.dumps(data, ensure_ascii=False, indent=None)
            
            # Encrypt the data
            encrypted_data = self.crypto.encrypt(json_data, self._master_password)
            
            # Save to file
            file_path = self.config.get_data_dir() / filename
            
            # Create backup if file exists and auto-backup is enabled
            if file_path.exists() and self.config.get('storage.auto_backup', True):
                self._create_backup(file_path)
            
            # Write encrypted data
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(encrypted_data)
                
        except Exception as e:
            raise RuntimeError(f"Failed to save encrypted data: {e}")
    
    def _load_encrypted_data(self, filename: str) -> Dict[str, Any]:
        """
        Load and decrypt data from file.
        
        Args:
            filename: Source filename
            
        Returns:
            Decrypted data dictionary
        """
        self._ensure_master_password()
        
        try:
            file_path = self.config.get_data_dir() / filename
            
            if not file_path.exists():
                return {}
            
            # Read encrypted data
            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            json_data = self.crypto.decrypt(encrypted_data, self._master_password)
            
            # Parse JSON
            return json.loads(json_data)
            
        except Exception as e:
            # Return empty dict on error (fail gracefully)
            print(f"Warning: Could not load {filename}: {e}")
            return {}
    
    def save_password_data(self, data: Dict[str, Any]):
        """Save password tracking data."""
        filename = self.config.get('data_paths.passwords_file', 'passwords.enc')
        self._save_encrypted_data(data, filename)
    
    def load_password_data(self) -> Dict[str, Any]:
        """Load password tracking data."""
        filename = self.config.get('data_paths.passwords_file', 'passwords.enc')
        return self._load_encrypted_data(filename)
    
    def save_reminders_data(self, data: Dict[str, Any]):
        """Save reminders data."""
        filename = self.config.get('data_paths.reminders_file', 'reminders.enc')
        self._save_encrypted_data(data, filename)
    
    def load_reminders_data(self) -> Dict[str, Any]:
        """Load reminders data."""
        filename = self.config.get('data_paths.reminders_file', 'reminders.enc')
        return self._load_encrypted_data(filename)
    
    def save_premium_data(self, data: Dict[str, Any]):
        """Save premium features data."""
        filename = self.config.get('data_paths.premium_file', 'premium.enc')
        self._save_encrypted_data(data, filename)
    
    def load_premium_data(self) -> Dict[str, Any]:
        """Load premium features data."""
        filename = self.config.get('data_paths.premium_file', 'premium.enc')
        return self._load_encrypted_data(filename)
    
    def store_encrypted_password(self, account: str, password: str):
        """
        Store an encrypted password for similarity checking.
        
        Args:
            account: Account name
            password: Password to store
        """
        try:
            # Load existing encrypted passwords
            passwords_data = self._load_encrypted_data('stored_passwords.enc')
            
            if 'passwords' not in passwords_data:
                passwords_data['passwords'] = {}
            
            if account not in passwords_data['passwords']:
                passwords_data['passwords'][account] = []
            
            # Add password to account (avoiding duplicates)
            if password not in passwords_data['passwords'][account]:
                passwords_data['passwords'][account].append(password)
            
            # Save back to file
            self._save_encrypted_data(passwords_data, 'stored_passwords.enc')
            
        except Exception as e:
            raise RuntimeError(f"Failed to store encrypted password: {e}")
    
    def get_decrypted_passwords(self) -> Dict[str, List[str]]:
        """
        Get decrypted passwords for similarity checking.
        
        Returns:
            Dictionary mapping accounts to lists of passwords
        """
        try:
            passwords_data = self._load_encrypted_data('stored_passwords.enc')
            return passwords_data.get('passwords', {})
        except Exception:
            return {}
    
    def _create_backup(self, file_path: Path):
        """
        Create a backup of a file.
        
        Args:
            file_path: Path to file to backup
        """
        try:
            backup_dir = self.config.get_backup_dir()
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{file_path.name}.{timestamp}.backup"
            backup_path = backup_dir / backup_name
            
            shutil.copy2(file_path, backup_path)
            
            # Clean up old backups
            self._cleanup_old_backups(file_path.name)
            
        except Exception as e:
            print(f"Warning: Could not create backup: {e}")
    
    def _cleanup_old_backups(self, original_filename: str):
        """
        Clean up old backup files.
        
        Args:
            original_filename: Original filename to clean backups for
        """
        try:
            backup_dir = self.config.get_backup_dir()
            max_backups = self.config.get('storage.backup_count', 5)
            
            # Find all backup files for this original file
            backup_files = []
            for backup_file in backup_dir.glob(f"{original_filename}.*.backup"):
                backup_files.append(backup_file)
            
            # Sort by modification time (newest first)
            backup_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            # Remove old backups
            for old_backup in backup_files[max_backups:]:
                old_backup.unlink()
                
        except Exception as e:
            print(f"Warning: Could not cleanup old backups: {e}")
    
    def export_all_data(self) -> Dict[str, Any]:
        """
        Export all application data.
        
        Returns:
            Dictionary containing all data
        """
        self._ensure_master_password()
        
        try:
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'version': '1.0',
                'data': {
                    'passwords': self.load_password_data(),
                    'reminders': self.load_reminders_data(),
                    'premium': self.load_premium_data(),
                    'stored_passwords': self.get_decrypted_passwords(),
                    'config': self.config.get_all_settings()
                }
            }
            
            return export_data
            
        except Exception as e:
            raise RuntimeError(f"Failed to export data: {e}")
    
    def import_all_data(self, import_data: Dict[str, Any], merge: bool = False):
        """
        Import application data.
        
        Args:
            import_data: Data to import
            merge: Whether to merge with existing data or replace
        """
        self._ensure_master_password()
        
        try:
            if 'data' not in import_data:
                raise ValueError("Invalid import data format")
            
            data = import_data['data']
            
            # Import each data type
            if 'passwords' in data:
                if merge:
                    existing = self.load_password_data()
                    # Simple merge - would need more sophisticated logic for production
                    existing.update(data['passwords'])
                    self.save_password_data(existing)
                else:
                    self.save_password_data(data['passwords'])
            
            if 'reminders' in data:
                if merge:
                    existing = self.load_reminders_data()
                    existing.update(data['reminders'])
                    self.save_reminders_data(existing)
                else:
                    self.save_reminders_data(data['reminders'])
            
            if 'premium' in data:
                if merge:
                    existing = self.load_premium_data()
                    existing.update(data['premium'])
                    self.save_premium_data(existing)
                else:
                    self.save_premium_data(data['premium'])
            
            # Import stored passwords for similarity checking
            if 'stored_passwords' in data:
                self._save_encrypted_data(
                    {'passwords': data['stored_passwords']}, 
                    'stored_passwords.enc'
                )
            
        except Exception as e:
            raise RuntimeError(f"Failed to import data: {e}")
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """
        Get storage statistics.
        
        Returns:
            Dictionary with storage information
        """
        try:
            data_dir = self.config.get_data_dir()
            backup_dir = self.config.get_backup_dir()
            
            # Calculate sizes
            data_files = list(data_dir.glob('*.enc')) + list(data_dir.glob('*.key'))
            backup_files = list(backup_dir.glob('*.backup'))
            
            total_data_size = sum(f.stat().st_size for f in data_files)
            total_backup_size = sum(f.stat().st_size for f in backup_files)
            
            stats = {
                'data_directory': str(data_dir),
                'backup_directory': str(backup_dir),
                'data_files_count': len(data_files),
                'backup_files_count': len(backup_files),
                'total_data_size_bytes': total_data_size,
                'total_backup_size_bytes': total_backup_size,
                'data_files': [f.name for f in data_files],
                'encryption_enabled': True,
                'auto_backup_enabled': self.config.get('storage.auto_backup', True)
            }
            
            return stats
            
        except Exception as e:
            return {'error': str(e)}
    
    def secure_delete_all_data(self):
        """
        Securely delete all stored data.
        Warning: This is irreversible!
        """
        try:
            data_dir = self.config.get_data_dir()
            backup_dir = self.config.get_backup_dir()
            
            # Remove all data files
            for data_file in data_dir.glob('*'):
                if data_file.is_file():
                    data_file.unlink()
            
            # Remove all backup files
            for backup_file in backup_dir.glob('*'):
                if backup_file.is_file():
                    backup_file.unlink()
            
            # Clear in-memory data
            self._master_password = None
            self._master_password_hash = None
            
        except Exception as e:
            raise RuntimeError(f"Failed to delete data: {e}")
    
    def verify_data_integrity(self) -> Dict[str, Any]:
        """
        Verify integrity of stored data.
        
        Returns:
            Dictionary with integrity check results
        """
        results = {
            'master_password_valid': False,
            'data_files_accessible': {},
            'encryption_working': False,
            'overall_status': 'failed'
        }
        
        try:
            # Check master password
            if self._master_password and self._master_password_hash:
                results['master_password_valid'] = True
            
            # Check each data file
            data_files = ['passwords.enc', 'reminders.enc', 'premium.enc', 'stored_passwords.enc']
            
            for filename in data_files:
                try:
                    data = self._load_encrypted_data(filename)
                    results['data_files_accessible'][filename] = True
                except Exception as e:
                    results['data_files_accessible'][filename] = f"Error: {e}"
            
            # Test encryption/decryption
            try:
                test_data = "integrity_test"
                encrypted = self.crypto.encrypt(test_data, self._master_password or "test")
                decrypted = self.crypto.decrypt(encrypted, self._master_password or "test")
                results['encryption_working'] = (decrypted == test_data)
            except Exception:
                results['encryption_working'] = False
            
            # Overall status
            if (results['master_password_valid'] and 
                results['encryption_working'] and 
                all(v is True for v in results['data_files_accessible'].values())):
                results['overall_status'] = 'healthy'
            elif results['master_password_valid'] and results['encryption_working']:
                results['overall_status'] = 'partial'
            
        except Exception as e:
            results['error'] = str(e)
        
        return results