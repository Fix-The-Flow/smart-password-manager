"""
Configuration Management Module
Handles application configuration and settings.
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


class Config:
    """Configuration manager for the Smart Password Manager."""
    
    def __init__(self, config_dir: Optional[str] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Custom configuration directory (default: user's home/.smart-password-manager)
        """
        if config_dir:
            self.config_dir = Path(config_dir)
        else:
            self.config_dir = Path.home() / '.smart-password-manager'
        
        self.config_file = self.config_dir / 'config.json'
        self._ensure_config_dir()
        self._load_config()
    
    def _ensure_config_dir(self):
        """Ensure configuration directory exists."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self):
        """Load configuration from file."""
        self.settings = self._get_default_config()
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    self.settings.update(user_config)
            except Exception as e:
                print(f"Warning: Could not load config file: {e}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration settings."""
        return {
            'security': {
                'master_password_min_length': 8,
                'password_hash_iterations': 100000,
                'encryption_key_size': 32,
                'similarity_threshold': 0.7
            },
            'passwords': {
                'default_length': 16,
                'default_include_uppercase': True,
                'default_include_lowercase': True,
                'default_include_numbers': True,
                'default_include_symbols': False,
                'exclude_ambiguous_chars': True
            },
            'reminders': {
                'default_reminder_days': 90,
                'snooze_days': 7,
                'max_reminder_count': 5
            },
            'premium': {
                'trial_period_days': 30,
                'max_hints_per_account': 5,
                'max_secure_notes_size': 10000  # bytes
            },
            'storage': {
                'backup_count': 5,
                'auto_backup': True,
                'compression_enabled': True
            },
            'ui': {
                'show_strength_meter': True,
                'show_crack_time': True,
                'use_colored_output': True,
                'verbose_output': False
            },
            'data_paths': {
                'passwords_file': 'passwords.enc',
                'reminders_file': 'reminders.enc',
                'premium_file': 'premium.enc',
                'backup_dir': 'backups'
            }
        }
    
    def save_config(self):
        """Save current configuration to file."""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise RuntimeError(f"Could not save configuration: {e}")
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to the configuration key (e.g., 'security.master_password_min_length')
            default: Default value if key is not found
            
        Returns:
            Configuration value or default
        """
        keys = key_path.split('.')
        value = self.settings
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any):
        """
        Set configuration value using dot notation.
        
        Args:
            key_path: Dot-separated path to the configuration key
            value: Value to set
        """
        keys = key_path.split('.')
        current = self.settings
        
        # Navigate to parent of target key
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set the final key
        current[keys[-1]] = value
    
    def get_data_dir(self) -> Path:
        """
        Get the data directory path.
        
        Returns:
            Path to data directory
        """
        data_dir = self.config_dir / 'data'
        data_dir.mkdir(exist_ok=True)
        return data_dir
    
    def get_backup_dir(self) -> Path:
        """
        Get the backup directory path.
        
        Returns:
            Path to backup directory
        """
        backup_dir = self.config_dir / self.get('data_paths.backup_dir', 'backups')
        backup_dir.mkdir(exist_ok=True)
        return backup_dir
    
    def get_file_path(self, file_key: str) -> Path:
        """
        Get full path for a data file.
        
        Args:
            file_key: Key in data_paths configuration
            
        Returns:
            Full path to the file
        """
        filename = self.get(f'data_paths.{file_key}')
        if not filename:
            raise ValueError(f"Unknown file key: {file_key}")
        
        return self.get_data_dir() / filename
    
    def reset_to_defaults(self):
        """Reset configuration to default values."""
        self.settings = self._get_default_config()
        self.save_config()
    
    def validate_config(self) -> Dict[str, str]:
        """
        Validate current configuration.
        
        Returns:
            Dictionary of validation errors (empty if valid)
        """
        errors = {}
        
        # Validate security settings
        min_length = self.get('security.master_password_min_length', 8)
        if not isinstance(min_length, int) or min_length < 4:
            errors['security.master_password_min_length'] = 'Must be an integer >= 4'
        
        iterations = self.get('security.password_hash_iterations', 100000)
        if not isinstance(iterations, int) or iterations < 10000:
            errors['security.password_hash_iterations'] = 'Must be an integer >= 10000'
        
        # Validate password settings
        default_length = self.get('passwords.default_length', 16)
        if not isinstance(default_length, int) or default_length < 4:
            errors['passwords.default_length'] = 'Must be an integer >= 4'
        
        # Validate reminder settings
        reminder_days = self.get('reminders.default_reminder_days', 90)
        if not isinstance(reminder_days, int) or reminder_days < 1:
            errors['reminders.default_reminder_days'] = 'Must be an integer >= 1'
        
        return errors
    
    def get_all_settings(self) -> Dict[str, Any]:
        """
        Get all configuration settings.
        
        Returns:
            Complete configuration dictionary
        """
        return self.settings.copy()
    
    def update_settings(self, new_settings: Dict[str, Any]):
        """
        Update multiple configuration settings.
        
        Args:
            new_settings: Dictionary of settings to update
        """
        def deep_update(base_dict, update_dict):
            for key, value in update_dict.items():
                if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                    deep_update(base_dict[key], value)
                else:
                    base_dict[key] = value
        
        deep_update(self.settings, new_settings)
    
    def export_config(self, file_path: str):
        """
        Export configuration to a file.
        
        Args:
            file_path: Path to export file
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=2, ensure_ascii=False)
        except Exception as e:
            raise RuntimeError(f"Could not export configuration: {e}")
    
    def import_config(self, file_path: str):
        """
        Import configuration from a file.
        
        Args:
            file_path: Path to import file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                imported_settings = json.load(f)
            
            # Validate imported settings
            temp_config = Config()
            temp_config.settings = imported_settings
            errors = temp_config.validate_config()
            
            if errors:
                error_msg = "Invalid configuration:\n" + "\n".join(f"  {k}: {v}" for k, v in errors.items())
                raise ValueError(error_msg)
            
            self.settings = imported_settings
            self.save_config()
            
        except Exception as e:
            raise RuntimeError(f"Could not import configuration: {e}")
    
    def __str__(self) -> str:
        """String representation of configuration."""
        return json.dumps(self.settings, indent=2, ensure_ascii=False)