"""
Reminder System Module
Manages password change reminders and notifications.
"""

import json
from datetime import datetime, timedelta
from typing import List, Tuple, Dict, Optional


class ReminderSystem:
    """Manages password change reminders and aging notifications."""
    
    def __init__(self, storage):
        """
        Initialize the reminder system.
        
        Args:
            storage: Storage instance for data persistence
        """
        self.storage = storage
        self.default_reminder_days = 90  # Default 90-day reminder
    
    def set_reminder(self, account: str, days: int, password_created: datetime = None) -> None:
        """
        Set a password change reminder for an account.
        
        Args:
            account: Account name
            days: Number of days until reminder
            password_created: When password was created (default: now)
        """
        try:
            if password_created is None:
                password_created = datetime.now()
            
            reminder_date = password_created + timedelta(days=days)
            
            reminders_data = self.storage.load_reminders_data()
            
            # Initialize structure if needed
            if 'reminders' not in reminders_data:
                reminders_data['reminders'] = {}
            
            reminders_data['reminders'][account] = {
                'password_created': password_created.isoformat(),
                'reminder_days': days,
                'reminder_date': reminder_date.isoformat(),
                'last_reminded': None,
                'reminder_count': 0,
                'is_active': True
            }
            
            self.storage.save_reminders_data(reminders_data)
            
        except Exception as e:
            raise RuntimeError(f"Failed to set reminder: {e}")
    
    def get_due_reminders(self) -> List[Tuple[str, int]]:
        """
        Get all reminders that are currently due.
        
        Returns:
            List of tuples (account, days_since_created)
        """
        due_reminders = []
        current_time = datetime.now()
        
        try:
            reminders_data = self.storage.load_reminders_data()
            
            for account, reminder in reminders_data.get('reminders', {}).items():
                if not reminder.get('is_active', True):
                    continue
                
                password_created = datetime.fromisoformat(reminder['password_created'])
                reminder_date = datetime.fromisoformat(reminder['reminder_date'])
                
                if current_time >= reminder_date:
                    days_old = (current_time - password_created).days
                    due_reminders.append((account, days_old))
            
            # Sort by days old (oldest first)
            due_reminders.sort(key=lambda x: x[1], reverse=True)
            
        except Exception as e:
            print(f"Error getting due reminders: {e}")
        
        return due_reminders
    
    def get_upcoming_reminders(self, days_ahead: int = 7) -> List[Tuple[str, int]]:
        """
        Get reminders that are due within the specified number of days.
        
        Args:
            days_ahead: Number of days to look ahead
            
        Returns:
            List of tuples (account, days_until_due)
        """
        upcoming_reminders = []
        current_time = datetime.now()
        cutoff_time = current_time + timedelta(days=days_ahead)
        
        try:
            reminders_data = self.storage.load_reminders_data()
            
            for account, reminder in reminders_data.get('reminders', {}).items():
                if not reminder.get('is_active', True):
                    continue
                
                reminder_date = datetime.fromisoformat(reminder['reminder_date'])
                
                if current_time <= reminder_date <= cutoff_time:
                    days_until = (reminder_date - current_time).days
                    upcoming_reminders.append((account, days_until))
            
            # Sort by days until due (soonest first)
            upcoming_reminders.sort(key=lambda x: x[1])
            
        except Exception as e:
            print(f"Error getting upcoming reminders: {e}")
        
        return upcoming_reminders
    
    def mark_reminded(self, account: str) -> None:
        """
        Mark that a reminder has been shown for an account.
        
        Args:
            account: Account name
        """
        try:
            reminders_data = self.storage.load_reminders_data()
            
            if account in reminders_data.get('reminders', {}):
                reminders_data['reminders'][account]['last_reminded'] = datetime.now().isoformat()
                reminders_data['reminders'][account]['reminder_count'] += 1
                
                self.storage.save_reminders_data(reminders_data)
            
        except Exception as e:
            print(f"Error marking reminder: {e}")
    
    def snooze_reminder(self, account: str, days: int = 7) -> None:
        """
        Snooze a reminder for the specified number of days.
        
        Args:
            account: Account name
            days: Number of days to snooze
        """
        try:
            reminders_data = self.storage.load_reminders_data()
            
            if account in reminders_data.get('reminders', {}):
                current_reminder_date = datetime.fromisoformat(
                    reminders_data['reminders'][account]['reminder_date']
                )
                new_reminder_date = current_reminder_date + timedelta(days=days)
                
                reminders_data['reminders'][account]['reminder_date'] = new_reminder_date.isoformat()
                reminders_data['reminders'][account]['last_reminded'] = datetime.now().isoformat()
                
                self.storage.save_reminders_data(reminders_data)
            
        except Exception as e:
            print(f"Error snoozing reminder: {e}")
    
    def disable_reminder(self, account: str) -> None:
        """
        Disable reminders for an account.
        
        Args:
            account: Account name
        """
        try:
            reminders_data = self.storage.load_reminders_data()
            
            if account in reminders_data.get('reminders', {}):
                reminders_data['reminders'][account]['is_active'] = False
                
                self.storage.save_reminders_data(reminders_data)
            
        except Exception as e:
            print(f"Error disabling reminder: {e}")
    
    def update_password_reminder(self, account: str, new_days: int = None) -> None:
        """
        Update reminder when password is changed.
        
        Args:
            account: Account name
            new_days: New reminder interval (default: use existing or default)
        """
        try:
            if new_days is None:
                new_days = self.default_reminder_days
            
            # Reset the reminder with current time as creation date
            self.set_reminder(account, new_days)
            
        except Exception as e:
            print(f"Error updating password reminder: {e}")
    
    def get_reminder_info(self, account: str) -> Optional[Dict]:
        """
        Get detailed reminder information for an account.
        
        Args:
            account: Account name
            
        Returns:
            Dictionary with reminder details or None if not found
        """
        try:
            reminders_data = self.storage.load_reminders_data()
            
            if account in reminders_data.get('reminders', {}):
                reminder = reminders_data['reminders'][account]
                password_created = datetime.fromisoformat(reminder['password_created'])
                reminder_date = datetime.fromisoformat(reminder['reminder_date'])
                current_time = datetime.now()
                
                info = {
                    'account': account,
                    'password_age_days': (current_time - password_created).days,
                    'reminder_interval': reminder['reminder_days'],
                    'is_due': current_time >= reminder_date,
                    'days_until_due': (reminder_date - current_time).days,
                    'reminder_count': reminder.get('reminder_count', 0),
                    'is_active': reminder.get('is_active', True)
                }
                
                if reminder.get('last_reminded'):
                    last_reminded = datetime.fromisoformat(reminder['last_reminded'])
                    info['days_since_last_reminder'] = (current_time - last_reminded).days
                else:
                    info['days_since_last_reminder'] = None
                
                return info
            
            return None
            
        except Exception as e:
            print(f"Error getting reminder info: {e}")
            return None
    
    def get_all_reminders(self) -> List[Dict]:
        """
        Get information about all reminders.
        
        Returns:
            List of reminder information dictionaries
        """
        all_reminders = []
        
        try:
            reminders_data = self.storage.load_reminders_data()
            
            for account in reminders_data.get('reminders', {}):
                info = self.get_reminder_info(account)
                if info:
                    all_reminders.append(info)
            
            # Sort by password age (oldest first)
            all_reminders.sort(key=lambda x: x['password_age_days'], reverse=True)
            
        except Exception as e:
            print(f"Error getting all reminders: {e}")
        
        return all_reminders
    
    def cleanup_old_reminders(self, days_old: int = 365) -> int:
        """
        Remove old, inactive reminders.
        
        Args:
            days_old: Remove reminders older than this many days
            
        Returns:
            Number of reminders removed
        """
        removed_count = 0
        cutoff_date = datetime.now() - timedelta(days=days_old)
        
        try:
            reminders_data = self.storage.load_reminders_data()
            
            accounts_to_remove = []
            
            for account, reminder in reminders_data.get('reminders', {}).items():
                if not reminder.get('is_active', True):
                    password_created = datetime.fromisoformat(reminder['password_created'])
                    if password_created < cutoff_date:
                        accounts_to_remove.append(account)
            
            for account in accounts_to_remove:
                del reminders_data['reminders'][account]
                removed_count += 1
            
            if removed_count > 0:
                self.storage.save_reminders_data(reminders_data)
            
        except Exception as e:
            print(f"Error cleaning up reminders: {e}")
        
        return removed_count
    
    def generate_reminder_report(self) -> Dict:
        """
        Generate a comprehensive reminder report.
        
        Returns:
            Dictionary containing reminder statistics
        """
        try:
            all_reminders = self.get_all_reminders()
            due_reminders = self.get_due_reminders()
            upcoming_reminders = self.get_upcoming_reminders()
            
            active_reminders = [r for r in all_reminders if r['is_active']]
            
            total_active = len(active_reminders)
            
            if total_active > 0:
                avg_password_age = sum(r['password_age_days'] for r in active_reminders) / total_active
                oldest_password = max(r['password_age_days'] for r in active_reminders)
                newest_password = min(r['password_age_days'] for r in active_reminders)
            else:
                avg_password_age = oldest_password = newest_password = 0
            
            report = {
                'total_accounts_tracked': len(all_reminders),
                'active_reminders': total_active,
                'due_now': len(due_reminders),
                'due_next_week': len(upcoming_reminders),
                'average_password_age_days': round(avg_password_age, 1),
                'oldest_password_days': oldest_password,
                'newest_password_days': newest_password,
                'security_health_score': max(0, 100 - (len(due_reminders) * 10))
            }
            
            return report
            
        except Exception as e:
            return {
                'error': str(e),
                'total_accounts_tracked': 0,
                'active_reminders': 0,
                'due_now': 0,
                'due_next_week': 0,
                'average_password_age_days': 0,
                'oldest_password_days': 0,
                'newest_password_days': 0,
                'security_health_score': 0
            }