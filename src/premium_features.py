"""
Premium Features Module
Handles premium functionality including password hints storage and advanced features.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import uuid


class PremiumFeatures:
    """Manages premium features and subscription handling."""
    
    def __init__(self, storage):
        """
        Initialize the premium features manager.
        
        Args:
            storage: Storage instance for data persistence
        """
        self.storage = storage
        self.trial_period_days = 30
    
    def is_premium_active(self) -> bool:
        """
        Check if premium features are active.
        
        Returns:
            True if premium is active, False otherwise
        """
        try:
            premium_data = self.storage.load_premium_data()
            
            if not premium_data.get('subscription'):
                return False
            
            subscription = premium_data['subscription']
            
            # Check if subscription is active
            if subscription.get('status') != 'active':
                return False
            
            # Check expiration date
            expiry_date = datetime.fromisoformat(subscription['expires_at'])
            return datetime.now() < expiry_date
            
        except Exception as e:
            print(f"Error checking premium status: {e}")
            return False
    
    def is_trial_active(self) -> bool:
        """
        Check if trial period is active.
        
        Returns:
            True if trial is active, False otherwise
        """
        try:
            premium_data = self.storage.load_premium_data()
            
            if not premium_data.get('trial'):
                return False
            
            trial = premium_data['trial']
            expiry_date = datetime.fromisoformat(trial['expires_at'])
            return datetime.now() < expiry_date and trial.get('status') == 'active'
            
        except Exception:
            return False
    
    def has_premium_access(self) -> bool:
        """
        Check if user has access to premium features (active subscription or trial).
        
        Returns:
            True if has premium access, False otherwise
        """
        return self.is_premium_active() or self.is_trial_active()
    
    def start_trial(self) -> bool:
        """
        Start a premium trial period.
        
        Returns:
            True if trial started successfully, False otherwise
        """
        try:
            if self.is_trial_active() or self.is_premium_active():
                return False  # Already have access
            
            premium_data = self.storage.load_premium_data()
            
            # Check if trial was already used
            if premium_data.get('trial', {}).get('used', False):
                return False
            
            trial_start = datetime.now()
            trial_end = trial_start + timedelta(days=self.trial_period_days)
            
            premium_data['trial'] = {
                'status': 'active',
                'started_at': trial_start.isoformat(),
                'expires_at': trial_end.isoformat(),
                'used': True
            }
            
            self.storage.save_premium_data(premium_data)
            return True
            
        except Exception as e:
            print(f"Error starting trial: {e}")
            return False
    
    def store_hint(self, account: str, hint: str) -> bool:
        """
        Store a password hint for an account (premium feature).
        
        Args:
            account: Account name
            hint: Password hint text
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.has_premium_access():
            return False
        
        try:
            premium_data = self.storage.load_premium_data()
            
            if 'hints' not in premium_data:
                premium_data['hints'] = {}
            
            premium_data['hints'][account] = {
                'hint': hint,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            self.storage.save_premium_data(premium_data)
            return True
            
        except Exception as e:
            print(f"Error storing hint: {e}")
            return False
    
    def get_hint(self, account: str) -> Optional[str]:
        """
        Get a password hint for an account (premium feature).
        
        Args:
            account: Account name
            
        Returns:
            Password hint or None if not found or no premium access
        """
        if not self.has_premium_access():
            return None
        
        try:
            premium_data = self.storage.load_premium_data()
            
            if account in premium_data.get('hints', {}):
                return premium_data['hints'][account]['hint']
            
            return None
            
        except Exception:
            return None
    
    def remove_hint(self, account: str) -> bool:
        """
        Remove a password hint for an account.
        
        Args:
            account: Account name
            
        Returns:
            True if removed successfully, False otherwise
        """
        if not self.has_premium_access():
            return False
        
        try:
            premium_data = self.storage.load_premium_data()
            
            if account in premium_data.get('hints', {}):
                del premium_data['hints'][account]
                self.storage.save_premium_data(premium_data)
                return True
            
            return False
            
        except Exception:
            return False
    
    def get_all_hints(self) -> Dict[str, Dict]:
        """
        Get all password hints (premium feature).
        
        Returns:
            Dictionary of account hints with metadata
        """
        if not self.has_premium_access():
            return {}
        
        try:
            premium_data = self.storage.load_premium_data()
            return premium_data.get('hints', {})
            
        except Exception:
            return {}
    
    def store_secure_note(self, account: str, note: str) -> bool:
        """
        Store a secure note for an account (premium feature).
        
        Args:
            account: Account name
            note: Secure note text
            
        Returns:
            True if stored successfully, False otherwise
        """
        if not self.has_premium_access():
            return False
        
        try:
            premium_data = self.storage.load_premium_data()
            
            if 'secure_notes' not in premium_data:
                premium_data['secure_notes'] = {}
            
            premium_data['secure_notes'][account] = {
                'note': note,
                'created_at': datetime.now().isoformat(),
                'updated_at': datetime.now().isoformat()
            }
            
            self.storage.save_premium_data(premium_data)
            return True
            
        except Exception as e:
            print(f"Error storing secure note: {e}")
            return False
    
    def get_secure_note(self, account: str) -> Optional[str]:
        """
        Get a secure note for an account (premium feature).
        
        Args:
            account: Account name
            
        Returns:
            Secure note or None if not found or no premium access
        """
        if not self.has_premium_access():
            return None
        
        try:
            premium_data = self.storage.load_premium_data()
            
            if account in premium_data.get('secure_notes', {}):
                return premium_data['secure_notes'][account]['note']
            
            return None
            
        except Exception:
            return None
    
    def generate_advanced_analytics(self) -> Dict:
        """
        Generate advanced password analytics (premium feature).
        
        Returns:
            Analytics dictionary
        """
        if not self.has_premium_access():
            return {'error': 'Premium access required'}
        
        try:
            # This would integrate with the uniqueness tracker and other components
            # For now, return mock analytics data
            analytics = {
                'password_strength_trend': self._generate_strength_trend(),
                'security_score_history': self._generate_security_history(),
                'threat_assessment': self._generate_threat_assessment(),
                'recommendations': self._generate_recommendations()
            }
            
            return analytics
            
        except Exception as e:
            return {'error': f'Failed to generate analytics: {e}'}
    
    def _generate_strength_trend(self) -> List[Dict]:
        """Generate password strength trend data."""
        # Mock data for demonstration
        return [
            {'date': '2024-09-01', 'avg_strength': 72.5},
            {'date': '2024-09-08', 'avg_strength': 75.2},
            {'date': '2024-09-15', 'avg_strength': 78.1},
            {'date': '2024-09-22', 'avg_strength': 81.3}
        ]
    
    def _generate_security_history(self) -> List[Dict]:
        """Generate security score history."""
        return [
            {'date': '2024-09-01', 'score': 68},
            {'date': '2024-09-08', 'score': 72},
            {'date': '2024-09-15', 'score': 76},
            {'date': '2024-09-22', 'score': 83}
        ]
    
    def _generate_threat_assessment(self) -> Dict:
        """Generate threat assessment."""
        return {
            'risk_level': 'Low',
            'vulnerable_passwords': 2,
            'reused_passwords': 1,
            'weak_passwords': 0,
            'compromised_accounts': 0,
            'last_breach_check': datetime.now().isoformat()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        return [
            "Update passwords older than 90 days",
            "Enable two-factor authentication where possible",
            "Consider using longer passwords (16+ characters)",
            "Replace any reused passwords with unique ones"
        ]
    
    def export_data(self, format_type: str = 'json') -> Optional[Dict]:
        """
        Export password data (premium feature).
        
        Args:
            format_type: Export format ('json', 'csv')
            
        Returns:
            Exported data or None if no premium access
        """
        if not self.has_premium_access():
            return None
        
        try:
            # This would integrate with all data sources
            export_data = {
                'exported_at': datetime.now().isoformat(),
                'format': format_type,
                'data': {
                    'hints': self.get_all_hints(),
                    'secure_notes': self._get_all_secure_notes(),
                    'analytics': self.generate_advanced_analytics()
                }
            }
            
            return export_data
            
        except Exception as e:
            print(f"Error exporting data: {e}")
            return None
    
    def _get_all_secure_notes(self) -> Dict:
        """Get all secure notes."""
        try:
            premium_data = self.storage.load_premium_data()
            return premium_data.get('secure_notes', {})
        except Exception:
            return {}
    
    def get_subscription_info(self) -> Dict:
        """
        Get current subscription information.
        
        Returns:
            Subscription details dictionary
        """
        try:
            premium_data = self.storage.load_premium_data()
            
            info = {
                'has_premium': self.is_premium_active(),
                'has_trial': self.is_trial_active(),
                'trial_used': premium_data.get('trial', {}).get('used', False)
            }
            
            if premium_data.get('subscription'):
                subscription = premium_data['subscription']
                info.update({
                    'subscription_status': subscription.get('status'),
                    'expires_at': subscription.get('expires_at'),
                    'plan_type': subscription.get('plan_type')
                })
            
            if premium_data.get('trial'):
                trial = premium_data['trial']
                info.update({
                    'trial_expires_at': trial.get('expires_at'),
                    'trial_started_at': trial.get('started_at')
                })
            
            return info
            
        except Exception as e:
            return {'error': str(e)}
    
    def activate_premium(self, plan_type: str = 'monthly') -> str:
        """
        Activate premium subscription (simulation for demo).
        
        Args:
            plan_type: 'monthly' or 'yearly'
            
        Returns:
            Activation token/confirmation
        """
        try:
            premium_data = self.storage.load_premium_data()
            
            # Calculate expiry based on plan type
            if plan_type == 'yearly':
                expires_at = datetime.now() + timedelta(days=365)
            else:
                expires_at = datetime.now() + timedelta(days=30)
            
            # Generate subscription ID
            subscription_id = str(uuid.uuid4())
            
            premium_data['subscription'] = {
                'id': subscription_id,
                'status': 'active',
                'plan_type': plan_type,
                'activated_at': datetime.now().isoformat(),
                'expires_at': expires_at.isoformat()
            }
            
            # Deactivate trial if active
            if premium_data.get('trial'):
                premium_data['trial']['status'] = 'expired'
            
            self.storage.save_premium_data(premium_data)
            
            return subscription_id
            
        except Exception as e:
            raise RuntimeError(f"Failed to activate premium: {e}")
    
    def get_premium_usage_stats(self) -> Dict:
        """
        Get premium feature usage statistics.
        
        Returns:
            Usage statistics dictionary
        """
        if not self.has_premium_access():
            return {'error': 'Premium access required'}
        
        try:
            premium_data = self.storage.load_premium_data()
            
            stats = {
                'hints_stored': len(premium_data.get('hints', {})),
                'secure_notes_stored': len(premium_data.get('secure_notes', {})),
                'analytics_generated': premium_data.get('analytics_count', 0),
                'exports_performed': premium_data.get('export_count', 0),
                'premium_since': premium_data.get('subscription', {}).get('activated_at')
            }
            
            return stats
            
        except Exception as e:
            return {'error': str(e)}