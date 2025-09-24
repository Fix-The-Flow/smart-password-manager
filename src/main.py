#!/usr/bin/env python3
"""
Smart Password Manager - Main Entry Point
A secure password generator and manager with uniqueness tracking and reminders.
"""

import argparse
import sys
import os
import getpass
from pathlib import Path

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from password_generator import PasswordGenerator
from uniqueness_tracker import UniquenessTracker
from reminder_system import ReminderSystem
from premium_features import PremiumFeatures
from utils.config import Config
from utils.storage import Storage


class SmartPasswordManager:
    """Main application class for the Smart Password Manager."""
    
    def __init__(self):
        self.config = Config()
        self.storage = Storage()
        self.password_generator = PasswordGenerator()
        self.uniqueness_tracker = UniquenessTracker(self.storage)
        self.reminder_system = ReminderSystem(self.storage)
        self.premium_features = PremiumFeatures(self.storage)
        self.master_password = None

    def authenticate(self):
        """Authenticate user with master password."""
        if not self.storage.master_password_exists():
            print("Welcome! Let's set up your master password.")
            while True:
                password = getpass.getpass("Enter a strong master password: ")
                confirm = getpass.getpass("Confirm master password: ")
                if password == confirm and len(password) >= 8:
                    self.storage.set_master_password(password)
                    self.master_password = password
                    print("✅ Master password set successfully!")
                    break
                else:
                    print("❌ Passwords don't match or are too short (minimum 8 characters)")
        else:
            password = getpass.getpass("Enter your master password: ")
            if self.storage.verify_master_password(password):
                self.master_password = password
                print("✅ Authentication successful!")
            else:
                print("❌ Invalid master password!")
                sys.exit(1)

    def generate_password(self, args):
        """Generate a new password with specified parameters."""
        try:
            password = self.password_generator.generate(
                length=args.length,
                include_uppercase=args.uppercase,
                include_lowercase=args.lowercase,
                include_numbers=args.numbers,
                include_symbols=args.symbols,
                pronounceable=args.pronounceable
            )
            
            # Check uniqueness if account is specified
            if args.account:
                if self.uniqueness_tracker.is_password_unique(password, args.account):
                    self.uniqueness_tracker.store_password(password, args.account)
                    print(f"✅ Password generated for {args.account}")
                    if args.reminder_days:
                        self.reminder_system.set_reminder(args.account, args.reminder_days)
                        print(f"⏰ Reminder set for {args.reminder_days} days")
                else:
                    print("⚠️  Warning: This password is similar to one you've used before!")
                    choice = input("Continue anyway? (y/N): ")
                    if choice.lower() != 'y':
                        return self.generate_password(args)  # Generate a new one
            
            print(f"🔐 Generated password: {password}")
            print(f"💪 Password strength: {self.password_generator.calculate_strength(password)}/100")
            
        except Exception as e:
            print(f"❌ Error generating password: {e}")

    def check_uniqueness(self, args):
        """Check if passwords for an account are unique."""
        passwords = self.uniqueness_tracker.get_account_passwords(args.account)
        if passwords:
            print(f"🔍 Found {len(passwords)} passwords for {args.account}")
            for i, pwd_hash in enumerate(passwords, 1):
                created_date = self.uniqueness_tracker.get_password_date(pwd_hash)
                print(f"  {i}. Created: {created_date}")
        else:
            print(f"ℹ️  No passwords found for {args.account}")

    def list_reminders(self):
        """List all active password reminders."""
        reminders = self.reminder_system.get_due_reminders()
        if reminders:
            print("⏰ Password Reminders Due:")
            for account, days_ago in reminders:
                print(f"  • {account}: Password is {days_ago} days old")
        else:
            print("✅ No password reminders due!")

    def manage_hint(self, args):
        """Manage password hints (premium feature)."""
        if not self.premium_features.is_premium_active():
            print("💎 This is a premium feature!")
            print("   Upgrade to store secure password hints and additional features.")
            upgrade = input("Would you like to learn about premium features? (y/N): ")
            if upgrade.lower() == 'y':
                self.show_premium_info()
            return

        if args.hint:
            self.premium_features.store_hint(args.account, args.hint)
            print(f"💎 Hint stored for {args.account}")
        else:
            hint = self.premium_features.get_hint(args.account)
            if hint:
                print(f"💎 Hint for {args.account}: {hint}")
            else:
                print(f"ℹ️  No hint found for {args.account}")

    def show_premium_info(self):
        """Display information about premium features."""
        print("\n💎 Smart Password Manager Premium")
        print("=" * 40)
        print("✨ Premium Features:")
        print("  • Secure password hints storage")
        print("  • Advanced password analytics")
        print("  • Breach monitoring alerts")
        print("  • Cross-device synchronization")
        print("  • Priority customer support")
        print("  • Export/Import capabilities")
        print("\n💰 Pricing: $9.99/month or $99/year")
        print("🌟 Try premium free for 30 days!")
        print("\nTo upgrade: python src/main.py premium --activate")

    def show_stats(self):
        """Show password statistics and security overview."""
        stats = {
            'total_passwords': self.uniqueness_tracker.get_total_count(),
            'unique_accounts': self.uniqueness_tracker.get_unique_accounts_count(),
            'due_reminders': len(self.reminder_system.get_due_reminders()),
            'average_strength': self.uniqueness_tracker.get_average_strength()
        }
        
        print("\n📊 Password Security Overview")
        print("=" * 35)
        print(f"🔐 Total passwords managed: {stats['total_passwords']}")
        print(f"🏢 Unique accounts: {stats['unique_accounts']}")
        print(f"⏰ Reminders due: {stats['due_reminders']}")
        print(f"💪 Average password strength: {stats['average_strength']:.1f}%")
        
        if stats['due_reminders'] > 0:
            print("\n⚠️  Action needed: Some passwords need updating!")


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(
        description="Smart Password Manager - Generate secure, unique passwords with reminders"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Generate password command
    gen_parser = subparsers.add_parser('generate', help='Generate a new password')
    gen_parser.add_argument('--length', type=int, default=16, help='Password length (default: 16)')
    gen_parser.add_argument('--account', type=str, help='Account name for uniqueness tracking')
    gen_parser.add_argument('--uppercase', action='store_true', default=True, help='Include uppercase letters')
    gen_parser.add_argument('--lowercase', action='store_true', default=True, help='Include lowercase letters')
    gen_parser.add_argument('--numbers', action='store_true', default=True, help='Include numbers')
    gen_parser.add_argument('--symbols', action='store_true', help='Include symbols')
    gen_parser.add_argument('--pronounceable', action='store_true', help='Generate pronounceable password')
    gen_parser.add_argument('--reminder-days', type=int, help='Set reminder after N days')
    
    # Check uniqueness command
    check_parser = subparsers.add_parser('check', help='Check password uniqueness for account')
    check_parser.add_argument('--account', type=str, required=True, help='Account name to check')
    
    # Reminders command
    subparsers.add_parser('reminders', help='List due password reminders')
    
    # Premium hint command
    hint_parser = subparsers.add_parser('hint', help='Manage password hints (premium)')
    hint_parser.add_argument('--account', type=str, required=True, help='Account name')
    hint_parser.add_argument('--hint', type=str, help='Password hint to store')
    
    # Premium info command
    subparsers.add_parser('premium', help='Show premium features information')
    
    # Stats command
    subparsers.add_parser('stats', help='Show password security statistics')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize application
    app = SmartPasswordManager()
    
    try:
        app.authenticate()
        
        # Route commands
        if args.command == 'generate':
            app.generate_password(args)
        elif args.command == 'check':
            app.check_uniqueness(args)
        elif args.command == 'reminders':
            app.list_reminders()
        elif args.command == 'hint':
            app.manage_hint(args)
        elif args.command == 'premium':
            app.show_premium_info()
        elif args.command == 'stats':
            app.show_stats()
            
    except KeyboardInterrupt:
        print("\n👋 Goodbye! Stay secure!")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()