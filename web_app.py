#!/usr/bin/env python3
"""
Smart Password Manager - Web Application
Flask-based web interface for the password manager.
"""

import sys
import os
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, BooleanField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Length, NumberRange
import secrets

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from password_generator import PasswordGenerator
from uniqueness_tracker import UniquenessTracker
from reminder_system import ReminderSystem
from premium_features import PremiumFeatures
from utils.config import Config
from utils.storage import Storage

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Initialize components
config = Config()
storage = Storage()
password_generator = PasswordGenerator()
uniqueness_tracker = UniquenessTracker(storage)
reminder_system = ReminderSystem(storage)
premium_features = PremiumFeatures(storage)

class LoginForm(FlaskForm):
    master_password = PasswordField('Master Password', validators=[DataRequired()])

class SetupForm(FlaskForm):
    master_password = PasswordField('Create Master Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])

class GeneratePasswordForm(FlaskForm):
    account = StringField('Account/Website', validators=[DataRequired()])
    length = IntegerField('Password Length', validators=[NumberRange(min=8, max=128)], default=16)
    include_uppercase = BooleanField('Include Uppercase Letters', default=True)
    include_lowercase = BooleanField('Include Lowercase Letters', default=True)
    include_numbers = BooleanField('Include Numbers', default=True)
    include_symbols = BooleanField('Include Symbols', default=False)
    pronounceable = BooleanField('Make Pronounceable', default=False)
    reminder_days = IntegerField('Reminder Days (optional)', validators=[NumberRange(min=1, max=365)])

@app.route('/')
def index():
    """Main dashboard page."""
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    # Get statistics
    stats = {
        'total_passwords': uniqueness_tracker.get_total_count(),
        'unique_accounts': uniqueness_tracker.get_unique_accounts_count(),
        'due_reminders': len(reminder_system.get_due_reminders()),
        'average_strength': uniqueness_tracker.get_average_strength()
    }
    
    reminders = reminder_system.get_due_reminders()
    
    return render_template('dashboard.html', stats=stats, reminders=reminders)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page."""
    if not storage.master_password_exists():
        return redirect(url_for('setup'))
    
    form = LoginForm()
    if form.validate_on_submit():
        if storage.verify_master_password(form.master_password.data):
            session['authenticated'] = True
            session['master_password'] = form.master_password.data
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid master password!', 'error')
    
    return render_template('login.html', form=form)

@app.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial setup page."""
    if storage.master_password_exists():
        return redirect(url_for('login'))
    
    form = SetupForm()
    if form.validate_on_submit():
        if form.master_password.data == form.confirm_password.data:
            storage.set_master_password(form.master_password.data)
            session['authenticated'] = True
            session['master_password'] = form.master_password.data
            flash('Master password set successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Passwords do not match!', 'error')
    
    return render_template('setup.html', form=form)

@app.route('/generate', methods=['GET', 'POST'])
def generate_password():
    """Password generation page."""
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    form = GeneratePasswordForm()
    generated_password = None
    password_strength = None
    
    if form.validate_on_submit():
        try:
            # Generate password
            password = password_generator.generate(
                length=form.length.data,
                include_uppercase=form.include_uppercase.data,
                include_lowercase=form.include_lowercase.data,
                include_numbers=form.include_numbers.data,
                include_symbols=form.include_symbols.data,
                pronounceable=form.pronounceable.data
            )
            
            # Check uniqueness
            if uniqueness_tracker.is_password_unique(password, form.account.data):
                uniqueness_tracker.store_password(password, form.account.data)
                
                # Set reminder if specified
                if form.reminder_days.data:
                    reminder_system.set_reminder(form.account.data, form.reminder_days.data)
                
                generated_password = password
                password_strength = password_generator.calculate_strength(password)
                flash(f'Password generated for {form.account.data}!', 'success')
            else:
                flash('Warning: This password is similar to one you\'ve used before!', 'warning')
                generated_password = password
                password_strength = password_generator.calculate_strength(password)
                
        except Exception as e:
            flash(f'Error generating password: {e}', 'error')
    
    return render_template('generate.html', form=form, 
                         generated_password=generated_password, 
                         password_strength=password_strength)

@app.route('/accounts')
def view_accounts():
    """View all accounts and passwords."""
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    # Get all accounts (this would need to be implemented in UniquenessTracker)
    accounts = []  # uniqueness_tracker.get_all_accounts()
    return render_template('accounts.html', accounts=accounts)

@app.route('/premium')
def premium():
    """Premium features page."""
    if 'authenticated' not in session:
        return redirect(url_for('login'))
    
    return render_template('premium.html')

@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    flash('Logged out successfully!', 'info')
    return redirect(url_for('login'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Create templates directory if it doesn't exist
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
static_dir = os.path.join(os.path.dirname(__file__), 'static')
os.makedirs(templates_dir, exist_ok=True)
os.makedirs(static_dir, exist_ok=True)

if __name__ == '__main__':
    print("🌐 Smart Password Manager Web App")
    print("================================")
    print("Starting web server...")
    print("Open your browser to: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    
    try:
        port = int(os.environ.get('PORT', 5000))
        debug_mode = os.environ.get('FLASK_ENV') != 'production'
        app.run(debug=debug_mode, host='0.0.0.0', port=port)
    except Exception as e:
        print(f"Error starting web app: {e}")
        import traceback
        traceback.print_exc()
        input("Press Enter to continue...")
