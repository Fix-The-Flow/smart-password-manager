"""
Password Generator Module
Generates cryptographically secure passwords with customizable complexity.
"""

import secrets
import string
import math
import re
from typing import List, Optional


class PasswordGenerator:
    """Secure password generator with multiple options and strength calculation."""
    
    # Character sets for password generation
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    NUMBERS = string.digits
    SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Pronounceable syllables for readable passwords
    CONSONANTS = "bcdfghjklmnpqrstvwxyz"
    VOWELS = "aeiou"
    
    def __init__(self):
        """Initialize the password generator."""
        self.entropy_pool = secrets.SystemRandom()
    
    def generate(self, 
                length: int = 16,
                include_uppercase: bool = True,
                include_lowercase: bool = True,
                include_numbers: bool = True,
                include_symbols: bool = False,
                pronounceable: bool = False,
                exclude_ambiguous: bool = True) -> str:
        """
        Generate a secure password with specified parameters.
        
        Args:
            length: Desired password length
            include_uppercase: Include uppercase letters
            include_lowercase: Include lowercase letters  
            include_numbers: Include numbers
            include_symbols: Include symbols
            pronounceable: Generate a pronounceable password
            exclude_ambiguous: Exclude ambiguous characters (0, O, l, 1, etc.)
            
        Returns:
            Generated password string
            
        Raises:
            ValueError: If invalid parameters provided
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")
            
        if not any([include_uppercase, include_lowercase, include_numbers, include_symbols]):
            raise ValueError("At least one character type must be enabled")
        
        if pronounceable:
            return self._generate_pronounceable(length)
        
        # Build character set
        charset = ""
        required_chars = []
        
        if include_lowercase:
            charset += self.LOWERCASE
            required_chars.append(self.entropy_pool.choice(self.LOWERCASE))
            
        if include_uppercase:
            charset += self.UPPERCASE
            required_chars.append(self.entropy_pool.choice(self.UPPERCASE))
            
        if include_numbers:
            charset += self.NUMBERS
            required_chars.append(self.entropy_pool.choice(self.NUMBERS))
            
        if include_symbols:
            charset += self.SYMBOLS
            required_chars.append(self.entropy_pool.choice(self.SYMBOLS))
        
        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = "0O1lI|"
            charset = ''.join(c for c in charset if c not in ambiguous)
        
        # Generate remaining characters
        remaining_length = length - len(required_chars)
        password_chars = required_chars + [
            self.entropy_pool.choice(charset) for _ in range(remaining_length)
        ]
        
        # Shuffle the password to avoid predictable patterns
        self.entropy_pool.shuffle(password_chars)
        
        return ''.join(password_chars)
    
    def _generate_pronounceable(self, length: int) -> str:
        """
        Generate a pronounceable password using syllable patterns.
        
        Args:
            length: Desired password length
            
        Returns:
            Pronounceable password string
        """
        password = ""
        
        while len(password) < length:
            # Generate consonant-vowel or vowel-consonant syllables
            if self.entropy_pool.choice([True, False]):
                # Consonant-vowel pattern
                consonant = self.entropy_pool.choice(self.CONSONANTS)
                vowel = self.entropy_pool.choice(self.VOWELS)
                syllable = consonant + vowel
            else:
                # Vowel-consonant pattern
                vowel = self.entropy_pool.choice(self.VOWELS)
                consonant = self.entropy_pool.choice(self.CONSONANTS)
                syllable = vowel + consonant
                
            # Occasionally add a number or capitalize
            if self.entropy_pool.randint(1, 4) == 1 and len(password) > 0:
                syllable = syllable.capitalize()
            elif self.entropy_pool.randint(1, 5) == 1:
                syllable += str(self.entropy_pool.randint(0, 9))
                
            password += syllable
        
        # Trim to exact length and ensure it meets complexity requirements
        password = password[:length]
        
        # Add a number if none present
        if not any(c.isdigit() for c in password):
            pos = self.entropy_pool.randint(0, len(password) - 1)
            password = password[:pos] + str(self.entropy_pool.randint(0, 9)) + password[pos+1:]
        
        # Add an uppercase if none present
        if not any(c.isupper() for c in password):
            pos = self.entropy_pool.randint(0, len(password) - 1)
            if password[pos].islower():
                password = password[:pos] + password[pos].upper() + password[pos+1:]
        
        return password
    
    def calculate_strength(self, password: str) -> int:
        """
        Calculate password strength score (0-100).
        
        Args:
            password: Password to analyze
            
        Returns:
            Strength score from 0-100
        """
        if not password:
            return 0
            
        score = 0
        length = len(password)
        
        # Length scoring (up to 25 points)
        if length >= 8:
            score += min(25, length * 2)
        
        # Character variety scoring (up to 30 points)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_symbol = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))
        
        variety_score = sum([has_lower, has_upper, has_digit, has_symbol]) * 7.5
        score += variety_score
        
        # Entropy calculation (up to 30 points)
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_symbol:
            charset_size += 32
            
        if charset_size > 0:
            entropy = length * math.log2(charset_size)
            # Normalize entropy to 0-30 scale
            entropy_score = min(30, entropy / 4)
            score += entropy_score
        
        # Pattern penalties (up to -15 points)
        penalties = 0
        
        # Repeated characters
        for char in set(password):
            count = password.count(char)
            if count > 2:
                penalties += count - 2
        
        # Sequential characters (abc, 123, etc.)
        sequential_count = 0
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                sequential_count += 1
        penalties += sequential_count * 3
        
        # Common patterns
        common_patterns = ['123', 'abc', 'qwe', 'password', '111', '000']
        for pattern in common_patterns:
            if pattern.lower() in password.lower():
                penalties += 5
        
        score = max(0, min(100, score - min(15, penalties)))
        
        return int(score)
    
    def get_strength_description(self, score: int) -> str:
        """
        Get a text description of password strength.
        
        Args:
            score: Strength score from calculate_strength()
            
        Returns:
            Human-readable strength description
        """
        if score < 30:
            return "Very Weak ❌"
        elif score < 50:
            return "Weak ⚠️"
        elif score < 70:
            return "Fair 🔶"
        elif score < 85:
            return "Good ✅"
        else:
            return "Excellent 💪"
    
    def generate_multiple(self, 
                         count: int, 
                         length: int = 16, 
                         **kwargs) -> List[str]:
        """
        Generate multiple passwords at once.
        
        Args:
            count: Number of passwords to generate
            length: Length of each password
            **kwargs: Additional arguments for generate()
            
        Returns:
            List of generated passwords
        """
        if count <= 0 or count > 100:
            raise ValueError("Count must be between 1 and 100")
            
        passwords = []
        for _ in range(count):
            passwords.append(self.generate(length=length, **kwargs))
        
        return passwords
    
    def estimate_crack_time(self, password: str) -> str:
        """
        Estimate time to crack password using brute force.
        
        Args:
            password: Password to analyze
            
        Returns:
            Human-readable time estimate
        """
        if not password:
            return "Instantly"
        
        # Determine character set size
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in self.SYMBOLS for c in password):
            charset_size += len(self.SYMBOLS)
        
        # Calculate combinations (assuming 50% success rate)
        combinations = (charset_size ** len(password)) / 2
        
        # Assume 10 billion attempts per second (modern hardware)
        attempts_per_second = 10_000_000_000
        seconds = combinations / attempts_per_second
        
        # Convert to human readable format
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 31536000000:
            return f"{seconds/31536000:.1f} years"
        else:
            return "Centuries or more"