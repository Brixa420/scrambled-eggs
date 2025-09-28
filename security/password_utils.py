"""Password utilities for secure password handling."""
import re
import bcrypt
from typing import Tuple, Optional, Dict, Any

from .utils import security_utils
from .config import get_config

# Initialize config
config = get_config()

class PasswordError(Exception):
    """Raised when there's an error with password operations."""
    pass

class PasswordPolicyError(PasswordError):
    """Raised when a password doesn't meet the policy requirements."""
    pass

class PasswordUtils:
    """Utilities for secure password handling."""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using bcrypt.
        
        Args:
            password: The plaintext password to hash
            
        Returns:
            The hashed password
            
        Raises:
            PasswordError: If hashing fails
        """
        if not password:
            raise PasswordError("Password cannot be empty")
            
        try:
            # Generate a salt and hash the password
            salt = bcrypt.gensalt(rounds=12)
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            raise PasswordError(f"Failed to hash password: {str(e)}")
    
    @staticmethod
    def check_password(hashed_password: str, user_password: str) -> bool:
        """
        Check if a password matches a hash.
        
        Args:
            hashed_password: The hashed password from the database
            user_password: The plaintext password to check
            
        Returns:
            True if the password matches, False otherwise
        """
        if not hashed_password or not user_password:
            return False
            
        try:
            return bcrypt.checkpw(
                user_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
    
    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """
        Validate that a password meets the strength requirements.
        
        Args:
            password: The password to validate
            
        Returns:
            A tuple of (is_valid, message) where is_valid is a boolean indicating
            if the password meets the requirements, and message is a string
            explaining why the password is invalid (or empty if valid)
        """
        if not password:
            return False, "Password cannot be empty"
            
        # Check minimum length
        if len(password) < config.PASSWORD_MIN_LENGTH:
            return False, f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters long"
            
        # Check for required character types
        errors = []
        
        if config.PASSWORD_REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("at least one uppercase letter")
            
        if config.PASSWORD_REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("at least one lowercase letter")
            
        if config.PASSWORD_REQUIRE_NUMBERS and not any(c.isdigit() for c in password):
            errors.append("at least one number")
            
        if config.PASSWORD_REQUIRE_SPECIAL and not any(c in "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~" for c in password):
            errors.append("at least one special character")
        
        if errors:
            message = "Password must contain " + ", ".join(errors)
            return False, message
            
        return True, ""
    
    @staticmethod
    def generate_strong_password(length: int = 16) -> str:
        """
        Generate a strong, random password.
        
        Args:
            length: The length of the password to generate (default: 16)
            
        Returns:
            A strong, random password
        """
        import secrets
        import string
        
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
            
        # Define character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:'\",.<>/?`~"
        
        # Ensure the password contains at least one of each required character type
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest of the password with random characters
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - len(password)))
        
        # Shuffle the password to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @staticmethod
    def is_password_compromised(password: str) -> bool:
        """
        Check if a password is known to be compromised.
        
        Note: In a real application, this would check against a database of
        compromised passwords (like Have I Been Pwned's API). This is a placeholder.
        
        Args:
            password: The password to check
            
        Returns:
            True if the password is known to be compromised, False otherwise
        """
        # In a real implementation, you would check against a database of compromised passwords
        # For example, using the Have I Been Pwned API
        # This is just a placeholder that checks for very common passwords
        
        common_passwords = [
            'password', '123456', '123456789', '12345', '12345678',
            '123123', '1234567', '1234567890', 'admin', 'welcome',
            'qwerty', 'abc123', 'letmein', 'monkey', 'password1'
        ]
        
        return password.lower() in common_passwords
    
    @staticmethod
    def get_password_policy() -> Dict[str, Any]:
        """
        Get the current password policy.
        
        Returns:
            A dictionary describing the password policy
        """
        return {
            'min_length': config.PASSWORD_MIN_LENGTH,
            'require_uppercase': config.PASSWORD_REQUIRE_UPPERCASE,
            'require_lowercase': config.PASSWORD_REQUIRE_LOWERCASE,
            'require_numbers': config.PASSWORD_REQUIRE_NUMBERS,
            'require_special': config.PASSWORD_REQUIRE_SPECIAL,
            'description': 'Passwords must be at least {} characters long{}'.format(
                config.PASSWORD_MIN_LENGTH,
                ' and contain at least one ' + 
                ', '.join(filter(None, [
                    'uppercase letter' if config.PASSWORD_REQUIRE_UPPERCASE else None,
                    'lowercase letter' if config.PASSWORD_REQUIRE_LOWERCASE else None,
                    'number' if config.PASSWORD_REQUIRE_NUMBERS else None,
                    'special character' if config.PASSWORD_REQUIRE_SPECIAL else None
                ])) + '.' if any([
                    config.PASSWORD_REQUIRE_UPPERCASE,
                    config.PASSWORD_REQUIRE_LOWERCASE,
                    config.PASSWORD_REQUIRE_NUMBERS,
                    config.PASSWORD_REQUIRE_SPECIAL
                ]) else ''
            )
        }


# Create an instance for easy importing
password_utils = PasswordUtils()
