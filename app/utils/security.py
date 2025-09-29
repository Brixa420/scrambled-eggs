"""Security utilities including password hashing, token generation, and encryption."""

import base64
import hmac
import json
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple, Union

# Third-party imports
from argon2 import PasswordHasher
from argon2 import Type as Argon2Type

from app.core.exceptions import DecryptionError, EncryptionError, IntegrityCheckError

# Application imports
from app.services.encryption import crypto

# Initialize Argon2 password hasher
DEFAULT_TIME_COST = 2
DEFAULT_MEMORY_COST = 102400  # 100MB
DEFAULT_PARALLELISM = 8
DEFAULT_HASH_LENGTH = 32
DEFAULT_SALT_LENGTH = 16

password_hasher = PasswordHasher(
    time_cost=DEFAULT_TIME_COST,
    memory_cost=DEFAULT_MEMORY_COST,
    parallelism=DEFAULT_PARALLELISM,
    hash_len=DEFAULT_HASH_LENGTH,
    salt_len=DEFAULT_SALT_LENGTH,
    type=Argon2Type.ID,
)


def generate_uuid() -> str:
    """
    Generate a UUID4 string.

    Returns:
        str: A UUID4 string
    """
    return str(uuid.uuid4())


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a secure random token.

    Args:
        length: Length of the token in bytes (default: 32)

    Returns:
        str: A hexadecimal string representation of the token
    """
    if length < 16:
        raise ValueError("Token length must be at least 16 bytes")
    return secrets.token_hex(length)


def generate_api_key() -> str:
    """
    Generate a secure API key.

    Returns:
        str: A base64-encoded API key
    """
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def encrypt_sensitive_data(
    data: Union[str, dict], context: Optional[dict] = None
) -> Dict[str, Any]:
    """
    Encrypt sensitive data using the Scrambled Eggs encryption service.

    Args:
        data: The data to encrypt (string or JSON-serializable dict)
        context: Optional context for key derivation

    Returns:
        Dict containing the encrypted data and metadata

    Example:
        encrypted = encrypt_sensitive_data({"ssn": "123-45-6789"}, {"user_id": "123"})
    """
    try:
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)

        return crypto.encrypt(data_str, context=context or {})
    except Exception as e:
        logging.error(f"Failed to encrypt data: {str(e)}", exc_info=True)
        raise EncryptionError("Failed to encrypt sensitive data") from e


def decrypt_sensitive_data(
    encrypted_data: Dict[str, Any], context: Optional[dict] = None
) -> Union[str, dict]:
    """
    Decrypt data that was encrypted with encrypt_sensitive_data().

    Args:
        encrypted_data: The encrypted data dictionary from encrypt_sensitive_data()
        context: The same context used for encryption

    Returns:
        The decrypted data (string or dict if it was originally a dict)

    Example:
        decrypted = decrypt_sensitive_data(encrypted_data, {"user_id": "123"})
    """
    try:
        result = crypto.decrypt(encrypted_data, context=context or {})
        decrypted = result["plaintext"].decode("utf-8")

        # Try to parse as JSON if it was a dict
        try:
            return json.loads(decrypted)
        except json.JSONDecodeError:
            return decrypted

    except Exception as e:
        logging.error(f"Failed to decrypt data: {str(e)}", exc_info=True)
        if isinstance(e, (DecryptionError, IntegrityCheckError)):
            raise
        raise DecryptionError("Failed to decrypt sensitive data") from e


def encrypt_field(field_value: str, field_name: str, user_id: str) -> Dict[str, Any]:
    """
    Helper to encrypt a single field with field-specific context.

    Args:
        field_value: The value to encrypt
        field_name: Name/type of the field (e.g., 'ssn', 'email')
        user_id: ID of the user who owns this data

    Returns:
        Encrypted data dictionary
    """
    context = {"field": field_name, "user_id": str(user_id), "purpose": "field_encryption"}
    return encrypt_sensitive_data(field_value, context)


def decrypt_field(encrypted_data: Dict[str, Any], field_name: str, user_id: str) -> str:
    """
    Helper to decrypt a single field with field-specific context.

    Args:
        encrypted_data: The encrypted data dictionary
        field_name: Name/type of the field (e.g., 'ssn', 'email')
        user_id: ID of the user who owns this data

    Returns:
        Decrypted field value as string
    """
    context = {"field": field_name, "user_id": str(user_id), "purpose": "field_encryption"}
    return decrypt_sensitive_data(encrypted_data, context)


def generate_encrypted_cookie(value: str, max_age: int = 3600) -> str:
    """
    Generate an encrypted and signed cookie value.

    Args:
        value: The value to store in the cookie
        max_age: Maximum age in seconds (default: 1 hour)

    Returns:
        Encrypted and signed cookie string
    """
    try:
        expires = datetime.utcnow() + timedelta(seconds=max_age)
        data = {
            "value": value,
            "expires": expires.isoformat(),
            "created_at": datetime.utcnow().isoformat(),
        }
        encrypted = encrypt_sensitive_data(data, {"purpose": "secure_cookie"})
        return base64.urlsafe_b64encode(json.dumps(encrypted).encode()).decode()
    except Exception as e:
        logging.error(f"Failed to generate encrypted cookie: {str(e)}", exc_info=True)
        raise EncryptionError("Failed to generate secure cookie") from e


def decrypt_cookie(encrypted_cookie: str) -> Optional[str]:
    """
    Decrypt and verify a cookie value.

    Args:
        encrypted_cookie: The encrypted cookie value

    Returns:
        The decrypted cookie value or None if invalid/expired
    """
    try:
        # Decode from URL-safe base64
        decoded = base64.urlsafe_b64decode(encrypted_cookie).decode()
        encrypted_data = json.loads(decoded)

        # Decrypt the data
        data = decrypt_sensitive_data(encrypted_data, {"purpose": "secure_cookie"})

        # Check expiration
        expires = datetime.fromisoformat(data["expires"])
        if datetime.utcnow() > expires:
            return None

        return data["value"]

    except Exception as e:
        logging.error(f"Failed to decrypt cookie: {str(e)}", exc_info=True)
        return None


def constant_time_compare(val1: str, val2: str) -> bool:
    """
    Compare two strings in constant time to avoid timing attacks.

    Args:
        val1: First string to compare
        val2: Second string to compare

    Returns:
        bool: True if strings are equal, False otherwise
    """
    return hmac.compare_digest(val1, val2)


def is_secure_password(password: str) -> Tuple[bool, str]:
    """
    Check if a password meets security requirements.

    Args:
        password: The password to check

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"

    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if len(password) > 4096:
        return False, "Password is too long (max 4096 characters)"

    # Check for common passwords
    common_passwords = [
        "password",
        "123456",
        "12345678",
        "1234",
        "qwerty",
        "12345",
        "dragon",
        "baseball",
        "football",
        "letmein",
        "monkey",
        "abc123",
        "mustang",
        "michael",
        "shadow",
        "master",
        "jennifer",
        "111111",
        "2000",
        "jordan",
        "superman",
        "harley",
        "1234567",
        "freedom",
    ]

    if password.lower() in common_passwords:
        return False, "Password is too common"

    # Check for character diversity
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    if not (has_upper and has_lower):
        return False, "Password must contain both uppercase and lowercase letters"

    if not has_digit:
        return False, "Password must contain at least one number"

    if not has_special:
        return False, "Password must contain at least one special character"

    # Check for repeated characters
    if re.search(r"(.)\1{3,}", password):
        return False, "Password contains too many repeated characters"

    # Check for common patterns
    if re.search(
        r"(123|234|345|456|567|678|789|890|098|987|876|765|654|543|432|321|210)", password
    ):
        return False, "Password contains common number sequences"

    # Check for personal information in password (basic check)
    personal_info = [
        "name",
        "user",
        "login",
        "first",
        "last",
        "birth",
        "date",
        "year",
        "month",
        "day",
        "pet",
        "child",
        "spouse",
        "city",
        "team",
    ]

    password_lower = password.lower()
    if any(info in password_lower for info in personal_info):
        return False, "Password appears to contain personal information"

    # Calculate password strength score (optional)
    score = 0
    if len(password) >= 16:
        score += 2
    elif len(password) >= 12:
        score += 1

    if has_upper and has_lower:
        score += 1

    if has_digit:
        score += 1

    if has_special:
        score += 2

    if score < 4:
        return False, "Password is too weak"

    return True, ""
