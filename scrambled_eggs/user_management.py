"""
User Management System for Scrambled Eggs
---------------------------------------
Handles user creation, authentication, and management.
"""

import hashlib
import json
import logging
import os
import secrets
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import argon2

logger = logging.getLogger(__name__)

# Default user data directory
USER_DATA_DIR = Path.home() / ".scrambled_eggs" / "users"
USER_DATA_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class User:
    """Represents a user in the system."""

    username: str
    password_hash: str
    salt: str
    is_admin: bool = False
    is_active: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_login: Optional[str] = None
    failed_login_attempts: int = 0
    password_changed_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    password_expiry_days: int = 90
    attributes: Dict = field(default_factory=dict)


class UserManager:
    """Manages user accounts and authentication."""

    def __init__(self, data_dir: Path = USER_DATA_DIR):
        """Initialize the user manager.

        Args:
            data_dir: Directory to store user data
        """
        self.data_dir = data_dir
        self.users: Dict[str, User] = {}
        self._load_users()

        # Initialize default admin if no users exist
        if not self.users:
            self._create_default_admin()

    def _load_users(self) -> None:
        """Load users from disk."""
        self.users = {}
        for user_file in self.data_dir.glob("*.json"):
            try:
                with open(user_file, "r") as f:
                    user_data = json.load(f)
                    self.users[user_data["username"]] = User(**user_data)
            except Exception as e:
                logger.error(f"Error loading user from {user_file}: {e}")

    def _save_user(self, user: User) -> None:
        """Save a user to disk.

        Args:
            user: User object to save
        """
        try:
            user_file = self.data_dir / f"{user.username}.json"
            with open(user_file, "w") as f:
                json.dump(asdict(user), f, indent=2)
        except Exception as e:
            logger.error(f"Error saving user {user.username}: {e}")
            raise

    def _create_default_admin(self) -> None:
        """Create a default admin user if no users exist."""
        if not any(u.is_admin for u in self.users.values()):
            self.create_user(
                username="admin",
                password="admin123",  # Should be changed on first login
                is_admin=True,
            )
            logger.warning(
                "Default admin user created with username 'admin' and password 'admin123'"
            )
            logger.warning("PLEASE CHANGE THE DEFAULT PASSWORD IMMEDIATELY!")

    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """Hash a password with Argon2.

        Args:
            password: Plain text password
            salt: Optional salt (generated if not provided)

        Returns:
            Tuple of (hashed_password, salt)
        """
        if salt is None:
            salt = secrets.token_hex(16)

        # Use Argon2 for password hashing
        hasher = argon2.PasswordHasher(
            time_cost=3,  # Number of iterations
            memory_cost=65536,  # 64MB memory usage
            parallelism=4,  # Number of threads
            hash_len=32,  # Hash length in bytes
            salt_len=16,  # Salt length in bytes
        )

        # Hash the password with the salt
        password_hash = hasher.hash(f"{password}{salt}")
        return password_hash, salt

    def create_user(
        self,
        username: str,
        password: str,
        is_admin: bool = False,
        attributes: Optional[Dict] = None,
    ) -> User:
        """Create a new user.

        Args:
            username: Unique username
            password: Plain text password
            is_admin: Whether the user has admin privileges
            attributes: Additional user attributes

        Returns:
            The created User object

        Raises:
            ValueError: If username already exists
        """
        if username in self.users:
            raise ValueError(f"Username '{username}' already exists")

        # Hash the password
        password_hash, salt = self._hash_password(password)

        # Create the user
        user = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            is_admin=is_admin,
            attributes=attributes or {},
        )

        # Save the user
        self.users[username] = user
        self._save_user(user)

        logger.info(f"Created user: {username} (Admin: {is_admin})")
        return user

    def authenticate(self, username: str, password: str) -> Optional[User]:
        """Authenticate a user.

        Args:
            username: Username
            password: Plain text password

        Returns:
            User object if authentication succeeds, None otherwise
        """
        user = self.users.get(username)
        if not user or not user.is_active:
            return None

        try:
            # Verify the password
            hasher = argon2.PasswordHasher()
            hasher.verify(f"{password}{user.salt}", user.password_hash)

            # Update last login time
            user.last_login = datetime.utcnow().isoformat()
            user.failed_login_attempts = 0
            self._save_user(user)

            return user

        except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.VerificationError):
            # Increment failed login attempts
            user.failed_login_attempts += 1
            self._save_user(user)
            return None
        except Exception as e:
            logger.error(f"Authentication error for user {username}: {e}")
            return None

    def change_password(self, username: str, current_password: str, new_password: str) -> bool:
        """Change a user's password.

        Args:
            username: Username
            current_password: Current plain text password
            new_password: New plain text password

        Returns:
            True if password was changed, False otherwise
        """
        user = self.authenticate(username, current_password)
        if not user:
            return False

        # Hash the new password
        user.password_hash, user.salt = self._hash_password(new_password)
        user.password_changed_at = datetime.utcnow().isoformat()

        # Save the updated user
        self._save_user(user)
        logger.info(f"Password changed for user: {username}")
        return True

    def reset_password(self, username: str, new_password: str, admin_username: str) -> bool:
        """Reset a user's password (admin only).

        Args:
            username: Username of the user whose password to reset
            new_password: New plain text password
            admin_username: Username of the admin performing the reset

        Returns:
            True if password was reset, False otherwise
        """
        admin = self.users.get(admin_username)
        if not admin or not admin.is_admin:
            logger.warning(f"Unauthorized password reset attempt by {admin_username}")
            return False

        user = self.users.get(username)
        if not user:
            return False

        # Hash the new password
        user.password_hash, user.salt = self._hash_password(new_password)
        user.password_changed_at = datetime.utcnow().isoformat()

        # Save the updated user
        self._save_user(user)
        logger.info(f"Password reset for user {username} by admin {admin_username}")
        return True

    def list_users(self) -> List[Dict]:
        """Get a list of all users.

        Returns:
            List of user dictionaries (without sensitive data)
        """
        return [
            {
                "username": user.username,
                "is_admin": user.is_admin,
                "is_active": user.is_active,
                "created_at": user.created_at,
                "last_login": user.last_login,
                "password_changed_at": user.password_changed_at,
                "password_expiry_days": user.password_expiry_days,
            }
            for user in self.users.values()
        ]

    def update_user(
        self,
        username: str,
        is_admin: Optional[bool] = None,
        is_active: Optional[bool] = None,
        attributes: Optional[Dict] = None,
        password_expiry_days: Optional[int] = None,
    ) -> bool:
        """Update user properties.

        Args:
            username: Username of the user to update
            is_admin: Whether the user should be an admin
            is_active: Whether the user account is active
            attributes: User attributes to update (merged with existing)
            password_expiry_days: Number of days until password expires

        Returns:
            True if the user was updated, False otherwise
        """
        user = self.users.get(username)
        if not user:
            return False

        if is_admin is not None:
            user.is_admin = is_admin

        if is_active is not None:
            user.is_active = is_active

        if attributes is not None:
            user.attributes.update(attributes)

        if password_expiry_days is not None:
            user.password_expiry_days = password_expiry_days

        self._save_user(user)
        logger.info(f"Updated user: {username}")
        return True

    def delete_user(self, username: str, admin_username: str) -> bool:
        """Delete a user (admin only).

        Args:
            username: Username of the user to delete
            admin_username: Username of the admin performing the deletion

        Returns:
            True if the user was deleted, False otherwise
        """
        admin = self.users.get(admin_username)
        if not admin or not admin.is_admin:
            logger.warning(f"Unauthorized delete attempt by {admin_username}")
            return False

        if username not in self.users:
            return False

        # Don't allow deleting yourself
        if username == admin_username:
            logger.warning(f"User {admin_username} attempted to delete their own account")
            return False

        # Delete the user file
        user_file = self.data_dir / f"{username}.json"
        try:
            if user_file.exists():
                user_file.unlink()
            del self.users[username]
            logger.info(f"Deleted user: {username} (by admin {admin_username})")
            return True
        except Exception as e:
            logger.error(f"Error deleting user {username}: {e}")
            return False
