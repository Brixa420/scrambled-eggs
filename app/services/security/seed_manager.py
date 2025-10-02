"""
Secure Seed Phrase Manager

This module provides secure management of Brixa wallet seed phrases with multiple
encryption layers and secure storage.
"""
import os
import json
import base64
import hashlib
import logging
import time
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List
from pathlib import Path
from functools import wraps
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from getpass import getpass
import argon2

# Constants for rate limiting
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes in seconds
ATTEMPT_WINDOW = 3600  # 1 hour in seconds

class SecurityException(Exception):
    """Base class for security-related exceptions."""
    pass

class TooManyAttempts(SecurityException):
    """Raised when too many failed attempts are detected."""
    pass

class AccountLocked(SecurityException):
    """Raised when an account is temporarily locked."""
    def __init__(self, unlock_time: datetime):
        self.unlock_time = unlock_time
        super().__init__(f"Account locked until {unlock_time}")

def handle_security_errors(func):
    """Decorator to handle security-related exceptions."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SecurityException as e:
            raise
        except Exception as e:
            logger.error(f"Security error in {func.__name__}: {str(e)}")
            raise SecurityException("A security error occurred") from e
    return wrapper

logger = logging.getLogger(__name__)

class SeedManager:
    """
    Secure seed phrase manager with multiple encryption layers.
    
    Encryption Layers:
    1. AES-256-GCM encryption with random IV for each encryption
    2. Argon2 key derivation for password hashing
    3. HMAC-SHA256 for data integrity
    4. Fernet encryption for additional security
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """Initialize the seed manager with storage path.
        
        Args:
            storage_path: Directory to store encrypted seed phrases
        "
    
    def _derive_keys(self, password: str, salt: bytes) -> Tuple[bytes, bytes, bytes]:
        """Derive encryption and HMAC keys from password and salt."""
        # Derive a master key using Argon2
        kdf = argon2.PasswordHasher(
            time_cost=self.argon2_time_cost,
            memory_cost=self.argon2_memory_cost,
            parallelism=self.argon2_parallelism,
            hash_len=96,  # 32*3 bytes for three keys
            salt=salt
        )
        
        master_key = kdf.hash(password.encode())
        master_key_bytes = hashlib.sha512(master_key.encode()).digest()
        
        # Split into encryption key, HMAC key, and Fernet key
        enc_key = master_key_bytes[:32]
        hmac_key = master_key_bytes[32:64]
        fernet_key = base64.urlsafe_b64encode(master_key_bytes[64:96])
        
        return enc_key, hmac_key, fernet_key
    
    def _encrypt_data(self, data: bytes, password: str) -> bytes:
        """Encrypt data with multiple layers of encryption."""
        # Generate random salt and nonce
        salt = os.urandom(self.salt_size)
        nonce = os.urandom(self.nonce_size)
        
        # Derive keys
        enc_key, hmac_key, fernet_key = self._derive_keys(password, salt)
        
        # Layer 1: AES-256-GCM encryption
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(data) + encryptor.finalize()
        tag = encryptor.tag
        
        # Combine salt, nonce, tag, and encrypted data
        encrypted_data = salt + nonce + tag + encrypted
        
        # Layer 2: HMAC for integrity
        h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        hmac_digest = h.finalize()
        
        # Layer 3: Fernet encryption
        f = Fernet(fernet_key)
        final_encrypted = f.encrypt(hmac_digest + encrypted_data)
        
        return final_encrypted
    
    def _decrypt_data(self, encrypted_data: bytes, password: str) -> bytes:
        """Decrypt data with multiple layers of decryption."""
        try:
            # Derive keys (we'll need to extract salt first)
            salt = encrypted_data[:self.salt_size]
            _, hmac_key, fernet_key = self._derive_keys(password, salt)
            
            # Layer 3: Fernet decryption
            f = Fernet(fernet_key)
            try:
                decrypted = f.decrypt(encrypted_data)
            except InvalidToken:
                raise ValueError("Invalid password or corrupted data")
            
            # Extract HMAC and verify integrity
            received_hmac = decrypted[:32]
            encrypted_payload = decrypted[32:]
            
            h = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
            h.update(encrypted_payload)
            try:
                h.verify(received_hmac)
            except Exception as e:
                raise ValueError("Data integrity check failed") from e
            
            # Extract components
            salt = encrypted_payload[:self.salt_size]
            nonce = encrypted_payload[self.salt_size:self.salt_size + self.nonce_size]
            tag = encrypted_payload[self.salt_size + self.nonce_size:self.salt_size + self.nonce_size + self.tag_size]
            ciphertext = encrypted_payload[self.salt_size + self.nonce_size + self.tag_size:]
            
            # Derive encryption key
            enc_key, _, _ = self._derive_keys(password, salt)
            
            # Layer 1: AES-256-GCM decryption
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            return decryptor.update(ciphertext) + decryptor.finalize()
            
        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise ValueError("Failed to decrypt data. Incorrect password or corrupted data.")
    
    def _init_security_db(self) -> None:
        """Initialize the security database for rate limiting."""
        self.db_path = self.storage_path / "security.db"
        new_db = not self.db_path.exists()
        
        self.conn = sqlite3.connect(str(self.db_path), timeout=10)
        self.conn.execute("PRAGMA journal_mode=WAL")
        
        if new_db:
            with self.conn:
                self.conn.execute("""
                    CREATE TABLE login_attempts (
                        wallet_id TEXT PRIMARY KEY,
                        attempts INTEGER DEFAULT 0,
                        last_attempt REAL,
                        locked_until REAL
                    )
                """)
                self.conn.execute("""
                    CREATE TABLE security_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        wallet_id TEXT,
                        event_type TEXT,
                        timestamp REAL,
                        ip_address TEXT,
                        user_agent TEXT,
                        details TEXT
                    )
                """)
    
    def _check_rate_limit(self, wallet_id: str) -> None:
        """Check if the wallet is rate limited.
        
        Args:
            wallet_id: The wallet ID to check
            
        Raises:
            AccountLocked: If the account is temporarily locked
            TooManyAttempts: If too many failed attempts were made
        """
        now = time.time()
        
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute(
                "SELECT attempts, last_attempt, locked_until FROM login_attempts WHERE wallet_id = ?",
                (wallet_id,)
            )
            result = cursor.fetchone()
            
            if result:
                attempts, last_attempt, locked_until = result
                
                # Check if account is locked
                if locked_until and now < locked_until:
                    raise AccountLocked(datetime.fromtimestamp(locked_until))
                
                # Reset attempts if the window has passed
                if last_attempt and (now - last_attempt) > self.attempt_window:
                    attempts = 0
                
                # Check if too many attempts
                if attempts >= self.max_attempts:
                    # Lock the account
                    locked_until = now + self.lockout_time
                    cursor.execute(
                        "UPDATE login_attempts SET locked_until = ? WHERE wallet_id = ?",
                        (locked_until, wallet_id)
                    )
                    raise AccountLocked(datetime.fromtimestamp(locked_until))
    
    def _record_attempt(self, wallet_id: str, success: bool, ip: str = "", user_agent: str = "") -> None:
        """Record a login attempt.
        
        Args:
            wallet_id: The wallet ID being accessed
            success: Whether the attempt was successful
            ip: The IP address of the client (optional)
            user_agent: The user agent string (optional)
        """
        now = time.time()
        
        with self.conn:
            cursor = self.conn.cursor()
            
            # Update login attempts
            if success:
                # Reset on successful login
                cursor.execute(
                    """
                    INSERT INTO login_attempts (wallet_id, attempts, last_attempt, locked_until)
                    VALUES (?, 0, ?, NULL)
                    ON CONFLICT(wallet_id) DO UPDATE SET
                        attempts = 0,
                        last_attempt = excluded.last_attempt,
                        locked_until = NULL
                    """,
                    (wallet_id, now)
                )
            else:
                # Increment failed attempts
                cursor.execute(
                    """
                    INSERT INTO login_attempts (wallet_id, attempts, last_attempt)
                    VALUES (?, 1, ?)
                    ON CONFLICT(wallet_id) DO UPDATE SET
                        attempts = attempts + 1,
                        last_attempt = excluded.last_attempt
                    """,
                    (wallet_id, now)
                )
            
            # Log the security event
            cursor.execute(
                """
                INSERT INTO security_events 
                (wallet_id, event_type, timestamp, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    wallet_id,
                    "login_success" if success else "login_failure",
                    now,
                    ip,
                    user_agent,
                    json.dumps({"attempt_time": now})
                )
            )
            
            # Commit the transaction
            self.conn.commit()
            
            # Log the attempt
            if success:
                logger.info(f"Successful login for wallet: {wallet_id}")
            else:
                logger.warning(f"Failed login attempt for wallet: {wallet_id}")
    
    @handle_security_errors
    def save_seed_phrase(self, wallet_id: str, seed_phrase: str, password: str) -> str:
        """Securely save a seed phrase to disk with multiple encryption layers.
        
        Args:
            wallet_id: Unique identifier for the wallet
            seed_phrase: The seed phrase to encrypt and save
            password: User-provided password for encryption
            
        Returns:
            str: Path to the saved seed phrase file
        """
        if not seed_phrase or not isinstance(seed_phrase, str):
            raise ValueError("Invalid seed phrase")
            
        if not password:
            raise ValueError("Password cannot be empty")
            
        # Ensure the storage directory exists with secure permissions
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Create a secure file path
        wallet_file = self.storage_path / f"{wallet_id}.seed"
        
        try:
            # Encrypt the seed phrase
            encrypted_data = self._encrypt_data(seed_phrase.encode('utf-8'), password)
            
            # Write to file with secure permissions
            with open(wallet_file, 'wb') as f:
                f.write(encrypted_data)
                
            # Set restrictive file permissions (read/write for owner only)
            wallet_file.chmod(0o600)
            
            logger.info(f"Seed phrase saved securely to {wallet_file}")
            return str(wallet_file)
            
        except Exception as e:
            logger.error(f"Failed to save seed phrase: {str(e)}")
            # Ensure we don't leave sensitive data in memory
            del encrypted_data
            raise RuntimeError("Failed to securely save seed phrase") from e
    
    def load_seed_phrase(self, wallet_id: str, password: str) -> str:
        """Load and decrypt a seed phrase from disk.
        
        Args:
            wallet_id: Unique identifier for the wallet
            password: User-provided password for decryption
            
        Returns:
            str: The decrypted seed phrase
        """
        wallet_file = self.storage_path / f"{wallet_id}.seed"
        
        if not wallet_file.exists():
            raise FileNotFoundError(f"No seed phrase found for wallet {wallet_id}")
            
        try:
            # Read the encrypted data
            with open(wallet_file, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt the seed phrase
            seed_phrase = self._decrypt_data(encrypted_data, password).decode('utf-8')
            
            return seed_phrase
            
        except Exception as e:
            logger.error(f"Failed to load seed phrase: {str(e)}")
            raise ValueError("Failed to decrypt seed phrase. Incorrect password or corrupted data.") from e
    
    def delete_seed_phrase(self, wallet_id: str) -> bool:
        """Securely delete a seed phrase file.
        
        Args:
            wallet_id: Unique identifier for the wallet
            
        Returns:
            bool: True if deletion was successful
        """
        wallet_file = self.storage_path / f"{wallet_id}.seed"
        
        if wallet_file.exists():
            try:
                # Securely overwrite the file before deletion
                with open(wallet_file, 'wb') as f:
                    file_size = wallet_file.stat().st_size
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
                
                # Delete the file
                wallet_file.unlink()
                logger.info(f"Securely deleted seed phrase for wallet {wallet_id}")
                return True
                
            except Exception as e:
                logger.error(f"Failed to securely delete seed phrase: {str(e)}")
                return False
        
        return False

    def get_wallet_list(self) -> list:
        """Get a list of all saved wallet IDs.
        
        Returns:
            list: List of wallet IDs
        """
        return [f.stem for f in self.storage_path.glob("*.seed") if f.is_file()]

    @staticmethod
    @classmethod
    def verify_seed_phrase(cls, seed_phrase: str, wordlist: list) -> bool:
        """Verify that a seed phrase is valid.
        
        Args:
            seed_phrase: The seed phrase to verify
            wordlist: The BIP-39 wordlist to use for verification
            
        Returns:
            bool: True if the seed phrase is valid, False otherwise
        """
        try:
            words = seed_phrase.strip().split()
            if len(words) not in [12, 15, 18, 21, 24]:
                return False
                
            # Convert words back to binary
            word_index_map = {word: i for i, word in enumerate(wordlist)}
            binary_str = ''
            for word in words:
                if word not in word_index_map:
                    return False
                binary_str += bin(word_index_map[word])[2:].zfill(11)
                
            # Split into entropy and checksum
            checksum_length = len(words) // 3  # 4 bits for 12 words, 5 for 15, etc.
            entropy_bits = binary_str[:-checksum_length]
            checksum = binary_str[-checksum_length:]
            
            # Calculate expected checksum
            entropy_bytes = bytes(int(entropy_bits[i:i+8], 2) 
                               for i in range(0, len(entropy_bits), 8))
            hash_bytes = hashlib.sha256(entropy_bytes).digest()
            expected_checksum = bin(hash_bytes[0])[2:].zfill(8)[:checksum_length]
            
            return checksum == expected_checksum
            
        except Exception:
            return False
    
    @classmethod
    def generate_seed_phrase(cls, strength: int = 256, wordlist: list = None) -> str:
        """Generate a new cryptographically secure seed phrase with verification.
        
        Args:
            strength: Bit strength (128, 160, 192, 224, or 256)
            wordlist: Optional custom wordlist to use
            
        Returns:
            str: Space-separated seed phrase
            
        Raises:
            ValueError: If the strength is invalid or generation fails verification
        """
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError("Strength must be one of: 128, 160, 192, 224, 256")
            
        # Use default BIP-39 wordlist if none provided
        if wordlist is None:
            wordlist = [...]  # BIP-39 wordlist would be loaded here
            
        # Generate multiple times until we get a valid one (should be first try, but just in case)
        for _ in range(3):
            # Generate random bytes
            entropy = os.urandom(strength // 8)
            
            # Calculate checksum
            hash_bytes = hashlib.sha256(entropy).digest()
            checksum_bits = bin(hash_bytes[0])[2:].zfill(8)[:strength // 32]
            
            # Convert to binary string and add checksum
            entropy_bits = ''.join([bin(b)[2:].zfill(8) for b in entropy])
            entropy_bits += checksum_bits
            
            # Split into 11-bit chunks
            chunks = [entropy_bits[i:i+11] for i in range(0, len(entropy_bits), 11)]
            
            # Convert to words
            words = [wordlist[int(chunk, 2)] for chunk in chunks]
            seed_phrase = ' '.join(words)
            
            # Verify the generated seed phrase
            if cls.verify_seed_phrase(seed_phrase, wordlist):
                return seed_phrase
                
        raise ValueError("Failed to generate a valid seed phrase after multiple attempts"))
