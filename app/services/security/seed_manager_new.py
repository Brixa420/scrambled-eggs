"""
Secure Seed Phrase Manager

This module provides secure management of Brixa wallet seed phrases with multiple
encryption layers, secure storage, and rate limiting.
"""
import os
import json
import base64
import hashlib
import logging
import time
import sqlite3
import threading
import secrets
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any, List, Union
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

# Constants for security
DEFAULT_ITERATIONS = 100000
SALT_SIZE = 32  # bytes
NONCE_SIZE = 16  # bytes for AES-GCM
TAG_SIZE = 16  # bytes for AES-GCM

# Rate limiting constants
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes in seconds
ATTEMPT_WINDOW = 3600  # 1 hour in seconds

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
        except SecurityException:
            raise
        except Exception as e:
            logger.error(f"Security error in {func.__name__}: {str(e)}")
            raise SecurityException("A security error occurred") from e
    return wrapper

class SeedManager:
    """
    Secure seed phrase manager with multiple encryption layers and rate limiting.
    
    Encryption Layers:
    1. AES-256-GCM encryption with random IV for each encryption
    2. Argon2 key derivation for password hashing
    3. HMAC-SHA256 for data integrity
    4. Fernet encryption for additional security
    """
    
    def __init__(self, storage_path: Optional[Union[str, Path]] = None):
        """Initialize the seed manager with storage path.
        
        Args:
            storage_path: Directory to store encrypted seed phrases
        """
        # Initialize storage path with secure permissions
        self.storage_path = Path(storage_path or "~/.brixa/wallets").expanduser()
        self.storage_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        
        # Initialize security database
        self._init_security_db()
        
        # Encryption parameters
        self.salt_size = SALT_SIZE
        self.nonce_size = NONCE_SIZE
        self.tag_size = TAG_SIZE
        
        # Argon2 parameters
        self.argon2_time_cost = 3
        self.argon2_memory_cost = 65536  # 64MB
        self.argon2_parallelism = 4
        
        # Secure memory storage with auto-cleanup
        self._secure_memory = {}
        self._memory_lock = threading.Lock()
        
        logger.info(f"Seed manager initialized. Storage path: {self.storage_path}")
    
    def _init_security_db(self) -> None:
        """Initialize the security database for rate limiting and logging."""
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
                if last_attempt and (now - last_attempt) > ATTEMPT_WINDOW:
                    attempts = 0
                
                # Check if too many attempts
                if attempts >= MAX_ATTEMPTS:
                    # Lock the account
                    locked_until = now + LOCKOUT_TIME
                    cursor.execute(
                        "UPDATE login_attempts SET locked_until = ? WHERE wallet_id = ?",
                        (locked_until, wallet_id)
                    )
                    self.conn.commit()
                    raise AccountLocked(datetime.fromtimestamp(locked_until))
    
    def _record_attempt(self, wallet_id: str, success: bool, 
                       ip: str = "", user_agent: str = "") -> None:
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
            
            self.conn.commit()
            
            # Log the attempt
            if success:
                logger.info(f"Successful login for wallet: {wallet_id}")
            else:
                logger.warning(f"Failed login attempt for wallet: {wallet_id}")
    
    def _derive_keys(self, password: str, salt: bytes) -> Tuple[bytes, bytes, bytes]:
        """Derive encryption and HMAC keys from password and salt.
        
        Args:
            password: User password
            salt: Random salt
            
        Returns:
            Tuple of (encryption_key, hmac_key, fernet_key)
        """
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
        """Encrypt data with multiple layers of encryption.
        
        Args:
            data: Data to encrypt
            password: Encryption password
            
        Returns:
            Encrypted data
        """
        # Generate random salt and nonce
        salt = secrets.token_bytes(self.salt_size)
        nonce = secrets.token_bytes(self.nonce_size)
        
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
        """Decrypt data with multiple layers of decryption.
        
        Args:
            encrypted_data: Data to decrypt
            password: Decryption password
            
        Returns:
            Decrypted data
            
        Raises:
            ValueError: If decryption fails
        """
        try:
            # Extract salt for key derivation
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
            tag = encrypted_payload[
                self.salt_size + self.nonce_size:
                self.salt_size + self.nonce_size + self.tag_size
            ]
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
    
    @handle_security_errors
    def save_seed_phrase(self, wallet_id: str, seed_phrase: str, password: str) -> Path:
        """Securely save a seed phrase to disk.
        
        Args:
            wallet_id: Unique identifier for the wallet
            seed_phrase: The seed phrase to encrypt and save
            password: User-provided password for encryption
            
        Returns:
            Path to the saved seed phrase file
            
        Raises:
            ValueError: If seed phrase is invalid or save fails
        """
        if not seed_phrase or not isinstance(seed_phrase, str):
            raise ValueError("Invalid seed phrase")
        
        # Ensure the seed phrase is properly formatted
        seed_phrase = ' '.join(seed_phrase.strip().split())
        
        # Encrypt the seed phrase
        encrypted_data = self._encrypt_data(seed_phrase.encode('utf-8'), password)
        
        # Save to file with restricted permissions
        wallet_file = self.storage_path / f"{wallet_id}.seed"
        
        try:
            with open(wallet_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Set restrictive file permissions
            wallet_file.chmod(0o600)
            
            # Store in secure memory
            with self._memory_lock:
                self._secure_memory[wallet_id] = {
                    'seed': seed_phrase,
                    'expires': time.time() + 300,  # 5 minutes
                    'access_count': 0
                }
            
            logger.info(f"Seed phrase saved for wallet: {wallet_id}")
            return wallet_file
            
        except Exception as e:
            logger.error(f"Failed to save seed phrase: {str(e)}")
            if wallet_file.exists():
                wallet_file.unlink()  # Clean up partially written file
            raise ValueError("Failed to save seed phrase") from e
    
    @handle_security_errors
    def get_seed_phrase(self, wallet_id: str, password: str, 
                        ip: str = "", user_agent: str = "") -> str:
        """Retrieve and decrypt a seed phrase.
        
        Args:
            wallet_id: Unique identifier for the wallet
            password: User-provided password for decryption
            ip: Client IP address for rate limiting (optional)
            user_agent: Client user agent for logging (optional)
            
        Returns:
            The decrypted seed phrase
            
        Raises:
            ValueError: If decryption fails or wallet doesn't exist
            AccountLocked: If the account is temporarily locked
        """
        # Check rate limits first
        self._check_rate_limit(wallet_id)
        
        try:
            # Check secure memory first
            with self._memory_lock:
                if wallet_id in self._secure_memory:
                    entry = self._secure_memory[wallet_id]
                    if time.time() < entry['expires']:
                        entry['access_count'] += 1
                        return entry['seed']
                    else:
                        # Remove expired entry
                        del self._secure_memory[wallet_id]
            
            # Read from disk
            wallet_file = self.storage_path / f"{wallet_id}.seed"
            if not wallet_file.exists():
                self._record_attempt(wallet_id, False, ip, user_agent)
                raise ValueError(f"No seed phrase found for wallet: {wallet_id}")
            
            with open(wallet_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Decrypt the data
            decrypted_data = self._decrypt_data(encrypted_data, password)
            seed_phrase = decrypted_data.decode('utf-8')
            
            # Store in secure memory
            with self._memory_lock:
                self._secure_memory[wallet_id] = {
                    'seed': seed_phrase,
                    'expires': time.time() + 300,  # 5 minutes
                    'access_count': 1
                }
            
            # Record successful attempt
            self._record_attempt(wallet_id, True, ip, user_agent)
            
            return seed_phrase
            
        except Exception as e:
            # Record failed attempt
            self._record_attempt(wallet_id, False, ip, user_agent)
            logger.error(f"Failed to decrypt seed phrase for wallet {wallet_id}: {str(e)}")
            if "Invalid password" in str(e) or "Data integrity check failed" in str(e):
                raise ValueError("Invalid password or corrupted data") from e
            raise
    
    def clear_secure_memory(self, wallet_id: str = None) -> None:
        """Clear sensitive data from memory.
        
        Args:
            wallet_id: Specific wallet ID to clear, or None to clear all
        """
        with self._memory_lock:
            if wallet_id:
                if wallet_id in self._secure_memory:
                    # Securely clear the memory
                    if 'seed' in self._secure_memory[wallet_id]:
                        # Overwrite the seed in memory
                        self._secure_memory[wallet_id]['seed'] = '\x00' * len(
                            self._secure_memory[wallet_id]['seed']
                        )
                    del self._secure_memory[wallet_id]
            else:
                # Securely clear all memory
                for wallet_id in list(self._secure_memory.keys()):
                    if 'seed' in self._secure_memory[wallet_id]:
                        self._secure_memory[wallet_id]['seed'] = '\x00' * len(
                            self._secure_memory[wallet_id]['seed']
                        )
                self._secure_memory.clear()
    
    def get_security_events(self, wallet_id: str = None, 
                          limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events for a wallet or all wallets.
        
        Args:
            wallet_id: Wallet ID to filter by, or None for all wallets
            limit: Maximum number of events to return
            
        Returns:
            List of security events, most recent first
        """
        query = """
            SELECT wallet_id, event_type, timestamp, ip_address, user_agent, details
            FROM security_events
            {where_clause}
            ORDER BY timestamp DESC
            LIMIT ?
        """
        
        params = [limit]
        where_clause = ""
        
        if wallet_id:
            where_clause = "WHERE wallet_id = ?"
            params.insert(0, wallet_id)
        
        cursor = self.conn.cursor()
        cursor.execute(query.format(where_clause=where_clause), params)
        
        events = []
        for row in cursor.fetchall():
            wallet_id, event_type, timestamp, ip, ua, details = row
            events.append({
                'wallet_id': wallet_id,
                'event_type': event_type,
                'timestamp': datetime.fromtimestamp(timestamp),
                'ip_address': ip,
                'user_agent': ua,
                'details': json.loads(details) if details else {}
            })
        
        return events
    
    def __del__(self):
        """Clean up resources and clear secure memory."""
        self.clear_secure_memory()
        if hasattr(self, 'conn'):
            self.conn.close()
