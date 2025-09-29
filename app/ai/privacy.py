"""
Privacy and Security Module for AI Instances
Handles secure data management and privacy-preserving techniques.
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
import logging
from cryptography.fernet import Fernet, InvalidToken
import hashlib
import hmac
import secrets

logger = logging.getLogger(__name__)

class PrivacyEngine:
    """Handles privacy and security for AI instances."""
    
    def __init__(self, ai_instance: 'AIInstance'):
        """Initialize with an AI instance.
        
        Args:
            ai_instance: The AI instance to secure
        """
        self.ai_instance = ai_instance
        self.privacy_config = self._load_privacy_config()
        self.differential_privacy = DifferentialPrivacy()
    
    def _load_privacy_config(self) -> Dict[str, Any]:
        """Load privacy configuration."""
        config_path = self.ai_instance.data_path / 'privacy_config.json'
        default_config = {
            'data_retention_days': 30,
            'require_consent': True,
            'allow_telemetry': False,
            'allow_personalization': True,
            'allow_data_export': False,
            'last_audit': datetime.utcnow().isoformat(),
            'privacy_budget': 100.0,  # For differential privacy
            'privacy_budget_replenish_rate': 1.0  # Per day
        }
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                    # Merge with defaults
                    return {**default_config, **config}
            except Exception as e:
                logger.error(f"Error loading privacy config: {e}")
        
        return default_config
    
    def _save_privacy_config(self) -> None:
        """Save privacy configuration."""
        config_path = self.ai_instance.data_path / 'privacy_config.json'
        with open(config_path, 'w') as f:
            json.dump(self.privacy_config, f, indent=2)
    
    def update_privacy_settings(self, settings: Dict[str, Any]) -> None:
        """Update privacy settings."""
        for key, value in settings.items():
            if key in self.privacy_config:
                self.privacy_config[key] = value
        self._save_privacy_config()
    
    def check_privacy_budget(self, cost: float = 1.0) -> bool:
        """Check if there's enough privacy budget for an operation."""
        self._replenish_privacy_budget()
        return self.privacy_config['privacy_budget'] >= cost
    
    def use_privacy_budget(self, cost: float = 1.0) -> bool:
        """Use a portion of the privacy budget."""
        if not self.check_privacy_budget(cost):
            return False
        
        self.privacy_config['privacy_budget'] -= cost
        self._save_privacy_config()
        return True
    
    def _replenish_privacy_budget(self) -> None:
        """Replenish privacy budget based on time passed."""
        last_updated = datetime.fromisoformat(self.privacy_config['last_audit'])
        now = datetime.utcnow()
        days_passed = (now - last_updated).total_seconds() / (24 * 3600)
        
        if days_passed > 0:
            replenish_amount = days_passed * self.privacy_config['privacy_budget_replenish_rate']
            self.privacy_config['privacy_budget'] = min(
                100.0,  # Max budget
                self.privacy_config['privacy_budget'] + replenish_amount
            )
            self.privacy_config['last_audit'] = now.isoformat()
            self._save_privacy_config()
    
    def apply_differential_privacy(self, data: List[float], epsilon: float = 1.0) -> List[float]:
        """Apply differential privacy to a dataset."""
        if not self.check_privacy_budget(epsilon):
            raise ValueError("Insufficient privacy budget")
        
        result = self.differential_privacy.add_noise(data, epsilon)
        self.use_privacy_budget(epsilon)
        return result
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using the instance's encryption key."""
        return self.ai_instance.encrypt_data(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using the instance's encryption key."""
        try:
            return self.ai_instance.decrypt_data(encrypted_data)
        except InvalidToken:
            logger.error("Failed to decrypt data - invalid token")
            raise
    
    def secure_delete(self, file_path: Path) -> None:
        """Securely delete a file."""
        try:
            if file_path.exists():
                # Overwrite with random data before deletion
                file_size = file_path.stat().st_size
                with open(file_path, 'r+b') as f:
                    f.write(os.urandom(file_size))
                file_path.unlink()
        except Exception as e:
            logger.error(f"Error securely deleting {file_path}: {e}")
    
    def cleanup_old_data(self) -> None:
        """Clean up old data based on retention policy."""
        retention_days = self.privacy_config.get('data_retention_days', 30)
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        
        # Example: Clean up old interaction logs
        logs_path = self.ai_instance.data_path / 'interaction_logs'
        if logs_path.exists():
            for log_file in logs_path.glob('*.log'):
                mtime = datetime.utcfromtimestamp(log_file.stat().st_mtime)
                if mtime < cutoff:
                    self.secure_delete(log_file)


class DifferentialPrivacy:
    """Implements differential privacy mechanisms."""
    
    def __init__(self, sensitivity: float = 1.0):
        """Initialize with sensitivity parameter.
        
        Args:
            sensitivity: The maximum effect a single record can have on the output
        """
        self.sensitivity = sensitivity
    
    def laplace_mechanism(self, data: List[float], epsilon: float) -> List[float]:
        """Apply the Laplace mechanism for differential privacy.
        
        Args:
            data: The data to privatize
            epsilon: Privacy parameter (smaller = more private)
            
        Returns:
            Privatized data with Laplace noise added
        """
        import numpy as np
        scale = self.sensitivity / epsilon
        noise = np.random.laplace(0, scale, len(data))
        return [d + n for d, n in zip(data, noise)]
    
    def add_noise(self, data: List[float], epsilon: float) -> List[float]:
        """Add noise to data using the Laplace mechanism."""
        return self.laplace_mechanism(data, epsilon)
    
    def randomized_response(self, value: bool, p: float = 0.75) -> bool:
        """Randomized response for binary data.
        
        Args:
            value: The true value
            p: Probability of telling the truth (0.5 < p < 1.0)
            
        Returns:
            Potentially flipped boolean value
        """
        import random
        if random.random() < p:
            return value
        return not value


class SecureHasher:
    """Secure hashing utilities."""
    
    @staticmethod
    def hash_data(data: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Hash data with a random salt using PBKDF2."""
        if salt is None:
            salt = secrets.token_bytes(16)
        
        # Use PBKDF2 with SHA-256
        dk = hashlib.pbkdf2_hmac(
            'sha256',
            data.encode('utf-8'),
            salt,
            100000  # Number of iterations
        )
        return dk, salt
    
    @staticmethod
    def verify_hash(stored_hash: bytes, stored_salt: bytes, data: str) -> bool:
        """Verify data against a stored hash and salt."""
        new_hash, _ = SecureHasher.hash_data(data, stored_salt)
        return hmac.compare_digest(new_hash, stored_hash)
