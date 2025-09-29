"""
AI Instance Management System
Handles creation, management, and lifecycle of personalized AI instances.
"""
import os
import uuid
import json
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime
import logging
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AIInstance:
    """Represents a single user's personalized AI instance."""
    
    def __init__(self, user_id: str, base_path: str = "data/ai_instances"):
        """Initialize a new AI instance for a user.
        
        Args:
            user_id: Unique identifier for the user
            base_path: Base directory for storing AI instance data
        """
        self.user_id = user_id
        self.instance_id = str(uuid.uuid4())
        self.base_path = Path(base_path) / user_id
        self.config_path = self.base_path / 'config.json'
        self.model_path = self.base_path / 'model'
        self.data_path = self.base_path / 'data'
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.created_at = datetime.utcnow()
        self.last_accessed = self.created_at
        self.is_active = False
        self._ensure_directories()
        self._load_config()
    
    def _ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.model_path.mkdir(exist_ok=True)
        self.data_path.mkdir(exist_ok=True)
    
    def _load_config(self) -> None:
        """Load instance configuration from disk."""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
                    self.instance_id = config.get('instance_id', self.instance_id)
                    self.encryption_key = config['encryption_key'].encode()
                    self.cipher_suite = Fernet(self.encryption_key)
                    self.created_at = datetime.fromisoformat(config['created_at'])
                    self.last_accessed = datetime.fromisoformat(config.get('last_accessed', 
                                                                       self.created_at.isoformat()))
            except Exception as e:
                logger.error(f"Error loading config for {self.user_id}: {e}")
                self._save_config()
        else:
            self._save_config()
    
    def _save_config(self) -> None:
        """Save instance configuration to disk."""
        config = {
            'user_id': self.user_id,
            'instance_id': self.instance_id,
            'encryption_key': self.encryption_key.decode(),
            'created_at': self.created_at.isoformat(),
            'last_accessed': datetime.utcnow().isoformat(),
            'version': '1.0.0'
        }
        with open(self.config_path, 'w') as f:
            json.dump(config, f, indent=2)
    
    def activate(self) -> None:
        """Activate the AI instance."""
        self.is_active = True
        self.last_accessed = datetime.utcnow()
        self._save_config()
        logger.info(f"Activated AI instance for user {self.user_id}")
    
    def deactivate(self) -> None:
        """Deactivate the AI instance."""
        self.is_active = False
        self._save_config()
        logger.info(f"Deactivated AI instance for user {self.user_id}")
    
    def encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data for this instance."""
        return self.cipher_suite.encrypt(data)
    
    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data for this instance."""
        return self.cipher_suite.decrypt(encrypted_data)
    
    def backup(self, backup_dir: str) -> str:
        """Create a backup of this instance."""
        backup_path = Path(backup_dir) / f"{self.user_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.zip"
        # Implementation for creating a zip backup would go here
        return str(backup_path)
    
    def __str__(self) -> str:
        return f"AIInstance(user_id={self.user_id}, instance_id={self.instance_id}, active={self.is_active})"


class AIManager:
    """Manages multiple AI instances."""
    
    def __init__(self, base_path: str = "data/ai_instances"):
        """Initialize the AI instance manager.
        
        Args:
            base_path: Base directory for storing all AI instances
        """
        self.base_path = Path(base_path)
        self.instances: Dict[str, AIInstance] = {}
        self._ensure_base_directory()
    
    def _ensure_base_directory(self) -> None:
        """Ensure the base directory exists."""
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def get_instance(self, user_id: str) -> AIInstance:
        """Get or create an AI instance for a user.
        
        Args:
            user_id: The user ID to get an instance for
            
        Returns:
            AIInstance: The user's AI instance
        """
        if user_id not in self.instances:
            self.instances[user_id] = AIInstance(user_id, str(self.base_path))
        return self.instances[user_id]
    
    def list_instances(self) -> List[str]:
        """List all available AI instances.
        
        Returns:
            List of user IDs with AI instances
        """
        return [d.name for d in self.base_path.iterdir() if d.is_dir()]
    
    def backup_all(self, backup_dir: str) -> List[str]:
        """Backup all instances.
        
        Args:
            backup_dir: Directory to store backups
            
        Returns:
            List of paths to backup files
        """
        Path(backup_dir).mkdir(parents=True, exist_ok=True)
        return [self.get_instance(user_id).backup(backup_dir) 
                for user_id in self.list_instances()]


# Singleton instance for the application
ai_manager = AIManager()
