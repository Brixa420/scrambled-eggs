"""
Clippy's Self-Updating Encryption System

This module handles the automatic updating of Clippy's encryption algorithms
using the Brixa blockchain. It provides functionality to check for updates,
download new encryption schemes, and apply them securely.
"""
import os
import json
import hashlib
import logging
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from .clippy_encryption import ClippyEncryption
from brixa.blockchain import BrixaBlockchain

logger = logging.getLogger(__name__)

class EncryptionUpdater:
    """
    Handles the updating of Clippy's encryption algorithms.
    
    This class is responsible for checking for updates to the encryption
    algorithms, verifying their authenticity, and applying them to the
    running system.
    """
    
    def __init__(self, 
                encryption: Optional[ClippyEncryption] = None,
                blockchain: Optional[BrixaBlockchain] = None,
                config_path: Optional[str] = None):
        """
        Initialize the EncryptionUpdater.
        
        Args:
            encryption: An instance of ClippyEncryption to update.
            blockchain: An instance of BrixaBlockchain for fetching updates.
            config_path: Path to the configuration directory.
        """
        self.encryption = encryption or ClippyEncryption()
        self.blockchain = blockchain or BrixaBlockchain()
        self.config_path = config_path or os.path.expanduser('~/.brixa/security')
        self.last_update_check = None
        self.update_interval = timedelta(hours=24)  # Check for updates daily
        
        # Ensure config directory exists
        os.makedirs(self.config_path, exist_ok=True)
        
        # Load update state
        self.state = self._load_state()
    
    def _load_state(self) -> Dict[str, Any]:
        """Load the update state from disk."""
        state_path = os.path.join(self.config_path, 'update_state.json')
        
        if not os.path.exists(state_path):
            return {
                'last_update_check': None,
                'last_update_time': None,
                'current_version': self.encryption.version,
                'update_available': False,
                'last_error': None
            }
        
        try:
            with open(state_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading update state: {e}")
            return {
                'last_update_check': None,
                'last_update_time': None,
                'current_version': self.encryption.version,
                'update_available': False,
                'last_error': str(e)
            }
    
    def _save_state(self) -> None:
        """Save the update state to disk."""
        state_path = os.path.join(self.config_path, 'update_state.json')
        
        try:
            with open(state_path, 'w') as f:
                json.dump(self.state, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving update state: {e}")
    
    def check_for_updates(self, force: bool = False) -> bool:
        """
        Check for updates to the encryption algorithms.
        
        Args:
            force: If True, check for updates even if the last check was recent.
            
        Returns:
            bool: True if an update is available, False otherwise.
        """
        now = datetime.utcnow()
        
        # Don't check too frequently
        if (not force and 
            self.state.get('last_update_check') and 
            (now - datetime.fromisoformat(self.state['last_update_check'])) < self.update_interval):
            return self.state.get('update_available', False)
        
        self.state['last_update_check'] = now.isoformat()
        self.state['last_error'] = None
        
        try:
            # Check for updates on the blockchain
            update_available = self.encryption.check_for_updates()
            
            if update_available:
                self.state['update_available'] = True
                self.state['current_version'] = self.encryption.version
                self.state['last_update_time'] = now.isoformat()
                logger.info(f"Encryption updated to version {self.encryption.version}")
            
            self._save_state()
            return update_available
            
        except Exception as e:
            self.state['last_error'] = str(e)
            self._save_state()
            logger.error(f"Error checking for updates: {e}")
            return False
    
    def apply_update(self, scheme: Dict[str, Any]) -> bool:
        """
        Apply an encryption scheme update.
        
        Args:
            scheme: The encryption scheme to apply.
            
        Returns:
            bool: True if the update was applied successfully, False otherwise.
        """
        try:
            # Verify the scheme is valid
            if not self._validate_scheme(scheme):
                return False
            
            # Apply the update
            self.encryption._apply_encryption_update(scheme)
            
            # Update state
            self.state['current_version'] = scheme['version']
            self.state['last_update_time'] = datetime.utcnow().isoformat()
            self.state['update_available'] = False
            self._save_state()
            
            logger.info(f"Successfully applied encryption update to version {scheme['version']}")
            return True
            
        except Exception as e:
            self.state['last_error'] = str(e)
            self._save_state()
            logger.error(f"Error applying update: {e}")
            return False
    
    def _validate_scheme(self, scheme: Dict[str, Any]) -> bool:
        """
        Validate an encryption scheme.
        
        Args:
            scheme: The encryption scheme to validate.
            
        Returns:
            bool: True if the scheme is valid, False otherwise.
        """
        # Check required fields
        required_fields = ['version', 'algorithms', 'signature', 'signed_by']
        for field in required_fields:
            if field not in scheme:
                logger.error(f"Missing required field in encryption scheme: {field}")
                return False
        
        # Verify the signature
        if not self._verify_scheme_signature(scheme):
            logger.error("Invalid signature for encryption scheme")
            return False
        
        # Check version format
        try:
            version_parts = [int(part) for part in scheme['version'].split('.')]
            if len(version_parts) < 2:
                raise ValueError("Version must have at least two parts")
        except (ValueError, AttributeError) as e:
            logger.error(f"Invalid version format: {e}")
            return False
        
        # Validate algorithms
        if not self._validate_algorithms(scheme['algorithms']):
            return False
        
        return True
    
    def _verify_scheme_signature(self, scheme: Dict[str, Any]) -> bool:
        """
        Verify the signature of an encryption scheme.
        
        Args:
            scheme: The encryption scheme to verify.
            
        Returns:
            bool: True if the signature is valid, False otherwise.
        """
        try:
            # Make a copy of the scheme and remove the signature
            scheme_copy = scheme.copy()
            signature = scheme_copy.pop('signature')
            signer = scheme_copy.pop('signed_by', None)
            
            if not signer:
                return False
            
            # Serialize the scheme for signing
            scheme_data = json.dumps(scheme_copy, sort_keys=True).encode('utf-8')
            
            # Verify the signature using the blockchain
            return self.blockchain.verify_signature(
                scheme_data,
                bytes.fromhex(signature),
                signer
            )
            
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False
    
    def _validate_algorithms(self, algorithms: Dict[str, Any]) -> bool:
        """
        Validate the algorithms in an encryption scheme.
        
        Args:
            algorithms: The algorithms to validate.
            
        Returns:
            bool: True if the algorithms are valid, False otherwise.
        """
        required_sections = ['key_derivation', 'encryption', 'signature']
        
        for section in required_sections:
            if section not in algorithms:
                logger.error(f"Missing required algorithm section: {section}")
                return False
        
        # Validate key derivation algorithm
        kd = algorithms['key_derivation']
        if kd['algorithm'] not in ['HKDF-SHA3-512', 'Argon2id', 'PBKDF2-SHA3-512']:
            logger.error(f"Unsupported key derivation algorithm: {kd['algorithm']}")
            return False
        
        # Validate encryption algorithm
        enc = algorithms['encryption']
        if enc['algorithm'] not in ['AES-256-GCM', 'ChaCha20-Poly1305']:
            logger.error(f"Unsupported encryption algorithm: {enc['algorithm']}")
            return False
        
        # Validate signature algorithm
        sig = algorithms['signature']
        if sig['algorithm'] not in ['Ed448', 'Ed25519', 'ECDSA-P384']:
            logger.error(f"Unsupported signature algorithm: {sig['algorithm']}")
            return False
        
        return True

# Singleton instance
encryption_updater = EncryptionUpdater()
