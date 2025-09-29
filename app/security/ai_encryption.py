""
AI-Assisted Encryption Module

This module provides AI-enhanced encryption capabilities that adapt to the content
being encrypted, providing additional security layers based on message analysis.
"""

import os
import json
import base64
import hashlib
from typing import Dict, Tuple, Optional, Any
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from ..ai.model_manager import ModelManager

class AIEncryptionService:
    """AI-enhanced encryption service with adaptive security features."""
    
    def __init__(self, model_manager: Optional[ModelManager] = None):
        """Initialize the AI encryption service."""
        self.model_manager = model_manager or ModelManager()
        self.fernet = None
        self._load_or_generate_keys()
        self._load_ai_models()
    
    def _load_or_generate_keys(self):
        """Load or generate encryption keys."""
        keys_dir = os.path.join('data', 'keys')
        os.makedirs(keys_dir, exist_ok=True)
        
        # Try to load existing keys
        key_file = os.path.join(keys_dir, 'encryption_keys.json')
        
        if os.path.exists(key_file):
            with open(key_file, 'r') as f:
                keys = json.load(f)
            self.fernet_key = base64.urlsafe_b64decode(keys['fernet_key'])
            self.aes_key = base64.urlsafe_b64decode(keys['aes_key'])
            self.hmac_key = base64.urlsafe_b64decode(keys['hmac_key'])
        else:
            # Generate new keys
            self.fernet_key = Fernet.generate_key()
            self.aes_key = os.urandom(32)  # 256-bit key
            self.hmac_key = os.urandom(32)  # 256-bit key
            
            # Save keys securely
            keys = {
                'fernet_key': base64.urlsafe_b64encode(self.fernet_key).decode(),
                'aes_key': base64.urlsafe_b64encode(self.aes_key).decode(),
                'hmac_key': base64.urlsafe_b64encode(self.hmac_key).decode()
            }
            with open(key_file, 'w') as f:
                json.dump(keys, f)
            
            # Set secure permissions (Unix-like systems)
            try:
                os.chmod(key_file, 0o600)
            except:
                pass
        
        self.fernet = Fernet(base64.urlsafe_b64encode(self.fernet_key))
    
    def _load_ai_models(self):
        """Load AI models for encryption and analysis."""
        self.encryption_model = self.model_manager.load_model("encryption")
        self.security_model = self.model_manager.load_model("security_analysis")
    
    def _generate_iv(self) -> bytes:
        """Generate a secure initialization vector."""
        return os.urandom(16)
    
    def _pad_data(self, data: bytes) -> bytes:
        """Pad data to be encrypted."""
        padder = padding.PKCS7(128).padder()
        return padder.update(data) + padder.finalize()
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Unpad decrypted data."""
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()
    
    def _calculate_hmac(self, data: bytes) -> bytes:
        """Calculate HMAC for data integrity verification."""
        h = hmac.new(self.hmac_key, data, hashlib.sha256)
        return h.digest()
    
    def _analyze_message(self, message: str) -> Dict[str, Any]:
        """Analyze message content for security assessment."""
        if not self.security_model:
            return {"sensitivity": "medium", "risk_factors": []}
        
        try:
            # Tokenize the message
            inputs = self.security_model["tokenizer"](
                message, 
                return_tensors="pt", 
                truncation=True, 
                max_length=512
            )
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.security_model["model"](**inputs)
            
            # Process outputs (example - adjust based on your model)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            
            # This is a simplified example - adjust based on your model's output
            risk_factors = []
            if probabilities[0][1] > 0.7:  # Assuming index 1 is the "sensitive" class
                risk_factors.append("sensitive_content")
            
            return {
                "sensitivity": "high" if risk_factors else "low",
                "risk_factors": risk_factors,
                "confidence": float(torch.max(probabilities))
            }
            
        except Exception as e:
            print(f"Error analyzing message: {e}")
            return {"sensitivity": "medium", "risk_factors": ["analysis_failed"]}
    
    def _get_encryption_parameters(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Determine encryption parameters based on message analysis."""
        if analysis["sensitivity"] == "high":
            return {
                "algorithm": "aes-256-gcm",
                "key_derivation_rounds": 1_000_000,
                "additional_layers": 2,
                "salt_length": 32
            }
        else:
            return {
                "algorithm": "aes-256-cbc",
                "key_derivation_rounds": 100_000,
                "additional_layers": 1,
                "salt_length": 16
            }
    
    def _derive_key(self, password: str, salt: bytes, rounds: int) -> bytes:
        """Derive a secure key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=rounds,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_message(self, message: str, password: str) -> Dict[str, Any]:
        """Encrypt a message with AI-enhanced security."""
        # Analyze the message
        analysis = self._analyze_message(message)
        params = self._get_encryption_parameters(analysis)
        
        # Generate a random salt
        salt = os.urandom(params["salt_length"])
        
        # Derive encryption key
        key = self._derive_key(password, salt, params["key_derivation_rounds"])
        
        # Generate IV
        iv = self._generate_iv()
        
        # Encrypt the message
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv) if params["algorithm"] == "aes-256-gcm" else modes.CBC(iv),
            backend=default_backend()
        )
        
        encryptor = cipher.encryptor()
        
        # Pad and encrypt the data
        padded_data = self._pad_data(message.encode('utf-8'))
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # For GCM mode, get the authentication tag
        auth_tag = None
        if params["algorithm"] == "aes-256-gcm":
            auth_tag = encryptor.tag
        
        # Add additional security layers based on analysis
        for _ in range(params["additional_layers"]):
            # Apply additional encryption layer (e.g., Fernet)
            ciphertext = self.fernet.encrypt(ciphertext)
        
        # Create the result dictionary
        result = {
            "ciphertext": base64.urlsafe_b64encode(ciphertext).decode('utf-8'),
            "salt": base64.urlsafe_b64encode(salt).decode('utf-8'),
            "iv": base64.urlsafe_b64encode(iv).decode('utf-8'),
            "algorithm": params["algorithm"],
            "security_analysis": analysis,
            "version": "1.0.0"
        }
        
        if auth_tag:
            result["auth_tag"] = base64.urlsafe_b64encode(auth_tag).decode('utf-8')
        
        # Add HMAC for integrity verification
        hmac_data = f"{result['ciphertext']}{result['salt']}{result['iv']}".encode('utf-8')
        result["hmac"] = base64.urlsafe_b64encode(self._calculate_hmac(hmac_data)).decode('utf-8')
        
        return result
    
    def decrypt_message(self, encrypted_data: Dict[str, Any], password: str) -> str:
        """Decrypt a message that was encrypted with this service."""
        try:
            # Verify HMAC
            hmac_data = f"{encrypted_data['ciphertext']}{encrypted_data['salt']}{encrypted_data['iv']}".encode('utf-8')
            calculated_hmac = self._calculate_hmac(hmac_data)
            stored_hmac = base64.urlsafe_b64decode(encrypted_data['hmac'])
            
            if not hmac.compare_digest(calculated_hmac, stored_hmac):
                raise ValueError("HMAC verification failed - message may have been tampered with")
            
            # Decode the data
            ciphertext = base64.urlsafe_b64decode(encrypted_data['ciphertext'])
            salt = base64.urlsafe_b64decode(encrypted_data['salt'])
            iv = base64.urlsafe_b64decode(encrypted_data['iv'])
            algorithm = encrypted_data.get('algorithm', 'aes-256-cbc')
            auth_tag = base64.urlsafe_b64decode(encrypted_data.get('auth_tag', '')) if 'auth_tag' in encrypted_data else None
            
            # Handle additional encryption layers
            for _ in range(2 if algorithm == "aes-256-gcm" else 1):
                ciphertext = self.fernet.decrypt(ciphertext)
            
            # Derive the key
            key = self._derive_key(password, salt, 1_000_000 if algorithm == "aes-256-gcm" else 100_000)
            
            # Set up the cipher
            if algorithm == "aes-256-gcm":
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.GCM(iv, auth_tag),
                    backend=default_backend()
                )
            else:
                cipher = Cipher(
                    algorithms.AES(key),
                    modes.CBC(iv),
                    backend=default_backend()
                )
            
            # Decrypt the data
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad and decode the message
            message = self._unpad_data(padded_data).decode('utf-8')
            
            return message
            
        except (ValueError, KeyError, InvalidToken) as e:
            raise ValueError(f"Decryption failed: {str(e)}")
        except Exception as e:
            raise Exception(f"An error occurred during decryption: {str(e)}")

# Example usage
if __name__ == "__main__":
    # Initialize the encryption service
    encryption_service = AIEncryptionService()
    
    # Encrypt a message
    message = "This is a sensitive message that needs strong encryption."
    password = "my_secure_password_123!"
    
    print("Encrypting message...")
    encrypted = encryption_service.encrypt_message(message, password)
    print(f"Encrypted data: {json.dumps(encrypted, indent=2)}")
    
    # Decrypt the message
    print("\nDecrypting message...")
    try:
        decrypted = encryption_service.decrypt_message(encrypted, password)
        print(f"Decrypted message: {decrypted}")
    except Exception as e:
        print(f"Decryption failed: {e}")
