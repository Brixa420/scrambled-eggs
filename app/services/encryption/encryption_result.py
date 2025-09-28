"""
Encryption Result Module

Defines the EncryptionResult class for storing encryption results.
"""
from dataclasses import dataclass, field
from typing import Dict, Any

@dataclass
class EncryptionResult:
    """Result of an encryption operation."""
    ciphertext: bytes
    key_id: str
    algorithm: str
    iv: bytes
    auth_tag: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary."""
        return {
            'ciphertext': self.ciphertext,
            'key_id': self.key_id,
            'algorithm': self.algorithm,
            'iv': self.iv,
            'auth_tag': self.auth_tag,
            'metadata': self.metadata
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EncryptionResult':
        """Create an EncryptionResult from a dictionary."""
        return cls(
            ciphertext=data['ciphertext'],
            key_id=data['key_id'],
            algorithm=data['algorithm'],
            iv=data['iv'],
            auth_tag=data['auth_tag'],
            metadata=data.get('metadata', {})
        )
