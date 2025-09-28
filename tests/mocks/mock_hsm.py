"""
Mock HSM client for testing.
"""
import asyncio
from typing import Dict, List, Optional, Union
import uuid
from datetime import datetime, timedelta

from scrambled_eggs.hsm import (
    HSMType, KeyType, KeyUsage, HSMKey, HSMInterface
)

class MockHSMClient(HSMInterface):
    """Mock HSM client for testing."""
    
    def __init__(self, config: Optional[dict] = None):
        super().__init__(hsm_type=HSMType.CLOUD_KMS)
        self._keys: Dict[str, HSMKey] = {}
        self._key_data: Dict[str, bytes] = {}
        self._config = config or {}
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize the mock HSM client."""
        self._initialized = True
    
    async def disconnect(self) -> None:
        """Disconnect from the mock HSM."""
        self._initialized = False
    
    async def create_key(
        self,
        key_type: Union[KeyType, str],
        key_size: int,
        key_id: Optional[str] = None,
        label: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        allowed_operations: Optional[List[Union[KeyUsage, str]]] = None,
        **kwargs
    ) -> HSMKey:
        """Create a mock key."""
        if not self._initialized:
            raise RuntimeError("HSM not initialized")
            
        key_id = key_id or f"mock-key-{uuid.uuid4().hex[:8]}"
        now = datetime.utcnow()
        
        if isinstance(key_type, str):
            key_type = KeyType(key_type.lower())
            
        if allowed_operations:
            allowed_operations = [
                op if isinstance(op, KeyUsage) else KeyUsage[op.upper()]
                for op in allowed_operations
            ]
        else:
            allowed_operations = list(KeyUsage)
        
        key = HSMKey(
            key_id=key_id,
            key_type=key_type,
            key_size=key_size,
            algorithm=f"{key_type.name.upper()}_{key_size}",
            attributes={
                'created_at': now,
                'enabled': True,
                'exportable': False,
                'tags': tags or {},
                'allowed_operations': [op.value for op in allowed_operations]
            },
            public_key=f"public-key-{key_id}".encode(),
            allowed_operations=allowed_operations,
            created_at=now,
            updated_at=now,
            tags=tags or {},
            description=label or f"Test {key_type.name} key"
        )
        
        self._keys[key_id] = key
        self._key_data[key_id] = os.urandom(32)  # Simulate key material
        
        return key
    
    async def get_key(self, key_id: str) -> Optional[HSMKey]:
        """Get a mock key by ID."""
        return self._keys.get(key_id)
    
    async def delete_key(self, key_id: str) -> bool:
        """Delete a mock key."""
        if key_id in self._keys:
            del self._keys[key_id]
            del self._key_data[key_id]
            return True
        return False
    
    async def encrypt(
        self,
        key_id: str,
        plaintext: bytes,
        **kwargs
    ) -> bytes:
        """Mock encryption (just returns the plaintext for testing)."""
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        return plaintext  # In a real test, this would actually encrypt
    
    async def decrypt(
        self,
        key_id: str,
        ciphertext: bytes,
        **kwargs
    ) -> bytes:
        """Mock decryption (just returns the ciphertext for testing)."""
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        return ciphertext  # In a real test, this would actually decrypt
    
    async def sign(
        self,
        key_id: str,
        data: bytes,
        **kwargs
    ) -> bytes:
        """Mock signing."""
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        return f"signature-for-{key_id}".encode()
    
    async def verify(
        self,
        key_id: str,
        data: bytes,
        signature: bytes,
        **kwargs
    ) -> bool:
        """Mock signature verification."""
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        return signature == f"signature-for-{key_id}".encode()
    
    async def rotate_key(self, key_id: str) -> HSMKey:
        """Mock key rotation."""
        if key_id not in self._keys:
            raise ValueError(f"Key {key_id} not found")
        
        old_key = self._keys[key_id]
        new_key = await self.create_key(
            key_type=old_key.key_type,
            key_size=old_key.key_size,
            label=f"{old_key.key_id}-rotated",
            tags=old_key.tags,
            allowed_operations=old_key.allowed_operations
        )
        
        # Mark the old key as rotated
        old_key.attributes['rotated'] = True
        old_key.attributes['replaced_by'] = new_key.key_id
        
        # Mark the new key as a rotation
        new_key.attributes['rotated_from'] = old_key.key_id
        
        return new_key
