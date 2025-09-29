"""
Wallet implementation for the Brixa blockchain.
"""
import os
import json
import base58
import hashlib
from dataclasses import dataclass
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from typing import Dict, Any, Optional

@dataclass
class Wallet:
    """A Brixa wallet for managing addresses and signing transactions."""
    private_key: bytes
    public_key: bytes
    address: str
    balance: int = 0

    @classmethod
    def create_new(cls) -> 'Wallet':
        """Create a new wallet with a random private key."""
        sk = SigningKey.generate(curve=SECP256k1)
        return cls.from_private_key(sk.to_string())

    @classmethod
    def from_private_key(cls, private_key: bytes) -> 'Wallet':
        """Create wallet from existing private key."""
        sk = SigningKey.from_string(private_key, curve=SECP256k1)
        vk = sk.verifying_key
        public_key = vk.to_string()
        address = cls.public_key_to_address(public_key)
        return cls(
            private_key=private_key,
            public_key=public_key,
            address=address
        )

    @staticmethod
    def public_key_to_address(public_key: bytes) -> str:
        """Convert public key to Brixa address."""
        # SHA-256 hash of public key
        sha256 = hashlib.sha256(public_key).digest()
        
        # RIPEMD-160 hash of SHA-256
        ripemd160 = hashlib.new('ripemd160', sha256).digest()
        
        # Add version byte (0x00 for mainnet)
        version_ripemd160 = b'\x00' + ripemd160
        
        # Double SHA-256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(version_ripemd160).digest()).digest()[:4]
        
        # Base58 encode
        return base58.b58encode(version_ripemd160 + checksum).decode('utf-8')

    def sign(self, data: Dict[str, Any]) -> str:
        """Sign data with private key."""
        sk = SigningKey.from_string(self.private_key, curve=SECP256k1)
        message = json.dumps(data, sort_keys=True).encode()
        signature = sk.sign_deterministic(message, hashfunc=hashlib.sha256)
        return signature.hex()

    @staticmethod
    def verify_signature(public_key: bytes, signature: str, data: Dict[str, Any]) -> bool:
        """Verify a signature."""
        try:
            vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
            message = json.dumps(data, sort_keys=True).encode()
            return vk.verify(bytes.fromhex(signature), message, hashfunc=hashlib.sha256)
        except Exception as e:
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert wallet to dictionary for storage."""
        return {
            'private_key': self.private_key.hex(),
            'public_key': self.public_key.hex(),
            'address': self.address,
            'balance': self.balance
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Wallet':
        """Create wallet from dictionary."""
        return cls(
            private_key=bytes.fromhex(data['private_key']),
            public_key=bytes.fromhex(data['public_key']),
            address=data['address'],
            balance=data.get('balance', 0)
        )

    def save_to_file(self, filename: str) -> None:
        """Save wallet to file."""
        with open(filename, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @classmethod
    def load_from_file(cls, filename: str) -> 'Wallet':
        """Load wallet from file."""
        with open(filename, 'r') as f:
            data = json.load(f)
            return cls.from_dict(data)

def create_wallet() -> Wallet:
    """
    Create a new wallet and save it to disk.
    
    Returns:
        Wallet: The newly created wallet
    """
    wallet = Wallet.create_new()
    
    # Create wallets directory if it doesn't exist
    os.makedirs('wallets', exist_ok=True)
    
    # Save wallet to file
    wallet_file = f"wallets/{wallet.address}.json"
    wallet.save_to_file(wallet_file)
    
    return wallet
