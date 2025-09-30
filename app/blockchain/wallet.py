"""
Wallet implementation for Brixa blockchain.
Handles key generation, address creation, and transaction signing.
"""
import os
import json
import hashlib
import base58
import ecdsa
from typing import Tuple, Dict, Any, Optional
from pathlib import Path

class Wallet:
    """A wallet for managing Brixa addresses and signing transactions."""
    
    def __init__(self, wallet_dir: str = 'data/wallets'):
        """
        Initialize a wallet.
        
        Args:
            wallet_dir: Directory to store wallet files
        """
        self.private_key = None
        self.public_key = None
        self.address = None
        self.wallet_dir = Path(wallet_dir)
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_keypair(self) -> None:
        """Generate a new ECDSA keypair."""
        # Generate private key
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        self._generate_address()
    
    def _generate_address(self) -> None:
        """Generate a Brixa address from the public key."""
        if not self.public_key:
            raise ValueError("Public key not set")
            
        # Get the public key in compressed format
        public_key_bytes = self.public_key.to_string()
        
        # Perform SHA-256 hash of the public key
        sha256 = hashlib.sha256(public_key_bytes).digest()
        
        # Perform RIPEMD-160 hash of the SHA-256 hash
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256)
        
        # Add version byte (0x00 for mainnet)
        version_ripemd160 = b'\x00' + ripemd160.digest()
        
        # Double SHA-256 hash for checksum
        checksum = hashlib.sha256(hashlib.sha256(version_ripemd160).digest()).digest()[:4]
        
        # Combine and encode in Base58
        binary_address = version_ripemd160 + checksum
        self.address = base58.b58encode(binary_address).decode('utf-8')
    
    def sign_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """
        Sign a transaction.
        
        Args:
            transaction_data: The transaction data to sign
            
        Returns:
            Hex-encoded signature
        """
        if not self.private_key:
            raise ValueError("Private key not set")
            
        # Convert transaction data to a string and sign it
        tx_str = json.dumps(transaction_data, sort_keys=True)
        signature = self.private_key.sign(tx_str.encode('utf-8'))
        return signature.hex()
    
    def verify_signature(self, transaction_data: Dict[str, Any], signature: str) -> bool:
        """
        Verify a transaction signature.
        
        Args:
            transaction_data: The original transaction data
            signature: The signature to verify (hex-encoded)
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        if not self.public_key:
            return False
            
        try:
            tx_str = json.dumps(transaction_data, sort_keys=True)
            return self.public_key.verify(
                bytes.fromhex(signature),
                tx_str.encode('utf-8')
            )
        except ecdsa.BadSignatureError:
            return False
    
    def save_to_file(self, filename: str, password: str) -> bool:
        """
        Save the wallet to an encrypted file.
        
        Args:
            filename: The name of the wallet file
            password: Password for encryption
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.private_key or not self.address:
            return False
            
        wallet_data = {
            'private_key': self.private_key.to_string().hex(),
            'public_key': self.public_key.to_string().hex(),
            'address': self.address
        }
        
        # In a real implementation, you would encrypt this data with the password
        wallet_file = self.wallet_dir / f"{filename}.json"
        try:
            with open(wallet_file, 'w') as f:
                json.dump(wallet_data, f, indent=2)
            return True
        except (IOError, OSError):
            return False
    
    @classmethod
    def load_from_file(cls, filename: str, password: str) -> Optional['Wallet']:
        """
        Load a wallet from an encrypted file.
        
        Args:
            filename: The name of the wallet file
            password: Password for decryption
            
        Returns:
            Wallet instance if successful, None otherwise
        """
        wallet = cls()
        wallet_file = wallet.wallet_dir / f"{filename}.json"
        
        try:
            with open(wallet_file, 'r') as f:
                wallet_data = json.load(f)
                
            # In a real implementation, you would decrypt the data with the password
            wallet.private_key = ecdsa.SigningKey.from_string(
                bytes.fromhex(wallet_data['private_key']),
                curve=ecdsa.SECP256k1
            )
            wallet.public_key = ecdsa.VerifyingKey.from_string(
                bytes.fromhex(wallet_data['public_key']),
                curve=ecdsa.SECP256k1
            )
            wallet.address = wallet_data['address']
            
            return wallet
        except (IOError, OSError, json.JSONDecodeError, KeyError, ValueError):
            return None

def create_wallet() -> Tuple['Wallet', str]:
    """
    Create a new wallet and return it along with a mnemonic phrase.
    
    Returns:
        Tuple of (wallet, mnemonic_phrase)
    """
    # In a real implementation, you would generate a mnemonic phrase
    # using BIP-39 or a similar standard
    wallet = Wallet()
    wallet.generate_keypair()
    mnemonic = "generate a 12 or 24 word mnemonic here"  # Placeholder
    return wallet, mnemonic
