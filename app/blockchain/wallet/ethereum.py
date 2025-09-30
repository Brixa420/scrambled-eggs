""
Ethereum wallet implementation.
"""
import os
import json
import binascii
import hashlib
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

from eth_account import Account
from eth_account.signers.local import LocalAccount
from web3 import Web3, HTTPProvider
from eth_typing import ChecksumAddress
from eth_utils import to_checksum_address

from .base import BaseWallet

class EthereumWallet(BaseWallet):
    """Ethereum wallet implementation using eth-account."""
    
    def __init__(self, network: str = 'mainnet', wallet_dir: str = 'data/wallets'):
        super().__init__(network=network, wallet_dir=wallet_dir)
        self.account: Optional[LocalAccount] = None
        self.web3 = self._init_web3()
    
    def _init_web3(self):
        """Initialize Web3 connection based on network."""
        if self.network == 'mainnet':
            # In a real implementation, replace with your Ethereum node URL
            provider_url = os.getenv('ETH_MAINNET_RPC', 'https://mainnet.infura.io/v3/YOUR-PROJECT-ID')
        elif self.network == 'testnet':
            provider_url = os.getenv('ETH_TESTNET_RPC', 'https://goerli.infura.io/v3/YOUR-PROJECT-ID')
        else:  # local devnet
            provider_url = 'http://localhost:8545'
            
        return Web3(HTTPProvider(provider_url))
    
    def generate_keypair(self) -> None:
        """Generate a new Ethereum keypair."""
        self.account = Account.create()
        self.private_key = self.account.key
        self.public_key = self.account.publickey
        self.address = self.account.address
    
    def get_balance(self, address: Optional[str] = None) -> int:
        """
        Get the balance of the specified address or the wallet's address.
        
        Args:
            address: Address to check balance for (default: wallet's address)
            
        Returns:
            Balance in wei
        """
        target_address = address or self.address
        if not target_address:
            return 0
            
        try:
            checksum_address = to_checksum_address(target_address)
            return self.web3.eth.get_balance(checksum_address)
        except Exception as e:
            print(f"Error getting balance: {e}")
            return 0
    
    def create_transaction(self, to_address: str, amount: int, **kwargs) -> Dict[str, Any]:
        """
        Create a new Ethereum transaction.
        
        Args:
            to_address: Recipient Ethereum address
            amount: Amount to send in wei
            **kwargs: Additional parameters (gas, gas_price, nonce, etc.)
            
        Returns:
            Unsigned transaction data
        """
        if not self.address:
            raise ValueError("Wallet not initialized")
            
        # Get transaction count for nonce
        nonce = kwargs.get('nonce', self.web3.eth.get_transaction_count(self.address))
        
        # Build transaction
        tx = {
            'nonce': nonce,
            'to': to_address,
            'value': amount,
            'gas': kwargs.get('gas', 21000),  # Default gas limit for simple ETH transfer
            'gasPrice': kwargs.get('gas_price', self.web3.eth.gas_price),
            'chainId': self.web3.eth.chain_id,
            'data': kwargs.get('data', b'')
        }
        
        return tx
    
    def sign_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """
        Sign an Ethereum transaction.
        
        Args:
            transaction_data: Unsigned transaction data
            
        Returns:
            Signed transaction as a hex string
        """
        if not self.private_key:
            raise ValueError("Private key not set")
            
        signed_tx = self.web3.eth.account.sign_transaction(
            transaction_data, 
            private_key=self.private_key
        )
        return signed_tx.rawTransaction.hex()
    
    def send_transaction(self, signed_tx: str) -> str:
        """
        Broadcast a signed transaction to the Ethereum network.
        
        Args:
            signed_tx: Signed transaction as a hex string
            
        Returns:
            Transaction hash
        """
        try:
            tx_hash = self.web3.eth.send_raw_transaction(bytes.fromhex(signed_tx))
            return tx_hash.hex()
        except Exception as e:
            print(f"Error sending transaction: {e}")
            raise
    
    def sign_message(self, message: str) -> str:
        """
        Sign a message with the wallet's private key.
        
        Args:
            message: Message to sign
            
        Returns:
            Signature as a hex string
        """
        if not self.private_key:
            raise ValueError("Private key not set")
            
        message_hash = self.web3.keccak(text=message)
        signature = self.web3.eth.account.signHash(
            message_hash, 
            private_key=self.private_key
        )
        return signature.signature.hex()
    
    def verify_message(self, message: str, signature: str, address: str) -> bool:
        """
        Verify a signed message.
        
        Args:
            message: Original message
            signature: Signature as a hex string
            address: Signer's address
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        message_hash = self.web3.keccak(text=message)
        recovered_address = self.web3.eth.account.recoverHash(
            message_hash, 
            signature=signature
        )
        return recovered_address.lower() == address.lower()
    
    def save_to_file(self, filename: str, password: str) -> bool:
        """
        Save the wallet to an encrypted file using Web3 keystore format.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for encryption
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.private_key:
            return False
            
        # Convert private key to bytes
        private_key_bytes = self.private_key
        if isinstance(private_key_bytes, str):
            if private_key_bytes.startswith('0x'):
                private_key_bytes = bytes.fromhex(private_key_bytes[2:])
            else:
                private_key_bytes = bytes.fromhex(private_key_bytes)
        
        # Create keystore
        keystore = Account.encrypt(
            private_key_bytes.hex(),
            password,
            iterations=1000000  # High iteration count for better security
        )
        
        # Add metadata
        keystore['address'] = self.address
        keystore['network'] = self.network
        
        # Save to file
        wallet_file = self.wallet_dir / f"{filename}_eth.json"
        try:
            with open(wallet_file, 'w') as f:
                json.dump(keystore, f, indent=2)
            return True
        except (IOError, OSError) as e:
            print(f"Error saving wallet: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, filename: str, password: str, network: str = 'mainnet') -> 'EthereumWallet':
        """
        Load a wallet from an encrypted keystore file.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for decryption
            network: Blockchain network ('mainnet', 'testnet')
            
        Returns:
            EthereumWallet instance if successful, None otherwise
        """
        wallet = cls(network=network)
        wallet_file = wallet.wallet_dir / f"{filename}_eth.json"
        
        try:
            with open(wallet_file, 'r') as f:
                keystore = json.load(f)
            
            # Decrypt private key
            private_key_bytes = Account.decrypt(keystore, password)
            private_key = private_key_bytes.hex()
            
            # Create account from private key
            wallet.account = Account.from_key(private_key)
            wallet.private_key = wallet.account.key
            wallet.public_key = wallet.account.publickey
            wallet.address = wallet.account.address
            
            return wallet
            
        except (IOError, json.JSONDecodeError, ValueError) as e:
            print(f"Error loading wallet: {e}")
            return None
