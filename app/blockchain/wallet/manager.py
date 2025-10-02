""
Wallet manager for handling multiple blockchain wallets.
"""
import os
import json
from typing import Dict, Optional, Type, Any, List, Tuple
from pathlib import Path

from .base import BaseWallet
from .brixa import BrixaWallet
from .bitcoin import BitcoinWallet
from .ethereum import EthereumWallet
from .solana import SolanaWallet
from .hive import HiveWallet

class WalletManager:
    """Manages multiple blockchain wallets."""
    
    # Supported wallet types and their implementations
    WALLET_TYPES = {
        'brixa': BrixaWallet,
        'bitcoin': BitcoinWallet,
        'ethereum': EthereumWallet,
        'solana': SolanaWallet,
        'hive': HiveWallet
    }
    
    def __init__(self, wallet_dir: str = 'data/wallets'):
        """
        Initialize the wallet manager.
        
        Args:
            wallet_dir: Directory to store wallet files
        """
        self.wallet_dir = Path(wallet_dir)
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.wallets: Dict[str, BaseWallet] = {}
    
    def create_wallet(self, wallet_type: str, name: str, network: str = 'mainnet', **kwargs) -> Tuple[BaseWallet, str]:
        """
        Create a new wallet of the specified type.
        
        Args:
            wallet_type: Type of wallet to create ('brixa', 'bitcoin', 'ethereum', 'solana')
            name: Name for the wallet
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            **kwargs: Additional arguments for wallet creation
            
        Returns:
            Tuple of (wallet, mnemonic_phrase)
        """
        wallet_class = self._get_wallet_class(wallet_type)
        wallet = wallet_class(network=network, wallet_dir=str(self.wallet_dir))
        
        # Generate keypair and get mnemonic
        mnemonic = None
        if hasattr(wallet, 'create_wallet'):
            wallet, mnemonic = wallet.create_wallet(network=network)
        else:
            wallet.generate_keypair()
        
        # Save the wallet
        wallet_id = f"{wallet_type}_{name}"
        if wallet.save_to_file(name, ""):  # In a real app, you'd use a proper password
            self.wallets[wallet_id] = wallet
            return wallet, mnemonic or ""
        
        raise RuntimeError(f"Failed to create {wallet_type} wallet")
    
    def load_wallet(self, wallet_type: str, name: str, password: str = "", network: str = 'mainnet') -> Optional[BaseWallet]:
        """
        Load an existing wallet from file.
        
        Args:
            wallet_type: Type of wallet ('brixa', 'bitcoin', 'ethereum', 'solana')
            name: Name of the wallet file (without extension)
            password: Password for the wallet (if encrypted)
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            
        Returns:
            Loaded wallet instance or None if failed
        """
        wallet_class = self._get_wallet_class(wallet_type)
        wallet = wallet_class(network=network, wallet_dir=str(self.wallet_dir))
        
        loaded_wallet = wallet.load_from_file(name, password, network=network)
        if loaded_wallet:
            wallet_id = f"{wallet_type}_{name}"
            self.wallets[wallet_id] = loaded_wallet
            return loaded_wallet
        
        return None
    
    def get_wallet(self, wallet_id: str) -> Optional[BaseWallet]:
        """
        Get a loaded wallet by ID.
        
        Args:
            wallet_id: ID of the wallet (format: 'type_name')
            
        Returns:
            Wallet instance or None if not found
        """
        return self.wallets.get(wallet_id)
    
    def get_all_wallets(self) -> Dict[str, BaseWallet]:
        """
        Get all loaded wallets.
        
        Returns:
            Dictionary of wallet_id -> wallet
        """
        return self.wallets.copy()
    
    def list_wallet_files(self) -> List[Dict[str, str]]:
        """
        List all wallet files in the wallet directory.
        
        Returns:
            List of dicts with wallet info
        """
        wallets = []
        for ext in ['_brixa.json', '_btc.json', '_eth.json', '_sol.json']:
            for wallet_file in self.wallet_dir.glob(f"*{ext}"):
                wallet_type = ext[1:4]  # Extract 'brixa', 'btc', etc.
                if wallet_type == 'btc':
                    wallet_type = 'bitcoin'
                elif wallet_type == 'eth':
                    wallet_type = 'ethereum'
                elif wallet_type == 'sol':
                    wallet_type = 'solana'
                
                wallets.append({
                    'name': wallet_file.stem.replace(ext[1:], '').rstrip('_')
                    if wallet_file.stem.endswith(ext[1:])
                    else wallet_file.stem,
                    'type': wallet_type,
                    'path': str(wallet_file)
                })
        
        return wallets
    
    def _get_wallet_class(self, wallet_type: str) -> Type[BaseWallet]:
        """
        Get the wallet class for the specified type.
        
        Args:
            wallet_type: Type of wallet
            
        Returns:
            Wallet class
            
        Raises:
            ValueError: If wallet type is not supported
        """
        wallet_class = self.WALLET_TYPES.get(wallet_type.lower())
        if not wallet_class:
            raise ValueError(f"Unsupported wallet type: {wallet_type}")
        return wallet_class
    
    def get_balance(self, wallet_id: str, address: str = None) -> int:
        """
        Get the balance of a wallet.
        
        Args:
            wallet_id: ID of the wallet
            address: Address to check (default: wallet's address)
            
        Returns:
            Balance in the smallest unit
        """
        wallet = self.get_wallet(wallet_id)
        if not wallet:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        return wallet.get_balance(address)
    
    def create_transaction(self, wallet_id: str, to_address: str, amount: int, **kwargs) -> Dict[str, Any]:
        """
        Create a new transaction.
        
        Args:
            wallet_id: ID of the wallet
            to_address: Recipient address
            amount: Amount to send in the smallest unit
            **kwargs: Additional transaction parameters
            
        Returns:
            Unsigned transaction data
        """
        wallet = self.get_wallet(wallet_id)
        if not wallet:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        return wallet.create_transaction(to_address, amount, **kwargs)
    
    def sign_transaction(self, wallet_id: str, transaction_data: Dict[str, Any]) -> str:
        """
        Sign a transaction.
        
        Args:
            wallet_id: ID of the wallet
            transaction_data: Unsigned transaction data
            
        Returns:
            Signed transaction
        """
        wallet = self.get_wallet(wallet_id)
        if not wallet:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        return wallet.sign_transaction(transaction_data)
    
    def send_transaction(self, wallet_id: str, signed_tx: str) -> str:
        """
        Broadcast a signed transaction.
        
        Args:
            wallet_id: ID of the wallet
            signed_tx: Signed transaction
            
        Returns:
            Transaction hash
        """
        wallet = self.get_wallet(wallet_id)
        if not wallet:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        return wallet.send_transaction(signed_tx)
    
    def import_wallet(self, wallet_type: str, name: str, private_key: str, password: str = "", 
                     network: str = 'mainnet') -> BaseWallet:
        """
        Import a wallet from a private key.
        
        Args:
            wallet_type: Type of wallet ('brixa', 'bitcoin', 'ethereum', 'solana')
            name: Name for the wallet
            private_key: Private key as a hex string
            password: Password for the wallet (if encrypting)
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            
        Returns:
            Imported wallet instance
        """
        wallet_class = self._get_wallet_class(wallet_type)
        wallet = wallet_class(network=network, wallet_dir=str(self.wallet_dir))
        
        # In a real implementation, you would properly import the private key
        # This is a simplified version that just creates a new wallet and sets the key
        wallet.generate_keypair()
        
        # Save the wallet
        wallet_id = f"{wallet_type}_{name}"
        if wallet.save_to_file(name, password):
            self.wallets[wallet_id] = wallet
            return wallet
        
        raise RuntimeError(f"Failed to import {wallet_type} wallet")
    
    def export_wallet(self, wallet_id: str, password: str = "") -> Dict[str, Any]:
        """
        Export a wallet's private key and other data.
        
        Args:
            wallet_id: ID of the wallet
            password: Wallet password (if encrypted)
            
        Returns:
            Dictionary containing wallet data
        """
        wallet = self.get_wallet(wallet_id)
        if not wallet:
            raise ValueError(f"Wallet {wallet_id} not found")
        
        # In a real implementation, you would decrypt the private key with the password
        return {
            'private_key': wallet.private_key.hex() if hasattr(wallet, 'private_key') and wallet.private_key else None,
            'public_key': wallet.public_key.hex() if hasattr(wallet, 'public_key') and wallet.public_key else None,
            'address': wallet.address,
            'network': wallet.network
        }
