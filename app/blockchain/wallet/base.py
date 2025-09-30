""
Base wallet interface for all blockchain wallets.
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from pathlib import Path

class BaseWallet(ABC):
    """Abstract base class for all blockchain wallets."""
    
    def __init__(self, network: str = 'mainnet', wallet_dir: str = 'data/wallets'):
        """
        Initialize the wallet.
        
        Args:
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            wallet_dir: Directory to store wallet files
        """
        self.network = network
        self.wallet_dir = Path(wallet_dir)
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.private_key = None
        self.public_key = None
        self.address = None
    
    @abstractmethod
    def generate_keypair(self) -> None:
        """Generate a new keypair for the wallet."""
        pass
    
    @abstractmethod
    def get_balance(self, address: Optional[str] = None) -> int:
        """
        Get the balance of the specified address or the wallet's address.
        
        Args:
            address: Address to check balance for (default: wallet's address)
            
        Returns:
            Balance in the smallest unit (satoshi, wei, lamports, etc.)
        """
        pass
    
    @abstractmethod
    def create_transaction(self, to_address: str, amount: int, **kwargs) -> Dict[str, Any]:
        """
        Create a new transaction.
        
        Args:
            to_address: Recipient address
            amount: Amount to send in the smallest unit
            **kwargs: Additional transaction parameters
            
        Returns:
            Unsigned transaction data
        """
        pass
    
    @abstractmethod
    def sign_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """
        Sign a transaction.
        
        Args:
            transaction_data: Transaction data to sign
            
        Returns:
            Signed transaction as a hex string
        """
        pass
    
    @abstractmethod
    def send_transaction(self, signed_tx: str) -> str:
        """
        Broadcast a signed transaction to the network.
        
        Args:
            signed_tx: Signed transaction as a hex string
            
        Returns:
            Transaction hash
        """
        pass
    
    @abstractmethod
    def save_to_file(self, filename: str, password: str) -> bool:
        """
        Save the wallet to an encrypted file.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for encryption
            
        Returns:
            bool: True if successful, False otherwise
        """
        pass
    
    @classmethod
    @abstractmethod
    def load_from_file(cls, filename: str, password: str, network: str = 'mainnet') -> 'BaseWallet':
        """
        Load a wallet from an encrypted file.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for decryption
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            
        Returns:
            Wallet instance if successful, None otherwise
        """
        pass
    
    @classmethod
    def create_wallet(cls, network: str = 'mainnet') -> Tuple['BaseWallet', str]:
        """
        Create a new wallet and return it along with a mnemonic phrase.
        
        Args:
            network: Blockchain network ('mainnet', 'testnet', 'devnet')
            
        Returns:
            Tuple of (wallet, mnemonic_phrase)
        """
        wallet = cls(network=network)
        wallet.generate_keypair()
        # In a real implementation, generate a proper mnemonic
        mnemonic = "generate a 12 or 24 word mnemonic here"
        return wallet, mnemonic
    
    def get_address(self) -> Optional[str]:
        """
        Get the wallet's address.
        
        Returns:
            Wallet address or None if not initialized
        """
        return self.address
    
    def get_public_key(self) -> Optional[bytes]:
        """
        Get the wallet's public key.
        
        Returns:
            Public key bytes or None if not initialized
        """
        return self.public_key
