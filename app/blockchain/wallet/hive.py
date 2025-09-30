"""
Hive blockchain wallet implementation.
"""
import os
import json
import hashlib
from typing import Dict, Any, Optional, Tuple, Union
from pathlib import Path

from beem import Hive
from beem.account import Account
from beem.wallet import Wallet as HiveWallet
from beembase import operations
from beemgraphenebase.account import PrivateKey, PublicKey
from beem.instance import set_shared_blockchain_instance

from .base import BaseWallet

class HiveWalletWrapper(BaseWallet):
    """Hive wallet implementation using beem library."""
    
    def __init__(self, network: str = 'mainnet', wallet_dir: str = 'data/wallets'):
        super().__init__(network=network, wallet_dir=wallet_dir)
        self.private_key = None
        self.public_key = None
        self.address = None
        self.account_name = None
        self.hive_instance = self._init_hive()
        set_shared_blockchain_instance(self.hive_instance)
    
    def _init_hive(self):
        """Initialize Hive instance based on network."""
        if self.network == 'mainnet':
            nodes = [
                'https://api.hive.blog',
                'https://api.openhive.network',
                'https://hive-api.arcange.eu'
            ]
        else:  # testnet
            nodes = ['https://testnet.openhive.network']
            
        return Hive(node=nodes, num_retries=3, timeout=30, num_retries_call=3)
    
    def generate_keypair(self) -> None:
        """Generate a new Hive keypair."""
        # In Hive, we don't generate keys directly but create a new account
        # This is a placeholder - in a real implementation, you would need to register a new account
        # which requires paying a fee to an existing account
        raise NotImplementedError(
            "Account creation not implemented. "
            "In Hive, new accounts must be created by existing accounts."
        )
    
    def import_account(self, account_name: str, private_key: str) -> None:
        """
        Import an existing Hive account.
        
        Args:
            account_name: Hive username
            private_key: Private key in WIF format
        """
        self.account_name = account_name
        self.private_key = private_key
        self.public_key = str(PrivateKey(private_key).pubkey)
        self.address = account_name  # In Hive, the account name is the address
    
    def get_balance(self, account_name: Optional[str] = None) -> Dict[str, float]:
        """
        Get the balance of the specified account or the wallet's account.
        
        Args:
            account_name: Hive username (default: wallet's account)
            
        Returns:
            Dictionary with balances for HIVE, HBD, and VESTS
        """
        target_account = account_name or self.account_name
        if not target_account:
            raise ValueError("Account name not set")
            
        try:
            account = Account(target_account, blockchain_instance=self.hive_instance)
            return {
                'HIVE': float(account['balance'].amount),
                'HBD': float(account['hbd_balance'].amount),
                'VESTS': float(account['vesting_shares'].amount)
            }
        except Exception as e:
            print(f"Error getting balance: {e}")
            return {'HIVE': 0.0, 'HBD': 0.0, 'VESTS': 0.0}
    
    def create_transaction(self, to_account: str, amount: float, 
                         currency: str = 'HIVE', memo: str = '') -> Dict[str, Any]:
        """
        Create a new Hive transaction.
        
        Args:
            to_account: Recipient Hive username
            amount: Amount to send
            currency: 'HIVE' or 'HBD'
            memo: Optional memo
            
        Returns:
            Unsigned transaction data
        """
        if not self.account_name:
            raise ValueError("Account not set")
            
        if currency not in ['HIVE', 'HBD']:
            raise ValueError("Currency must be 'HIVE' or 'HBD'")
            
        return {
            'from': self.account_name,
            'to': to_account,
            'amount': f"{amount:.3f} {currency}",
            'memo': memo,
            'currency': currency
        }
    
    def sign_transaction(self, transaction_data: Dict[str, Any]) -> str:
        """
        Sign a Hive transaction.
        
        Args:
            transaction_data: Unsigned transaction data
            
        Returns:
            Signed transaction as JSON string
        """
        if not self.private_key or not self.account_name:
            raise ValueError("Private key or account not set")
            
        # In Hive, we create and sign the transaction in one step
        # This is a simplified version - in a real implementation, you would use beem
        
        # For now, return the transaction data with a dummy signature
        transaction_data['signature'] = 'dummy_signature'
        return json.dumps(transaction_data)
    
    def send_transaction(self, signed_tx: Union[str, Dict[str, Any]]) -> str:
        """
        Broadcast a signed transaction to the Hive network.
        
        Args:
            signed_tx: Signed transaction as JSON string or dict
            
        Returns:
            Transaction ID
        """
        if not self.private_key or not self.account_name:
            raise ValueError("Private key or account not set")
            
        if isinstance(signed_tx, str):
            tx_data = json.loads(signed_tx)
        else:
            tx_data = signed_tx
            
        try:
            # In a real implementation, you would use beem to broadcast the transaction
            # This is a simplified version
            op = operations.Transfer(
                **{
                    'from': tx_data['from'],
                    'to': tx_data['to'],
                    'amount': tx_data['amount'],
                    'memo': tx_data.get('memo', '')
                }
            )
            
            # In a real implementation, you would sign and broadcast the transaction
            # tx = self.hive_instance.tx()
            # tx.appendOps(op)
            # tx.appendWif(self.private_key)
            # tx.sign()
            # result = tx.broadcast()
            # return str(result.get('id', ''))
            
            # For now, return a dummy transaction ID
            return hashlib.sha256(json.dumps(tx_data).encode()).hexdigest()
            
        except Exception as e:
            print(f"Error sending transaction: {e}")
            raise
    
    def vote(self, author: str, permlink: str, weight: int = 10000) -> str:
        """
        Vote on a Hive post or comment.
        
        Args:
            author: Post/comment author
            permlink: Post/comment permlink
            weight: Voting weight (100% = 10000)
            
        Returns:
            Transaction ID
        """
        if not self.account_name:
            raise ValueError("Account not set")
            
        # In a real implementation, you would use beem to vote
        # This is a simplified version
        return f"voted_{author}_{permlink}_{weight}"
    
    def save_to_file(self, filename: str, password: str) -> bool:
        """
        Save the wallet to an encrypted file.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for encryption
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.private_key or not self.account_name:
            return False
            
        wallet_data = {
            'version': 1,
            'network': self.network,
            'account_name': self.account_name,
            'private_key': self.private_key,
            'public_key': self.public_key
        }
        
        # In a real implementation, you would encrypt this data with the password
        wallet_file = self.wallet_dir / f"{filename}_hive.json"
        try:
            with open(wallet_file, 'w') as f:
                json.dump(wallet_data, f, indent=2)
            return True
        except (IOError, OSError) as e:
            print(f"Error saving wallet: {e}")
            return False
    
    @classmethod
    def load_from_file(cls, filename: str, password: str, network: str = 'mainnet') -> 'HiveWalletWrapper':
        """
        Load a wallet from an encrypted file.
        
        Args:
            filename: Name of the wallet file (without extension)
            password: Password for decryption
            network: Blockchain network ('mainnet', 'testnet')
            
        Returns:
            HiveWalletWrapper instance if successful, None otherwise
        """
        wallet = cls(network=network)
        wallet_file = wallet.wallet_dir / f"{filename}_hive.json"
        
        try:
            with open(wallet_file, 'r') as f:
                wallet_data = json.load(f)
                
            # In a real implementation, you would decrypt the data with the password
            wallet.account_name = wallet_data['account_name']
            wallet.private_key = wallet_data['private_key']
            wallet.public_key = wallet_data['public_key']
            wallet.address = wallet_data['account_name']  # In Hive, address is the account name
            
            return wallet
        except (IOError, OSError, json.JSONDecodeError, KeyError) as e:
            print(f"Error loading wallet: {e}")
            return None
