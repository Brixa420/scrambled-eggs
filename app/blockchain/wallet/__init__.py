"""
Multi-blockchain wallet support for Brixa.

This module provides wallet functionality for multiple blockchains including:
- Brixa (native)
- Bitcoin
- Ethereum
- Solana
- Hive
"""

from .base import BaseWallet
from .brixa import BrixaWallet
from .bitcoin import BitcoinWallet
from .ethereum import EthereumWallet
from .solana import SolanaWallet
from .hive import HiveWalletWrapper as HiveWallet
from .manager import WalletManager

__all__ = [
    'BaseWallet',
    'BrixaWallet',
    'BitcoinWallet',
    'EthereumWallet',
    'SolanaWallet',
    'HiveWallet',
    'WalletManager'
]
