"""
Brixa Smart Contract Platform

This module provides the core functionality for Brixa's smart contract platform,
including the virtual machine, contract language, and development tools.
"""

__version__ = '0.1.0'

# Core components
from .vm import VirtualMachine, ExecutionContext
from .language import Compiler, Decompiler
from .sdk import ContractSDK
from .contracts import (
    BRC20,
    BRC721,
    BRC1155,
    Governor,
    Treasury
)

__all__ = [
    'VirtualMachine',
    'ExecutionContext',
    'Compiler',
    'Decompiler',
    'ContractSDK',
    'BRC20',
    'BRC721',
    'BRC1155',
    'Governor',
    'Treasury'
]
