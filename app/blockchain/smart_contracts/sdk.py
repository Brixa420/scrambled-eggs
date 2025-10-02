""
Brixa Smart Contract SDK

Provides high-level tools and utilities for developing, testing, and deploying
smart contracts on the Brixa blockchain.
"""
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, Type, TypeVar

from .vm import VirtualMachine, ExecutionContext, OpCode
from .language import Compiler, Decompiler, ParseError

T = TypeVar('T')

class Contract:
    """Represents a compiled smart contract."""
    
    def __init__(self, bytecode: bytes, abi: Dict[str, Any] = None):
        self.bytecode = bytecode
        self.abi = abi or {}
        self.address = None
    
    @classmethod
    def from_source(cls, source: str, abi: Dict[str, Any] = None) -> 'Contract':
        """Create a contract from Brixa Smart Contract Language source code."""
        compiler = Compiler()
        bytecode = compiler.compile(source)
        return cls(bytecode, abi)
    
    @classmethod
    def from_file(cls, file_path: Union[str, Path], abi_file: Union[str, Path] = None) -> 'Contract':
        """Load a contract from a file."""
        file_path = Path(file_path)
        with open(file_path, 'r') as f:
            source = f.read()
        
        abi = None
        if abi_file:
            abi_path = Path(abi_file) if abi_file else file_path.with_suffix('.json')
            if abi_path.exists():
                with open(abi_path, 'r') as f:
                    abi = json.load(f)
        
        return cls.from_source(source, abi)
    
    def deploy(self, vm: VirtualMachine, sender: bytes = None, value: int = 0) -> bytes:
        """Deploy the contract to the blockchain."""
        if sender is None:
            # Default to zero address if no sender is specified
            sender = bytes(20)
            
        self.address = vm.create_contract(self.bytecode, sender, value)
        return self.address
    
    def call(self, 
             vm: VirtualMachine, 
             function: str, 
             args: List[Any] = None,
             sender: bytes = None,
             value: int = 0) -> Any:
        """Call a contract function."""
        if self.address is None:
            raise ValueError("Contract has not been deployed yet")
            
        if args is None:
            args = []
            
        if sender is None:
            sender = bytes(20)  # Zero address for read-only calls
        
        # Encode the function call
        data = self._encode_function_call(function, args)
        
        # Execute the call
        result = vm.call_contract(self.address, data, sender, value)
        
        # Decode the result if we have an ABI
        if self.abi and 'functions' in self.abi and function in self.abi['functions']:
            return self._decode_function_result(function, result)
            
        return result
    
    def _encode_function_call(self, function: str, args: List[Any]) -> bytes:
        """Encode a function call according to the ABI."""
        # Simple implementation - in a real SDK, this would use proper ABI encoding
        # This is a placeholder that would be replaced with proper encoding
        if not self.abi or 'functions' not in self.abi or function not in self.abi['functions']:
            return b''.join(arg if isinstance(arg, bytes) else str(arg).encode() for arg in args)
            
        # TODO: Implement proper ABI encoding based on function signature
        return function.encode() + b''.join(
            arg if isinstance(arg, bytes) else str(arg).encode() 
            for arg in args
        )
    
    def _decode_function_result(self, function: str, data: bytes) -> Any:
        """Decode a function's return value according to the ABI."""
        # Simple implementation - in a real SDK, this would use proper ABI decoding
        if not data:
            return None
            
        # Try to decode as JSON first
        try:
            return json.loads(data.decode('utf-8', errors='replace'))
        except:
            pass
            
        # Fall back to raw bytes
        return data

class Account:
    """Represents a blockchain account with a keypair."""
    
    def __init__(self, private_key: bytes = None):
        if private_key is None:
            # Generate a new private key
            private_key = os.urandom(32)
        
        self.private_key = private_key
        self.public_key = self._derive_public_key(private_key)
        self.address = self._derive_address(self.public_key)
    
    @staticmethod
    def _derive_public_key(private_key: bytes) -> bytes:
        """Derive the public key from a private key."""
        # In a real implementation, this would use proper elliptic curve cryptography
        # This is a simplified version for demonstration purposes
        from hashlib import sha256
        return sha256(private_key).digest()
    
    @staticmethod
    def _derive_address(public_key: bytes) -> bytes:
        """Derive an address from a public key."""
        # In a real implementation, this would use proper hashing and formatting
        # This is a simplified version for demonstration purposes
        from hashlib import sha256
        return sha256(public_key).digest()[:20]  # 20-byte address
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the account's private key."""
        # In a real implementation, this would use proper digital signatures
        # This is a simplified version for demonstration purposes
        from hashlib import sha256
        return sha256(self.private_key + message).digest()
    
    @classmethod
    def from_private_key(cls, private_key_hex: str) -> 'Account':
        """Create an account from a hex-encoded private key."""
        import binascii
        private_key = binascii.unhexlify(private_key_hex)
        return cls(private_key)
    
    def __str__(self) -> str:
        return f"Account(address={self.address.hex()})"

class BrixaSDK:
    """Main SDK class for interacting with the Brixa blockchain."""
    
    def __init__(self, rpc_url: str = None, chain_id: int = 1):
        """Initialize the SDK.
        
        Args:
            rpc_url: URL of the Brixa JSON-RPC endpoint
            chain_id: ID of the Brixa chain to connect to
        """
        self.rpc_url = rpc_url or "http://localhost:8545"
        self.chain_id = chain_id
        self.vm = VirtualMachine()
        self.accounts: Dict[bytes, Account] = {}
        self.contracts: Dict[bytes, Contract] = {}
    
    def create_account(self) -> Account:
        """Create a new account with a random private key."""
        account = Account()
        self.accounts[account.address] = account
        return account
    
    def add_account(self, private_key: bytes) -> Account:
        """Add an existing account by private key."""
        account = Account(private_key)
        self.accounts[account.address] = account
        return account
    
    def get_balance(self, address: bytes) -> int:
        """Get the balance of an address in wei."""
        # In a real implementation, this would query the blockchain
        # For now, we'll just return a default value
        return 0
    
    def deploy_contract(self, 
                       contract: Contract, 
                       sender: Account = None, 
                       value: int = 0) -> bytes:
        """Deploy a contract to the blockchain."""
        if sender is None:
            if not self.accounts:
                raise ValueError("No accounts available. Create or add an account first.")
            sender = next(iter(self.accounts.values()))
        
        address = contract.deploy(self.vm, sender.address, value)
        self.contracts[address] = contract
        return address
    
    def call_contract(self, 
                     address: bytes, 
                     function: str, 
                     args: List[Any] = None,
                     sender: Account = None,
                     value: int = 0) -> Any:
        """Call a contract function."""
        if address not in self.contracts:
            raise ValueError(f"No contract found at address {address.hex()}")
        
        contract = self.contracts[address]
        return contract.call(
            self.vm, 
            function, 
            args or [],
            sender.address if sender else None,
            value
        )
    
    def compile_contract(self, source: str, abi: Dict[str, Any] = None) -> Contract:
        """Compile a contract from source code."""
        return Contract.from_source(source, abi)
    
    def load_contract(self, 
                     file_path: Union[str, Path], 
                     abi_file: Union[str, Path] = None) -> Contract:
        """Load a contract from a file."""
        return Contract.from_file(file_path, abi_file)
    
    def send_transaction(self, 
                        to: bytes, 
                        data: bytes = b'', 
                        value: int = 0,
                        sender: Account = None) -> bytes:
        """Send a transaction to the blockchain."""
        if sender is None:
            if not self.accounts:
                raise ValueError("No accounts available. Create or add an account first.")
            sender = next(iter(self.accounts.values()))
        
        # In a real implementation, this would:
        # 1. Create a transaction object
        # 2. Sign it with the sender's private key
        # 3. Send it to the blockchain
        # 4. Return the transaction hash
        
        # For now, we'll just return a dummy transaction hash
        return os.urandom(32)
    
    def get_transaction_receipt(self, tx_hash: bytes) -> Dict[str, Any]:
        """Get the receipt for a transaction."""
        # In a real implementation, this would query the blockchain
        # For now, we'll return a dummy receipt
        return {
            'transactionHash': tx_hash.hex(),
            'blockNumber': 1,
            'status': 1,
            'gasUsed': 21000,
            'logs': []
        }

# Example usage
if __name__ == "__main__":
    # Initialize the SDK
    sdk = BrixaSDK()
    
    # Create a new account
    alice = sdk.create_account()
    print(f"Created account: {alice}")
    
    # Define a simple contract
    contract_source = """
    contract SimpleStorage {
        uint256 public value;
        
        function set(uint256 _value) public {
            value = _value;
        }
        
        function get() public view returns (uint256) {
            return value;
        }
    }
    """
    
    # Compile the contract
    contract = sdk.compile_contract(contract_source)
    
    # Deploy the contract
    contract_address = sdk.deploy_contract(contract, alice)
    print(f"Deployed contract to: {contract_address.hex()}")
    
    # Interact with the contract
    tx_hash = sdk.call_contract(contract_address, "set", [42], alice)
    print(f"Transaction hash: {tx_hash.hex()}")
    
    # Wait for the transaction to be mined
    receipt = sdk.get_transaction_receipt(tx_hash)
    print(f"Transaction mined in block {receipt['blockNumber']}")
    
    # Read from the contract
    result = sdk.call_contract(contract_address, "get")
    print(f"Value from contract: {result}")
