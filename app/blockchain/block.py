"""
Block implementation for Brixa blockchain.
A Bitcoin-like blockchain implementation with BXA tokens.
"""
import hashlib
import json
import time
import struct
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Constants
MAX_BLOCK_SIZE = 1000000  # 1MB block size limit (adjustable)
VERSION = 1  # Block version

class Block:
    """
    A block in the Brixa blockchain.
    Follows Bitcoin's block structure with BXA tokens.
    """
    
    def __init__(
        self,
        version: int = VERSION,
        previous_hash: str = '0' * 64,
        merkle_root: str = '',
        timestamp: Optional[float] = None,
        bits: int = 0x1d00ffff,  # Default difficulty bits (same as Bitcoin)
        nonce: int = 0,
        transactions: Optional[List[Dict[str, Any]]] = None,
        hash: Optional[str] = None,
        height: int = 0,
    ):
        """
        Initialize a new block.
        
        Args:
            version: Block version number
            previous_hash: Hash of the previous block in hex
            merkle_root: Merkle root of transactions
            timestamp: When the block was created (default: current time)
            bits: Compact representation of the target difficulty
            nonce: The nonce used for mining
            transactions: List of transactions in the block
            hash: The block's hash (calculated if not provided)
            height: The block height in the chain
        """
        self.version = version
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root or self.calculate_merkle_root(transactions or [])
        self.timestamp = timestamp or time.time()
        self.bits = bits
        self.nonce = nonce
        self.transactions = transactions or []
        self.hash = hash
        self.height = height
    
    def serialize_header(self) -> bytes:
        """Serialize block header for hashing."""
        # Version (4 bytes, little endian)
        version = struct.pack('<L', self.version)
        
        # Previous block hash (32 bytes, little endian)
        prev_hash = bytes.fromhex(self.previous_hash)[::-1]
        
        # Merkle root (32 bytes, little endian)
        merkle_root = bytes.fromhex(self.merkle_root)[::-1]
        
        # Timestamp (4 bytes, little endian)
        timestamp = struct.pack('<L', int(self.timestamp))
        
        # Bits (4 bytes)
        bits = struct.pack('<L', self.bits)
        
        # Nonce (4 bytes, little endian)
        nonce = struct.pack('<L', self.nonce)
        
        return version + prev_hash + merkle_root + timestamp + bits + nonce
    
    def calculate_hash(self) -> str:
        """Calculate the double SHA-256 hash of the block header."""
        header = self.serialize_header()
        hash1 = hashlib.sha256(header).digest()
        hash2 = hashlib.sha256(hash1).digest()
        return hash2[::-1].hex()  # Convert to big-endian hex
    
    def calculate_merkle_root(self, transactions: List[Dict[str, Any]]) -> str:
        """Calculate the Merkle root of transactions."""
        if not transactions:
            return hashlib.sha256().hexdigest()
            
        # Start with the transaction hashes (txids)
        hashes = [bytes.fromhex(tx['txid'])[::-1] for tx in transactions]
        
        while len(hashes) > 1:
            # If odd number of hashes, duplicate the last one
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
                
            new_hashes = []
            for i in range(0, len(hashes), 2):
                # Concatenate and hash pairs of hashes
                concat = hashes[i] + hashes[i+1]
                new_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
                new_hashes.append(new_hash)
                
            hashes = new_hashes
            
        return hashes[0][::-1].hex() if hashes else ''
    
    def mine_block(self, target: int) -> None:
        """
        Mine the block by finding a nonce that results in a hash below the target.
        
        Args:
            target: The target difficulty as a 256-bit integer
        """
        # Convert target to a 32-byte big-endian integer
        target_bytes = target.to_bytes(32, byteorder='big')
        
        while True:
            # Calculate the hash
            self.hash = self.calculate_hash()
            hash_int = int.from_bytes(bytes.fromhex(self.hash), byteorder='big')
            
            # Check if hash is below target
            if hash_int < target:
                break
                
            # Increment nonce and try again
            self.nonce += 1
            
            # If nonce overflows, update timestamp and try again
            if self.nonce >= 0xffffffff:
                self.nonce = 0
                self.timestamp = time.time()
                
            # Update merkle root if transactions changed (for future use)
            if self.transactions:
                self.merkle_root = self.calculate_merkle_root(self.transactions)
    
    def is_valid(self, previous_block: Optional['Block'] = None) -> Tuple[bool, str]:
        """
        Validate the block.
        
        Args:
            previous_block: The previous block in the chain
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Check block hash is valid
        calculated_hash = self.calculate_hash()
        if self.hash != calculated_hash:
            return False, f"Invalid block hash. Expected {calculated_hash}, got {self.hash}"
        
        # Convert bits to target
        exponent = self.bits >> 24
        coefficient = self.bits & 0x007fffff
        target = coefficient << (8 * (exponent - 3))
        
        # Check proof of work (hash must be below target)
        hash_int = int.from_bytes(bytes.fromhex(self.hash), byteorder='big')
        if hash_int > target:
            return False, f"Block hash {self.hash} does not meet target difficulty"
        
        # If this isn't the genesis block, check previous hash and height
        if previous_block:
            if self.previous_hash != previous_block.hash:
                return False, f"Invalid previous hash. Expected {previous_block.hash}, got {self.previous_hash}"
            if self.height != previous_block.height + 1:
                return False, f"Invalid height. Expected {previous_block.height + 1}, got {self.height}"
        
        # Check timestamp is not too far in the future (2 hours)
        max_future_time = time.time() + 2 * 60 * 60
        if self.timestamp > max_future_time:
            return False, f"Block timestamp {self.timestamp} is too far in the future"
            
        # Check transactions
        if not self.transactions:
            return False, "Block must contain at least one transaction (coinbase)"
            
        # First transaction must be coinbase
        if not self.transactions[0].get('is_coinbase', False):
            return False, "First transaction in block must be coinbase"
            
        # Verify merkle root
        calculated_merkle = self.calculate_merkle_root(self.transactions)
        if self.merkle_root != calculated_merkle:
            return False, f"Invalid merkle root. Expected {calculated_merkle}, got {self.merkle_root}"
                
        return True, ""
        return True
    
    def _is_valid_memory(self, memory: Dict[str, Any]) -> bool:
        """
        Validate a memory structure.
        
        Args:
            memory: The memory to validate
            
        Returns:
            bool: True if the memory is valid, False otherwise
        """
        required_fields = {'id', 'timestamp', 'content'}
        if not all(field in memory for field in required_fields):
            return False
            
        # Check timestamp is a valid number
        try:
            timestamp = float(memory['timestamp'])
            if timestamp < 0 or timestamp > time.time() + 300:  # Allow 5 min in future for clock skew
                return False
        except (ValueError, TypeError):
            return False
            
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the block to a dictionary."""
        return {
            'version': self.version,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'timestamp': self.timestamp,
            'bits': self.bits,
            'nonce': self.nonce,
            'transactions': self.transactions,
            'hash': self.hash,
            'height': self.height,
            'block_reward': self.get_block_reward()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create a block from a dictionary."""
        return cls(
            version=data.get('version', VERSION),
            previous_hash=data['previous_hash'],
            merkle_root=data.get('merkle_root', ''),
            timestamp=data['timestamp'],
            bits=data.get('bits', 0x1d00ffff),
            nonce=data.get('nonce', 0),
            transactions=data.get('transactions', []),
            hash=data.get('hash'),
            height=data.get('height', 0)
        )
    
    def get_block_reward(self) -> int:
        """
        Calculate the block reward based on block height (halving every 210,000 blocks).
        
        Returns:
            int: Block reward in satoshis
        """
        halvings = self.height // 210000
        
        # If we've had more than 64 halvings, the reward is 0
        if halvings >= 64:
            return 0
            
        # Start with 50 BXA (in satoshis)
        reward = 50 * 100_000_000
        
        # Halve the reward every 210,000 blocks
        reward >>= halvings
        
        return reward

def create_genesis_block() -> Block:
    """
    Create the genesis block for the Brixa blockchain.
    This is a hardcoded genesis block similar to Bitcoin's.
    """
    # Timestamp: 2025-10-01 00:00:00 (unix timestamp 1761907200)
    genesis_time = 1761907200
    
    # Create a coinbase transaction
    genesis_coinbase = {
        'version': 1,
        'locktime': 0,
        'is_coinbase': True,
        'txid': '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        'inputs': [{
            'txid': '0000000000000000000000000000000000000000000000000000000000000000',
            'vout': 0xffffffff,
            'script_sig': '04ffff001d0104455468652054696d65732030332f4a616e2f32303235204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73',
            'sequence': 0xffffffff
        }],
        'outputs': [{
            'value': 50 * 100_000_000,  # 50 BXA in satoshis
            'script_pubkey': '4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f1ac',
            'address': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'  # Satoshi's address (for reference)
        }]
    }
    
    # Create the genesis block
    genesis = Block(
        version=1,
        previous_hash='0000000000000000000000000000000000000000000000000000000000000000',
        merkle_root='4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
        timestamp=genesis_time,
        bits=0x1d00ffff,  # Initial difficulty
        nonce=2083236893,  # Nonce that produces the genesis hash
        transactions=[genesis_coinbase],
        height=0
    )
    
    # Set the hash
    genesis.hash = genesis.calculate_hash()
    
    return genesis
