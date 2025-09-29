"""
Block implementation for Clippy's blockchain memory system.
Inspired by Bitcoin's block structure but optimized for AI memory storage.
"""
import hashlib
import json
import time
from typing import List, Dict, Any, Optional
from datetime import datetime

class Block:
    """
    A block in the Clippy blockchain memory system.
    Each block contains memories and links to the previous block.
    """
    
    def __init__(
        self,
        index: int,
        timestamp: float,
        memories: List[Dict[str, Any]],
        previous_hash: str,
        nonce: int = 0,
        hash: Optional[str] = None,
        difficulty: int = 4
    ):
        """
        Initialize a new block.
        
        Args:
            index: The block's position in the chain
            timestamp: When the block was created
            memories: List of memory transactions
            previous_hash: Hash of the previous block
            nonce: The nonce used for mining
            hash: The block's hash (calculated if not provided)
            difficulty: Number of leading zeros required in hash
        """
        self.index = index
        self.timestamp = timestamp
        self.memories = memories
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.difficulty = difficulty
        self.hash = hash or self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate the SHA-256 hash of the block."""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'memories': self.memories,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'difficulty': self.difficulty
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()
    
    def mine_block(self, difficulty: int) -> None:
        """
        Mine the block by finding a hash that meets the difficulty criteria.
        
        Args:
            difficulty: Number of leading zeros required in the hash
        """
        self.difficulty = difficulty
        target = '0' * difficulty
        
        while self.hash[0:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def is_valid(self, previous_block: Optional['Block'] = None) -> bool:
        """
        Validate the block.
        
        Args:
            previous_block: The previous block in the chain
            
        Returns:
            bool: True if the block is valid, False otherwise
        """
        # Check block hash is valid
        if self.hash != self.calculate_hash():
            return False
        
        # Check proof of work
        if self.hash[0:self.difficulty] != '0' * self.difficulty:
            return False
        
        # If this isn't the genesis block, check previous hash
        if previous_block and self.previous_hash != previous_block.hash:
            return False
        
        # Check all memories in the block are valid
        for memory in self.memories:
            if not self._is_valid_memory(memory):
                return False
                
        return True
    
    def _is_valid_memory(self, memory: Dict[str, Any]) -> bool:
        """Validate a memory structure."""
        required_fields = {'id', 'timestamp', 'content', 'context'}
        if not all(field in memory for field in required_fields):
            return False
            
        # Add more validation as needed
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the block to a dictionary."""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'memories': self.memories,
            'previous_hash': self.previous_hash,
            'hash': self.hash,
            'nonce': self.nonce,
            'difficulty': self.difficulty
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create a Block from a dictionary."""
        return cls(
            index=data['index'],
            timestamp=data['timestamp'],
            memories=data['memories'],
            previous_hash=data['previous_hash'],
            nonce=data.get('nonce', 0),
            hash=data.get('hash'),
            difficulty=data.get('difficulty', 4)
        )
    
    def __str__(self) -> str:
        """String representation of the block."""
        return (f"Block {self.index} [\n"
                f"  Timestamp: {datetime.fromtimestamp(self.timestamp)}\n"
                f"  Previous Hash: {self.previous_hash}\n"
                f"  Hash: {self.hash}\n"
                f"  Nonce: {self.nonce}\n"
                f"  Difficulty: {self.difficulty}\n"
                f"  Memory Count: {len(self.memories)}\n"
                "]")


def create_genesis_block() -> Block:
    """Create the genesis block for a new Clippy blockchain."""
    return Block(
        index=0,
        timestamp=time.time(),
        memories=[{
            'id': 'genesis',
            'timestamp': time.time(),
            'content': 'Genesis block for Clippy memory chain',
            'context': 'system',
            'type': 'system'
        }],
        previous_hash='0' * 64,  # Standard genesis previous hash
        difficulty=4
    )
