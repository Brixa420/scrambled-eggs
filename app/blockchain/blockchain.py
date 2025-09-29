"""
Blockchain implementation for Clippy's memory system.
Manages the chain of blocks and provides methods for adding new memories.
"""
import json
import os
from typing import List, Dict, Any, Optional
from pathlib import Path

from .block import Block, create_genesis_block

class Blockchain:
    """
    A simple blockchain implementation for storing Clippy's memories.
    """
    
    def __init__(self, chain_dir: str = 'data/blockchain'):
        """
        Initialize the blockchain.
        
        Args:
            chain_dir: Directory to store blockchain data
        """
        self.chain: List[Block] = []
        self.pending_memories: List[Dict[str, Any]] = []
        self.difficulty = 4
        self.chain_dir = Path(chain_dir)
        self.chain_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load the blockchain
        self._initialize_chain()
    
    def _initialize_chain(self) -> None:
        """Initialize the blockchain, loading from disk if available."""
        chain_file = self.chain_dir / 'chain.json'
        
        if chain_file.exists():
            self._load_chain()
        else:
            # Create a new blockchain with genesis block
            self.chain = [create_genesis_block()]
            self._save_chain()
    
    def _load_chain(self) -> None:
        """Load the blockchain from disk."""
        chain_file = self.chain_dir / 'chain.json'
        try:
            with open(chain_file, 'r') as f:
                chain_data = json.load(f)
                self.chain = [Block.from_dict(block_data) for block_data in chain_data]
        except (json.JSONDecodeError, FileNotFoundError):
            # If loading fails, create a new chain
            self.chain = [create_genesis_block()]
    
    def _save_chain(self) -> None:
        """Save the blockchain to disk."""
        chain_file = self.chain_dir / 'chain.json'
        chain_data = [block.to_dict() for block in self.chain]
        
        # Write to a temporary file first, then rename to ensure atomicity
        temp_file = chain_file.with_suffix('.tmp')
        with open(temp_file, 'w') as f:
            json.dump(chain_data, f, indent=2)
        
        # On Windows, we need to remove the destination file first
        if chain_file.exists():
            chain_file.unlink()
        temp_file.rename(chain_file)
    
    def get_latest_block(self) -> Block:
        """Get the latest block in the chain."""
        return self.chain[-1]
    
    def add_memory(self, memory: Dict[str, Any]) -> None:
        """
        Add a new memory to be included in the next block.
        
        Args:
            memory: The memory to add (must be a dictionary with required fields)
        """
        # Add required fields if not present
        memory.setdefault('timestamp', time.time())
        memory.setdefault('id', hashlib.sha256(
            f"{memory['timestamp']}{json.dumps(memory.get('content', ''))}".encode()
        ).hexdigest())
        
        self.pending_memories.append(memory)
    
    def mine_pending_memories(self) -> Block:
        """
        Mine a new block with the pending memories.
        
        Returns:
            The newly mined block
        """
        if not self.pending_memories:
            raise ValueError("No pending memories to mine")
        
        latest_block = self.get_latest_block()
        
        new_block = Block(
            index=latest_block.index + 1,
            timestamp=time.time(),
            memories=self.pending_memories.copy(),
            previous_hash=latest_block.hash,
            difficulty=self.difficulty
        )
        
        # Mine the block (find a valid nonce)
        new_block.mine_block(self.difficulty)
        
        # Add the block to the chain
        self.chain.append(new_block)
        self.pending_memories = []
        
        # Save the updated chain
        self._save_chain()
        
        return new_block
    
    def is_chain_valid(self) -> bool:
        """
        Check if the blockchain is valid.
        
        Returns:
            bool: True if the chain is valid, False otherwise
        """
        # Check if the genesis block is valid
        if len(self.chain) > 0:
            if not self.chain[0].is_valid():
                return False
        
        # Check each subsequent block
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Check if the block is valid and properly linked
            if not current_block.is_valid(previous_block):
                return False
            
            # Check if the block's hash matches its content
            if current_block.hash != current_block.calculate_hash():
                return False
            
            # Check if the previous hash is correct
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_memories(self, filter_func=None, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get memories from the blockchain, optionally filtered.
        
        Args:
            filter_func: Optional function to filter memories
            limit: Maximum number of memories to return
            
        Returns:
            List of matching memories
        """
        memories = []
        
        # Iterate through blocks in reverse order (newest first)
        for block in reversed(self.chain):
            for memory in block.memories:
                if filter_func is None or filter_func(memory):
                    memories.append(memory)
                    if len(memories) >= limit:
                        return memories
        
        return memories
    
    def get_memory_by_id(self, memory_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a memory by its ID.
        
        Args:
            memory_id: The ID of the memory to find
            
        Returns:
            The memory if found, None otherwise
        """
        for block in reversed(self.chain):
            for memory in block.memories:
                if memory.get('id') == memory_id:
                    return memory
        return None
    
    def get_chain_length(self) -> int:
        """Get the length of the blockchain."""
        return len(self.chain)
    
    def get_total_memories(self) -> int:
        """Get the total number of memories stored in the blockchain."""
        return sum(len(block.memories) for block in self.chain)
    
    def get_block_by_index(self, index: int) -> Optional[Block]:
        """
        Get a block by its index.
        
        Args:
            index: The index of the block to retrieve
            
        Returns:
            The block if found, None otherwise
        """
        if 0 <= index < len(self.chain):
            return self.chain[index]
        return None


def get_blockchain() -> Blockchain:
    """Get or create a blockchain instance."""
    if not hasattr(get_blockchain, '_instance'):
        get_blockchain._instance = Blockchain()
    return get_blockchain._instance
