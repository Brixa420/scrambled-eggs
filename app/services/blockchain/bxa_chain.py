"""
Brixa (BXA) Blockchain Implementation

This module implements the Brixa blockchain with Bitcoin-style tokenomics.
"""
import hashlib
import json
import time
from datetime import datetime
from typing import List, Dict, Optional, Tuple
import logging

from app.core.tokenomics import BXATokenomics

logger = logging.getLogger(__name__)

class BXABlock:
    """Represents a block in the BXA blockchain"""
    
    def __init__(
        self,
        index: int,
        timestamp: float,
        transactions: List[Dict],
        previous_hash: str,
        difficulty: int,
        nonce: int = 0,
        hash: Optional[str] = None,
        miner: Optional[str] = None
    ):
        self.index = index
        self.timestamp = timestamp
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.difficulty = difficulty
        self.nonce = nonce
        self.hash = hash if hash else self.calculate_hash()
        self.miner = miner
        self.merkle_root = self.calculate_merkle_root()
    
    def calculate_hash(self) -> str:
        """Calculate the hash of the block"""
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def calculate_merkle_root(self) -> str:
        """Calculate the Merkle root of the block's transactions"""
        if not self.transactions:
            return hashlib.sha256(b"").hexdigest()
            
        # Convert transactions to hashes
        transaction_hashes = [
            hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
            for tx in self.transactions
        ]
        
        return self._compute_merkle_root(transaction_hashes)
    
    def _compute_merkle_root(self, hashes: List[str]) -> str:
        """Recursively compute the Merkle root"""
        if len(hashes) == 0:
            return ""
            
        if len(hashes) == 1:
            return hashes[0]
            
        # If odd number of hashes, duplicate the last one
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])
            
        new_hashes = []
        for i in range(0, len(hashes), 2):
            combined = hashes[i] + hashes[i + 1]
            new_hashes.append(hashlib.sha256(combined.encode()).hexdigest())
            
        return self._compute_merkle_root(new_hashes)
    
    def to_dict(self) -> Dict:
        """Convert block to dictionary"""
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": self.transactions,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
            "merkle_root": self.merkle_root,
            "miner": self.miner
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'BXABlock':
        """Create a block from a dictionary"""
        return cls(
            index=data['index'],
            timestamp=data['timestamp'],
            transactions=data['transactions'],
            previous_hash=data['previous_hash'],
            difficulty=data['difficulty'],
            nonce=data['nonce'],
            hash=data['hash'],
            miner=data.get('miner')
        )

class BXAChain:
    """Brixa Blockchain Implementation"""
    
    def __init__(self, node_id: str):
        self.chain: List[BXABlock] = []
        self.pending_transactions: List[Dict] = []
        self.nodes = set()
        self.node_id = node_id
        self.difficulty = 4  # Initial difficulty (number of leading zeros)
        self.mining_reward = BXATokenomics.get_block_reward(0)  # Initial block reward
        self.target_block_time = 10 * 60  # 10 minutes in seconds (same as Bitcoin)
        
        # Create the genesis block
        self.create_genesis_block()
    
    def create_genesis_block(self) -> None:
        """Create the genesis block"""
        genesis_block = BXABlock(
            index=0,
            timestamp=time.time(),
            transactions=[],
            previous_hash="0" * 64,  # Genesis block has no previous hash
            difficulty=self.difficulty,
            nonce=0
        )
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
    
    def get_latest_block(self) -> BXABlock:
        """Get the latest block in the chain"""
        return self.chain[-1]
    
    def mine_pending_transactions(self, miner_address: str) -> Optional[BXABlock]:
        """
        Mine pending transactions and create a new block
        
        Args:
            miner_address: Address of the miner who will receive the block reward
            
        Returns:
            The newly mined block, or None if no transactions to mine
        """
        if not self.pending_transactions:
            logger.warning("No transactions to mine")
            return None
            
        # Create a reward transaction for the miner
        reward_tx = {
            'from': 'network',
            'to': miner_address,
            'amount': float(self.mining_reward),
            'timestamp': time.time(),
            'type': 'reward'
        }
        
        # Add the reward transaction to pending transactions
        self.pending_transactions.append(reward_tx)
        
        # Create the new block
        previous_block = self.get_latest_block()
        new_block = BXABlock(
            index=previous_block.index + 1,
            timestamp=time.time(),
            transactions=self.pending_transactions,
            previous_hash=previous_block.hash,
            difficulty=self.difficulty,
            miner=miner_address
        )
        
        # Mine the block (proof of work)
        self.proof_of_work(new_block)
        
        # Add the block to the chain
        self.chain.append(new_block)
        
        # Reset pending transactions
        self.pending_transactions = []
        
        # Adjust difficulty every 2016 blocks (same as Bitcoin)
        if new_block.index % 2016 == 0:
            self.adjust_difficulty()
        
        # Update mining reward based on halving schedule
        self.mining_reward = BXATokenomics.get_block_reward(new_block.index)
        
        return new_block
    
    def proof_of_work(self, block: BXABlock) -> str:
        """
        Simple Proof of Work algorithm:
        - Find a number 'nonce' such that hash(block + nonce) has 'difficulty' leading zeros
        
        Args:
            block: The block to mine
            
        Returns:
            The hash of the mined block
        """
        target = '0' * self.difficulty
        
        while True:
            block.hash = block.calculate_hash()
            if block.hash.startswith(target):
                break
            block.nonce += 1
            
        return block.hash
    
    def add_transaction(self, transaction: Dict) -> int:
        """
        Add a new transaction to the list of pending transactions
        
        Args:
            transaction: The transaction to add
            
        Returns:
            The index of the block that will hold this transaction
        """
        # TODO: Validate transaction before adding
        
        self.pending_transactions.append(transaction)
        return self.get_latest_block().index + 1
    
    def is_chain_valid(self, chain: List[BXABlock] = None) -> bool:
        """
        Check if a given blockchain is valid
        
        Args:
            chain: The blockchain to validate (defaults to self.chain)
            
        Returns:
            True if the chain is valid, False otherwise
        """
        if chain is None:
            chain = self.chain
            
        # Check if the genesis block is valid
        if chain[0].hash != chain[0].calculate_hash():
            return False
            
        # Check each subsequent block
        for i in range(1, len(chain)):
            current_block = chain[i]
            previous_block = chain[i - 1]
            
            # Check if the block's hash is valid
            if current_block.hash != current_block.calculate_hash():
                return False
                
            # Check if the block points to the correct previous hash
            if current_block.previous_hash != previous_block.hash:
                return False
                
            # Check proof of work
            target = '0' * self.difficulty
            if not current_block.hash.startswith(target):
                return False
                
        return True
    
    def adjust_difficulty(self) -> None:
        """
        Adjust the mining difficulty based on the time it took to mine the last 2016 blocks
        (same as Bitcoin's 2-week adjustment period)
        """
        if len(self.chain) < 2016:
            return
            
        # Get the first and last block of the last 2016 blocks
        first_block = self.chain[-2016]
        last_block = self.chain[-1]
        
        # Calculate the time difference in seconds
        time_diff = last_block.timestamp - first_block.timestamp
        
        # Target time for 2016 blocks is 2016 * 10 minutes = 20160 minutes = 2 weeks
        target_time = 2016 * 10 * 60  # in seconds
        
        # Adjust difficulty
        if time_diff < target_time * 0.9:  # Too fast
            self.difficulty += 1
        elif time_diff > target_time * 1.1:  # Too slow
            self.difficulty = max(1, self.difficulty - 1)
    
    def get_balance(self, address: str) -> float:
        """
        Get the balance of an address
        
        Args:
            address: The address to get the balance for
            
        Returns:
            The balance of the address
        """
        balance = 0.0
        
        for block in self.chain:
            for tx in block.transactions:
                if tx['to'] == address:
                    balance += tx['amount']
                if tx.get('from') == address:
                    balance -= tx['amount']
                    
        return balance
    
    def get_tokenomics_summary(self) -> dict:
        """
        Get a summary of the current tokenomics
        
        Returns:
            Dictionary with tokenomics information
        """
        current_block = len(self.chain) - 1  # 0-based index
        return BXATokenomics.get_tokenomics_summary(current_block)
    
    def to_dict(self) -> Dict:
        """Convert blockchain to dictionary"""
        return {
            'chain': [block.to_dict() for block in self.chain],
            'pending_transactions': self.pending_transactions,
            'nodes': list(self.nodes),
            'node_id': self.node_id,
            'difficulty': self.difficulty,
            'mining_reward': float(self.mining_reward)
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'BXAChain':
        """Create a blockchain from a dictionary"""
        blockchain = cls(data['node_id'])
        blockchain.chain = [BXABlock.from_dict(block) for block in data['chain']]
        blockchain.pending_transactions = data['pending_transactions']
        blockchain.nodes = set(data['nodes'])
        blockchain.difficulty = data['difficulty']
        blockchain.mining_reward = data['mining_reward']
        return blockchain
