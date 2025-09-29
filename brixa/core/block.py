"""
Block implementation for the Brixa blockchain.
"""
import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from ..utils.crypto import calculate_merkle_root
from ..consensus.pom import ProofOfMemory, PoMConfig

@dataclass
class Block:
    """A block in the Brixa blockchain.
    
    Attributes:
        index: The position of the block in the blockchain
        timestamp: When the block was created (UNIX timestamp)
        previous_hash: Hash of the previous block
        transactions: List of transactions in the block
        version: Block version number
        nonce: The nonce used in mining
        difficulty: The difficulty target for mining
        proof: The proof of work/proof of memory
        hash: The block's hash (calculated)
        merkle_root: The Merkle root of transactions (calculated)
    """
    index: int
    timestamp: float
    previous_hash: str
    transactions: List[Dict[str, Any]]
    version: int = 1
    nonce: int = 0
    difficulty: int = 4
    proof: bytes = field(default_factory=bytes)
    hash: str = field(init=False)
    merkle_root: str = field(init=False)
    
    def __post_init__(self):
        """Calculate the block's hash and merkle root after initialization."""
        self.merkle_root = calculate_merkle_root([tx['txid'] for tx in self.transactions])
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        """Calculate the block's hash.
        
        The hash includes all block data including the proof and nonce.
        
        Returns:
            The SHA-256 hash of the block header as a hex string
        """
        block_data = {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'proof': self.proof.hex() if self.proof else '',
            'transactions': self.transactions,
            'version': self.version
        }
        block_string = json.dumps(block_data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
        
    def mine(self, difficulty: int = 4) -> None:
        """Mine the block using Proof-of-Memory.
        
        Args:
            difficulty: The number of leading zeros required in the proof
        """
        pom = ProofOfMemory(PoMConfig(difficulty=difficulty))
        self.proof, self.nonce, time_taken = pom.generate_proof(self.calculate_hash())
        self.hash = self.calculate_hash()
        print(f"Mined block {self.index} in {time_taken:.2f}s with nonce {self.nonce}")
        print(f"Block hash: {self.hash}")
        print(f"Proof: {self.proof.hex()}")
        
    def is_valid_proof(self) -> bool:
        """Verify that the block's proof is valid.
        
        Returns:
            bool: True if the proof is valid, False otherwise
        """
        pom = ProofOfMemory(PoMConfig(difficulty=self.difficulty))
        return pom.verify_proof(
            self.calculate_hash(),
            self.proof,
            self.nonce
        )
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert block to dictionary for serialization.
        
        Returns:
            Dict containing block data
        """
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'transactions': self.transactions,
            'version': self.version,
            'nonce': self.nonce,
            'difficulty': self.difficulty,
            'hash': self.hash,
            'merkle_root': self.merkle_root,
            'proof': self.proof.hex() if self.proof else ''
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Block':
        """Create block from dictionary."""
        block = cls(
            version=data['version'],
            index=data['index'],
            timestamp=data['timestamp'],
            previous_hash=data['previous_hash'],
            transactions=data['transactions'],
            nonce=data['nonce'],
            difficulty=data.get('difficulty', 4)
        )
        block.hash = data['hash']
        return block

def create_genesis_block() -> Block:
    """Create the genesis block for the Brixa blockchain."""
    genesis_transactions = [{
        'txid': '0' * 64,
        'version': 1,
        'inputs': [],
        'outputs': [{
            'value': 0,
            'script_pubkey': 'Brixa Genesis Block',
            'address': 'B1TCO1NST1TUT1ON'
        }],
        'locktime': 0
    }]
    return Block(
        index=0,
        timestamp=datetime(2025, 1, 1).timestamp(),
        previous_hash='0' * 64,
        transactions=genesis_transactions
    )
