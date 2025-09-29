"""
Blockchain implementation for Brixa.

This module implements the core blockchain functionality including block validation,
transaction processing, and consensus using Proof-of-Memory.
"""
import json
import os
import time
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional

from .block import Block, create_genesis_block
from ..consensus.pom import ProofOfMemory, PoMConfig

class Blockchain:
    """Brixa blockchain implementation."""
    
    def __init__(self, data_dir: str = 'data'):
        """Initialize the blockchain."""
        self.chain: List[Block] = []
        self.pending_transactions: List[Dict[str, Any]] = []
        self.difficulty = 4
        self.data_dir = data_dir
        self.chain_file = os.path.join(data_dir, 'blocks.dat')
        
        # Create data directory if it doesn't exist
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize or load blockchain
        if os.path.exists(self.chain_file):
            self.load_chain()
        else:
            self.chain = [create_genesis_block()]
            self.save_chain()

    def add_block(self, block: Block) -> bool:
        """Add a new block to the blockchain."""
        if not self.is_valid_block(block, self.get_latest_block()):
            return False
            
        self.chain.append(block)
        self.save_chain()
        return True

    def mine_pending_transactions(self, miner_address: str) -> Optional[Block]:
        """Mine pending transactions and create a new block.
        
        Args:
            miner_address: The address that will receive the block reward
            
        Returns:
            The newly mined block, or None if no transactions to mine
        """
        if not self.pending_transactions:
            print("No pending transactions to mine")
            return None

        print(f"Mining block with {len(self.pending_transactions)} transactions...")
        
        try:
            # Add coinbase transaction
            coinbase_tx = self.create_coinbase_tx(miner_address)
            block_transactions = [coinbase_tx] + self.pending_transactions

            previous_block = self.get_latest_block()
            new_block = Block(
                index=len(self.chain),
                timestamp=time.time(),
                previous_hash=previous_block.hash,
                transactions=block_transactions,
                difficulty=self.difficulty
            )

            # Mine the block using Proof-of-Memory
            print("Starting mining process...")
            start_time = time.time()
            new_block.mine(self.difficulty)
            
            # Verify the block before adding to the chain
            if not self.is_valid_block(new_block, previous_block):
                print("Error: Mined block is not valid!")
                return None
            
            # Add to chain and clear pending transactions
            self.chain.append(new_block)
            self.pending_transactions = []
            self.save_chain()
            
            end_time = time.time()
            print(f"Successfully mined block {new_block.index} in {end_time - start_time:.2f} seconds")
            print(f"Block hash: {new_block.hash}")
            
            return new_block
            
        except Exception as e:
            print(f"Error mining block: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def create_coinbase_tx(self, miner_address: str) -> Dict[str, Any]:
        """Create a coinbase transaction for block rewards."""
        return {
            'txid': hashlib.sha256(f"{time.time()}{miner_address}".encode()).hexdigest(),
            'version': 1,
            'inputs': [{
                'txid': '0' * 64,
                'vout': 0xffffffff,
                'script_sig': f"Brixa Block Reward {len(self.chain)}",
                'sequence': 0xffffffff
            }],
            'outputs': [{
                'value': self.get_block_reward(),
                'script_pubkey': f"OP_DUP OP_HASH160 {miner_address} OP_EQUALVERIFY OP_CHECKSIG",
                'address': miner_address
            }],
            'locktime': 0
        }

    def get_block_reward(self) -> int:
        """Calculate current block reward (halving every 210,000 blocks)."""
        halvings = len(self.chain) // 210000
        if halvings >= 64:
            return 0
        return 50 * (10**8) >> halvings  # 50 BXA in satoshis

    def is_valid_block(self, new_block: Block, previous_block: Block) -> bool:
        """Validate a new block before adding to the chain.
        
        Args:
            new_block: The block to validate
            previous_block: The previous block in the chain
            
        Returns:
            bool: True if the block is valid, False otherwise
        """
        # Check block structure
        if new_block.index != previous_block.index + 1:
            print(f"Invalid block index: expected {previous_block.index + 1}, got {new_block.index}")
            return False
            
        if new_block.previous_hash != previous_block.hash:
            print(f"Invalid previous hash: expected {previous_block.hash}, got {new_block.previous_hash}")
            return False
            
        if new_block.hash != new_block.calculate_hash():
            print("Block hash does not match calculated hash")
            return False
            
        # Verify the proof of work
        if not new_block.is_valid_proof():
            print("Invalid proof of work")
            return False
            
        # Verify transactions
        if not self.verify_block_transactions(new_block):
            print("Invalid transactions in block")
            return False
            
        return True
        
    def verify_block_transactions(self, block: Block) -> bool:
        """Verify all transactions in a block.
        
        Args:
            block: The block containing transactions to verify
            
        Returns:
            bool: True if all transactions are valid, False otherwise
        """
        # Skip coinbase transaction (first transaction)
        for tx in block.transactions[1:]:
            if not self.verify_transaction(tx):
                return False
        return True
        
    def verify_transaction(self, tx: Dict[str, Any]) -> bool:
        """Verify a transaction.
        
        Args:
            tx: The transaction to verify
            
        Returns:
            bool: True if the transaction is valid, False otherwise
        """
        # Basic transaction validation
        required_fields = {'txid', 'version', 'inputs', 'outputs'}
        if not all(field in tx for field in required_fields):
            return False
            
        # Verify inputs and outputs
        if not tx['inputs'] or not tx['outputs']:
            return False
            
        # Verify the transaction hash
        tx_copy = tx.copy()
        tx_copy.pop('txid', None)
        calculated_hash = hashlib.sha256(json.dumps(tx_copy, sort_keys=True).encode()).hexdigest()
        
        return tx['txid'] == calculated_hash

    def get_latest_block(self) -> Block:
        """Get the latest block in the chain."""
        return self.chain[-1]

    def get_balance(self, address: str) -> int:
        """Get balance for a given address."""
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                # Add outputs to this address
                for output in tx.get('outputs', []):
                    if output.get('address') == address:
                        balance += output.get('value', 0)
                
                # Subtract inputs from this address
                for input_tx in tx.get('inputs', []):
                    if input_tx.get('address') == address:
                        balance -= input_tx.get('value', 0)
        return balance

    def save_chain(self) -> None:
        """Save blockchain to disk."""
        chain_data = [block.to_dict() for block in self.chain]
        with open(self.chain_file, 'w') as f:
            json.dump(chain_data, f, indent=2)

    def load_chain(self) -> None:
        """Load blockchain from disk."""
        try:
            with open(self.chain_file, 'r') as f:
                chain_data = json.load(f)
                self.chain = [Block.from_dict(block_data) for block_data in chain_data]
        except (FileNotFoundError, json.JSONDecodeError):
            self.chain = [create_genesis_block()]

    def is_chain_valid(self) -> bool:
        """Check if the entire blockchain is valid.
        
        Returns:
            bool: True if the blockchain is valid, False otherwise
        """
        # Check genesis block
        if not self.chain:
            print("Blockchain is empty")
            return False
            
        # Verify each block in the chain
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            # Verify block hash
            if current.hash != current.calculate_hash():
                print(f"Block {i} has invalid hash")
                return False
                
            # Verify block links
            if current.previous_hash != previous.hash:
                print(f"Block {i} has invalid previous hash")
                return False
                
            # Verify proof of work
            if not current.is_valid_proof():
                print(f"Block {i} has invalid proof of work")
                return False
                
            # Verify transactions
            if not self.verify_block_transactions(current):
                print(f"Block {i} contains invalid transactions")
                return False
        
        print("Blockchain is valid")
        return True
