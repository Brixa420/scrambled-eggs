"""
Brixa Miner Module

This module handles the mining operations for the Brixa blockchain,
including proof-of-work calculations and block creation.
"""

import time
import asyncio
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
import json

from ..block import Block
from ..blockchain import Blockchain
from ..transaction import Transaction, create_coinbase_tx
from ..consensus.proof_of_work import ProofOfWork

class BrixaMiner:
    """Handles the mining operations for the Brixa blockchain."""
    
    def __init__(self, blockchain: Blockchain, miner_address: str, data_dir: str = 'data/miner'):
        """
        Initialize the Brixa miner.
        
        Args:
            blockchain: The blockchain instance
            miner_address: The address that will receive mining rewards
            data_dir: Directory to store miner data
        """
        self.blockchain = blockchain
        self.miner_address = miner_address
        self.is_mining = False
        self.current_block: Optional[Block] = None
        self.pow = ProofOfWork(blockchain)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.on_block_mined: Optional[Callable[[Block], None]] = None
    
    async def start_mining(self) -> None:
        """Start the mining process asynchronously."""
        if self.is_mining:
            return
            
        self.is_mining = True
        await self._mine_loop()
    
    def stop_mining(self) -> None:
        """Stop the mining process."""
        self.is_mining = False
    
    async def _mine_loop(self) -> None:
        """Main mining loop that creates and mines new blocks."""
        while self.is_mining:
            try:
                # Get pending transactions (excluding coinbase)
                pending_txs = self.blockchain.get_pending_transactions()
                
                # Create and mine new block
                self.current_block = await self._create_new_block(pending_txs)
                
                if await self._mine_block(self.current_block):
                    # Add block to blockchain
                    success = await self.blockchain.add_block(self.current_block)
                    if success:
                        print(f"Mined block {self.current_block.index} with hash {self.current_block.hash}")
                        if self.on_block_mined:
                            self.on_block_mined(self.current_block)
                    else:
                        print(f"Failed to add block {self.current_block.index} to chain")
                
                # Small delay to prevent tight loop when not mining
                await asyncio.sleep(0.1)
                
            except Exception as e:
                print(f"Error in mining loop: {e}")
                await asyncio.sleep(1)  # Prevent tight error loop
    
    async def _create_new_block(self, pending_txs: List[Transaction]) -> Block:
        """
        Create a new block with pending transactions.
        
        Args:
            pending_txs: List of pending transactions to include
            
        Returns:
            Block: The newly created block
        """
        last_block = self.blockchain.get_latest_block()
        height = last_block.index + 1
        
        # Calculate total fees from pending transactions
        total_fees = sum(tx.fee for tx in pending_txs if not tx.is_coinbase())
        
        # Create coinbase transaction (miner reward + fees)
        coinbase_tx = self.pow.create_coinbase_transaction(
            self.miner_address,
            height,
            total_fees
        )
        
        # Include coinbase as first transaction
        transactions = [coinbase_tx] + pending_txs
        
        # Get current difficulty
        difficulty = self.blockchain.get_difficulty()
        
        # Create new block
        return Block(
            index=height,
            timestamp=int(time.time()),
            transactions=transactions,
            previous_hash=last_block.hash,
            difficulty=difficulty,
            nonce=0,
            miner_address=self.miner_address
        )
    
    async def _mine_block(self, block: Block, batch_size: int = 10000) -> bool:
        """
        Mine a block using proof-of-work.
        
        Args:
            block: The block to mine
            batch_size: Number of nonces to try before checking for stop
            
        Returns:
            bool: True if block was successfully mined, False if mining was stopped
        """
        # Update timestamp before mining
        block.timestamp = int(time.time())
        
        # Mine the block
        return await asyncio.get_event_loop().run_in_executor(
            None,
            self._mine_block_sync,
            block,
            batch_size
        )
    
    def _mine_block_sync(self, block: Block, batch_size: int) -> bool:
        """Synchronous version of mine_block for executor."""
        nonce = 0
        
        while self.is_mining:
            # Try a batch of nonces
            for _ in range(batch_size):
                block.nonce = nonce
                block.timestamp = int(time.time())  # Update timestamp for each attempt
                
                if self.pow.validate_block(block):
                    return True
                    
                nonce += 1
                
            # Small sleep to prevent 100% CPU usage
            time.sleep(0.001)
            
        return False
    
    def get_mining_info(self) -> Dict[str, Any]:
        """
        Get current mining information.
        
        Returns:
            dict: Mining information including status, current block, etc.
        """
        return {
            'mining': self.is_mining,
            'miner_address': self.miner_address,
            'current_block': self.current_block.to_dict() if self.current_block else None,
            'difficulty': self.blockchain.get_difficulty(),
            'network_hashrate': self.estimate_network_hashrate(),
        }
    
    def estimate_network_hashrate(self, blocks: int = 144) -> float:
        """
        Estimate the current network hashrate.
        
        Args:
            blocks: Number of blocks to use for estimation
            
        Returns:
            float: Estimated network hashrate in hashes per second
        """
        chain = self.blockchain.get_chain()
        if len(chain) < 2:
            return 0.0
            
        # Use the last 'blocks' blocks, or all blocks if chain is shorter
        blocks = min(blocks, len(chain) - 1)
        start_block = chain[-blocks - 1]
        end_block = chain[-1]
        
        # Calculate total work (sum of 2^difficulty for each block)
        total_work = sum(2 ** block.difficulty for block in chain[-blocks:])
        
        # Calculate time span in seconds
        time_span = end_block.timestamp - start_block.timestamp
        if time_span == 0:
            return 0.0
            
        # Hashrate = total work / time span
        return total_work / time_span
