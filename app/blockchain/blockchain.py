"""
Blockchain implementation for Brixa.
Manages the chain of blocks and provides methods for adding new transactions.
Implements a Bitcoin-like blockchain with BXA tokens.
"""
import json
import os
import time
import struct
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Callable, TypeVar, Generic, Type

from .block import Block, create_genesis_block, VERSION as BLOCK_VERSION
from .transaction import (
    Transaction, TransactionInput, TransactionOutput, 
    create_coinbase_transaction, verify_transaction,
    MAX_MONEY, DEFAULT_SEQUENCE, LOCKTIME_THRESHOLD
)

# Type variable for generic blockchain storage
T = TypeVar('T')

class BlockchainStorage(Generic[T]):
    """Generic blockchain storage interface."""
    def __init__(self, data_dir: str):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str) -> Optional[T]:
        """Get a value from storage."""
        raise NotImplementedError
    
    def put(self, key: str, value: T) -> bool:
        """Store a value in storage."""
        raise NotImplementedError
    
    def delete(self, key: str) -> bool:
        """Delete a value from storage."""
        raise NotImplementedError


class JSONFileStorage(BlockchainStorage[dict]):
    """JSON file-based storage for blockchain data."""
    def get(self, key: str) -> Optional[dict]:
        """Get a value from JSON file storage."""
        file_path = self.data_dir / f"{key}.json"
        if not file_path.exists():
            return None
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
    
    def put(self, key: str, value: dict) -> bool:
        """Store a value in JSON file storage."""
        file_path = self.data_dir / f"{key}.json"
        try:
            with open(file_path, 'w') as f:
                json.dump(value, f, indent=2)
            return True
        except IOError:
            return False
    
    def delete(self, key: str) -> bool:
        """Delete a value from JSON file storage."""
        file_path = self.data_dir / f"{key}.json"
        try:
            if file_path.exists():
                file_path.unlink()
            return True
        except IOError:
            return False

class Blockchain:
    """
    A blockchain implementation for Brixa.
    Implements a Bitcoin-like blockchain with BXA tokens.
    """
    
    def __init__(self, data_dir: str = 'data/blockchain', network: str = 'mainnet'):
        """
        Initialize the blockchain.
        
        Args:
            data_dir: Directory to store blockchain data
            network: Network type ('mainnet', 'testnet', 'regtest')
        """
        # Network parameters
        self.network = network
        self.max_block_size = 1_000_000  # 1MB block size limit
        self.max_sigops_per_block = 20_000  # Max signature operations per block
        self.coinbase_maturity = 100  # Number of confirmations before coinbase can be spent
        
        # Storage
        self.storage = JSONFileStorage(data_dir)
        
        # Chain state
        self.chain: List[Block] = []
        self.best_block_hash: Optional[str] = None
        self.chain_tip: Optional[Block] = None
        
        # UTXO set (txid -> {vout -> output})
        self.utxo_set: Dict[str, Dict[int, TransactionOutput]] = {}
        
        # Mempool (txid -> transaction)
        self.mempool: Dict[str, Transaction] = {}
        
        # Orphan transactions (txid -> transaction)
        self.orphan_txs: Dict[str, Transaction] = {}
        
        # Block index (hash -> block)
        self.block_index: Dict[str, Block] = {}
        
        # Chain parameters
        self.genesis_block = create_genesis_block()
        self.difficulty_bits = 0x1d00ffff  # Initial difficulty bits
        self.target_timespan = 14 * 24 * 60 * 60  # 2 weeks in seconds (difficulty adjustment)
        self.target_spacing = 10 * 60  # 10 minutes between blocks (target)
        
        # Initialize or load the blockchain
        self._initialize_chain()
    
    def _initialize_chain(self) -> None:
        """Initialize the blockchain, loading from disk if available."""
        # Try to load blockchain state from storage
        chain_state = self.storage.get('chain_state')
        
        if chain_state and 'best_block_hash' in chain_state:
            # Load existing chain
            self._load_chain_state(chain_state)
        else:
            # Initialize new blockchain with genesis block
            self.chain = [self.genesis_block]
            self.best_block_hash = self.genesis_block.hash
            self.chain_tip = self.genesis_block
            self.block_index[self.genesis_block.hash] = self.genesis_block
            
            # Initialize UTXO set with genesis block outputs
            self._update_utxo_set(self.genesis_block)
            
            # Save initial state
            self._save_chain_state()
    
    def _load_chain_state(self, chain_state: Dict[str, Any]) -> None:
        """Load blockchain state from storage."""
        try:
            # Load best block
            self.best_block_hash = chain_state['best_block_hash']
            
            # Load block index
            block_index_data = self.storage.get('block_index') or {}
            self.block_index = {}
            
            # Reconstruct chain from block index
            current_hash = self.best_block_hash
            chain = []
            
            while current_hash in block_index_data:
                block_data = block_index_data[current_hash]
                block = Block.from_dict(block_data)
                self.block_index[current_hash] = block
                chain.append(block)
                current_hash = block.previous_hash
            
            # Reverse to get the correct order (genesis first)
            self.chain = list(reversed(chain))
            
            if self.chain:
                self.chain_tip = self.chain[-1]
            
            # Load UTXO set
            utxo_data = self.storage.get('utxo_set') or {}
            self.utxo_set = {}
            
            for txid, outputs in utxo_data.items():
                self.utxo_set[txid] = {
                    int(vout): TransactionOutput.from_dict(output_data)
                    for vout, output_data in outputs.items()
                }
            
            # Load mempool
            mempool_data = self.storage.get('mempool') or {}
            self.mempool = {
                txid: Transaction.from_dict(tx_data)
                for txid, tx_data in mempool_data.items()
            }
            
        except (KeyError, json.JSONDecodeError) as e:
            # If loading fails, reset to genesis
            self.chain = [self.genesis_block]
            self.best_block_hash = self.genesis_block.hash
            self.chain_tip = self.genesis_block
            self.block_index = {self.genesis_block.hash: self.genesis_block}
            self.utxo_set = {}
            self.mempool = {}
            
            # Save initial state
            self._save_chain_state()
    
    def _save_chain_state(self) -> None:
        """Save the current blockchain state to storage."""
        # Save chain state
        chain_state = {
            'best_block_hash': self.best_block_hash,
            'height': len(self.chain) - 1 if self.chain else 0,
            'timestamp': int(time.time())
        }
        self.storage.put('chain_state', chain_state)
        
        # Save block index
        block_index = {
            block.hash: block.to_dict()
            for block in self.chain
        }
        self.storage.put('block_index', block_index)
        
        # Save UTXO set
        utxo_data = {
            txid: {str(vout): output.to_dict() for vout, output in outputs.items()}
            for txid, outputs in self.utxo_set.items()
        }
        self.storage.put('utxo_set', utxo_data)
        
        # Save mempool
        mempool_data = {
            txid: tx.to_dict()
            for txid, tx in self.mempool.items()
        }
        self.storage.put('mempool', mempool_data)
    
    def _update_utxo_set(self, block: Block) -> None:
        """
        Update the UTXO set with transactions from a newly added block.
        
        Args:
            block: The block containing transactions to process
        """
        for tx_data in block.transactions:
            tx = Transaction.from_dict(tx_data)
            
            # Skip if this is a coinbase transaction (handled separately)
            if tx.is_coinbase:
                continue
            
            # Process inputs (remove spent outputs)
            for tx_input in tx.inputs:
                # Skip coinbase inputs
                if tx_input.txid == '0' * 64:  # Coinbase txid
                    continue
                    
                # Remove the spent output from UTXO set
                if tx_input.txid in self.utxo_set and tx_input.vout in self.utxo_set[tx_input.txid]:
                    del self.utxo_set[tx_input.txid][tx_input.vout]
                    
                    # Remove the transaction from UTXO set if no more outputs
                    if not self.utxo_set[tx_input.txid]:
                        del self.utxo_set[tx_input.txid]
            
            # Process outputs (add new UTXOs)
            for vout, output in enumerate(tx.outputs):
                if tx.txid not in self.utxo_set:
                    self.utxo_set[tx.txid] = {}
                self.utxo_set[tx.txid][vout] = output
    
    def get_balance(self, address: str, min_confirmations: int = 6) -> int:
        """
        Get the spendable balance of an address by scanning the UTXO set.
        
        Args:
            address: The address to get the balance for
            min_confirmations: Minimum number of confirmations required
            
        Returns:
            The spendable balance in satoshis
        """
        balance = 0
        
        # Get the current block height for confirmation calculation
        current_height = len(self.chain) - 1 if self.chain else 0
        
        # Track unconfirmed transactions from mempool that spend our UTXOs
        spent_utxos = set()
        
        # Check mempool for transactions that spend our UTXOs
        for tx in self.mempool.values():
            for tx_input in tx.inputs:
                if tx_input.txid in self.utxo_set and tx_input.vout in self.utxo_set[tx_input.txid]:
                    spent_utxos.add((tx_input.txid, tx_input.vout))
        
        # Calculate balance from UTXOs
        for txid, outputs in self.utxo_set.items():
            for vout, output in outputs.items():
                # Skip if this UTXO is spent in mempool
                if (txid, vout) in spent_utxos:
                    continue
                
                # Skip if not enough confirmations (for coinbase transactions)
                if txid == '0' * 64:  # Coinbase txid
                    tx_block = self._find_tx_block(txid)
                    if tx_block and current_height - tx_block.height + 1 < self.coinbase_maturity:
                        continue
                
                # Add to balance if address matches
                if output.address == address:
                    balance += output.value
        
        return balance
    
    def _find_tx_block(self, txid: str) -> Optional[Block]:
        """Find the block containing a transaction."""
        for block in reversed(self.chain):
            for tx_data in block.transactions:
                if isinstance(tx_data, dict) and tx_data.get('txid') == txid:
                    return block
                elif hasattr(tx_data, 'txid') and tx_data.txid == txid:
                    return block
        return None
    
    def add_transaction(self, transaction: Transaction, allow_orphan: bool = False) -> Tuple[bool, str]:
        """
        Add a new transaction to the mempool.
        
        Args:
            transaction: The transaction to add
            allow_orphan: Whether to allow orphan transactions (missing inputs)
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        # Check if transaction already exists
        if transaction.txid in self.mempool or transaction.txid in self.orphan_txs:
            return False, "Transaction already in mempool"
        
        # Basic transaction validation
        try:
            # Verify transaction structure
            if not transaction.verify():
                return False, "Invalid transaction structure"
                
            # Check for double spends in mempool
            for tx_input in transaction.inputs:
                # Check if input is already spent in mempool
                for tx in self.mempool.values():
                    for input_tx in tx.inputs:
                        if input_tx.txid == tx_input.txid and input_tx.vout == tx_input.vout:
                            return False, "Double spend attempt detected"
            
            # Check if all inputs are available
            missing_inputs = []
            for tx_input in transaction.inputs:
                if tx_input.txid not in self.utxo_set or tx_input.vout not in self.utxo_set[tx_input.txid]:
                    missing_inputs.append(f"{tx_input.txid}:{tx_input.vout}")
            
            if missing_inputs and not allow_orphan:
                if len(missing_inputs) > 0:
                    return False, f"Missing inputs: {', '.join(missing_inputs[:3])}{'...' if len(missing_inputs) > 3 else ''}"
            
            # Verify transaction against UTXO set
            if not verify_transaction(transaction, self.utxo_set):
                return False, "Transaction verification failed"
            
            # If we have missing inputs but allow_orphan is True, add to orphan pool
            if missing_inputs:
                if allow_orphan:
                    self.orphan_txs[transaction.txid] = transaction
                    return True, "Orphan transaction added (missing inputs)"
                return False, f"Missing inputs: {', '.join(missing_inputs[:3])}{'...' if len(missing_inputs) > 3 else ''}
            
            # Add to mempool
            self.mempool[transaction.txid] = transaction
            
            # Process any orphan transactions that might be waiting for this one
            self._process_orphans(transaction.txid)
            
            return True, "Transaction added to mempool"
            
        except Exception as e:
            return False, f"Error processing transaction: {str(e)}"
    
    def mine_block(self, miner_address: str) -> Optional[Block]:
        """
        Mine a new block containing transactions from the mempool.
        
        Args:
            miner_address: The address of the miner who will receive the block reward
            
        Returns:
            The new block if successful, None otherwise
        """
        # Get current time for block timestamp
        current_time = int(time.time())
        
        # Get the previous block
        prev_block = self.chain[-1] if self.chain else None
        
        # Calculate the block reward (halving every 210,000 blocks)
        height = len(self.chain)
        block_reward = self._get_block_reward(height)
        
        # Select transactions from mempool (prioritize by fee rate)
        selected_txs = self._select_transactions()
        
        # Create coinbase transaction
        coinbase_tx = create_coinbase_transaction(
            address=miner_address,
            value=block_reward,
            height=height
        )
        
        # Add coinbase as first transaction
        block_transactions = [coinbase_tx] + selected_txs
        
        # Calculate merkle root
        tx_hashes = [tx.txid for tx in block_transactions]
        merkle_root = self._calculate_merkle_root(tx_hashes)
        
        # Create a new block
        new_block = Block(
            version=BLOCK_VERSION,
            previous_hash=prev_block.hash if prev_block else '0' * 64,
            merkle_root=merkle_root,
            timestamp=current_time,
            bits=self.difficulty_bits,
            nonce=0,
            transactions=[tx.to_dict() for tx in block_transactions],
            height=height
        )
        
        # Mine the block (find a valid nonce)
        target = self._bits_to_target(self.difficulty_bits)
        new_block.mine(target)
        
        # Add the block to the blockchain
        success, message = self.add_block(new_block)
        
        if success:
            # Remove included transactions from mempool
            for tx in selected_txs:
                if tx.txid in self.mempool:
                    del self.mempool[tx.txid]
            
            # Save the updated chain state
            self._save_chain_state()
            
            return new_block
        
        return None
    
    def _select_transactions(self) -> List[Transaction]:
        """Select transactions from mempool to include in the next block."""
        # Sort transactions by fee rate (highest first)
        sorted_txs = sorted(
            self.mempool.values(),
            key=lambda tx: self._calculate_fee_rate(tx),
            reverse=True
        )
        
        selected_txs = []
        block_size = 0
        
        # Simple selection algorithm: take transactions in order of fee rate until block is full
        for tx in sorted_txs:
            # Estimate transaction size (in bytes)
            tx_size = len(tx.serialize())
            
            # Check if adding this transaction would exceed the block size limit
            if block_size + tx_size > self.max_block_size:
                continue
            
            # Add transaction to block
            selected_txs.append(tx)
            block_size += tx_size
            
            # Don't include too many transactions
            if len(selected_txs) >= 2000:  # Reasonable limit
                break
        
        return selected_txs
    
    def _calculate_fee_rate(self, tx: Transaction) -> float:
        """Calculate the fee rate (satoshis per byte) for a transaction."""
        # Calculate transaction size in bytes
        tx_size = len(tx.serialize())
        if tx_size == 0:
            return 0.0
        
        # Calculate total input value
        input_value = 0
        for tx_input in tx.inputs:
            if tx_input.txid in self.utxo_set and tx_input.vout in self.utxo_set[tx_input.txid]:
                input_value += self.utxo_set[tx_input.txid][tx_input.vout].value
        
        # Calculate total output value
        output_value = sum(output.value for output in tx.outputs)
        
        # Calculate fee and fee rate
        fee = input_value - output_value
        return fee / tx_size if fee > 0 else 0.0
    
    def _get_block_reward(self, height: int) -> int:
        """Calculate the block reward for a given block height."""
        # Initial block reward (50 BXA in satoshis)
        reward = 50 * 100_000_000
        
        # Halve the reward every 210,000 blocks (approximately every 4 years)
        halvings = height // 210000
        
        # If we've had more than 64 halvings, the reward is 0
        if halvings >= 64:
            return 0
        
        # Right shift to divide by 2 for each halving
        return reward >> halvings
    
    def _calculate_merkle_root(self, tx_hashes: List[str]) -> str:
        """Calculate the merkle root from a list of transaction hashes."""
        if not tx_hashes:
            return '0' * 64
            
        # Convert hex hashes to binary
        hashes = [bytes.fromhex(txid)[::-1] for txid in tx_hashes]
        
        while len(hashes) > 1:
            # If odd number of hashes, duplicate the last one
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])
            
            new_hashes = []
            
            # Process pairs of hashes
            for i in range(0, len(hashes), 2):
                # Concatenate the two hashes
                concat = hashes[i] + hashes[i+1]
                # Double SHA-256 hash
                new_hash = hashlib.sha256(hashlib.sha256(concat).digest()).digest()
                new_hashes.append(new_hash)
            
            hashes = new_hashes
        
        # Convert back to hex (little-endian)
        return hashes[0][::-1].hex()
    
    def _bits_to_target(self, bits: int) -> int:
        """Convert compact bits to target value."""
        # Extract exponent and coefficient from bits
        exponent = bits >> 24
        coefficient = bits & 0x007fffff
        
        # Calculate target
        if exponent <= 3:
            target = coefficient >> (8 * (3 - exponent))
        else:
            target = coefficient << (8 * (exponent - 3))
        
        return target
    
    def add_block(self, block: Block) -> Tuple[bool, str]:
        """
        Add a new block to the blockchain.
        
        Args:
            block: The block to add
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        try:
            # Check if block already exists
            if block.hash in self.block_index:
                return False, "Block already exists"
            
            # Verify block structure and proof of work
            if not block.verify():
                return False, "Invalid block structure or proof of work"
            
            # Check previous block hash
            if block.previous_hash != (self.chain[-1].hash if self.chain else '0' * 64):
                return False, "Invalid previous block hash"
            
            # Verify block timestamp
            current_time = int(time.time())
            if block.timestamp > current_time + 2 * 60 * 60:  # 2 hours in future
                return False, "Block timestamp too far in the future"
            
            # Verify transactions
            if not self._verify_block_transactions(block):
                return False, "Invalid transactions in block"
            
            # Add to blockchain
            self.chain.append(block)
            self.block_index[block.hash] = block
            
            # Update UTXO set
            self._update_utxo_set(block)
            
            # Update best block
            self.best_block_hash = block.hash
            self.chain_tip = block
            
            # Process any orphan blocks that might be waiting for this one
            self._process_orphan_blocks(block.hash)
            
            return True, "Block added successfully"
            
        except Exception as e:
            return False, f"Error adding block: {str(e)}"
    
    def _verify_block_transactions(self, block: Block) -> bool:
        """Verify all transactions in a block."""
        # First transaction must be coinbase
        if not block.transactions or not block.transactions[0].get('is_coinbase', False):
            return False
        
        # Check transaction merkle root
        tx_hashes = [tx.get('txid', '') for tx in block.transactions]
        calculated_root = self._calculate_merkle_root(tx_hashes)
        if calculated_root != block.merkle_root:
            return False
        
        # Verify each transaction
        for tx_data in block.transactions:
            tx = Transaction.from_dict(tx_data)
            
            # Skip coinbase transaction for now
            if tx.is_coinbase:
                continue
            
            # Verify transaction
            if not verify_transaction(tx, self.utxo_set):
                return False
            
            # Check for double spends
            for tx_input in tx.inputs:
                if tx_input.txid not in self.utxo_set or tx_input.vout not in self.utxo_set[tx_input.txid]:
                    return False
        
        return True
    
    def _process_orphan_blocks(self, new_block_hash: str) -> None:
        """Process any orphan blocks that might be waiting for this block."""
        # This would be implemented to handle orphan blocks
        pass
    
    def _process_orphans(self, new_txid: str) -> None:
        """Process any orphan transactions that might be waiting for this transaction."""
        # This would be implemented to handle orphan transactions
        pass
    
    def get_block_by_hash(self, block_hash: str) -> Optional[Block]:
        """
        Get a block by its hash.
        
        Args:
            block_hash: The hash of the block to retrieve
            
        Returns:
            The block if found, None otherwise
        """
        return self.block_index.get(block_hash)
    
    def get_block_by_height(self, height: int) -> Optional[Block]:
        """
        Get a block by its height.
        
        Args:
            height: The height of the block to retrieve
            
        Returns:
            The block if found, None otherwise
        """
        if 0 <= height < len(self.chain):
            return self.chain[height]
        return None
    
    def get_transaction(self, txid: str) -> Optional[Dict[str, Any]]:
        """
        Get a transaction by its ID.
        
        Args:
            txid: The transaction ID to look up
            
        Returns:
            The transaction data if found, None otherwise
        """
        # Check mempool first
        if txid in self.mempool:
            return self.mempool[txid].to_dict()
        
        # Check blockchain
        for block in reversed(self.chain):
            for tx_data in block.transactions:
                if isinstance(tx_data, dict) and tx_data.get('txid') == txid:
                    return tx_data
                elif hasattr(tx_data, 'txid') and tx_data.txid == txid:
                    return tx_data.to_dict()
        
        return None
    
    def get_chain_length(self) -> int:
        """Get the length of the blockchain."""
        return len(self.chain)
    
    def get_difficulty(self) -> float:
        """Get the current proof-of-work difficulty."""
        if not self.chain:
            return 1.0
            
        # Calculate difficulty from bits
        target = self._bits_to_target(self.chain[-1].bits)
        if target == 0:
            return float('inf')
            
        # Difficulty is (max target) / (current target)
        max_target = 0x00000000ffff0000000000000000000000000000000000000000000000000000
        return float(max_target) / target


def get_blockchain() -> Blockchain:
    """Get or create a blockchain instance."""
    if not hasattr(get_blockchain, '_instance'):
        get_blockchain._instance = Blockchain()
    return get_blockchain._instance
