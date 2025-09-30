"""
Proof of Work (PoW) implementation for Brixa blockchain.
Handles mining, difficulty adjustment, and validation.
"""
import time
import threading
import queue
import logging
from typing import Optional, Tuple, List, Dict, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass
from ..block import Block
from ..transaction import Transaction, TransactionInput, TransactionOutput, create_coinbase_tx

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class MiningResult:
    """Result of a mining operation."""
    success: bool
    hash: Optional[str] = None
    nonce: Optional[int] = None
    timestamp: Optional[float] = None
    error: Optional[str] = None

class ProofOfWork:
    """Handles Proof of Work consensus mechanism for Brixa blockchain."""
    
    # Target time between blocks in seconds (2.5 minutes)
    TARGET_BLOCK_TIME = 150
    # Number of blocks between difficulty adjustments
    DIFFICULTY_ADJUSTMENT_BLOCKS = 2016  # ~3.5 weeks at 2.5 min/block
    # Maximum target difficulty (minimum difficulty)
    MAX_TARGET = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
    # Initial block reward in BXA
    INITIAL_BLOCK_REWARD = 50 * 10**8  # 50 BXA in satoshis
    # Halving interval in blocks (~4 years at 2.5 min/block)
    HALVING_INTERVAL = 840000
    
    def __init__(self, blockchain):
        """Initialize the PoW consensus mechanism."""
        self.blockchain = blockchain
    
    def mine_block(self, 
                  block: Block, 
                  max_nonce: int = 2**32, 
                  num_threads: int = 1,
                  progress_callback: Optional[Callable[[int, float], None]] = None) -> MiningResult:
        """
        Mine a block using proof-of-work.
        
        Args:
            block: The block to mine
            max_nonce: Maximum nonce value to try before giving up
            num_threads: Number of threads to use for mining (default: 1)
            progress_callback: Optional callback function that receives (hashes_tried, hash_rate)
            
        Returns:
            MiningResult: Object containing mining result and statistics
        """
        if not block.transactions or not any(tx.get('is_coinbase', False) for tx in block.transactions):
            return MiningResult(False, error="Block must contain at least one coinbase transaction")
            
        # Calculate target from bits
        target = self.calculate_target(block.bits)
        
        # Update timestamp
        current_time = int(time.time())
        block.timestamp = current_time
        
        # If single-threaded, use the simpler implementation
        if num_threads <= 1:
            return self._mine_block_single_thread(block, target, max_nonce, progress_callback)
        else:
            return self._mine_block_multi_thread(block, target, max_nonce, num_threads, progress_callback)
    
    def _mine_block_single_thread(self, 
                               block: Block, 
                               target: int, 
                               max_nonce: int,
                               progress_callback: Optional[Callable[[int, float], None]] = None) -> MiningResult:
        """Mine a block using a single thread."""
        start_time = time.time()
        hashes = 0
        last_log_time = start_time
        
        while block.nonce < max_nonce:
            # Calculate hash
            block_hash = block.calculate_hash()
            hashes += 1
            
            # Check if hash meets target difficulty
            if int(block_hash, 16) <= target:
                end_time = time.time()
                hash_rate = hashes / (end_time - start_time) if (end_time - start_time) > 0 else 0
                logger.info(f"Block mined! Hash: {block_hash}")
                logger.info(f"Nonce: {block.nonce}, Hash rate: {hash_rate:.2f} hashes/sec")
                return MiningResult(True, hash=block_hash, nonce=block.nonce, timestamp=block.timestamp)
                
            # Update nonce
            block.nonce += 1
            
            # Periodically log progress and check for stop conditions
            current_time = time.time()
            if current_time - last_log_time >= 1.0:  # Log every second
                elapsed = current_time - start_time
                hash_rate = hashes / elapsed if elapsed > 0 else 0
                
                if progress_callback:
                    progress_callback(hashes, hash_rate)
                
                logger.debug(f"Hash rate: {hash_rate:.2f} hashes/sec, Nonce: {block.nonce}")
                last_log_time = current_time
            
            # If we've tried all nonces, update timestamp and try again
            if block.nonce >= max_nonce:
                block.timestamp = int(time.time())
                block.nonce = 0
        
        return MiningResult(False, error="Failed to find a valid nonce")
    
    def _mine_block_multi_thread(self, 
                              block: Block, 
                              target: int, 
                              max_nonce: int,
                              num_threads: int,
                              progress_callback: Optional[Callable[[int, float], None]] = None) -> MiningResult:
        """Mine a block using multiple threads."""
        result_queue = queue.Queue()
        stop_event = threading.Event()
        start_time = time.time()
        
        # Calculate nonce range per thread
        nonce_range = max_nonce // num_threads
        threads = []
        
        # Create worker threads
        for i in range(num_threads):
            start_nonce = i * nonce_range
            end_nonce = (i + 1) * nonce_range if i < num_threads - 1 else max_nonce
            
            worker = threading.Thread(
                target=self._mine_worker,
                args=(block, target, start_nonce, end_nonce, result_queue, stop_event, progress_callback)
            )
            worker.daemon = True
            threads.append(worker)
        
        # Start all threads
        for thread in threads:
            thread.start()
        
        # Wait for a result or all threads to complete
        try:
            result = result_queue.get(timeout=3600)  # 1 hour timeout
            stop_event.set()  # Signal other threads to stop
            
            # Wait for all threads to finish
            for thread in threads:
                thread.join(timeout=5.0)
            
            return result
            
        except queue.Empty:
            stop_event.set()
            for thread in threads:
                thread.join(timeout=5.0)
            
            return MiningResult(False, error="Mining timed out")
    
    def _mine_worker(self, 
                   block_template: Block, 
                   target: int, 
                   start_nonce: int, 
                   end_nonce: int, 
                   result_queue: queue.Queue,
                   stop_event: threading.Event,
                   progress_callback: Optional[Callable[[int, float], None]] = None):
        """Worker function for multi-threaded mining."""
        # Create a local copy of the block to avoid thread safety issues
        block = Block(
            version=block_template.version,
            previous_hash=block_template.previous_hash,
            merkle_root=block_template.merkle_root,
            timestamp=block_template.timestamp,
            bits=block_template.bits,
            nonce=start_nonce,
            transactions=block_template.transactions,
            height=block_template.height
        )
        
        hashes = 0
        start_time = time.time()
        last_log_time = start_time
        
        for nonce in range(start_nonce, end_nonce):
            if stop_event.is_set():
                return
                
            block.nonce = nonce
            block_hash = block.calculate_hash()
            hashes += 1
            
            # Check if hash meets target difficulty
            if int(block_hash, 16) <= target:
                result_queue.put(MiningResult(
                    success=True,
                    hash=block_hash,
                    nonce=nonce,
                    timestamp=block.timestamp
                ))
                return
            
            # Periodically log progress
            current_time = time.time()
            if current_time - last_log_time >= 1.0:  # Log every second
                elapsed = current_time - start_time
                hash_rate = hashes / elapsed if elapsed > 0 else 0
                
                if progress_callback:
                    progress_callback(hashes, hash_rate)
                
                logger.debug(f"Thread {threading.get_ident()}: {hash_rate:.2f} hashes/sec, Nonce: {nonce}")
                last_log_time = current_time
        
        # If we get here, we didn't find a valid nonce in our range
        result_queue.put(MiningResult(False, error=f"No valid nonce in range {start_nonce}-{end_nonce}"))
    
    def validate_block(self, block: Block, previous_block: Optional[Block] = None) -> Tuple[bool, str]:
        """
        Validate a block's proof-of-work and other consensus rules.
        
        Args:
            block: The block to validate
            previous_block: The previous block in the chain (optional, for additional validation)
            
        Returns:
            Tuple[bool, str]: (is_valid, error_message)
        """
        # Check block hash exists
        if not block.hash:
            return False, "Block has no hash"
            
        # Verify block hash matches header
        try:
            calculated_hash = block.calculate_hash()
            if block.hash != calculated_hash:
                return False, f"Invalid block hash. Expected {calculated_hash}, got {block.hash}"
        except Exception as e:
            return False, f"Error calculating block hash: {str(e)}"
            
        # Convert bits to target
        try:
            target = self.calculate_target(block.bits)
        except Exception as e:
            return False, f"Invalid difficulty bits: {str(e)}"
        
        # Check proof of work (hash must be below target)
        try:
            hash_int = int(block.hash, 16)
            if hash_int > target:
                return False, f"Block hash {block.hash} does not meet target difficulty"
        except (ValueError, TypeError) as e:
            return False, f"Invalid block hash format: {str(e)}"
            
        # Check timestamp is not too far in the future (2 hours)
        current_time = time.time()
        max_future_time = current_time + 2 * 60 * 60  # 2 hours in the future
        if block.timestamp > max_future_time:
            return False, f"Block timestamp {block.timestamp} is too far in the future (current time: {current_time})"
            
        # If previous block is provided, do additional validation
        if previous_block:
            # Check block timestamp is greater than previous block's timestamp
            if block.timestamp <= previous_block.timestamp:
                return False, f"Block timestamp {block.timestamp} is not greater than previous block's timestamp {previous_block.timestamp}"
                
            # Check block height is one more than previous block
            if hasattr(block, 'height') and hasattr(previous_block, 'height') and block.height != previous_block.height + 1:
                return False, f"Invalid block height. Expected {previous_block.height + 1}, got {block.height}"
            
            # Check previous hash matches
            if block.previous_hash != previous_block.hash:
                return False, f"Invalid previous hash. Expected {previous_block.hash}, got {block.previous_hash}"
        
        # Check transactions
        if not block.transactions:
            return False, "Block must contain at least one transaction (coinbase)"
            
        # First transaction must be coinbase
        if not block.transactions[0].get('is_coinbase', False):
            return False, "First transaction in block must be coinbase"
            
        # Verify merkle root
        try:
            calculated_merkle = block.calculate_merkle_root(block.transactions)
            if block.merkle_root != calculated_merkle:
                return False, f"Invalid merkle root. Expected {calculated_merkle}, got {block.merkle_root}"
        except Exception as e:
            return False, f"Error calculating merkle root: {str(e)}"
        
        # Verify coinbase transaction
        coinbase_tx = block.transactions[0]
        if not self._validate_coinbase_transaction(coinbase_tx, block.height):
            return False, "Invalid coinbase transaction"
                
        # TODO: Add more validation rules as needed (e.g., transaction validation, signature verification)
                
        return True, ""
    
    def _validate_coinbase_transaction(self, tx: Dict[str, Any], block_height: int) -> bool:
        """
        Validate a coinbase transaction.
        
        Args:
            tx: The coinbase transaction to validate
            block_height: The height of the block containing this transaction
            
        Returns:
            bool: True if the coinbase transaction is valid, False otherwise
        """
        if not tx.get('is_coinbase', False):
            return False
            
        # Coinbase transaction must have exactly one input
        if len(tx.get('inputs', [])) != 1:
            return False
            
        # Coinbase transaction input must have a special format
        coinbase_input = tx['inputs'][0]
        if coinbase_input.get('txid') != '0' * 64 or coinbase_input.get('vout') != 0xffffffff:
            return False
            
        # Coinbase script must be between 2 and 100 bytes
        script_sig = coinbase_input.get('script_sig', '')
        if not (2 <= len(script_sig) // 2 <= 100):  # Divide by 2 because it's hex-encoded
            return False
            
        # Coinbase transaction must have at least one output
        if not tx.get('outputs'):
            return False
            
        # Total output value must not exceed block reward + fees
        # Note: This is a simplified check; in a real implementation, you'd need to track fees
        block_reward = self.get_block_reward(block_height)
        total_output = sum(output.get('value', 0) for output in tx.get('outputs', []))
        
        if total_output > block_reward:  # In a real implementation, add fees to the right side
            return False
            
        return True
    
    def calculate_target(self, difficulty_bits: int) -> int:
        """
        Calculate the target from difficulty bits.
        
        Args:
            difficulty_bits: The compact representation of difficulty
            
        Returns:
            int: The target as a 256-bit integer
        """
        exponent = difficulty_bits >> 24
        coefficient = difficulty_bits & 0x007fffff
        
        if exponent <= 3:
            return coefficient >> (8 * (3 - exponent))
        else:
            return coefficient << (8 * (exponent - 3))
    
    def calculate_difficulty(self, previous_blocks: List[Block]) -> int:
        """
        Calculate the new difficulty based on previous blocks.
        Implements Bitcoin's difficulty adjustment algorithm.
        
        Args:
            previous_blocks: List of previous blocks for difficulty calculation
            
        Returns:
            int: The new difficulty in compact format (bits)
            
        Raises:
            ValueError: If previous_blocks is empty
        """
        if not previous_blocks:
            raise ValueError("Cannot calculate difficulty: no previous blocks provided")
            
        # For the first few blocks, return the minimum difficulty
        if len(previous_blocks) < 2:
            return self.bits_from_target(self.MAX_TARGET)
            
        # If we haven't reached the first adjustment interval, return the genesis difficulty
        if len(previous_blocks) < self.DIFFICULTY_ADJUSTMENT_BLOCKS:
            return previous_blocks[0].bits
            
        # Get the block at the beginning of the current adjustment period
        first_block = previous_blocks[-self.DIFFICULTY_ADJUSTMENT_BLOCKS]
        last_block = previous_blocks[-1]
        
        # Calculate the actual time taken for the last DIFFICULTY_ADJUSTMENT_BLOCKS
        actual_time = last_block.timestamp - first_block.timestamp
        
        # Clamp the adjustment to factor of 4 to prevent extreme changes
        actual_time = max(actual_time, self.TARGET_BLOCK_TIME * self.DIFFICULTY_ADJUSTMENT_BLOCKS // 4)
        actual_time = min(actual_time, self.TARGET_BLOCK_TIME * self.DIFFICULTY_ADJUSTMENT_BLOCKS * 4)
        
        # Calculate the new target
        old_target = self.calculate_target(last_block.bits)
        new_target = (old_target * actual_time) // (self.TARGET_BLOCK_TIME * self.DIFFICULTY_ADJUSTMENT_BLOCKS)
        
        # Clamp to minimum difficulty (maximum target)
        if new_target > self.MAX_TARGET:
            new_target = self.MAX_TARGET
            
        # Convert target back to compact format (bits)
        return self.bits_from_target(new_target)
    
    def bits_from_target(self, target: int) -> int:
        """
        Convert a target to compact bits format.
        
        Args:
            target: The target as a 256-bit integer
            
        Returns:
            int: Compact representation of the target
        """
        target = min(target, self.MAX_TARGET)
        
        # Convert to big-endian bytes
        target_bytes = target.to_bytes(32, byteorder='big')
        
        # Find first non-zero byte
        first_nonzero = 0
        while first_nonzero < 32 and target_bytes[first_nonzero] == 0:
            first_nonzero += 1
            
        if first_nonzero == 32:
            return 0
            
        # Get the first 3 significant bytes
        significant_bytes = bytearray(3)
        if first_nonzero <= 28:
            significant_bytes = target_bytes[first_nonzero:first_nonzero+3]
        else:
            significant_bytes = target_bytes[first_nonzero:29] + b'\x00' * (3 - (29 - first_nonzero))
            
        # Calculate exponent and coefficient
        exponent = 32 - first_nonzero
        coefficient = int.from_bytes(significant_bytes, byteorder='big')
        
        return (exponent << 24) | coefficient
    
    def get_block_reward(self, height: int) -> int:
        """
        Calculate the block reward for a given block height.
        
        Args:
            height: The block height
            
        Returns:
            int: The block reward in satoshis
        """
        halvings = height // self.HALVING_INTERVAL
        
        # If we've had more than 64 halvings, reward is 0
        if halvings >= 64:
            return 0
            
        # Calculate reward after halvings
        reward = self.INITIAL_BLOCK_REWARD
        reward >>= halvings  # Divide by 2 for each halving
        
        return reward
    
    def create_coinbase_transaction(self, miner_address: str, height: int, fees: int = 0) -> Transaction:
        """
        Create a coinbase transaction for a new block.
        
        Args:
            miner_address: The address to receive the block reward
            height: The block height
            fees: Total fees from transactions in the block
            
        Returns:
            Transaction: The coinbase transaction
        """
        reward = self.get_block_reward(height) + fees
        return create_coinbase_tx(miner_address, reward, height)
    
    def validate_timestamp(self, block: Block, previous_block: Block) -> bool:
        """
        Validate the block timestamp.
        
        Args:
            block: The block to validate
            previous_block: The previous block in the chain
            
        Returns:
            bool: True if timestamp is valid, False otherwise
        """
        current_time = int(time.time())
        
        # Block timestamp must not be more than 2 hours in the future
        if block.timestamp > current_time + 7200:
            return False
            
        # Block timestamp must be greater than the median of the last 11 blocks
        return block.timestamp > self.get_median_time_past(previous_block)
    
    def get_median_time_past(self, block: Block, num_blocks: int = 11) -> int:
        """
        Calculate the median time past of the last N blocks.
        
        Args:
            block: The current block
            num_blocks: Number of blocks to consider
            
        Returns:
            int: The median timestamp of the last N blocks
        """
        # Get the last N blocks (including the current one)
        timestamps = []
        current = block
        
        for _ in range(num_blocks):
            timestamps.append(current.timestamp)
            if not hasattr(current, 'previous_hash') or not current.previous_hash:
                break
            # In a real implementation, we'd get the previous block from the blockchain
            # For now, we'll just return the current block's timestamp
            break
            
        # Sort the timestamps and return the median
        timestamps.sort()
        return timestamps[len(timestamps) // 2]
