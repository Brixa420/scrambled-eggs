"""
Brixa (BXA) Tokenomics

This module defines the tokenomics for the Brixa cryptocurrency (BXA),
modeled after Bitcoin's tokenomics with a fixed supply and halving schedule.
"""
from decimal import Decimal, getcontext
from datetime import datetime, timedelta
import math

# Set decimal precision
getcontext().prec = 20

# Constants
TOTAL_SUPPLY = 21_000_000  # 21 million BXA, same as Bitcoin
BLOCK_REWARD_START = 50  # Initial block reward in BXA
HALVING_INTERVAL = 210_000  # Halving occurs every 210,000 blocks (approx. 4 years)
BLOCK_TIME = 10 * 60  # 10 minutes per block (same as Bitcoin)

# Genesis block timestamp (set to the time of network launch)
GENESIS_TIMESTAMP = datetime(2025, 10, 1, 0, 0, 0)  # Example date, update to actual launch

class BXATokenomics:
    """
    Implements Brixa's tokenomics based on Bitcoin's model.
    """
    
    @staticmethod
    def get_block_reward(block_height: int) -> Decimal:
        """
        Calculate the block reward for a given block height.
        
        Args:
            block_height: The height of the block
            
        Returns:
            The block reward in BXA
        """
        halvings = block_height // HALVING_INTERVAL
        
        # If we've had more than 64 halvings, the reward is effectively 0
        if halvings >= 64:
            return Decimal(0)
            
        # Calculate reward after halvings
        reward = Decimal(BLOCK_REWARD_START) / (2 ** halvings)
        return reward.quantize(Decimal('1.00000000'))  # 8 decimal places
    
    @staticmethod
    def get_halving_interval() -> int:
        """Get the number of blocks between halvings"""
        return HALVING_INTERVAL
    
    @staticmethod
    def get_blocks_until_halving(current_block: int) -> int:
        """
        Calculate how many blocks until the next halving.
        
        Args:
            current_block: The current block height
            
        Returns:
            Number of blocks until the next halving
        """
        next_halving_block = ((current_block // HALVING_INTERVAL) + 1) * HALVING_INTERVAL
        return max(0, next_halving_block - current_block)
    
    @staticmethod
    def get_halving_date(current_block: int) -> datetime:
        """
        Estimate the date of the next halving.
        
        Args:
            current_block: The current block height
            
        Returns:
            Estimated datetime of the next halving
        """
        blocks_until_halving = BXATokenomics.get_blocks_until_halving(current_block)
        minutes_until_halving = blocks_until_halving * (BLOCK_TIME / 60)  # Convert to minutes
        return datetime.utcnow() + timedelta(minutes=minutes_until_halving)
    
    @staticmethod
    def get_total_supply_after_block(block_height: int) -> Decimal:
        """
        Calculate the total supply after a given block height.
        
        Args:
            block_height: The block height to calculate supply for
            
        Returns:
            Total supply in BXA after the given block
        """
        total = Decimal(0)
        halving = 0
        remaining_blocks = block_height
        
        while remaining_blocks > 0:
            blocks_this_halving = min(remaining_blocks, HALVING_INTERVAL)
            reward = Decimal(BLOCK_REWARD_START) / (2 ** halving)
            total += blocks_this_halving * reward
            remaining_blocks -= blocks_this_halving
            halving += 1
            
            # After 64 halvings, block reward is effectively 0
            if halving >= 64:
                break
                
        return total.quantize(Decimal('1.00000000'))
    
    @staticmethod
    def get_circulating_supply(current_block: int) -> Decimal:
        """
        Get the current circulating supply.
        
        Args:
            current_block: The current block height
            
        Returns:
            Current circulating supply in BXA
        """
        return BXATokenomics.get_total_supply_after_block(current_block)
    
    @staticmethod
    def get_inflation_rate(current_block: int) -> Decimal:
        """
        Calculate the current annual inflation rate.
        
        Args:
            current_block: The current block height
            
        Returns:
            Annual inflation rate as a percentage (e.g., 1.75 for 1.75%)
        """
        blocks_per_year = (365 * 24 * 60) / (BLOCK_TIME / 60)  # Blocks per year
        current_supply = BXATokenomics.get_circulating_supply(current_block)
        
        if current_supply == 0:
            return Decimal('0')
            
        block_reward = BXATokenomics.get_block_reward(current_block)
        annual_inflation = (block_reward * blocks_per_year) / current_supply * 100
        
        return annual_inflation.quantize(Decimal('0.01'))
    
    @staticmethod
    def get_halving_count(block_height: int) -> int:
        """
        Get the number of halvings that have occurred by a given block height.
        
        Args:
            block_height: The block height
            
        Returns:
            Number of halvings that have occurred
        """
        return min(block_height // HALVING_INTERVAL, 64)
    
    @classmethod
    def get_tokenomics_summary(cls, current_block: int) -> dict:
        """
        Get a summary of the current tokenomics.
        
        Args:
            current_block: The current block height
            
        Returns:
            Dictionary with tokenomics summary
        """
        return {
            "total_supply": float(TOTAL_SUPPLY),
            "circulating_supply": float(cls.get_circulating_supply(current_block)),
            "block_reward": float(cls.get_block_reward(current_block)),
            "blocks_until_halving": cls.get_blocks_until_halving(current_block),
            "next_halving_date": cls.get_halving_date(current_block).isoformat(),
            "current_halving": cls.get_halving_count(current_block),
            "inflation_rate": float(cls.get_inflation_rate(current_block)),
            "block_time_seconds": BLOCK_TIME,
            "halving_interval_blocks": HALVING_INTERVAL,
            "blocks_per_day": (24 * 60) / (BLOCK_TIME / 60),  # Blocks per day
            "blocks_per_year": (365 * 24 * 60) / (BLOCK_TIME / 60),  # Blocks per year
        }
