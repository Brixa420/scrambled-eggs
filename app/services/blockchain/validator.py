"""
Brixa Network Validator

This module implements the network validator for the Brixa blockchain,
including staking, validation rules, and slashing conditions.
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from decimal import Decimal

from app.core.tokenomics import BXATokenomics
from .bxa_chain import BXAChain, BXABlock

logger = logging.getLogger(__name__)

@dataclass
class Validator:
    """Represents a network validator"""
    address: str
    staked_amount: Decimal
    joined_at: datetime
    last_validated: Optional[datetime] = None
    total_rewards: Decimal = Decimal('0')
    slash_count: int = 0
    is_active: bool = True
    
    def to_dict(self) -> Dict:
        """Convert validator to dictionary"""
        return {
            'address': self.address,
            'staked_amount': float(self.staked_amount),
            'joined_at': self.joined_at.isoformat(),
            'last_validated': self.last_validated.isoformat() if self.last_validated else None,
            'total_rewards': float(self.total_rewards),
            'slash_count': self.slash_count,
            'is_active': self.is_active
        }

class BXAValidator:
    """
    Handles network validation, staking, and slashing for the Brixa blockchain.
    """
    
    def __init__(self, blockchain: BXAChain):
        self.blockchain = blockchain
        self.validators: Dict[str, Validator] = {}
        self.slashing_penalty = Decimal('0.01')  # 1% slashing penalty
        self.min_stake = Decimal('1000')  # Minimum stake to become a validator
        self.unbonding_period = timedelta(days=14)  # 14-day unbonding period
        self.unbonding_requests: Dict[str, Dict] = {}  # address -> {amount, unlock_time}
        
    def register_validator(self, address: str, stake_amount: Decimal) -> bool:
        """
        Register a new validator with a stake
        
        Args:
            address: Validator's address
            stake_amount: Amount of BXA to stake
            
        Returns:
            bool: True if registration was successful
        """
        if stake_amount < self.min_stake:
            logger.warning(f"Stake amount {stake_amount} is below minimum {self.min_stake}")
            return False
            
        if address in self.validators:
            logger.warning(f"Validator {address} already registered")
            return False
            
        # In a real implementation, this would check the actual balance
        # and transfer the staked amount to the staking contract
        
        self.validators[address] = Validator(
            address=address,
            staked_amount=stake_amount,
            joined_at=datetime.utcnow()
        )
        
        logger.info(f"New validator registered: {address} with stake {stake_amount} BXA")
        return True
    
    def unregister_validator(self, address: str) -> bool:
        """
        Unregister a validator and initiate unbonding
        
        Args:
            address: Validator's address
            
        Returns:
            bool: True if unbonding was initiated
        """
        if address not in self.validators:
            logger.warning(f"Validator {address} not found")
            return False
            
        # Schedule unbonding
        unlock_time = datetime.utcnow() + self.unbonding_period
        self.unbonding_requests[address] = {
            'amount': self.validators[address].staked_amount,
            'unlock_time': unlock_time
        }
        
        # Mark as inactive
        self.validators[address].is_active = False
        
        logger.info(f"Validator {address} unregistered, unbonding until {unlock_time}")
        return True
    
    def complete_unbonding(self, address: str) -> bool:
        """
        Complete the unbonding process and return staked amount
        
        Args:
            address: Validator's address
            
        Returns:
            bool: True if unbonding was completed
        """
        if address not in self.unbonding_requests:
            logger.warning(f"No unbonding request found for {address}")
            return False
            
        request = self.unbonding_requests[address]
        
        if datetime.utcnow() < request['unlock_time']:
            logger.warning(f"Unbonding period not yet completed for {address}")
            return False
            
        # In a real implementation, this would transfer the staked amount back to the validator
        amount = request['amount']
        del self.unbonding_requests[address]
        
        if address in self.validators:
            del self.validators[address]
            
        logger.info(f"Unbonding completed for {address}, returned {amount} BXA")
        return True
    
    def validate_block(self, block: BXABlock, validator_address: str) -> bool:
        """
        Validate a new block
        
        Args:
            block: The block to validate
            validator_address: Address of the validating node
            
        Returns:
            bool: True if the block is valid
        """
        # Check if validator is registered and active
        if validator_address not in self.validators or not self.validators[validator_address].is_active:
            logger.warning(f"Unauthorized validator: {validator_address}")
            return False
            
        # Update last validated timestamp
        self.validators[validator_address].last_validated = datetime.utcnow()
        
        # Basic block validation
        if not self._validate_block_structure(block):
            return False
            
        # Verify proof of work
        if not self._validate_proof_of_work(block):
            return False
            
        # Verify transactions (simplified)
        if not self._validate_transactions(block.transactions):
            return False
            
        # Verify block reward
        if not self._validate_block_reward(block):
            return False
            
        return True
    
    def _validate_block_structure(self, block: BXABlock) -> bool:
        """Validate block structure"""
        if not block.hash or not block.previous_hash:
            return False
            
        if block.index < 0:
            return False
            
        # Verify block hash matches calculated hash
        return block.hash == block.calculate_hash()
    
    def _validate_proof_of_work(self, block: BXABlock) -> bool:
        """Validate proof of work"""
        target = '0' * self.blockchain.difficulty
        return block.hash.startswith(target)
    
    def _validate_transactions(self, transactions: List[Dict]) -> bool:
        """Validate transactions in the block (simplified)"""
        # In a real implementation, this would verify signatures, balances, etc.
        return True
    
    def _validate_block_reward(self, block: BXABlock) -> bool:
        """Validate block reward"""
        if not block.transactions:
            return False
            
        # The first transaction should be the coinbase (mining reward)
        coinbase_tx = block.transactions[0]
        
        # Calculate expected reward
        expected_reward = BXATokenomics.get_block_reward(block.index)
        
        # In a real implementation, we'd also check the fee distribution
        return coinbase_tx.get('amount') == float(expected_reward)
    
    def slash_validator(self, validator_address: str, reason: str) -> bool:
        """
        Slash a validator for misbehavior
        
        Args:
            validator_address: Address of the validator to slash
            reason: Reason for slashing
            
        Returns:
            bool: True if slashing was successful
        """
        if validator_address not in self.validators:
            logger.warning(f"Validator {validator_address} not found")
            return False
            
        validator = self.validators[validator_address]
        
        # Calculate slashing penalty
        penalty = validator.staked_amount * self.slashing_penalty
        new_stake = validator.staked_amount - penalty
        
        # Apply penalty
        validator.staked_amount = new_stake
        validator.slash_count += 1
        
        # If stake falls below minimum, deactivate validator
        if new_stake < self.min_stake:
            validator.is_active = False
            logger.warning(f"Validator {validator_address} deactivated due to low stake")
        
        logger.warning(
            f"Validator {validator_address} slashed: {penalty} BXA "
            f"(new stake: {new_stake} BXA), reason: {reason}"
        )
        
        return True
    
    def distribute_rewards(self, block: BXABlock) -> None:
        """
        Distribute staking rewards to validators
        
        Args:
            block: The block being validated
        """
        if not block.transactions:
            return
            
        # Get the block reward (first transaction is coinbase)
        coinbase_tx = block.transactions[0]
        total_reward = Decimal(str(coinbase_tx.get('amount', 0)))
        
        if total_reward <= 0:
            return
            
        # Get active validators
        active_validators = [
            v for v in self.validators.values() 
            if v.is_active and v.staked_amount >= self.min_stake
        ]
        
        if not active_validators:
            return
            
        # Calculate total stake
        total_stake = sum(v.staked_amount for v in active_validators)
        
        if total_stake <= 0:
            return
            
        # Distribute rewards proportionally to stake
        for validator in active_validators:
            # Calculate reward based on stake
            reward = (validator.staked_amount / total_stake) * total_reward
            
            # Add to validator's rewards
            validator.total_rewards += reward
            
            # In a real implementation, this would transfer the reward
            logger.info(
                f"Distributed {reward:.8f} BXA reward to validator {validator.address} "
                f"(stake: {validator.staked_amount} BXA)"
            )
    
    def get_validator_info(self, address: str) -> Optional[Dict]:
        """Get information about a validator"""
        if address not in self.validators:
            return None
            
        validator = self.validators[address]
        return validator.to_dict()
    
    def get_active_validators(self) -> List[Dict]:
        """Get list of active validators"""
        return [
            v.to_dict() 
            for v in self.validators.values() 
            if v.is_active
        ]
    
    def get_network_stats(self) -> Dict:
        """Get network statistics"""
        active_validators = [v for v in self.validators.values() if v.is_active]
        total_staked = sum(v.staked_amount for v in active_validators)
        
        return {
            'total_validators': len(self.validators),
            'active_validators': len(active_validators),
            'total_staked': float(total_staked),
            'min_stake': float(self.min_stake),
            'slashing_penalty': float(self.slashing_penalty * 100),  # as percentage
            'unbonding_period_days': self.unbonding_period.days
        }
