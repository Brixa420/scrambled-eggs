""
Clippy Miner and Validator Service

This module integrates Brixa mining and validation capabilities into Clippy,
turning it into a full blockchain node that can participate in consensus.
"""
import asyncio
import logging
from typing import Dict, Optional, List, Tuple
from decimal import Decimal
from datetime import datetime, timedelta

from app.services.blockchain.bxa_chain import BXAChain
from app.services.blockchain.validator import BXAValidator
from app.core.config import settings
from app.models.clippy import ClippyNode

logger = logging.getLogger(__name__)

class ClippyMinerValidator:
    """
    Service that enables Clippy to function as both a miner and validator
    in the Brixa network.
    """
    
    def __init__(self, node_id: str = "clippy-node"):
        """Initialize the Clippy miner/validator.
        
        Args:
            node_id: Unique identifier for this node
        """
        self.node_id = node_id
        self.chain = BXAChain(node_id=node_id)
        self.validator = BXAValidator(self.chain)
        self.is_mining = False
        self.is_validating = False
        self.mining_task = None
        self.validation_task = None
        self.node_info = ClippyNode(
            node_id=node_id,
            is_miner=False,
            is_validator=False,
            last_active=datetime.utcnow(),
            status="inactive",
            version=settings.APP_VERSION
        )
    
    async def start_mining(self, wallet_address: str) -> bool:
        """Start the mining process.
        
        Args:
            wallet_address: Address to receive mining rewards
            
        Returns:
            bool: True if mining started successfully
        """
        if self.is_mining:
            logger.warning("Mining is already running")
            return False
            
        self.is_mining = True
        self.node_info.is_miner = True
        self.node_info.status = "mining"
        
        # Start mining in the background
        self.mining_task = asyncio.create_task(self._mine_blocks(wallet_address))
        logger.info(f"Mining started on node {self.node_id}")
        return True
    
    async def stop_mining(self) -> None:
        """Stop the mining process."""
        self.is_mining = False
        self.node_info.is_miner = False
        self.node_info.status = "active" if self.is_validating else "inactive"
        
        if self.mining_task and not self.mining_task.done():
            self.mining_task.cancel()
            try:
                await self.mining_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Mining stopped")
    
    async def start_validating(self, wallet_address: str, stake_amount: Decimal) -> bool:
        """Start the validation process.
        
        Args:
            wallet_address: Address of the validator (must match the staked address)
            stake_amount: Amount of BXA to stake (must be >= minimum stake)
            
        Returns:
            bool: True if validation started successfully
        """
        if self.is_validating:
            logger.warning("Validation is already running")
            return False
            
        # Register as a validator
        success = self.validator.register_validator(
            address=wallet_address,
            stake_amount=stake_amount
        )
        
        if not success:
            logger.error("Failed to register as validator")
            return False
            
        self.is_validating = True
        self.node_info.is_validator = True
        self.node_info.status = "validating" if not self.is_mining else "mining_and_validating"
        
        # Start validation in the background
        self.validation_task = asyncio.create_task(self._validate_blocks())
        logger.info(f"Validation started on node {self.node_id}")
        return True
    
    async def stop_validating(self) -> None:
        """Stop the validation process and unregister as a validator."""
        self.is_validating = False
        self.node_info.is_validator = False
        self.node_info.status = "mining" if self.is_mining else "inactive"
        
        # Unregister as a validator
        self.validator.unregister_validator(self.node_info.wallet_address)
        
        if self.validation_task and not self.validation_task.done():
            self.validation_task.cancel()
            try:
                await self.validation_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Validation stopped")
    
    async def _mine_blocks(self, wallet_address: str) -> None:
        """Background task to mine new blocks."""
        while self.is_mining:
            try:
                # Check if we're still supposed to be mining
                if not self.is_mining:
                    break
                    
                # Mine a new block
                new_block = self.chain.mine_pending_transactions(miner_address=wallet_address)
                
                if new_block:
                    logger.info(f"Mined new block: {new_block.hash}")
                    
                    # If we're also validating, process the new block
                    if self.is_validating:
                        await self._process_new_block(new_block)
                
                # Small delay to prevent 100% CPU usage
                await asyncio.sleep(0.1)
                
            except asyncio.CancelledError:
                logger.info("Mining task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in mining task: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _validate_blocks(self) -> None:
        """Background task to validate new blocks and participate in consensus."""
        while self.is_validating:
            try:
                # Check if we're still supposed to be validating
                if not self.is_validating:
                    break
                
                # Get the latest block
                latest_block = self.chain.get_latest_block()
                
                # Validate the latest block
                is_valid = self.validator.validate_block(latest_block)
                
                if not is_valid:
                    logger.warning(f"Invalid block detected: {latest_block.hash}")
                    # In a real implementation, we would handle this by forking or other consensus mechanisms
                
                # Small delay to prevent 100% CPU usage
                await asyncio.sleep(1)
                
            except asyncio.CancelledError:
                logger.info("Validation task cancelled")
                break
            except Exception as e:
                logger.error(f"Error in validation task: {e}")
                await asyncio.sleep(5)  # Wait before retrying
    
    async def _process_new_block(self, block: dict) -> None:
        """Process a newly mined block.
        
        Args:
            block: The newly mined block
        """
        # In a real implementation, this would broadcast the block to the network
        # and update the local blockchain state
        logger.debug(f"Processing new block: {block.hash}")
    
    def get_node_info(self) -> dict:
        """Get information about this node.
        
        Returns:
            dict: Node information
        """
        self.node_info.last_active = datetime.utcnow()
        self.node_info.peer_count = len(self.chain.nodes) if hasattr(self.chain, 'nodes') else 0
        self.node_info.block_height = len(self.chain.chain) if hasattr(self.chain, 'chain') else 0
        
        return self.node_info.dict()
    
    async def stop(self) -> None:
        """Stop all mining and validation processes."""
        if self.is_mining:
            await self.stop_mining()
        if self.is_validating:
            await self.stop_validating()
        
        logger.info("Clippy miner/validator stopped")
