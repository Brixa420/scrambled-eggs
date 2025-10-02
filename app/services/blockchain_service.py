"""
Blockchain service for managing Brixa mining, validation, and network operations.
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List, Tuple

from app.blockchain import (
    BrixaMiner, 
    BrixaValidator, 
    Blockchain, 
    get_blockchain,
    Wallet,
    Network
)
from app.core.blockchain_config import get_blockchain_config
from app.blockchain.transaction import Transaction, TransactionInput, TransactionOutput

logger = logging.getLogger(__name__)


class BlockchainService:
    """Service for managing Brixa blockchain operations."""
    
    def __init__(self):
        """Initialize the blockchain service."""
        self.config = get_blockchain_config()
        self.blockchain: Optional[Blockchain] = None
        self.miner: Optional[BrixaMiner] = None
        self.validator: Optional[BrixaValidator] = None
        self.wallet: Optional[Wallet] = None
        self.network: Optional[Network] = None
        self._mining_task: Optional[asyncio.Task] = None
        self._validation_task: Optional[asyncio.Task] = None
        self._network_task: Optional[asyncio.Task] = None
    
    async def initialize(self) -> None:
        """Initialize the blockchain service."""
        try:
            # Initialize blockchain
            self.blockchain = get_blockchain()
            
            # Initialize wallet
            self.wallet = Wallet()
            if self.config.wallet_file and self.config.wallet_password:
                self.wallet = Wallet.load_from_file(
                    self.config.wallet_file, 
                    self.config.wallet_password
                )
            
            if not self.wallet or not self.wallet.address:
                logger.warning("No wallet loaded, generating a new one")
                self.wallet, _ = create_wallet()
                if self.config.wallet_file and self.config.wallet_password:
                    self.wallet.save_to_file(
                        self.config.wallet_file,
                        self.config.wallet_password
                    )
            
            logger.info(f"Initialized wallet with address: {self.wallet.address}")
            
            # Initialize network
            self.network = Network(
                host=self.config.p2p_host,
                port=self.config.p2p_port
            )
            
            # Add bootstrap nodes
            for node in self.config.bootstrap_nodes:
                host, port = node.split(':')
                self.network.known_peers.add((host, int(port)))
            
            # Start network
            await self.network.start()
            self._network_task = asyncio.create_task(self._network_loop())
            
            # Initialize miner if enabled
            if self.config.enable_mining and self.wallet.address:
                self.miner = BrixaMiner(self.blockchain, self.wallet.address)
                logger.info(f"Initialized Brixa miner with address: {self.wallet.address}")
            
            # Initialize validator if enabled
            if self.config.enable_validation and self.wallet.address:
                self.validator = BrixaValidator(self.blockchain, self.wallet.address)
                logger.info(f"Initialized Brixa validator with address: {self.wallet.address}")
            
            logger.info("Blockchain service initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize blockchain service: {e}", exc_info=True)
            raise
    
    async def start(self) -> None:
        """Start the blockchain service."""
        try:
            if not self.network or not self.network.running:
                await self.network.start()
                
            if self.miner and self.config.enable_mining:
                self._mining_task = asyncio.create_task(self._mining_loop())
                logger.info("Started mining")
                
            if self.validator and self.config.enable_validation:
                self._validation_task = asyncio.create_task(self._validation_loop())
                logger.info("Started validation")
                
            logger.info("Blockchain service started successfully")
                
        except Exception as e:
            logger.error(f"Failed to start blockchain service: {e}", exc_info=True)
            raise
    
    async def stop(self) -> None:
        """Stop the blockchain service."""
        try:
            if self._mining_task:
                self._mining_task.cancel()
                try:
                    await self._mining_task
                except asyncio.CancelledError:
                    pass
                self._mining_task = None
                
            if self._validation_task:
                self._validation_task.cancel()
                try:
                    await self._validation_task
                except asyncio.CancelledError:
                    pass
                self._validation_task = None
                
            if self._network_task:
                self._network_task.cancel()
                try:
                    await self._network_task
                except asyncio.CancelledError:
                    pass
                self._network_task = None
                
            if self.network:
                await self.network.stop()
                
            logger.info("Blockchain service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping blockchain service: {e}", exc_info=True)
            raise
    
    async def _mining_loop(self) -> None:
        """Mining loop for the blockchain service."""
        while True:
            try:
                if self.miner and self.blockchain:
                    await asyncio.sleep(10)  # Mine a block every 10 seconds
                    block = await self.miner.mine_block()
                    if block:
                        logger.info(f"Mined new block: {block.hash}")
                        # Broadcast the new block to the network
                        if self.network:
                            await self.network.broadcast_block(block.to_dict())
            except asyncio.CancelledError:
                logger.info("Mining loop cancelled")
                raise
            except Exception as e:
                logger.error(f"Error in mining loop: {e}", exc_info=True)
                await asyncio.sleep(10)  # Wait before retrying
    
    async def _validation_loop(self) -> None:
        """Validation loop for the blockchain service."""
        while True:
            try:
                if self.validator:
                    await asyncio.sleep(30)  # Validate every 30 seconds
                    is_valid = await self.validator.validate_chain()
                    if not is_valid:
                        logger.warning("Blockchain validation failed!")
                        # In a real implementation, you would trigger recovery logic here
            except asyncio.CancelledError:
                logger.info("Validation loop cancelled")
                raise
            except Exception as e:
                logger.error(f"Error in validation loop: {e}", exc_info=True)
                await asyncio.sleep(30)  # Wait before retrying
                
    async def _network_loop(self) -> None:
        """Network loop for handling incoming messages."""
        while True:
            try:
                # In a real implementation, you would process network messages here
                await asyncio.sleep(10)
            except asyncio.CancelledError:
                logger.info("Network loop cancelled")
                raise
            except Exception as e:
                logger.error(f"Error in network loop: {e}", exc_info=True)
                await asyncio.sleep(10)  # Wait before retrying
    
    async def create_transaction(
        self, 
        recipient: str, 
        amount: int, 
        fee: int = 1000
    ) -> Optional[Dict[str, Any]]:
        """
        Create a new transaction.
        
        Args:
            recipient: Recipient address
            amount: Amount to send in satoshis
            fee: Transaction fee in satoshis
            
        Returns:
            Transaction data if successful, None otherwise
        """
        if not self.wallet or not self.blockchain:
            return None
            
        # Get unspent transaction outputs
        utxos = self._get_utxos_for_address(self.wallet.address, amount + fee)
        if not utxos:
            logger.error("Insufficient balance")
            return None
            
        # Create transaction inputs
        inputs = []
        total_input = 0
        
        for txid, vout, value in utxos:
            inputs.append(transactionInput(
                txid=txid,
                vout=vout,
                script_sig=f""  # Will be signed later
            ))
            total_input += value
            if total_input >= amount + fee:
                break
                
        # Create transaction outputs
        outputs = [
            TransactionOutput(
                value=amount,
                script_pubkey=f"OP_DUP OP_HASH160 {recipient} OP_EQUALVERIFY OP_CHECKSIG",
                address=recipient
            )
        ]
        
        # Add change output if needed
        change = total_input - amount - fee
        if change > 0:
            outputs.append(transactionOutput(
                value=change,
                script_pubkey=f"OP_DUP OP_HASH160 {self.wallet.address} OP_EQUALVERIFY OP_CHECKSIG",
                address=self.wallet.address
            ))
        
        # Create and sign the transaction
        tx = Transaction(inputs=inputs, outputs=outputs)
        
        # Sign the transaction
        tx_data = tx.to_dict()
        signature = self.wallet.sign_transaction(tx_data)
        
        # Add signature to inputs
        for tx_input in tx.inputs:
            tx_input.script_sig = signature
            
        # Verify the transaction
        if not tx.verify():
            logger.error("Failed to verify transaction")
            return None
            
        # Add to mempool
        if not self.blockchain.add_transaction(tx):
            logger.error("Failed to add transaction to mempool")
            return None
            
        # Broadcast the transaction
        if self.network:
            await self.network.broadcast_transaction(tx.to_dict())
            
        return tx.to_dict()
    
    def _get_utxos_for_address(self, address: str, amount: int) -> List[Tuple[str, int, int]]:
        """
        Get unspent transaction outputs for an address.
        
        Args:
            address: Address to get UTXOs for
            amount: Minimum total amount needed
            
        Returns:
            List of (txid, vout, value) tuples
        """
        if not self.blockchain:
            return []
            
        utxos = []
        total = 0
        
        # In a real implementation, you would query the UTXO set
        # This is a simplified version that just returns dummy data
        # Replace this with actual UTXO lookup logic
        
        # Example dummy data - remove in production
        if address == self.wallet.address:
            utxos = [
                ("dummy_txid_1", 0, 50000000),  # 0.5 BXA
                ("dummy_txid_2", 1, 250000000), # 2.5 BXA
            ]
        
        # Filter and sort UTXOs by value (smallest first)
        utxos = sorted(utxos, key=lambda x: x[2])
        
        # Select UTXOs until we have enough
        selected_utxos = []
        for txid, vout, value in utxos:
            selected_utxos.append((txid, vout, value))
            total += value
            if total >= amount:
                break
                
        return selected_utxos if total >= amount else []
    
    def get_balance(self, address: Optional[str] = None) -> int:
        """
        Get the balance for an address.
        
        Args:
            address: Address to get balance for (default: wallet address)
            
        Returns:
            Balance in satoshis
        """
        if not address and self.wallet:
            address = self.wallet.address
            
        if not address or not self.blockchain:
            return 0
            
        return self.blockchain.get_balance(address)
                "reward": self.config.mining_reward,
            },
            "validation": {
                "enabled": self.validator is not None,
                "validator_address": self.config.validator_address if self.validator else None,
                "minimum_stake": self.config.minimum_stake,
            },
            "blockchain": {
                "block_height": len(self.blockchain.chain) if self.blockchain else 0,
                "pending_transactions": len(self.blockchain.pending_memories) if self.blockchain else 0,
                "network_nodes": len(self.config.bootstrap_nodes) if self.blockchain else 0,
            },
        }
