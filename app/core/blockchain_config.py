"""
Configuration for the Brixa blockchain integration.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any


@dataclass
class BlockchainConfig:
    """Blockchain configuration settings."""
    
    # Mining settings
    enable_mining: bool = False
    miner_address: Optional[str] = None
    mining_threads: int = 1
    mining_difficulty: int = 4  # Number of leading zeros required in block hash
    mining_reward: float = 50.0  # BXA per block
    
    # Validation settings
    enable_validation: bool = False
    validator_address: Optional[str] = None
    minimum_stake: float = 1000.0  # Minimum BXA required to become a validator
    
    # Network settings
    bootstrap_nodes: list[str] = field(default_factory=lambda: [
        "brixa-node1.scrambled-eggs.dev:8333",
        "brixa-node2.scrambled-eggs.dev:8333"
    ])
    
    # Storage settings
    blockchain_data_dir: str = str(Path.home() / ".scrambled-eggs" / "blockchain")
    
    # Transaction settings
    transaction_fee: float = 0.001  # BXA per transaction
    max_transaction_size: int = 100 * 1024  # 100KB
    
    # Consensus settings
    block_time_target: int = 300  # 5 minutes in seconds
    
    # RPC settings
    enable_rpc: bool = True
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 8332
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            "enable_mining": self.enable_mining,
            "miner_address": self.miner_address,
            "mining_threads": self.mining_threads,
            "mining_difficulty": self.mining_difficulty,
            "mining_reward": self.mining_reward,
            "enable_validation": self.enable_validation,
            "validator_address": self.validator_address,
            "minimum_stake": self.minimum_stake,
            "bootstrap_nodes": self.bootstrap_nodes,
            "blockchain_data_dir": self.blockchain_data_dir,
            "transaction_fee": self.transaction_fee,
            "max_transaction_size": self.max_transaction_size,
            "block_time_target": self.block_time_target,
            "enable_rpc": self.enable_rpc,
            "rpc_host": self.rpc_host,
            "rpc_port": self.rpc_port,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BlockchainConfig':
        """Create configuration from dictionary."""
        config = cls()
        for key, value in data.items():
            if hasattr(config, key):
                setattr(config, key, value)
        return config


# Global blockchain config instance
_blockchain_config: Optional[BlockchainConfig] = None


def get_blockchain_config() -> BlockchainConfig:
    """Get or create the global blockchain configuration."""
    global _blockchain_config
    if _blockchain_config is None:
        _blockchain_config = BlockchainConfig()
    return _blockchain_config


def init_blockchain_config(**kwargs) -> None:
    """Initialize the global blockchain configuration."""
    global _blockchain_config
    _blockchain_config = BlockchainConfig(**kwargs)
    
    # Ensure data directory exists
    Path(_blockchain_config.blockchain_data_dir).mkdir(parents=True, exist_ok=True)
