""
Clippy Node Models

This module defines the data models for the Clippy miner and validator node.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

class ClippyNode(BaseModel):
    """Model representing a Clippy node in the Brixa network."""
    
    # Core node information
    node_id: str = Field(..., description="Unique identifier for this node")
    version: str = Field(..., description="Version of the node software")
    status: str = Field("inactive", description="Current status of the node")
    last_active: datetime = Field(default_factory=datetime.utcnow, description="When the node was last active")
    
    # Node capabilities
    is_miner: bool = Field(False, description="Whether this node is currently mining")
    is_validator: bool = Field(False, description="Whether this node is currently validating")
    
    # Network information
    peer_count: int = Field(0, description="Number of connected peers")
    block_height: int = Field(0, description="Current block height")
    
    # Mining statistics
    hash_rate: Optional[float] = Field(None, description="Current hash rate in hashes/second")
    total_mined: int = Field(0, description="Total number of blocks mined")
    
    # Validation statistics
    total_validated: int = Field(0, description="Total number of blocks validated")
    validation_accuracy: float = Field(1.0, description="Validation accuracy score (0.0 to 1.0)")
    
    # Staking information
    staked_amount: float = Field(0.0, description="Amount of BXA staked")
    staking_rewards: float = Field(0.0, description="Total staking rewards earned")
    
    # System metrics
    cpu_usage: Optional[float] = Field(None, description="Current CPU usage percentage")
    memory_usage: Optional[float] = Field(None, description="Current memory usage in MB")
    uptime: float = Field(0.0, description="Uptime in seconds")
    
    # Network addresses
    p2p_address: Optional[str] = Field(None, description="P2P network address")
    rpc_address: Optional[str] = Field(None, description="RPC API address")
    
    # Node configuration
    config: Dict[str, Any] = Field(default_factory=dict, description="Node configuration")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "node_id": "clippy-node-1",
                "version": "1.0.0",
                "status": "mining_and_validating",
                "last_active": "2025-09-30T09:15:00Z",
                "is_miner": True,
                "is_validator": True,
                "peer_count": 12,
                "block_height": 15042,
                "hash_rate": 42.5,
                "total_mined": 14,
                "total_validated": 1245,
                "validation_accuracy": 0.998,
                "staked_amount": 2500.0,
                "staking_rewards": 125.75,
                "cpu_usage": 34.2,
                "memory_usage": 512.8,
                "uptime": 86400,
                "p2p_address": "/ip4/192.168.1.100/tcp/30333",
                "rpc_address": "http://localhost:9933",
                "config": {
                    "mining_threads": 4,
                    "max_peers": 50,
                    "sync_mode": "full"
                }
            }
        }


class NodeMetrics(BaseModel):
    """Model for node performance and health metrics."""
    
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When these metrics were collected")
    
    # System metrics
    cpu_usage: float = Field(..., ge=0, le=100, description="CPU usage percentage")
    memory_usage: float = Field(..., ge=0, description="Memory usage in MB")
    disk_usage: float = Field(..., ge=0, le=100, description="Disk usage percentage")
    network_in: float = Field(0.0, description="Network input in KB/s")
    network_out: float = Field(0.0, description="Network output in KB/s")
    
    # Blockchain metrics
    block_height: int = Field(..., ge=0, description="Current block height")
    peer_count: int = Field(0, ge=0, description="Number of connected peers")
    
    # Mining metrics
    is_mining: bool = Field(False, description="Whether the node is currently mining")
    hash_rate: Optional[float] = Field(None, ge=0, description="Current hash rate in H/s")
    
    # Validation metrics
    is_validating: bool = Field(False, description="Whether the node is currently validating")
    last_validated: Optional[datetime] = Field(None, description="When the last block was validated")
    
    # Error tracking
    error_count: int = Field(0, ge=0, description="Number of errors since last report")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class NodeConfig(BaseModel):
    """Configuration model for a Clippy node."""
    
    # Node identification
    node_id: str = Field(..., description="Unique identifier for this node")
    network: str = Field("mainnet", description="Network to connect to (mainnet/testnet/devnet)")
    
    # Mining configuration
    enable_mining: bool = Field(False, description="Enable mining")
    mining_threads: int = Field(1, ge=1, le=64, description="Number of mining threads to use")
    miner_address: Optional[str] = Field(None, description="Address to receive mining rewards")
    
    # Validation configuration
    enable_validation: bool = Field(False, description="Enable block validation")
    validator_address: Optional[str] = Field(None, description="Validator address")
    stake_amount: float = Field(0.0, ge=0, description="Amount of BXA to stake")
    
    # Network configuration
    p2p_port: int = Field(30333, ge=1024, le=65535, description="P2P network port")
    rpc_port: int = Field(9933, ge=1024, le=65535, description="RPC API port")
    max_peers: int = Field(25, ge=1, le=1000, description="Maximum number of peers to connect to")
    
    # Storage configuration
    data_dir: str = Field("./data", description="Directory to store blockchain data")
    
    # Logging configuration
    log_level: str = Field("INFO", description="Logging level")
    log_file: Optional[str] = Field(None, description="File to write logs to")
    
    # Performance settings
    cache_size: int = Field(256, ge=64, description="Cache size in MB")
    db_max_open_files: int = Field(64, ge=1, description="Maximum number of open database files")
    
    # API configuration
    enable_rpc: bool = Field(True, description="Enable JSON-RPC server")
    rpc_cors_domain: str = Field("*", description="Allowed CORS domains for RPC")
    
    class Config:
        schema_extra = {
            "example": {
                "node_id": "clippy-node-1",
                "network": "mainnet",
                "enable_mining": True,
                "mining_threads": 4,
                "miner_address": "BXA1aBcDeFgHiJkLmNoPqRsTuVwXyZ",
                "enable_validation": True,
                "validator_address": "BXA1aBcDeFgHiJkLmNoPqRsTuVwXyZ",
                "stake_amount": 1000.0,
                "p2p_port": 30333,
                "rpc_port": 9933,
                "max_peers": 25,
                "data_dir": "./data",
                "log_level": "INFO",
                "log_file": "clippy-node.log",
                "cache_size": 256,
                "db_max_open_files": 64,
                "enable_rpc": True,
                "rpc_cors_domain": "*"
            }
        }
