"""
Clippy Miner and Validator API Endpoints

This module provides API endpoints to control the Clippy miner and validator.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from decimal import Decimal
import asyncio

from app.services.clippy.miner_validator import ClippyMinerValidator
from app.models.clippy import NodeMetrics, NodeConfig
from app.api import deps
from app.models.user import User
from app.core.config import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

# Request/Response Models
class MiningStartRequest(BaseModel):
    """Request model for starting the miner."""
    wallet_address: str = Field(..., description="Address to receive mining rewards")
    threads: int = Field(1, ge=1, le=64, description="Number of mining threads to use")

class MiningStatusResponse(BaseModel):
    """Response model for mining status."""
    is_mining: bool
    hash_rate: Optional[float]
    total_mined: int
    current_block: int
    miner_address: Optional[str]

class ValidationStartRequest(BaseModel):
    """Request model for starting validation."""
    wallet_address: str = Field(..., description="Address to use for validation")
    stake_amount: float = Field(..., gt=0, description="Amount of BXA to stake")

class ValidationStatusResponse(BaseModel):
    """Response model for validation status."""
    is_validating: bool
    staked_amount: float
    total_validated: int
    validation_accuracy: float
    validator_address: Optional[str]

class NodeStatusResponse(BaseModel):
    """Response model for node status."""
    node_id: str
    version: str
    status: str
    is_mining: bool
    is_validating: bool
    block_height: int
    peer_count: int
    uptime: float
    network: str
    sync_status: str
    last_block_time: Optional[str]
    
# Dependencies
def get_clippy_service() -> ClippyMinerValidator:
    """Get the Clippy miner/validator service."""
    # In a real implementation, this would get the service from the app state
    # For this example, we'll create a new instance
    return ClippyMinerValidator(node_id="clippy-node-1")

# API Endpoints
@router.post("/mining/start", response_model=MiningStatusResponse)
async def start_mining(
    request: MiningStartRequest,
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """
    Start the mining process.
    
    Requires authentication and appropriate permissions.
    """
    if clippy.is_mining:
        return {
            "is_mining": True,
            "hash_rate": clippy.get_node_info().get("hash_rate"),
            "total_mined": clippy.get_node_info().get("total_mined", 0),
            "current_block": clippy.get_node_info().get("block_height", 0),
            "miner_address": request.wallet_address
        }
    
    success = await clippy.start_mining(wallet_address=request.wallet_address)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to start mining"
        )
    
    return {
        "is_mining": True,
        "hash_rate": None,  # Will be updated after some mining
        "total_mined": 0,
        "current_block": clippy.get_node_info().get("block_height", 0),
        "miner_address": request.wallet_address
    }

@router.post("/mining/stop", response_model=MiningStatusResponse)
async def stop_mining(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Stop the mining process."""
    if not clippy.is_mining:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mining is not running"
        )
    
    await clippy.stop_mining()
    
    return {
        "is_mining": False,
        "hash_rate": None,
        "total_mined": clippy.get_node_info().get("total_mined", 0),
        "current_block": clippy.get_node_info().get("block_height", 0),
        "miner_address": None
    }

@router.get("/mining/status", response_model=MiningStatusResponse)
async def get_mining_status(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Get the current mining status."""
    node_info = clippy.get_node_info()
    return {
        "is_mining": node_info.get("is_mining", False),
        "hash_rate": node_info.get("hash_rate"),
        "total_mined": node_info.get("total_mined", 0),
        "current_block": node_info.get("block_height", 0),
        "miner_address": node_info.get("miner_address")
    }

@router.post("/validation/start", response_model=ValidationStatusResponse)
async def start_validation(
    request: ValidationStartRequest,
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """
    Start the validation process.
    
    Requires a minimum stake amount and appropriate permissions.
    """
    if clippy.is_validating:
        return {
            "is_validating": True,
            "staked_amount": clippy.get_node_info().get("staked_amount", 0),
            "total_validated": clippy.get_node_info().get("total_validated", 0),
            "validation_accuracy": clippy.get_node_info().get("validation_accuracy", 1.0),
            "validator_address": request.wallet_address
        }
    
    success = await clippy.start_validating(
        wallet_address=request.wallet_address,
        stake_amount=Decimal(str(request.stake_amount))
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to start validation. Insufficient stake or already validating."
        )
    
    return {
        "is_validating": True,
        "staked_amount": request.stake_amount,
        "total_validated": 0,
        "validation_accuracy": 1.0,
        "validator_address": request.wallet_address
    }

@router.post("/validation/stop", response_model=ValidationStatusResponse)
async def stop_validation(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Stop the validation process and initiate unbonding."""
    if not clippy.is_validating:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Validation is not running"
        )
    
    await clippy.stop_validating()
    
    return {
        "is_validating": False,
        "staked_amount": 0,
        "total_validated": clippy.get_node_info().get("total_validated", 0),
        "validation_accuracy": clippy.get_node_info().get("validation_accuracy", 1.0),
        "validator_address": None
    }

@router.get("/validation/status", response_model=ValidationStatusResponse)
async def get_validation_status(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Get the current validation status."""
    node_info = clippy.get_node_info()
    return {
        "is_validating": node_info.get("is_validator", False),
        "staked_amount": node_info.get("staked_amount", 0),
        "total_validated": node_info.get("total_validated", 0),
        "validation_accuracy": node_info.get("validation_accuracy", 1.0),
        "validator_address": node_info.get("validator_address")
    }

@router.get("/status", response_model=NodeStatusResponse)
async def get_node_status(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Get the current status of the Clippy node."""
    node_info = clippy.get_node_info()
    
    return {
        "node_id": node_info.get("node_id", "clippy-node"),
        "version": node_info.get("version", "1.0.0"),
        "status": node_info.get("status", "inactive"),
        "is_mining": node_info.get("is_miner", False),
        "is_validating": node_info.get("is_validator", False),
        "block_height": node_info.get("block_height", 0),
        "peer_count": node_info.get("peer_count", 0),
        "uptime": node_info.get("uptime", 0),
        "network": "mainnet",  # Would come from config
        "sync_status": "synced" if node_info.get("is_synced", True) else "syncing",
        "last_block_time": node_info.get("last_block_time")
    }

@router.get("/metrics", response_model=NodeMetrics)
async def get_node_metrics(
    current_user: User = Depends(deps.get_current_active_user),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Get detailed metrics about the node's performance."""
    # In a real implementation, this would collect actual system metrics
    node_info = clippy.get_node_info()
    
    return {
        "cpu_usage": 15.5,  # Example value
        "memory_usage": 512.3,  # MB
        "disk_usage": 45.2,  # %
        "network_in": 125.5,  # KB/s
        "network_out": 87.3,  # KB/s
        "block_height": node_info.get("block_height", 0),
        "peer_count": node_info.get("peer_count", 0),
        "is_mining": node_info.get("is_miner", False),
        "hash_rate": node_info.get("hash_rate"),
        "is_validating": node_info.get("is_validator", False),
        "last_validated": node_info.get("last_validated"),
        "error_count": 0
    }

@router.get("/config", response_model=NodeConfig)
async def get_node_config(
    current_user: User = Depends(deps.get_current_active_admin),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Get the current node configuration."""
    node_info = clippy.get_node_info()
    
    return {
        "node_id": node_info.get("node_id", "clippy-node"),
        "network": "mainnet",
        "enable_mining": node_info.get("is_miner", False),
        "mining_threads": 4,  # Would come from config
        "miner_address": node_info.get("miner_address"),
        "enable_validation": node_info.get("is_validator", False),
        "validator_address": node_info.get("validator_address"),
        "stake_amount": node_info.get("staked_amount", 0.0),
        "p2p_port": 30333,
        "rpc_port": 9933,
        "max_peers": 25,
        "data_dir": "./data",
        "log_level": "INFO",
        "cache_size": 256,
        "db_max_open_files": 64,
        "enable_rpc": True,
        "rpc_cors_domain": "*"
    }

@router.put("/config", response_model=NodeConfig)
async def update_node_config(
    config: NodeConfig,
    current_user: User = Depends(deps.get_current_active_admin),
    clippy: ClippyMinerValidator = Depends(get_clippy_service)
):
    """Update the node configuration."""
    # In a real implementation, this would update the node's configuration
    # and potentially restart services if needed
    
    # For now, we'll just return the received config
    return config

@router.post("/restart")
async def restart_node(
    current_user: User = Depends(deps.get_current_active_admin)
):
    """Restart the Clippy node."""
    # In a real implementation, this would trigger a graceful restart
    return {"status": "restarting"}

@router.post("/shutdown")
async def shutdown_node(
    current_user: User = Depends(deps.get_current_active_admin)
):
    """Shut down the Clippy node."""
    # In a real implementation, this would trigger a graceful shutdown
    return {"status": "shutting_down"}
