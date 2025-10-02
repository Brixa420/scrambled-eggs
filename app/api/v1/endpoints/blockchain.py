"""
Blockchain API endpoints for Brixa integration.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional

from app.core.blockchain_config import get_blockchain_config, init_blockchain_config
from app.services.blockchain_service import BlockchainService
from app.api.deps import get_current_active_user
from app.models.user import User

router = APIRouter()

# Global blockchain service instance
_blockchain_service: Optional[BlockchainService] = None


def get_blockchain_service() -> BlockchainService:
    """Get or create the global blockchain service instance."""
    global _blockchain_service
    if _blockchain_service is None:
        _blockchain_service = BlockchainService()
    return _blockchain_service


@router.get("/status", response_model=Dict[str, Any])
async def get_blockchain_status(
    service: BlockchainService = Depends(get_blockchain_service)
) -> Dict[str, Any]:
    """
    Get the current status of the Brixa blockchain service.
    """
    return service.get_status()


@router.post("/mining/start")
async def start_mining(
    current_user: User = Depends(get_current_active_user),
    service: BlockchainService = Depends(get_blockchain_service)
) -> Dict[str, str]:
    """
    Start the Brixa mining process.
    
    Requires authentication and appropriate permissions.
    """
    config = get_blockchain_config()
    if not config.enable_mining:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Mining is not enabled in the configuration"
        )
    
    if service.miner is None:
        # Initialize miner if not already done
        service.miner = BrixaMiner(service.blockchain, config.miner_address)
    
    # Start mining in the background
    await service.start()
    
    return {"status": "Mining started successfully"}


@router.post("/mining/stop")
async def stop_mining(
    current_user: User = Depends(get_current_active_user),
    service: BlockchainService = Depends(get_blockchain_service)
) -> Dict[str, str]:
    """
    Stop the Brixa mining process.
    
    Requires authentication and appropriate permissions.
    """
    if service.miner is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Mining is not currently active"
        )
    
    # Stop mining
    service.miner.stop_mining()
    
    return {"status": "Mining stopped successfully"}


@router.post("/validation/start")
async def start_validation(
    current_user: User = Depends(get_current_active_user),
    service: BlockchainService = Depends(get_blockchain_service)
) -> Dict[str, str]:
    """
    Start the Brixa validation process.
    
    Requires authentication, appropriate permissions, and staked BXA tokens.
    """
    config = get_blockchain_config()
    if not config.enable_validation:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Validation is not enabled in the configuration"
        )
    
    if service.validator is None:
        # Initialize validator if not already done
        service.validator = BrixaValidator(service.blockchain, config.validator_address)
    
    # Start validation in the background
    await service.start()
    
    return {"status": "Validation started successfully"}


@router.post("/validation/stop")
async def stop_validation(
    current_user: User = Depends(get_current_active_user),
    service: BlockchainService = Depends(get_blockchain_service)
) -> Dict[str, str]:
    """
    Stop the Brixa validation process.
    
    Requires authentication and appropriate permissions.
    """
    if service.validator is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Validation is not currently active"
        )
    
    # Stop validation
    service.validator.stop_validating()
    
    return {"status": "Validation stopped successfully"}


@router.get("/config", response_model=Dict[str, Any])
async def get_blockchain_config_endpoint() -> Dict[str, Any]:
    """
    Get the current blockchain configuration.
    
    Some sensitive information may be redacted.
    """
    config = get_blockchain_config()
    config_dict = config.to_dict()
    
    # Redact sensitive information
    if "miner_address" in config_dict and config_dict["miner_address"]:
        config_dict["miner_address"] = "*****" + config_dict["miner_address"][-4:]
    if "validator_address" in config_dict and config_dict["validator_address"]:
        config_dict["validator_address"] = "*****" + config_dict["validator_address"][-4:]
    
    return config_dict
