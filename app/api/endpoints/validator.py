"""
Validator API Endpoints

This module provides API endpoints for validator operations including staking,
validation, and slashing in the Brixa blockchain network.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Dict, Any
from datetime import datetime
from decimal import Decimal

from app.services.blockchain.validator import BXAValidator
from app.services.blockchain.bxa_chain import BXAChain
from app.models.user import User
from app.api import deps
from app.db.session import SessionLocal
from app.core.config import settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

# Request/Response Models
class ValidatorRegisterRequest(BaseModel):
    """Request model for registering as a validator"""
    stake_amount: float = Field(..., gt=0, description="Amount of BXA to stake")
    
    @validator('stake_amount')
    def validate_stake_amount(cls, v):
        if v < 1000:  # Minimum stake amount
            raise ValueError("Minimum stake amount is 1000 BXA")
        return v

class ValidatorInfo(BaseModel):
    """Validator information response model"""
    address: str
    staked_amount: float
    joined_at: str
    last_validated: Optional[str] = None
    total_rewards: float
    slash_count: int
    is_active: bool

class NetworkStats(BaseModel):
    """Network statistics response model"""
    total_validators: int
    active_validators: int
    total_staked: float
    min_stake: float
    slashing_penalty: float  # as percentage
    unbonding_period_days: int

class ValidatorListResponse(BaseModel):
    """Response model for listing validators"""
    validators: List[ValidatorInfo]
    stats: NetworkStats

class SlashRequest(BaseModel):
    """Request model for slashing a validator"""
    reason: str = Field(..., min_length=10, description="Reason for slashing")

# Helper function to get validator service
def get_validator_service(db: SessionLocal = Depends(deps.get_db)) -> BXAValidator:
    # In a real implementation, this would get the blockchain instance from your app state
    # For this example, we'll create a new one
    blockchain = BXAChain(node_id="api-node")
    return BXAValidator(blockchain)

# API Endpoints
@router.post("/register", response_model=ValidatorInfo, status_code=status.HTTP_201_CREATED)
async def register_validator(
    request: ValidatorRegisterRequest,
    current_user: User = Depends(deps.get_current_active_user),
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Register as a network validator by staking BXA.
    
    Requires a minimum stake of 1000 BXA.
    """
    try:
        # In a real implementation, this would check the user's balance and transfer the stake
        # For now, we'll assume the user has sufficient balance
        
        success = validator_service.register_validator(
            address=current_user.wallet_address,
            stake_amount=Decimal(str(request.stake_amount))
        )
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Failed to register as validator. Insufficient balance or already registered."
            )
            
        # Get the validator info
        validator_info = validator_service.get_validator_info(current_user.wallet_address)
        if not validator_info:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve validator information"
            )
            
        return validator_info
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/unregister", status_code=status.HTTP_202_ACCEPTED)
async def unregister_validator(
    current_user: User = Depends(deps.get_current_active_user),
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Unregister as a validator and initiate the unbonding process.
    
    The staked amount will be locked for the unbonding period (14 days)
    before it can be withdrawn.
    """
    success = validator_service.unregister_validator(current_user.wallet_address)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to unregister validator. Not registered or already unregistering."
        )
        
    return {"message": "Unbonding initiated. Your stake will be available after the unbonding period."}

@router.get("/info", response_model=ValidatorInfo)
async def get_validator_info(
    address: Optional[str] = None,
    current_user: User = Depends(deps.get_current_active_user),
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Get information about a validator.
    
    If no address is provided, returns information about the current user's validator node.
    """
    validator_address = address or current_user.wallet_address
    validator_info = validator_service.get_validator_info(validator_address)
    
    if not validator_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Validator not found"
        )
        
    return validator_info

@router.get("/list", response_model=ValidatorListResponse)
async def list_validators(
    active_only: bool = True,
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    List all validators in the network.
    
    By default, only active validators are returned.
    """
    validators = validator_service.get_active_validators() if active_only else [
        v.to_dict() for v in validator_service.validators.values()
    ]
    
    return {
        "validators": validators,
        "stats": validator_service.get_network_stats()
    }

@router.post("/slash/{validator_address}", status_code=status.HTTP_200_OK)
async def slash_validator(
    validator_address: str,
    request: SlashRequest,
    current_user: User = Depends(deps.get_current_active_moderator),  # Only moderators can slash
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Slash a validator for misbehavior.
    
    This will penalize the validator by a percentage of their stake.
    Requires moderator privileges.
    """
    success = validator_service.slash_validator(
        validator_address=validator_address,
        reason=request.reason
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to slash validator. Not found or already slashed."
        )
        
    return {"message": f"Validator {validator_address} has been slashed."}

@router.get("/network-stats", response_model=NetworkStats)
async def get_network_stats(
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Get network statistics including total staked, active validators, etc.
    """
    return validator_service.get_network_stats()

@router.post("/withdraw", status_code=status.HTTP_200_OK)
async def withdraw_stake(
    current_user: User = Depends(deps.get_current_active_user),
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Withdraw staked BXA after the unbonding period has completed.
    """
    # In a real implementation, this would check the unbonding requests
    # and transfer the staked amount back to the user's wallet
    
    # This is a simplified version
    success = True  # Replace with actual implementation
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No withdrawable stake found or unbonding period not completed."
        )
        
    return {"message": "Stake has been successfully withdrawn to your wallet."}

# Admin Endpoints (protected)
@router.get("/admin/validators", response_model=List[ValidatorInfo])
async def admin_list_validators(
    current_user: User = Depends(deps.get_current_active_admin),
    validator_service: BXAValidator = Depends(get_validator_service)
):
    """
    Admin endpoint to list all validators, including inactive ones.
    Requires admin privileges.
    """
    return [v.to_dict() for v in validator_service.validators.values()]
