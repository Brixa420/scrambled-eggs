"""
Moderation API Endpoints

This module contains API endpoints for content moderation, reporting, and appeals.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from typing import List, Optional

from app import crud, models, schemas
from app.api import deps
from app.services.integration_service import BrixaIntegrationService
from app.core.config import settings

router = APIRouter()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login")

@router.post("/report", response_model=schemas.ReportResponse)
async def create_report(
    report_in: schemas.ReportCreate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Submit a content report
    """
    integration = BrixaIntegrationService(db)
    result = await integration.submit_report(report=report_in, reporter=current_user)
    
    if not result.get('success'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get('error', 'Failed to submit report')
        )
        
    return {
        "id": result['report_id'],
        "status": "submitted",
        "tx_hash": result['tx_hash']
    }

@router.post("/moderate", response_model=schemas.ModerationActionResponse)
async def moderate_content(
    action_in: schemas.ModerationActionCreate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_moderator),
):
    """
    Take moderation action on content
    """
    integration = BrixaIntegrationService(db)
    result = await integration._take_moderation_action(
        content_id=action_in.content_id,
        user_id=action_in.user_id,
        action_type=action_in.action_type,
        reason=action_in.reason,
        severity=action_in.severity,
        moderator_id=current_user.id
    )
    
    if not result.get('success'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get('error', 'Failed to perform moderation action')
        )
    
    return {
        "action_id": result['action_id'],
        "status": "completed",
        "tx_hash": result['tx_hash']
    }

@router.get("/reports", response_model=List[schemas.ReportResponse])
async def list_reports(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_moderator),
):
    """
    List content reports (moderators only)
    """
    # In a real implementation, this would query the database
    # with appropriate filters and pagination
    # reports = crud.report.get_multi(db, skip=skip, limit=limit, status=status)
    # return reports
    
    # Placeholder response
    return []

@router.post("/appeal", response_model=schemas.AppealResponse)
async def create_appeal(
    appeal_in: schemas.AppealCreate,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Submit an appeal for a moderation action
    """
    integration = BrixaIntegrationService(db)
    appeal = await integration.appeals.create_appeal(
        appeal_in=appeal_in,
        user_id=current_user.id
    )
    
    return {
        "id": 1,  # Would be appeal.id in real implementation
        "status": "submitted",
        "message": "Appeal submitted successfully"
    }

@router.get("/reputation/{user_id}", response_model=schemas.ReputationResponse)
async def get_reputation(
    user_id: int,
    db: Session = Depends(deps.get_db),
    current_user: models.User = Depends(deps.get_current_active_user),
):
    """
    Get a user's reputation score
    """
    integration = BrixaIntegrationService(db)
    score = await integration.blockchain.get_reputation_score(user_id)
    
    return {
        "user_id": user_id,
        "score": score,
        "level": _get_reputation_level(score)
    }

def _get_reputation_level(score: int) -> str:
    """Convert reputation score to a user-friendly level"""
    if score >= 1000:
        return "trusted"
    elif score >= 100:
        return "established"
    elif score >= 0:
        return "new"
    elif score >= -50:
        return "restricted"
    else:
        return "banned"

# Add more endpoints as needed
