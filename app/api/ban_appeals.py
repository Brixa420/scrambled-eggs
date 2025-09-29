from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from typing import List, Optional
from datetime import datetime
import logging

from app.core.security import get_current_user
from app.models.user import User
from app.models.ban_appeal import BanAppeal, BanAppealStatus
from app.services.ban_appeal_service import ban_appeal_service
from app import db

router = APIRouter()
logger = logging.getLogger(__name__)

@router.post("/appeals")
async def create_ban_appeal(
    ban_reason: str,
    appeal_text: str,
    current_user: User = Depends(get_current_user)
):
    """
    Create a new ban appeal.
    """
    # Check if user is actually banned
    if not current_user.is_banned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You are not currently banned"
        )
    
    # Check for existing pending appeal
    existing_appeal = BanAppeal.query.filter_by(
        user_id=current_user.id,
        status=BanAppealStatus.PENDING
    ).first()
    
    if existing_appeal:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You already have a pending appeal"
        )
    
    # Create new appeal
    appeal = BanAppeal(
        user_id=current_user.id,
        ban_reason=ban_reason,
        appeal_text=appeal_text,
        status=BanAppealStatus.PENDING
    )
    
    db.session.add(appeal)
    db.session.commit()
    
    # Process the appeal with AI
    try:
        status, message = await ban_appeal_service.process_appeal(appeal)
        appeal.status = status
        appeal.updated_at = datetime.utcnow()
        
        # If approved, unban the user
        if status == BanAppealStatus.APPROVED:
            current_user.is_banned = False
            current_user.ban_reason = None
            appeal.reviewed_at = datetime.utcnow()
            appeal.reviewed_by = None  # System auto-approved
        
        db.session.commit()
        
    except Exception as e:
        logger.error(f"Error processing ban appeal: {str(e)}", exc_info=True)
        # Don't fail the request if AI processing fails
        message = "Your appeal has been submitted and is pending review."
    
    return {
        "status": "success",
        "message": message,
        "appeal_id": appeal.id,
        "appeal_status": appeal.status.value
    }

@router.get("/appeals/my")
async def get_my_appeals(
    current_user: User = Depends(get_current_user)
):
    """
    Get the current user's ban appeals.
    """
    appeals = BanAppeal.query.filter_by(
        user_id=current_user.id
    ).order_by(BanAppeal.created_at.desc()).all()
    
    return {
        "status": "success",
        "appeals": [appeal.to_dict() for appeal in appeals]
    }

@router.get("/appeals/{appeal_id}")
async def get_appeal(
    appeal_id: int,
    current_user: User = Depends(get_current_user)
):
    """
    Get details of a specific ban appeal.
    """
    appeal = BanAppeal.query.get(appeal_id)
    
    if not appeal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Appeal not found"
        )
    
    # Only the appeal owner or an admin can view the appeal
    if appeal.user_id != current_user.id and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this appeal"
        )
    
    return {
        "status": "success",
        "appeal": appeal.to_dict()
    }

# Admin endpoints
@router.get("/admin/appeals")
async def list_appeals(
    status: Optional[str] = None,
    limit: int = 20,
    offset: int = 0,
    current_user: User = Depends(get_current_user)
):
    """
    List all ban appeals (admin only).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view all appeals"
        )
    
    query = BanAppeal.query
    
    if status:
        try:
            status_enum = BanAppealStatus(status.lower())
            query = query.filter_by(status=status_enum)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status. Must be one of: {', '.join(e.value for e in BanAppealStatus)}"
            )
    
    total = query.count()
    appeals = query.order_by(BanAppeal.created_at.desc()).offset(offset).limit(limit).all()
    
    return {
        "status": "success",
        "total": total,
        "appeals": [appeal.to_dict() for appeal in appeals]
    }

@router.post("/admin/appeals/{appeal_id}/review")
async def review_appeal(
    appeal_id: int,
    action: str,  # "approve" or "reject"
    notes: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Review a ban appeal (admin only).
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can review appeals"
        )
    
    appeal = BanAppeal.query.get(appeal_id)
    if not appeal:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Appeal not found"
        )
    
    if appeal.status != BanAppealStatus.PENDING and appeal.status != BanAppealStatus.FURTHER_REVIEW_NEEDED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This appeal has already been processed"
        )
    
    # Update appeal status
    if action.lower() == "approve":
        appeal.status = BanAppealStatus.APPROVED
        appeal.user.is_banned = False
        appeal.user.ban_reason = None
        message = "The ban has been lifted."
    elif action.lower() == "reject":
        appeal.status = BanAppealStatus.REJECTED
        message = "The ban remains in place."
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid action. Must be 'approve' or 'reject'"
        )
    
    # Update appeal details
    appeal.reviewed_at = datetime.utcnow()
    appeal.reviewed_by = current_user.id
    appeal.reviewer_notes = notes
    
    db.session.commit()
    
    return {
        "status": "success",
        "message": f"Appeal {appeal.status.value}. {message}",
        "appeal_status": appeal.status.value
    }
