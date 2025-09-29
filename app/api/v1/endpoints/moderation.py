"""
Moderation API endpoints for content moderation, user actions, and appeals.
"""
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query, UploadFile, File
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from enum import Enum
import logging

from app.core.security import get_current_user, get_current_active_user
from app.models.user import User
from app.services.moderation_service import ModerationService
from app.models.moderation import (
    ContentType,
    ViolationType,
    ModerationAction,
    ModerationStatus,
    ContentViolation,
    ModerationReview,
    ModerationAppeal,
    UserWarning,
    UserSuspension,
    UserBan,
    ContentFilter
)
from app.db.session import SessionLocal
from app.core.config import settings

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize moderation service
moderation_service = ModerationService()

# Pydantic models for request/response schemas
class ContentScanRequest(BaseModel):
    content_type: ContentType
    content: str  # URL or content identifier
    context: Optional[Dict[str, Any]] = None
    user_id: Optional[int] = None

class ViolationReport(BaseModel):
    content_id: str
    content_type: ContentType
    violation_type: ViolationType
    description: str
    context: Optional[Dict[str, Any]] = None

class WarningCreate(BaseModel):
    user_id: int
    reason: str
    violation_id: Optional[int] = None
    expires_at: Optional[datetime] = None

class SuspensionCreate(BaseModel):
    user_id: int
    reason: str
    duration_days: int = 7
    violation_id: Optional[int] = None

class BanCreate(BaseModel):
    user_id: int
    reason: str
    permanent: bool = False
    violation_id: Optional[int] = None

class AppealCreate(BaseModel):
    moderation_action_id: int
    action_type: str  # 'warning', 'suspension', or 'ban'
    reason: str
    evidence: Optional[str] = None

class ContentFilterCreate(BaseModel):
    filter_type: str  # 'keyword', 'user', 'content_type', etc.
    value: str
    action: str = 'warn'  # 'warn', 'hide', 'block'
    expires_at: Optional[datetime] = None

class AppealDecision(BaseModel):
    decision: str  # 'approve' or 'deny'
    reason: str

# Helper function to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Content Scanning & Reporting
@router.post("/scan", response_model=Dict[str, Any])
async def scan_content(
    request: ContentScanRequest,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Scan content for potential policy violations.
    """
    try:
        result = await moderation_service.scan_content(
            content_type=request.content_type,
            content=request.content,
            context=request.context,
            user_id=request.user_id or current_user.id,
            db=db
        )
        return result
    except Exception as e:
        logger.error(f"Error scanning content: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to scan content"
        )

@router.post("/report", status_code=status.HTTP_201_CREATED)
async def report_violation(
    report: ViolationReport,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Report a content violation.
    """
    try:
        violation = await moderation_service.report_violation(
            content_id=report.content_id,
            content_type=report.content_type,
            violation_type=report.violation_type,
            reporter_id=current_user.id,
            description=report.description,
            context=report.context,
            db=db
        )
        return {"violation_id": violation.id, "status": "reported"}
    except Exception as e:
        logger.error(f"Error reporting violation: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to report violation"
        )

# Moderation Actions
@router.post("/warnings", status_code=status.HTTP_201_CREATED)
async def issue_warning(
    warning: WarningCreate,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Issue a warning to a user.
    Requires moderator or admin privileges.
    """
    if not current_user.is_moderator and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        user_warning = await moderation_service.issue_user_warning(
            user_id=warning.user_id,
            issued_by=current_user.id,
            reason=warning.reason,
            violation_id=warning.violation_id,
            expires_at=warning.expires_at,
            db=db
        )
        return {"warning_id": user_warning.id, "status": "issued"}
    except Exception as e:
        logger.error(f"Error issuing warning: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to issue warning"
        )

@router.post("/suspensions", status_code=status.HTTP_201_CREATED)
async def suspend_user(
    suspension: SuspensionCreate,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Suspend a user's account.
    Requires moderator or admin privileges.
    """
    if not current_user.is_moderator and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        user_suspension = await moderation_service.suspend_user(
            user_id=suspension.user_id,
            issued_by=current_user.id,
            reason=suspension.reason,
            duration_days=suspension.duration_days,
            violation_id=suspension.violation_id,
            db=db
        )
        return {"suspension_id": user_suspension.id, "status": "suspended"}
    except Exception as e:
        logger.error(f"Error suspending user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to suspend user"
        )

@router.post("/bans", status_code=status.HTTP_201_CREATED)
async def ban_user(
    ban: BanCreate,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Ban a user's account.
    Requires admin privileges.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    try:
        user_ban = await moderation_service.ban_user(
            user_id=ban.user_id,
            issued_by=current_user.id,
            reason=ban.reason,
            permanent=ban.permanent,
            violation_id=ban.violation_id,
            db=db
        )
        return {"ban_id": user_ban.id, "status": "banned"}
    except Exception as e:
        logger.error(f"Error banning user: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ban user"
        )

# Appeals
@router.post("/appeals", status_code=status.HTTP_201_CREATED)
async def create_appeal(
    appeal: AppealCreate,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Create an appeal for a moderation action.
    """
    try:
        new_appeal = await moderation_service.create_appeal(
            user_id=current_user.id,
            moderation_action_id=appeal.moderation_action_id,
            action_type=appeal.action_type,
            reason=appeal.reason,
            evidence=appeal.evidence,
            db=db
        )
        return {"appeal_id": new_appeal.id, "status": "submitted"}
    except Exception as e:
        logger.error(f"Error creating appeal: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create appeal"
        )

@router.post("/appeals/{appeal_id}/process")
async def process_appeal(
    appeal_id: int,
    decision: AppealDecision,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Process an appeal (approve or deny).
    Requires moderator or admin privileges.
    """
    if not current_user.is_moderator and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        result = await moderation_service.process_appeal(
            appeal_id=appeal_id,
            resolved_by=current_user.id,
            decision=decision.decision == 'approve',
            reason=decision.reason,
            db=db
        )
        return {"status": "processed", "action": decision.decision}
    except Exception as e:
        logger.error(f"Error processing appeal: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process appeal"
        )

# Content Filtering
@router.post("/filters", status_code=status.HTTP_201_CREATED)
async def create_content_filter(
    content_filter: ContentFilterCreate,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Create a content filter for the current user.
    """
    try:
        new_filter = await moderation_service.create_content_filter(
            user_id=current_user.id,
            filter_type=content_filter.filter_type,
            value=content_filter.value,
            action=content_filter.action,
            expires_at=content_filter.expires_at,
            db=db
        )
        return {"filter_id": new_filter.id, "status": "created"}
    except Exception as e:
        logger.error(f"Error creating content filter: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create content filter"
        )

@router.get("/filters", response_model=List[Dict[str, Any]])
async def list_content_filters(
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    List all content filters for the current user.
    """
    try:
        filters = await moderation_service.get_user_filters(
            user_id=current_user.id,
            db=db
        )
        return [{
            "id": f.id,
            "filter_type": f.filter_type,
            "value": f.value,
            "action": f.action,
            "created_at": f.created_at,
            "expires_at": f.expires_at
        } for f in filters]
    except Exception as e:
        logger.error(f"Error listing content filters: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list content filters"
        )

@router.delete("/filters/{filter_id}", status_code=status.HTTP_200_OK)
async def delete_content_filter(
    filter_id: int,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Delete a content filter.
    """
    try:
        success = await moderation_service.delete_content_filter(
            filter_id=filter_id,
            user_id=current_user.id,
            db=db
        )
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Filter not found or access denied"
            )
        return {"status": "deleted"}
    except Exception as e:
        logger.error(f"Error deleting content filter: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete content filter"
        )

# Moderator Endpoints
@router.get("/queue", response_model=List[Dict[str, Any]])
async def get_moderation_queue(
    status: Optional[str] = Query(None, description="Filter by status"),
    content_type: Optional[ContentType] = None,
    limit: int = Query(50, le=100, ge=1),
    offset: int = 0,
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Get the moderation queue for moderators.
    Requires moderator or admin privileges.
    """
    if not current_user.is_moderator and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        queue = await moderation_service.get_moderation_queue(
            status=status,
            content_type=content_type,
            limit=limit,
            offset=offset,
            db=db
        )
        return queue
    except Exception as e:
        logger.error(f"Error getting moderation queue: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get moderation queue"
        )

@router.get("/stats", response_model=Dict[str, Any])
async def get_moderation_stats(
    time_frame: str = Query("7d", description="Time frame for stats (e.g., 24h, 7d, 30d)"),
    current_user: User = Depends(get_current_active_user),
    db: SessionLocal = Depends(get_db)
):
    """
    Get moderation statistics.
    Requires moderator or admin privileges.
    """
    if not current_user.is_moderator and not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    try:
        stats = await moderation_service.get_moderation_stats(
            time_frame=time_frame,
            db=db
        )
        return stats
    except Exception as e:
        logger.error(f"Error getting moderation stats: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get moderation stats"
        )
