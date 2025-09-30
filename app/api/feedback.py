"""
Feedback API Endpoints

This module provides API endpoints for submitting and managing user feedback.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from typing import List, Optional
from datetime import datetime
import time

from app.services.feedback.feedback_service import (
    FeedbackService,
    Feedback,
    FeedbackType,
    FeedbackStatus
)
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()

def get_feedback_service() -> FeedbackService:
    """Dependency to get feedback service instance."""
    return FeedbackService()

@router.post("/feedback", response_model=Feedback)
async def submit_feedback(
    feedback_type: str,
    content: str,
    metadata: Optional[dict] = None,
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Submit new feedback.
    
    - **feedback_type**: Type of feedback (bug, feature, general, etc.)
    - **content**: Feedback content
    - **metadata**: Additional metadata (optional)
    """
    try:
        feedback = feedback_service.add_feedback(
            feedback_type=feedback_type,
            content=content,
            user_id=str(current_user.id) if current_user else None,
            metadata=metadata or {}
        )
        return feedback
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/feedback", response_model=List[Feedback])
async def list_feedback(
    feedback_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    List feedback with optional filtering.
    
    - **feedback_type**: Filter by feedback type
    - **status**: Filter by status
    - **limit**: Number of results to return (max 100)
    - **offset**: Pagination offset
    """
    # Regular users can only see their own feedback
    user_id = str(current_user.id) if current_user else None
    
    # Admins can see all feedback
    if current_user and current_user.is_admin:
        user_id = None
    
    feedback = feedback_service.list_feedback(
        user_id=user_id,
        feedback_type=feedback_type,
        status=status,
        limit=min(limit, 100),  # Cap limit at 100
        offset=offset
    )
    
    return feedback

@router.get("/feedback/{feedback_id}", response_model=Feedback)
async def get_feedback(
    feedback_id: str,
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Get feedback by ID.
    
    - **feedback_id**: ID of the feedback to retrieve
    """
    feedback = feedback_service.get_feedback(feedback_id)
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Feedback not found"
        )
    
    # Check permissions
    if (not current_user or 
        (not current_user.is_admin and 
         (not feedback.user_id or feedback.user_id != str(current_user.id)))):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this feedback"
        )
    
    return feedback

@router.put("/feedback/{feedback_id}/status", response_model=Feedback)
async def update_feedback_status(
    feedback_id: str,
    status: str,
    metadata: Optional[dict] = None,
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Update feedback status.
    
    - **feedback_id**: ID of the feedback to update
    - **status**: New status (open, in_progress, resolved, wont_fix, duplicate)
    - **metadata**: Additional metadata (optional)
    """
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can update feedback status"
        )
    
    feedback = feedback_service.update_feedback_status(
        feedback_id=feedback_id,
        status=status,
        metadata=metadata
    )
    
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Feedback not found"
        )
    
    return feedback

@router.get("/feedback/stats")
async def get_feedback_stats(
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Get feedback statistics.
    
    Returns counts by type, status, and recent activity.
    """
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only administrators can view feedback statistics"
        )
    
    return feedback_service.get_feedback_stats()
