"""
Feedback API endpoints for users to submit and manage their feedback.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Optional
from uuid import UUID

from app.services.feedback.feedback_service import FeedbackService, Feedback, FeedbackType, FeedbackStatus
from app.api.dependencies import get_current_user
from app.models.user import User

router = APIRouter()
feedback_service = FeedbackService()

@router.post("/", response_model=Feedback, status_code=status.HTTP_201_CREATED)
async def submit_feedback(
    feedback_type: FeedbackType,
    content: str,
    current_user: User = Depends(get_current_user)
) -> Feedback:
    """
    Submit new feedback.
    """
    try:
        feedback = feedback_service.add_feedback(
            user_id=current_user.id,
            feedback_type=feedback_type,
            content=content
        )
        return feedback
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.get("/", response_model=List[Feedback])
async def list_feedback(
    skip: int = 0,
    limit: int = 10,
    feedback_type: Optional[FeedbackType] = None,
    current_user: User = Depends(get_current_user)
) -> List[Feedback]:
    """
    List feedback items for the current user.
    Admins can see all feedback.
    """
    is_admin = any(role.name == "admin" for role in current_user.roles)
    return feedback_service.list_feedback(
        user_id=None if is_admin else current_user.id,
        feedback_type=feedback_type,
        skip=skip,
        limit=limit
    )

@router.get("/{feedback_id}", response_model=Feedback)
async def get_feedback(
    feedback_id: UUID,
    current_user: User = Depends(get_current_user)
) -> Feedback:
    """
    Get a specific feedback item by ID.
    Users can only access their own feedback unless they are admins.
    """
    feedback = feedback_service.get_feedback(str(feedback_id))
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Feedback not found"
        )
    
    is_admin = any(role.name == "admin" for role in current_user.roles)
    if not is_admin and str(feedback.user_id) != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this feedback"
        )
    
    return feedback
