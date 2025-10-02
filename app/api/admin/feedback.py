"""
Admin Feedback API Endpoints

This module provides admin-only API endpoints for managing user feedback.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from app.services.feedback.feedback_service import FeedbackService, Feedback, FeedbackStatus
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()

def get_feedback_service() -> FeedbackService:
    """Dependency to get feedback service instance."""
    return FeedbackService()

@router.get("", response_model=Dict[str, Any])
async def admin_list_feedback(
    type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Admin endpoint to list all feedback with filtering and pagination.
    
    - **type**: Filter by feedback type (bug, feature, general, etc.)
    - **status**: Filter by status (open, in_progress, resolved, etc.)
    - **search**: Search term to filter feedback
    - **page**: Page number (1-based)
    - **per_page**: Number of items per page (max 100)
    """
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    # Calculate offset for pagination
    offset = (page - 1) * per_page
    
    # Get filtered feedback
    feedback = feedback_service.list_feedback(
        feedback_type=type,
        status=status,
        limit=per_page,
        offset=offset
    )
    
    # If search term provided, filter in-memory
    if search:
        search = search.lower()
        feedback = [
            f for f in feedback
            if (search in f.content.lower() or 
                (f.metadata and search in str(f.metadata).lower()))
        ]
    
    # Get total count for pagination
    total = len(feedback)  # This is simplified; in production, use a COUNT query
    
    return {
        "items": [f.to_dict() for f in feedback],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page
    }

@router.put("/{feedback_id}/status", response_model=Dict[str, Any])
async def admin_update_feedback_status(
    feedback_id: str,
    status_update: Dict[str, str],
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Admin endpoint to update feedback status.
    
    - **feedback_id**: ID of the feedback to update
    - **status**: New status (open, in_progress, resolved, wont_fix, duplicate)
    - **note**: Optional admin note
    """
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    status_value = status_update.get('status')
    note = status_update.get('note', '')
    
    if not status_value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Status is required"
        )
    
    # Validate status
    try:
        status_enum = FeedbackStatus(status_value.lower())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(e.value for e in FeedbackStatus)}"
        )
    
    # Prepare metadata update
    metadata_update = {
        'updated_by': str(current_user.id),
        'updated_at': datetime.utcnow().isoformat(),
    }
    
    if note:
        metadata_update['admin_note'] = note
    
    # Update status
    feedback = feedback_service.update_feedback_status(
        feedback_id=feedback_id,
        status=status_value,
        metadata=metadata_update
    )
    
    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Feedback not found"
        )
    
    return {
        "success": True,
        "feedback": feedback.to_dict()
    }

@router.get("/stats", response_model=Dict[str, Any])
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
            detail="Admin privileges required"
        )
    
    return feedback_service.get_feedback_stats()

@router.get("/export", response_model=List[Dict[str, Any]])
async def export_feedback(
    format: str = 'json',
    current_user: User = Depends(get_current_user),
    feedback_service: FeedbackService = Depends(get_feedback_service)
):
    """
    Export feedback data.
    
    - **format**: Export format (json or csv)
    """
    if not current_user or not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    
    # Get all feedback (in production, you might want to paginate this)
    feedback = feedback_service.list_feedback(limit=1000)
    
    if format.lower() == 'csv':
        # Convert to CSV format
        import io
        import csv
        
        if not feedback:
            return []
            
        # Prepare CSV data
        output = io.StringIO()
        fieldnames = [
            'id', 'type', 'status', 'content', 'user_id', 
            'created_at', 'updated_at', 'metadata'
        ]
        
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        
        for item in feedback:
            row = item.to_dict()
            # Convert metadata to string for CSV
            if 'metadata' in row and row['metadata']:
                row['metadata'] = json.dumps(row['metadata'])
            writer.writerow(row)
        
        # Return as a file download
        from fastapi.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": "attachment; filename=feedback_export.csv"
            }
        )
    
    # Default to JSON
    return [item.to_dict() for item in feedback]
