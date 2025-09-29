from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import JSONResponse
from typing import Optional, List
from datetime import datetime, timedelta
import logging

from app.core.security import get_current_user
from app.models.user import User
from app.models.content_moderation import ContentReport, UserVerification, ModerationStatus
from app.services.ai_moderation import AIModerationService
from app.core.config import settings
from app import db

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize AI moderation service
ai_moderation = AIModerationService(settings)

@router.post("/report")
async def report_content(
    content_id: str,
    content_type: str,
    reason: str,
    current_user: User = Depends(get_current_user)
):
    """
    Report content for moderation.
    """
    try:
        # Check if user already reported this content
        existing_report = ContentReport.query.filter_by(
            reporter_id=current_user.id,
            content_id=content_id,
            content_type=content_type
        ).first()
        
        if existing_report:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={"message": "Content already reported"}
            )
        
        # Create new report
        report = ContentReport(
            reporter_id=current_user.id,
            content_id=content_id,
            content_type=content_type,
            reason=reason,
            status=ModerationStatus.PENDING
        )
        
        db.session.add(report)
        db.session.commit()
        
        # TODO: Trigger content analysis
        
        return {"status": "success", "report_id": report.id}
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error reporting content: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit report"
        )

@router.post("/verify-age")
async def verify_age(
    document: UploadFile = File(...),
    selfie: Optional[UploadFile] = None,
    current_user: User = Depends(get_current_user)
):
    """
    Verify user's age using AI.
    """
    try:
        # Check if already verified
        existing_verification = UserVerification.query.filter_by(user_id=current_user.id).first()
        if existing_verification and existing_verification.is_age_verified:
            return {
                "status": "already_verified",
                "verified": True,
                "age": existing_verification.verified_age
            }
        
        # Read document image
        document_data = await document.read()
        selfie_data = await selfie.read() if selfie else None
        
        # Verify age using AI
        is_verified, estimated_age, details = await ai_moderation.verify_age(
            document_data, 
            selfie_data
        )
        
        if is_verified:
            # Save verification
            verification = existing_verification or UserVerification(user_id=current_user.id)
            verification.is_age_verified = True
            verification.verification_method = "ai"
            verification.verified_at = datetime.utcnow()
            verification.verified_age = estimated_age
            verification.verification_expiry = datetime.utcnow() + timedelta(days=365)  # 1 year expiry
            verification.verification_data = details
            
            db.session.add(verification)
            db.session.commit()
            
            return {
                "status": "success",
                "verified": True,
                "age": estimated_age,
                "details": {
                    "method": "ai_verification",
                    "expires_at": verification.verification_expiry.isoformat()
                }
            }
        else:
            return {
                "status": "verification_failed",
                "verified": False,
                "error": details.get('error', 'verification_failed'),
                "message": details.get('message', 'Could not verify age')
            }
            
    except Exception as e:
        logger.error(f"Error in age verification: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to verify age"
        )

@router.get("/status/{content_id}")
async def get_moderation_status(
    content_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get moderation status for content.
    """
    reports = ContentReport.query.filter_by(content_id=content_id).all()
    
    # For demo purposes, return a mock response
    # In production, this would check actual moderation status
    return {
        "content_id": content_id,
        "status": "clean",  # or 'pending', 'under_review', 'violation'
        "reports_count": len(reports),
        "last_checked": datetime.utcnow().isoformat()
    }
