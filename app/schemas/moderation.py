"""
Moderation Schemas

This module contains Pydantic models for moderation-related API requests and responses.
"""
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.user import UserBase

class ViolationType(str, Enum):
    """Types of content violations"""
    CSAM = "csam"
    BESTIALITY = "bestiality"
    VIOLENCE = "violence"
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    SPAM = "spam"
    COPYRIGHT = "copyright"
    OTHER = "other"

class SeverityLevel(str, Enum):
    """Severity levels for moderation actions"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ModerationStatus(str, Enum):
    """Status of moderation actions and reports"""
    PENDING = "pending"
    UNDER_REVIEW = "under_review"
    RESOLVED = "resolved"
    DISMISSED = "dismissed"
    APPEALED = "appealed"
    REVOKED = "revoked"

class ReportBase(BaseModel):
    """Base model for content reports"""
    content_id: str = Field(..., description="ID of the content being reported")
    content_type: str = Field(..., description="Type of content (post, comment, media, etc.)")
    report_type: ViolationType = Field(..., description="Type of violation being reported")
    description: Optional[str] = Field(None, description="Additional details about the report")

class ReportCreate(ReportBase):
    """Schema for creating a new report"""
    pass

class ReportResponse(ReportBase):
    """Schema for report responses"""
    id: int
    status: ModerationStatus
    reporter_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class ModerationActionType(str, Enum):
    """Types of moderation actions"""
    WARNING = "warning"
    REMOVE_CONTENT = "remove_content"
    SUSPEND_USER = "suspend_user"
    BAN_USER = "ban_user"
    RESTRICT = "restrict"
    APPROVE = "approve"
    ESCALATE = "escalate"

class ModerationActionBase(BaseModel):
    """Base model for moderation actions"""
    content_id: str = Field(..., description="ID of the content being moderated")
    user_id: int = Field(..., description="ID of the user who created the content")
    action_type: ModerationActionType = Field(..., description="Type of action being taken")
    reason: str = Field(..., description="Reason for the moderation action")
    severity: SeverityLevel = Field(default=SeverityLevel.MEDIUM, description="Severity of the violation")

class ModerationActionCreate(ModerationActionBase):
    """Schema for creating a new moderation action"""
    pass

class ModerationActionResponse(ModerationActionBase):
    """Schema for moderation action responses"""
    id: int
    moderator_id: int
    status: ModerationStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    tx_hash: Optional[str] = Field(None, description="Blockchain transaction hash")
    
    class Config:
        orm_mode = True

class AppealBase(BaseModel):
    """Base model for appeals"""
    content_id: str = Field(..., description="ID of the content being appealed")
    action_id: int = Field(..., description="ID of the moderation action being appealed")
    reason: str = Field(..., description="Reason for the appeal")
    evidence: Optional[str] = Field(None, description="Additional evidence supporting the appeal")

class AppealCreate(AppealBase):
    """Schema for creating a new appeal"""
    pass

class AppealResponse(AppealBase):
    """Schema for appeal responses"""
    id: int
    user_id: int
    status: ModerationStatus
    created_at: datetime
    updated_at: Optional[datetime] = None
    moderator_notes: Optional[str] = None
    
    class Config:
        orm_mode = True

class ContentViolationBase(BaseModel):
    """Base model for content violations"""
    content_id: str
    content_type: str
    violation_type: ViolationType
    confidence: float = Field(..., ge=0.0, le=1.0)
    details: Dict[str, Any] = {}
    status: ModerationStatus = ModerationStatus.PENDING

class ContentViolationCreate(ContentViolationBase):
    """Schema for creating a new content violation"""
    pass

class ContentViolationResponse(ContentViolationBase):
    """Schema for content violation responses"""
    id: int
    reported_at: datetime
    resolved_at: Optional[datetime] = None
    
    class Config:
        orm_mode = True

class ReputationResponse(BaseModel):
    """Schema for user reputation responses"""
    user_id: int
    score: int
    level: str
    
    class Config:
        orm_mode = True

class ContentScanResult(BaseModel):
    """Schema for content scan results"""
    content_id: str
    has_violations: bool = False
    violations: List[Dict[str, Any]] = []
    highest_severity: Optional[SeverityLevel] = None
    highest_severity_violation: Optional[ViolationType] = None
    highest_confidence: float = 0.0
    requires_age_verification: bool = False
    is_safe: bool = True
    
    class Config:
        orm_mode = True
