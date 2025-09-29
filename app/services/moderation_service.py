"""
Moderation Service

Handles content moderation, including:
- Content scanning and violation detection
- Automated moderation actions
- User warnings, suspensions, and bans
- Moderation review workflow
- User appeals
"""
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Union

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.user import User
from app.models.moderation import (
    ContentViolation,
    ModerationReview,
    ModerationAppeal,
    UserWarning,
    UserSuspension,
    UserBan,
    ContentFilter,
    ModerationSettings,
    ContentType,
    ViolationType,
    ModerationAction,
    ModerationStatus,
)
from app.schemas.moderation import (
    ContentScanResult,
    ContentScanRequest,
    ModerationActionRequest,
    AppealRequest,
    AppealResponse,
    ContentFilterCreate,
)

logger = logging.getLogger(__name__)


class ModerationService:
    """Service for handling content moderation operations"""

    def __init__(self, db: Session):
        self.db = db
        self.settings = self._get_or_create_settings()

    def _get_or_create_settings(self) -> ModerationSettings:
        """Get or create default moderation settings"""
        settings = self.db.query(ModerationSettings).first()
        if not settings:
            settings = ModerationSettings()
            self.db.add(settings)
            self.db.commit()
            self.db.refresh(settings)
        return settings

    def update_settings(self, settings_data: Dict) -> ModerationSettings:
        """Update moderation settings"""
        for key, value in settings_data.items():
            if hasattr(self.settings, key):
                setattr(self.settings, key, value)
        self.settings.updated_at = datetime.utcnow()
        self.db.commit()
        self.db.refresh(self.settings)
        return self.settings

    async def scan_content(
        self, content_request: ContentScanRequest, current_user: User
    ) -> ContentScanResult:
        """
        Scan content for policy violations
        
        Args:
            content_request: Content to scan
            current_user: User who uploaded the content
            
        Returns:
            ContentScanResult with violation details if found
        """
        # TODO: Implement actual content scanning with AI/ML models
        # For now, we'll just return a mock result
        
        # Check if content is in user's own filters
        if await self._matches_user_filters(content_request, current_user.id):
            return ContentScanResult(
                has_violation=True,
                violation_type=ViolationType.OTHER,
                confidence=90,
                message="Content matches user's filter criteria",
            )
            
        # Check for CSAM (example - would use actual model in production)
        if await self._detect_csam(content_request):
            return await self._handle_violation(
                content_request,
                current_user.id,
                ViolationType.CSAM,
                "Potential CSAM content detected",
                95,
            )
            
        # Check for bestiality (example)
        if await self._detect_bestiality(content_request):
            return await self._handle_violation(
                content_request,
                current_user.id,
                ViolationType.BESTIALITY,
                "Potential bestiality content detected",
                85,
            )
            
        # Check for violence (example)
        if await self._detect_violence(content_request):
            return await self._handle_violation(
                content_request,
                current_user.id,
                ViolationType.VIOLENCE,
                "Potential violent content detected",
                80,
            )
            
        # No violations found
        return ContentScanResult(has_violation=False)

    async def _handle_violation(
        self,
        content_request: ContentScanRequest,
        user_id: int,
        violation_type: ViolationType,
        message: str,
        confidence: int,
    ) -> ContentScanResult:
        """Handle a detected violation"""
        # Create violation record
        violation = ContentViolation(
            content_id=content_request.content_id,
            content_type=content_request.content_type,
            content_url=content_request.content_url,
            content_preview=content_request.content_preview,
            violation_type=violation_type,
            confidence_score=confidence,
            user_id=user_id,
            status=ModerationStatus.PENDING,
            detected_at=datetime.utcnow(),
        )
        
        self.db.add(violation)
        self.db.commit()
        self.db.refresh(violation)
        
        # Take automatic action based on violation type
        await self._take_automatic_action(violation)
        
        return ContentScanResult(
            has_violation=True,
            violation_id=violation.id,
            violation_type=violation_type,
            confidence=confidence,
            message=message,
            action_taken=violation.action_taken,
        )

    async def _take_automatic_action(self, violation: ContentViolation) -> None:
        """Take automatic action based on violation type and settings"""
        action = None
        
        # Check if auto-moderation is enabled
        if not self.settings.auto_mod_enabled:
            return
            
        # Determine action based on violation type
        if violation.violation_type == ViolationType.CSAM and self.settings.auto_remove_csam:
            action = ModerationAction.TAKEDOWN
            await self._issue_user_warning(
                user_id=violation.user_id,
                violation_type=violation.violation_type,
                content_id=violation.content_id,
                content_type=violation.content_type,
                reason="Violation of content policy: " + str(violation.violation_type.value),
            )
            
        elif violation.violation_type == ViolationType.BESTIALITY and self.settings.auto_remove_bestiality:
            action = ModerationAction.TAKEDOWN
            await self._issue_user_warning(
                user_id=violation.user_id,
                violation_type=violation.violation_type,
                content_id=violation.content_id,
                content_type=violation.content_type,
                reason="Violation of content policy: " + str(violation.violation_type.value),
            )
            
        elif violation.violation_type == ViolationType.VIOLENCE and self.settings.auto_remove_violence:
            action = ModerationAction.TAKEDOWN
            await self._issue_user_warning(
                user_id=violation.user_id,
                violation_type=violation.violation_type,
                content_id=violation.content_id,
                content_type=violation.content_type,
                reason="Violation of content policy: " + str(violation.violation_type.value),
            )
        
        # Update violation with action taken
        if action:
            violation.action_taken = action
            violation.status = ModerationStatus.RESOLVED
            violation.resolved_at = datetime.utcnow()
            self.db.commit()
    
    async def _issue_user_warning(
        self,
        user_id: int,
        violation_type: ViolationType,
        content_id: Optional[str] = None,
        content_type: Optional[ContentType] = None,
        reason: str = "",
        issued_by: int = 0,  # 0 = system
    ) -> UserWarning:
        """Issue a warning to a user"""
        warning = UserWarning(
            user_id=user_id,
            issued_by=issued_by,
            reason=reason,
            violation_type=violation_type,
            content_id=content_id,
            content_type=content_type,
        )
        
        self.db.add(warning)
        self.db.commit()
        self.db.refresh(warning)
        
        # Check if user should be suspended based on warnings
        await self._check_user_warnings(user_id)
        
        return warning
    
    async def _check_user_warnings(self, user_id: int) -> None:
        """Check if user has too many active warnings and suspend if needed"""
        # Count active warnings
        active_warnings = (
            self.db.query(UserWarning)
            .filter(
                UserWarning.user_id == user_id,
                UserWarning.is_active == True,  # noqa: E712
                UserWarning.expires_at > datetime.utcnow(),
            )
            .count()
        )
        
        # Check if user should be suspended
        if active_warnings >= self.settings.warnings_before_suspension:
            await self.suspend_user(
                user_id=user_id,
                reason=f"Exceeded maximum allowed warnings ({active_warnings} warnings)",
                issued_by=0,  # system
            )
    
    async def suspend_user(
        self, 
        user_id: int, 
        reason: str, 
        issued_by: int = 0,  # 0 = system
        duration_days: Optional[int] = None,
    ) -> UserSuspension:
        """Suspend a user's account"""
        # Check if user is already suspended
        existing_suspension = (
            self.db.query(UserSuspension)
            .filter(
                UserSuspension.user_id == user_id,
                UserSuspension.is_active == True,  # noqa: E712
            )
            .first()
        )
        
        if existing_suspension:
            return existing_suspension
        
        # Count previous suspensions
        suspension_count = (
            self.db.query(UserSuspension)
            .filter(UserSuspension.user_id == user_id)
            .count()
        )
        
        # Determine suspension duration
        if duration_days is None:
            suspension_days = [
                self.settings.first_suspension_days,
                self.settings.second_suspension_days,
                self.settings.third_suspension_days,
            ]
            duration_days = suspension_dours[min(suspension_count, 2)]
        
        expires_at = datetime.utcnow() + timedelta(days=duration_days)
        
        # Create suspension
        suspension = UserSuspension(
            user_id=user_id,
            issued_by=issued_by,
            reason=reason,
            expires_at=expires_at,
            violation_ids=[],  # TODO: Link to relevant violations
        )
        
        self.db.add(suspension)
        self.db.commit()
        self.db.refresh(suspension)
        
        # Check if user should be banned based on suspensions
        if suspension_count + 1 >= self.settings.suspensions_before_ban:
            await self.ban_user(
                user_id=user_id,
                reason=f"Exceeded maximum allowed suspensions ({suspension_count + 1} suspensions)",
                issued_by=0,  # system
                is_permanent=True,
            )
        
        return suspension
    
    async def ban_user(
        self,
        user_id: int,
        reason: str,
        issued_by: int = 0,  # 0 = system
        is_permanent: bool = True,
        duration_days: Optional[int] = None,
    ) -> UserBan:
        """Ban a user's account"""
        # Check if user is already banned
        existing_ban = (
            self.db.query(UserBan)
            .filter(
                UserBan.user_id == user_id,
                UserBan.is_active == True,  # noqa: E712
            )
            .first()
        )
        
        if existing_ban:
            return existing_ban
        
        # Count previous bans
        ban_count = self.db.query(UserBan).filter(UserBan.user_id == user_id).count()
        
        # Create ban
        ban = UserBan(
            user_id=user_id,
            issued_by=issued_by,
            reason=reason,
            is_permanent=is_permanent,
            expires_at=datetime.utcnow() + timedelta(days=duration_days) if duration_days else None,
            previous_bans=ban_count,
            violation_ids=[],  # TODO: Link to relevant violations
        )
        
        self.db.add(ban)
        self.db.commit()
        self.db.refresh(ban)
        
        return ban
    
    async def create_appeal(
        self, appeal_data: AppealRequest, user: User
    ) -> AppealResponse:
        """Create an appeal for a moderation action"""
        violation = (
            self.db.query(ContentViolation)
            .filter(
                ContentViolation.id == appeal_data.violation_id,
                ContentViolation.user_id == user.id,
            )
            .first()
        )
        
        if not violation:
            raise ValueError("Violation not found or access denied")
        
        # Check if appeal already exists
        existing_appeal = (
            self.db.query(ModerationAppeal)
            .filter(ModerationAppeal.violation_id == violation.id)
            .first()
        )
        
        if existing_appeal:
            raise ValueError("Appeal already exists for this violation")
        
        # Create appeal
        appeal = ModerationAppeal(
            violation_id=violation.id,
            user_id=user.id,
            reason=appeal_data.reason,
            status=ModerationStatus.PENDING,
            submitted_at=datetime.utcnow(),
        )
        
        self.db.add(appeal)
        self.db.commit()
        self.db.refresh(appeal)
        
        # Update violation status
        violation.status = ModerationStatus.APPEALED
        self.db.commit()
        
        return AppealResponse(
            id=appeal.id,
            status=appeal.status,
            submitted_at=appeal.submitted_at,
        )
    
    async def process_appeal(
        self, appeal_id: int, decision: ModerationAction, moderator: User, notes: str = ""
    ) -> ModerationAppeal:
        """Process a user appeal"""
        appeal = (
            self.db.query(ModerationAppeal)
            .filter(ModerationAppeal.id == appeal_id)
            .first()
        )
        
        if not appeal:
            raise ValueError("Appeal not found")
        
        # Update appeal
        appeal.status = ModerationStatus.RESOLVED if decision != ModerationAction.UNDER_REVIEW else ModerationStatus.IN_REVIEW
        appeal.resolution = notes
        appeal.resolved_by = moderator.id
        appeal.resolved_at = datetime.utcnow()
        
        # Update violation
        violation = appeal.violation
        if decision != ModerationAction.UNDER_REVIEW:
            violation.status = ModerationStatus.RESOLVED
            violation.action_taken = decision
            violation.resolved_at = datetime.utcnow()
        
        # Create review record
        review = ModerationReview(
            violation_id=violation.id,
            moderator_id=moderator.id,
            decision=decision,
            notes=notes,
            is_confirmed=True,
        )
        
        self.db.add(review)
        self.db.commit()
        self.db.refresh(appeal)
        
        return appeal
    
    async def add_content_filter(
        self, filter_data: ContentFilterCreate, user_id: int
    ) -> ContentFilter:
        """Add a content filter for a user"""
        # Check if filter already exists
        existing_filter = (
            self.db.query(ContentFilter)
            .filter(
                ContentFilter.user_id == user_id,
                ContentFilter.filter_type == filter_data.filter_type,
                ContentFilter.filter_value == filter_data.filter_value,
            )
            .first()
        )
        
        if existing_filter:
            if not existing_filter.is_active:
                existing_filter.is_active = True
                self.db.commit()
                self.db.refresh(existing_filter)
            return existing_filter
        
        # Create new filter
        content_filter = ContentFilter(
            user_id=user_id,
            filter_name=filter_data.filter_name,
            filter_type=filter_data.filter_type,
            filter_value=filter_data.filter_value,
            is_active=True,
        )
        
        self.db.add(content_filter)
        self.db.commit()
        self.db.refresh(content_filter)
        
        return content_filter
    
    async def remove_content_filter(self, filter_id: int, user_id: int) -> bool:
        """Remove or deactivate a content filter"""
        content_filter = (
            self.db.query(ContentFilter)
            .filter(
                ContentFilter.id == filter_id,
                ContentFilter.user_id == user_id,
            )
            .first()
        )
        
        if not content_filter:
            return False
        
        # Soft delete by deactivating
        content_filter.is_active = False
        self.db.commit()
        
        return True
    
    async def _matches_user_filters(
        self, content_request: ContentScanRequest, user_id: int
    ) -> bool:
        """Check if content matches any of the user's filters"""
        # Get user's active filters
        filters = (
            self.db.query(ContentFilter)
            .filter(
                ContentFilter.user_id == user_id,
                ContentFilter.is_active == True,  # noqa: E712
            )
            .all()
        )
        
        for filter_ in filters:
            # Simple contains check - in a real app, this would be more sophisticated
            if filter_.filter_type == "keyword" and filter_.filter_value.lower() in content_request.content_preview.lower():
                return True
                
        return False
    
    # Placeholder detection methods - would be implemented with actual ML models
    async def _detect_csam(self, content_request: ContentScanRequest) -> bool:
        """Detect CSAM content (placeholder)"""
        # TODO: Implement actual CSAM detection
        return False
    
    async def _detect_bestiality(self, content_request: ContentScanRequest) -> bool:
        """Detect bestiality content (placeholder)"""
        # TODO: Implement actual bestiality detection
        return False
    
    async def _detect_violence(self, content_request: ContentScanRequest) -> bool:
        """Detect violent content (placeholder)"""
        # TODO: Implement actual violence detection
        return False
