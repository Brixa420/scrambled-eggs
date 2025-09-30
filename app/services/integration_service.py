"""
Integration Service for Brixa Platform

This module handles the integration between different components of the system,
including AI moderation, blockchain, and the reporting system.
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from sqlalchemy.orm import Session

from app.services.ai_moderation import AIModerationService
from app.services.blockchain_moderation import BlockchainModerationService
from app.services.staking import StakingService
from app.services.reward_service import RewardService
from app.services.appeal_service import AppealService
from app.models.user import User
from app.models.moderation import ContentViolation, ModerationAction, ModerationStatus
from app.schemas.moderation import ContentScanResult, ReportCreate

logger = logging.getLogger(__name__)

class BrixaIntegrationService:
    """Service for integrating various components of the Brixa platform"""
    
    def __init__(self, db: Session):
        """Initialize the integration service with required components"""
        self.db = db
        self.ai_moderation = AIModerationService()
        self.blockchain = BlockchainModerationService(db)
        self.staking = StakingService(db, self.blockchain)
        self.rewards = RewardService(db, self.blockchain)
        self.appeals = AppealService(db, self.blockchain)
        
    async def process_content(self, content: Dict[str, Any]) -> ContentScanResult:
        """
        Process content through the entire moderation pipeline
        
        Args:
            content: Dictionary containing content data and metadata
            
        Returns:
            ContentScanResult with moderation results
        """
        try:
            # 1. Run AI moderation
            scan_result = await self.ai_moderation.moderate_content(content)
            
            # 2. If violations found, take appropriate actions
            if scan_result.has_violations:
                await self._handle_violations(scan_result, content)
                
            # 3. Update user reputation based on content quality
            await self._update_user_reputation(
                user_id=content['user_id'],
                has_violations=scan_result.has_violations,
                severity=scan_result.highest_severity
            )
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Error processing content: {e}", exc_info=True)
            raise
    
    async def submit_report(self, report: ReportCreate, reporter: User) -> Dict[str, Any]:
        """
        Process a user report
        
        Args:
            report: Report data
            reporter: User submitting the report
            
        Returns:
            Dict with report status and details
        """
        try:
            # 1. Create report record
            report_data = report.dict()
            report_data['reporter_id'] = reporter.id
            report_data['status'] = ModerationStatus.PENDING
            
            # In a real implementation, save to database
            # report_record = ContentReport(**report_data)
            # self.db.add(report_record)
            # self.db.commit()
            
            # 2. If reporter has staked tokens, give weight to their report
            if await self.staking.has_min_stake(reporter.id):
                report_data['weight'] = 2.0  # Higher weight for staked users
            
            # 3. Log the report on the blockchain
            tx_hash = await self.blockchain.record_moderation_action(
                moderator_id=reporter.id,
                target_id=report.content_id,
                action_type='report',
                reason=report.reason
            )
            
            # 4. Check if this report triggers any automatic actions
            report_count = 3  # Would come from database in real implementation
            if report_count >= 3:  # Threshold for auto-review
                await self._escalate_report(report_data)
            
            return {
                "success": True,
                "report_id": 1,  # Would be report_record.id in real implementation
                "tx_hash": tx_hash
            }
            
        except Exception as e:
            logger.error(f"Error submitting report: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    async def _handle_violations(self, scan_result: ContentScanResult, content: Dict[str, Any]) -> None:
        """Handle content violations by taking appropriate actions"""
        # 1. Record the violation
        violation = ContentViolation(
            content_id=content['id'],
            content_type=content['type'],
            violation_type=scan_result.highest_severity_violation,
            confidence=scan_result.highest_confidence,
            details={
                'violations': [v.dict() for v in scan_result.violations],
                'content_preview': content.get('preview', '')[:200]  # Store preview
            },
            status=ModerationStatus.PENDING,
            reported_at=datetime.utcnow()
        )
        
        # In a real implementation, save to database
        # self.db.add(violation)
        # self.db.commit()
        
        # 2. Take automatic action based on violation severity
        if scan_result.highest_severity in ['high', 'critical']:
            await self._take_moderation_action(
                content_id=content['id'],
                user_id=content['user_id'],
                action_type='remove_content',
                reason=f"Automated removal: {scan_result.highest_severity_violation}",
                severity=scan_result.highest_severity
            )
    
    async def _take_moderation_action(
        self,
        content_id: str,
        user_id: int,
        action_type: str,
        reason: str,
        severity: str = 'medium',
        moderator_id: Optional[int] = None
    ) -> Dict[str, Any]:
        """Take moderation action and update all relevant systems"""
        try:
            # 1. Record the action
            action = ModerationAction(
                content_id=content_id,
                user_id=user_id,
                moderator_id=moderator_id,
                action_type=action_type,
                reason=reason,
                severity=severity,
                status=ModerationStatus.COMPLETED,
                created_at=datetime.utcnow()
            )
            
            # In a real implementation, save to database
            # self.db.add(action)
            # self.db.commit()
            
            # 2. Update blockchain
            tx_hash = await self.blockchain.record_moderation_action(
                moderator_id=moderator_id or 0,  # 0 for system actions
                target_id=content_id,
                action_type=action_type,
                reason=reason,
                severity=severity
            )
            
            # 3. Update user reputation
            await self._update_user_reputation(
                user_id=user_id,
                has_violations=True,
                severity=severity,
                action_type=action_type
            )
            
            # 4. If this was a manual action by a moderator, reward them
            if moderator_id and moderator_id > 0:
                await self.rewards.distribute_rewards(
                    user_id=moderator_id,
                    action_type='moderation',
                    content_id=content_id
                )
            
            return {
                "success": True,
                "action_id": 1,  # Would be action.id in real implementation
                "tx_hash": tx_hash
            }
            
        except Exception as e:
            logger.error(f"Error taking moderation action: {e}", exc_info=True)
            return {"success": False, "error": str(e)}
    
    async def _update_user_reputation(
        self,
        user_id: int,
        has_violations: bool,
        severity: str = 'medium',
        action_type: Optional[str] = None
    ) -> None:
        """Update user reputation based on content and actions"""
        try:
            # Calculate reputation change
            if has_violations:
                # Penalize for violations
                severity_multiplier = {
                    'low': 1,
                    'medium': 2,
                    'high': 5,
                    'critical': 10
                }.get(severity.lower(), 1)
                
                reputation_change = -5 * severity_multiplier
            else:
                # Reward for clean content
                reputation_change = 1
            
            # Update reputation on blockchain
            await self.blockchain.update_reputation(
                user_id=user_id,
                amount=reputation_change,
                reason=f"Content moderation: {action_type or 'automatic'}"
            )
            
        except Exception as e:
            logger.error(f"Error updating user reputation: {e}", exc_info=True)
    
    async def _escalate_report(self, report: Dict[str, Any]) -> None:
        """Escalate a report for review by senior moderators"""
        # In a real implementation, this would:
        # 1. Notify senior moderators
        # 2. Update report status
        # 3. Potentially take automatic actions
        pass

    # Add more integration methods as needed
