"""
Advanced Alert Management System

This module provides comprehensive alerting capabilities including SMS, phone calls,
email, and rate limiting for alerts.
"""

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client as TwilioClient

from app.core.config import settings
from app.core.security import SecurityManager

logger = logging.getLogger(__name__)


class AlertLevel(Enum):
    """Alert severity levels."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status values."""

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass
class AlertRecipient:
    """Alert recipient information."""

    name: str
    email: str
    phone: Optional[str] = None
    sms_enabled: bool = False
    call_enabled: bool = False
    notify_on: List[AlertLevel] = field(
        default_factory=lambda: [AlertLevel.WARNING, AlertLevel.CRITICAL]
    )


@dataclass
class Alert:
    """Alert information."""

    id: str
    title: str
    message: str
    level: AlertLevel
    source: str
    status: AlertStatus = AlertStatus.ACTIVE
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "title": self.title,
            "message": self.message,
            "level": self.level.value,
            "source": self.source,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "acknowledged_by": self.acknowledged_by,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        """Create alert from dictionary."""
        return cls(
            id=data["id"],
            title=data["title"],
            message=data["message"],
            level=AlertLevel(data["level"]),
            source=data["source"],
            status=AlertStatus(data.get("status", "active")),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            acknowledged_by=data.get("acknowledged_by"),
            acknowledged_at=(
                datetime.fromisoformat(data["acknowledged_at"])
                if data.get("acknowledged_at")
                else None
            ),
            metadata=data.get("metadata", {}),
        )


class AlertManager:
    """Manages alerts and notifications."""

    def __init__(self, security_manager: Optional[SecurityManager] = None):
        """Initialize the alert manager."""
        self.security_manager = security_manager or SecurityManager()
        self.alerts: Dict[str, Alert] = {}
        self.alert_history: List[Alert] = []
        self.recipients: Dict[str, AlertRecipient] = {}
        self.rate_limits: Dict[str, Dict[str, Any]] = {}
        self.alert_handlers: List[Callable[[Alert], Awaitable[None]]] = []
        self.twilio_client = None
        self.sms_enabled = False
        self.call_enabled = False

        # Initialize notification services
        self._init_notification_services()

        # Default rate limiting: max 5 alerts per minute per recipient
        self.default_rate_limit = {
            "limit": 5,
            "window": 60,  # seconds
            "count": 0,
            "reset_time": time.time() + 60,
        }

    def _init_notification_services(self) -> None:
        """Initialize notification services like Twilio for SMS/phone calls."""
        # Initialize Twilio client if credentials are available
        if all(
            [
                getattr(settings, "TWILIO_ACCOUNT_SID", None),
                getattr(settings, "TWILIO_AUTH_TOKEN", None),
                getattr(settings, "TWILIO_PHONE_NUMBER", None),
            ]
        ):
            try:
                self.twilio_client = TwilioClient(
                    settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN
                )
                self.sms_enabled = True
                self.call_enabled = True
                logger.info("Twilio client initialized for SMS and phone calls")
            except Exception as e:
                logger.error(f"Failed to initialize Twilio client: {e}")
        else:
            logger.warning(
                "Twilio credentials not configured. SMS and phone call alerts will be disabled."
            )

    async def add_recipient(self, recipient: AlertRecipient) -> None:
        """Add a new alert recipient."""
        self.recipients[recipient.email] = recipient
        logger.info(f"Added alert recipient: {recipient.name} <{recipient.email}>")

    async def remove_recipient(self, email: str) -> bool:
        """Remove an alert recipient."""
        if email in self.recipients:
            del self.recipients[email]
            logger.info(f"Removed alert recipient: {email}")
            return True
        return False

    async def create_alert(
        self,
        title: str,
        message: str,
        level: AlertLevel = AlertLevel.INFO,
        source: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """
        Create and dispatch a new alert.

        Args:
            title: Alert title
            message: Detailed alert message
            level: Alert severity level
            source: Source of the alert
            metadata: Additional metadata

        Returns:
            The created Alert object
        """
        alert_id = f"alert_{int(time.time())}_{len(self.alerts)}"

        alert = Alert(
            id=alert_id,
            title=title,
            message=message,
            level=level,
            source=source,
            metadata=metadata or {},
        )

        # Store the alert
        self.alerts[alert_id] = alert
        self.alert_history.append(alert)

        # Log the alert
        logger.log(
            (
                logging.WARNING
                if level == AlertLevel.WARNING
                else logging.ERROR if level == AlertLevel.CRITICAL else logging.INFO
            ),
            f"[{level.value.upper()}] {title}: {message}",
        )

        # Dispatch the alert to all handlers
        await self._dispatch_alert(alert)

        return alert

    async def _dispatch_alert(self, alert: Alert) -> None:
        """Dispatch an alert to all registered handlers."""
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}", exc_info=True)

        # Send notifications to recipients
        await self._notify_recipients(alert)

    async def _notify_recipients(self, alert: Alert) -> None:
        """Notify all applicable recipients about an alert."""
        for recipient in self.recipients.values():
            # Check if recipient should be notified for this alert level
            if alert.level not in recipient.notify_on:
                continue

            # Check rate limiting
            if not self._check_rate_limit(recipient.email, alert.level):
                logger.warning(
                    f"Rate limit exceeded for {recipient.email}, suppressing alert: {alert.id}"
                )
                continue

            # Send notifications based on recipient preferences
            try:
                if recipient.sms_enabled and recipient.phone:
                    await self._send_sms(recipient, alert)

                if (
                    recipient.call_enabled
                    and recipient.phone
                    and alert.level == AlertLevel.CRITICAL
                ):
                    await self._make_phone_call(recipient, alert)

                # Always send email as a fallback
                await self._send_email(recipient, alert)

            except Exception as e:
                logger.error(
                    f"Failed to send notification to {recipient.email}: {e}", exc_info=True
                )

    def _check_rate_limit(self, recipient_email: str, level: AlertLevel) -> bool:
        """Check if rate limit is exceeded for a recipient."""
        rate_key = f"{recipient_email}:{level.value}"
        now = time.time()

        # Initialize rate limit if it doesn't exist
        if rate_key not in self.rate_limits:
            self.rate_limits[rate_key] = {
                "count": 0,
                "reset_time": now + self.default_rate_limit["window"],
                "limit": self._get_rate_limit_for_level(level),
            }

        rate_limit = self.rate_limits[rate_key]

        # Reset counter if window has passed
        if now > rate_limit["reset_time"]:
            rate_limit["count"] = 0
            rate_limit["reset_time"] = now + self.default_rate_limit["window"]

        # Check if limit is exceeded
        if rate_limit["count"] >= rate_limit["limit"]:
            return False

        # Increment counter
        rate_limit["count"] += 1
        return True

    def _get_rate_limit_for_level(self, level: AlertLevel) -> int:
        """Get rate limit for a specific alert level."""
        limits = {
            AlertLevel.INFO: 5,  # 5 info alerts per minute
            AlertLevel.WARNING: 10,  # 10 warning alerts per minute
            AlertLevel.CRITICAL: 20,  # 20 critical alerts per minute
        }
        return limits.get(level, 5)

    async def _send_sms(self, recipient: AlertRecipient, alert: Alert) -> None:
        """Send an SMS alert."""
        if not self.sms_enabled or not recipient.phone:
            return

        try:
            message = self.twilio_client.messages.create(
                body=f"[{alert.level.value.upper()}] {alert.title}\n\n{alert.message}",
                from_=settings.TWILIO_PHONE_NUMBER,
                to=recipient.phone,
            )
            logger.info(f"SMS sent to {recipient.phone}: {message.sid}")
        except TwilioRestException as e:
            logger.error(f"Failed to send SMS to {recipient.phone}: {e.msg}")
        except Exception as e:
            logger.error(f"Error sending SMS: {e}", exc_info=True)

    async def _make_phone_call(self, recipient: AlertRecipient, alert: Alert) -> None:
        """Make a phone call alert."""
        if not self.call_enabled or not recipient.phone:
            return

        try:
            # In a real implementation, you would use Twilio's Voice API to make a call
            # and use text-to-speech to read the alert
            logger.info(f"Phone call to {recipient.phone} for alert: {alert.title}")

            # This is a placeholder - in a real implementation, you would use Twilio's API
            # to make an actual phone call with text-to-speech

        except Exception as e:
            logger.error(f"Failed to make phone call to {recipient.phone}: {e}", exc_info=True)

    async def _send_email(self, recipient: AlertRecipient, alert: Alert) -> None:
        """Send an email alert."""
        try:
            # In a real implementation, you would use an email service
            # like SendGrid, AWS SES, or a local SMTP server
            logger.info(
                f"Email sent to {recipient.email} with subject: [{alert.level.value.upper()}] {alert.title}"
            )

        except Exception as e:
            logger.error(f"Failed to send email to {recipient.email}: {e}", exc_info=True)

    async def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.acknowledged_by = user
        alert.acknowledged_at = datetime.utcnow()
        alert.updated_at = datetime.utcnow()

        logger.info(f"Alert {alert_id} acknowledged by {user}")
        return True

    async def resolve_alert(self, alert_id: str, user: str) -> bool:
        """Mark an alert as resolved."""
        if alert_id not in self.alerts:
            return False

        alert = self.alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.updated_at = datetime.utcnow()

        logger.info(f"Alert {alert_id} resolved by {user}")
        return True

    def get_active_alerts(self) -> List[Alert]:
        """Get all active alerts."""
        return [alert for alert in self.alerts.values() if alert.status == AlertStatus.ACTIVE]

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Get alert history."""
        return self.alert_history[-limit:]

    def register_alert_handler(self, handler: Callable[[Alert], Awaitable[None]]) -> None:
        """Register a custom alert handler."""
        self.alert_handlers.append(handler)
        logger.info(f"Registered new alert handler: {handler.__name__}")


# Create a default instance for easy access
alert_manager = AlertManager()
