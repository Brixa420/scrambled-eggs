"""Audit logging for security events and system activities."""

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from flask import current_app, g, has_request_context, request

from .config import get_config
from .utils import security_utils

# Initialize config
config = get_config()


class AuditLogger:
    """Audit logger for security events and system activities."""

    def __init__(self, app=None):
        """Initialize the audit logger."""
        self.app = app
        self.logger = None

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """Initialize the audit logger with the Flask app."""
        # Configure the audit logger
        log_dir = Path(app.config.get("LOG_DIR", "logs"))
        log_dir.mkdir(exist_ok=True)

        log_file = log_dir / "audit.log"

        # Create a formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S %Z"
        )

        # Create a file handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            filename=log_file, maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"  # 10MB
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        # Create a console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)

        # Configure the root logger
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

        # Remove any existing handlers
        for handler in self.logger.handlers[:]:
            self.logger.removeHandler(handler)

        # Add the handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)

        # Prevent the log messages from being propagated to the root logger
        self.logger.propagate = False

        # Store the logger on the app
        app.extensions["audit_logger"] = self

        # Log application startup
        self.log_event(
            "application_startup",
            message="Application started",
            level="info",
            meta={"python_version": sys.version, "platform": sys.platform, "argv": sys.argv},
        )

    def log_event(
        self,
        event_type: str,
        message: str,
        level: str = "info",
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        request_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a security or audit event.

        Args:
            event_type: Type of event (e.g., 'login_success', 'login_failed', 'password_reset')
            message: Human-readable description of the event
            level: Log level ('debug', 'info', 'warning', 'error', 'critical')
            user_id: ID of the user associated with the event (if any)
            ip_address: IP address where the event originated
            request_id: ID of the request (if applicable)
            meta: Additional metadata about the event
        """
        if not self.logger:
            return

        # Get the current timestamp in UTC
        timestamp = datetime.now(timezone.utc).isoformat()

        # Get request context if available
        if has_request_context():
            if not ip_address:
                ip_address = request.remote_addr
            if not request_id and hasattr(g, "request_id"):
                request_id = g.request_id
            if not user_id and hasattr(g, "user") and g.user:
                user_id = str(g.user.id)

        # Prepare the log entry
        log_entry = {
            "timestamp": timestamp,
            "event_type": event_type,
            "level": level.upper(),
            "message": message,
            "user_id": user_id,
            "ip_address": ip_address,
            "request_id": request_id,
            "meta": meta or {},
        }

        # Add request details if available
        if has_request_context():
            log_entry.update(
                {
                    "http_method": request.method,
                    "path": request.path,
                    "endpoint": request.endpoint,
                    "user_agent": request.user_agent.string if request.user_agent else None,
                    "referrer": request.referrer,
                    "query_params": dict(request.args),
                }
            )

        # Log the event
        log_method = getattr(self.logger, level.lower(), self.logger.info)
        log_method(json.dumps(log_entry, default=str))

        # Also log to standard output in development
        if current_app and current_app.debug:
            print(f"[AUDIT] {timestamp} - {event_type} - {message}")

    def log_security_event(
        self,
        event_type: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[Union[str, Dict[str, Any]]] = None,
    ) -> None:
        """
        Log a security-related event.

        Args:
            event_type: Type of security event
            user_id: ID of the user associated with the event (if any)
            ip_address: IP address where the event originated
            details: Additional details about the event
        """
        # Map event types to log levels
        event_levels = {
            # Authentication events
            "login_success": "info",
            "login_failed": "warning",
            "logout": "info",
            "password_changed": "info",
            "password_reset_requested": "info",
            "password_reset_success": "info",
            "account_locked": "warning",
            "account_unlocked": "info",
            "account_created": "info",
            "account_deleted": "warning",
            "account_updated": "info",
            # Authorization events
            "permission_denied": "warning",
            "role_changed": "info",
            "permission_granted": "info",
            "permission_revoked": "info",
            # Security events
            "csrf_validation_failed": "warning",
            "rate_limit_exceeded": "warning",
            "suspicious_activity": "warning",
            "security_alert": "error",
            "security_breach": "critical",
            "file_upload": "info",
            "file_download": "info",
            "file_deleted": "warning",
            "configuration_changed": "info",
            "system_error": "error",
            # Default level
            "default": "info",
        }

        # Get the log level for this event type
        level = event_levels.get(event_type, event_levels["default"])

        # Log the event
        self.log_event(
            event_type=event_type,
            message=f"Security event: {event_type}",
            level=level,
            user_id=user_id,
            ip_address=ip_address,
            meta={"details": details} if details else None,
        )

    def log_activity(
        self,
        activity_type: str,
        message: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log a user or system activity.

        Args:
            activity_type: Type of activity
            message: Description of the activity
            user_id: ID of the user who performed the activity
            ip_address: IP address where the activity originated
            meta: Additional metadata about the activity
        """
        self.log_event(
            event_type=f"activity_{activity_type}",
            message=message,
            level="info",
            user_id=user_id,
            ip_address=ip_address,
            meta=meta,
        )


# Create an instance for easy importing
audit_logger = AuditLogger()
