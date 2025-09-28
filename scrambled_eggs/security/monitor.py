"""
Security monitoring system for detecting and responding to potential breaches.
"""
import time
import random
import logging
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)

class BreachSeverity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class SecurityEvent:
    event_type: str
    severity: BreachSeverity
    details: Dict
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()

class SecurityMonitor:
    """Monitors for security events and triggers appropriate responses."""
    
    def __init__(self, ai_alert_callback: Optional[Callable] = None):
        self.failed_attempts = {}
        self.breach_detected = False
        self.ai_alert_callback = ai_alert_callback
        self.active_layers = 1  # Start with basic encryption
        self.last_breach_time = 0
        self.breach_cooldown = 300  # 5 minutes cooldown between breach responses
        
        # Thresholds for breach detection
        self.max_attempts_per_minute = 10
        self.suspicious_patterns = [
            "brute_force",
            "timing_attack",
            "replay_attack",
            "key_compromise"
        ]
        
        logger.info("Security monitor initialized")
    
    def log_attempt(self, client_id: str, success: bool, metadata: Optional[Dict] = None):
        """Log an authentication or decryption attempt."""
        now = time.time()
        
        # Initialize client tracking if needed
        if client_id not in self.failed_attempts:
            self.failed_attempts[client_id] = {
                'attempts': [],
                'last_attempt': 0,
                'suspicion_level': 0
            }
        
        client = self.failed_attempts[client_id]
        client['attempts'].append((now, success, metadata))
        client['last_attempt'] = now
        
        # Clean up old attempts (older than 1 minute)
        client['attempts'] = [a for a in client['attempts'] if now - a[0] < 60]
        
        # Check for suspicious activity
        recent_failures = sum(1 for a in client['attempts'] if not a[1])
        
        if recent_failures > self.max_attempts_per_minute:
            self.detect_breach(
                "rate_limit_exceeded",
                BreachSeverity.HIGH,
                {
                    'attempts': recent_failures,
                    'metadata': metadata
                }
            )
    
    def log_activity(self, activity_type: str):
        """Log normal system activity.
        
        Args:
            activity_type: Type of normal activity (e.g., 'normal_traffic')
        """
        # This is a no-op for now, but could be used for baseline behavior analysis
        pass
        
    def detect_breach(self, breach_type: str, severity: BreachSeverity, details: Dict) -> bool:
        """Detect a potential security breach and trigger response.
        
        Returns:
            bool: True if a breach was detected, False otherwise
        """
        now = time.time()
        
        # Check if we're still in cooldown from the last breach
        if now - self.last_breach_time < self.breach_cooldown:
            return False
        
        # Log the breach
        self.breach_detected = True
        self.last_breach_time = now
        
        # Update suspicion level for the client if available
        client_id = details.get('client_id')
        if client_id and client_id in self.failed_attempts:
            self.failed_attempts[client_id]['suspicion_level'] += 1
        
        # Trigger AI alert if configured
        if self.ai_alert_callback:
            try:
                self.ai_alert_callback(breach_type, severity, details)
            except Exception as e:
                logger.error(f"Error in AI alert callback: {e}")
        
        logger.warning(
            f"Security breach detected: {breach_type} (Severity: {severity.name})"
            f" - Details: {details}"
        )
        
        return True
