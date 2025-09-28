"""
Security Manager for Scrambled Eggs

Manages security policies, handles security events, and enforces access controls.
"""
import logging
import json
import time
from typing import Dict, List, Optional, Set, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum, auto
from datetime import datetime, timedelta
import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

from ..core.crypto import CryptoEngine
from .ai_orchestrator import AICryptoOrchestrator
from .gate_system import GateSystem, GateType

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels for the system."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    PARANOID = 4

class SecurityEventType(Enum):
    """Types of security events that can be detected."""
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    ANOMALY_DETECTED = "anomaly_detected"
    SYSTEM_COMPROMISE = "system_compromise"
    PASSWORD_GUESS = "password_guess"
    SESSION_HIJACK = "session_hijack"
    MALICIOUS_INPUT = "malicious_input"
    CONFIG_CHANGE = "config_change"
    KEY_ROTATION = "key_rotation"
    GATE_COMPROMISE = "gate_compromise"
    NETWORK_INTRUSION = "network_intrusion"
    DATA_LEAK = "data_leak"
    CRYPTO_FAILURE = "crypto_failure"
    RESOURCE_ABUSE = "resource_abuse"
    PRIVILEGE_ESCALATION = "privilege_escalation"

@dataclass
class SecurityEvent:
    """Represents a security event that occurred in the system."""
    event_type: SecurityEventType
    severity: SecurityLevel
    source: str
    description: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    details: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    event_id: str = field(init=False)
    
    def __post_init__(self):
        """Generate a unique event ID."""
        event_str = f"{self.timestamp.isoformat()}-{self.event_type.value}-{self.source}"
        self.event_id = hashlib.sha256(event_str.encode()).hexdigest()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serializable dictionary."""
        return {
            'event_id': self.event_id,
            'event_type': self.event_type.value,
            'severity': self.severity.name,
            'source': self.source,
            'description': self.description,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details,
            'resolved': self.resolved
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityEvent':
        """Create from a dictionary."""
        event = cls(
            event_type=SecurityEventType(data['event_type']),
            severity=SecurityLevel[data['severity']],
            source=data['source'],
            description=data['description'],
            timestamp=datetime.fromisoformat(data['timestamp']),
            details=data.get('details', {}),
            resolved=data.get('resolved', False)
        )
        event.event_id = data['event_id']
        return event

class SecurityPolicy:
    """Defines security policies for the system."""
    
    def __init__(self):
        self.policies = self._load_default_policies()
    
    def _load_default_policies(self) -> Dict[str, Any]:
        """Load default security policies."""
        return {
            'authentication': {
                'max_login_attempts': 5,
                'lockout_time': 300,  # 5 minutes
                'session_timeout': 3600,  # 1 hour
                'password_min_length': 12,
                'password_complexity': {
                    'require_uppercase': True,
                    'require_lowercase': True,
                    'require_digits': True,
                    'require_special_chars': True,
                    'min_entropy': 3.0  # bits per character
                }
            },
            'network': {
                'max_requests_per_minute': 100,
                'max_connections_per_ip': 50,
                'blacklist_duration': 86400,  # 24 hours
                'rate_limit_window': 60,  # 1 minute
                'enable_tor': False,
                'require_encryption': True
            },
            'crypto': {
                'key_rotation_interval': 86400,  # 24 hours
                'min_key_strength': 256,  # bits
                'preferred_algorithms': [
                    'AES-256-GCM',
                    'ChaCha20-Poly1305',
                    'RSA-4096',
                    'ECDSA-SHA512'
                ],
                'forbidden_algorithms': [
                    'DES',
                    'RC4',
                    'MD5',
                    'SHA1'
                ]
            },
            'logging': {
                'retention_days': 90,
                'log_sensitive_data': False,
                'log_failed_attempts': True,
                'log_successful_logins': True
            },
            'monitoring': {
                'enable_intrusion_detection': True,
                'anomaly_threshold': 3.0,  # Standard deviations
                'alert_on_high_severity': True,
                'alert_emails': ['security@example.com']
            }
        }
    
    def get_policy(self, section: str, key: str = None, default=None) -> Any:
        """Get a policy value by section and optional key."""
        if section not in self.policies:
            return default
            
        if key is None:
            return self.policies[section]
            
        return self.policies[section].get(key, default)
    
    def update_policy(self, section: str, key: str, value: Any) -> bool:
        """Update a policy value."""
        if section not in self.policies:
            return False
            
        if key not in self.policies[section]:
            return False
            
        self.policies[section][key] = value
        return True

class SecurityManager:
    """Manages security policies and handles security events."""
    
    def __init__(self, crypto_engine: CryptoEngine, gate_system: GateSystem):
        self.crypto_engine = crypto_engine
        self.gate_system = gate_system
        self.ai_orchestrator = AICryptoOrchestrator(crypto_engine)
        self.security_level = SecurityLevel.MEDIUM
        self.security_events: List[SecurityEvent] = []
        self.blacklisted_ips: Set[str] = set()
        self.rate_limits: Dict[str, List[datetime]] = {}
        self.failed_attempts: Dict[str, int] = {}
        self.locked_accounts: Dict[str, datetime] = {}
        self.active_sessions: Dict[str, Dict] = {}
        self.policy = SecurityPolicy()
        self.audit_log: List[Dict] = []
        self._load_state()
        
        # Initialize security metrics
        self.metrics = {
            'events_processed': 0,
            'threats_blocked': 0,
            'failed_logins': 0,
            'successful_logins': 0,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def _load_state(self) -> None:
        """Load security manager state from persistent storage."""
        try:
            # In a real implementation, this would load from a secure storage
            # For now, we'll just initialize with defaults
            pass
        except Exception as e:
            logger.error(f"Failed to load security state: {str(e)}")
    
    def _save_state(self) -> None:
        """Save security manager state to persistent storage."""
        try:
            # In a real implementation, this would save to a secure storage
            pass
        except Exception as e:
            logger.error(f"Failed to save security state: {str(e)}")
    
    def _log_audit_event(self, action: str, status: str, details: Dict = None) -> None:
        """Log an audit event."""
        if details is None:
            details = {}
            
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': action,
            'status': status,
            'source_ip': details.get('source_ip', 'unknown'),
            'user': details.get('user', 'system'),
            'details': {k: v for k, v in details.items() if k not in ['source_ip', 'user']}
        }
        
        self.audit_log.append(event)
        logger.info(f"AUDIT: {action} - {status}")
    
    def handle_event(self, event: SecurityEvent) -> None:
        """Handle a security event."""
        self.security_events.append(event)
        self.metrics['events_processed'] += 1
        
        # Log the event
        logger.warning(
            f"Security event: {event.event_type.value} - {event.description} "
            f"(Severity: {event.severity.name})"
        )
        
        # Update threat level based on event severity
        self._update_threat_level(event)
        
        # Take appropriate action based on event type
        if event.event_type == SecurityEventType.BRUTE_FORCE_ATTEMPT:
            self._handle_brute_force(event)
        elif event.event_type == SecurityEventType.UNAUTHORIZED_ACCESS:
            self._handle_unauthorized_access(event)
        elif event.event_type == SecurityEventType.RATE_LIMIT_EXCEEDED:
            self._handle_rate_limit(event)
        elif event.event_type == SecurityEventType.ANOMALY_DETECTED:
            self._handle_anomaly(event)
        elif event.event_type == SecurityEventType.SYSTEM_COMPROMISE:
            self._handle_compromise(event)
        elif event.event_type == SecurityEventType.SESSION_HIJACK:
            self._handle_session_hijack(event)
        elif event.event_type == SecurityEventType.KEY_ROTATION:
            self._handle_key_rotation(event)
        
        # Update metrics
        self.metrics['last_updated'] = datetime.utcnow().isoformat()
        self._save_state()
    
    def _update_threat_level(self, event: SecurityEvent) -> None:
        """Update the current threat level based on security events."""
        # Define how much each severity level affects the threat score
        threat_score_increase = {
            SecurityLevel.LOW: 0.1,
            SecurityLevel.MEDIUM: 0.3,
            SecurityLevel.HIGH: 0.6,
            SecurityLevel.PARANOID: 1.0
        }.get(event.severity, 0.1)
        
        # Update the AI orchestrator's threat model
        self.ai_orchestrator.analyze_gate_performance(
            gate_id=0,  # Global threat level
            metrics={'threat_score': threat_score_increase}
        )
        
        # Check if we need to increase the security level
        current_threat = self._calculate_current_threat_level()
        if current_threat > self.security_level.value:
            self.increase_security_level()
    
    def _calculate_current_threat_level(self) -> float:
        """Calculate the current threat level based on recent events."""
        # In a real implementation, this would analyze recent events and metrics
        # to determine the current threat level
        return self.security_level.value
    
    def _handle_brute_force(self, event: SecurityEvent) -> None:
        """Handle brute force attack attempts."""
        source_ip = event.details.get('source_ip')
        if not source_ip:
            return
            
        # Update failed attempts counter
        self.failed_attempts[source_ip] = self.failed_attempts.get(source_ip, 0) + 1
        
        # Check if we should block this IP
        max_attempts = self.policy.get_policy('authentication', 'max_login_attempts', 5)
        if self.failed_attempts[source_ip] >= max_attempts:
            lockout_time = self.policy.get_policy('authentication', 'lockout_time', 300)
            self.blacklisted_ips.add(source_ip)
            self.locked_accounts[source_ip] = datetime.utcnow() + timedelta(seconds=lockout_time)
            
            logger.warning(f"IP {source_ip} blacklisted due to multiple failed login attempts")
            self._log_audit_event(
                'ip_blacklisted',
                'success',
                {
                    'ip': source_ip,
                    'reason': 'brute_force_attempt',
                    'failed_attempts': self.failed_attempts[source_ip],
                    'lockout_until': self.locked_accounts[source_ip].isoformat()
                }
            )
            
            # Rotate any affected encryption keys
            self._rotate_affected_keys(source_ip)
    
    def _handle_unauthorized_access(self, event: SecurityEvent) -> None:
        """Handle unauthorized access attempts."""
        # Increase security level
        self.increase_security_level()
        
        # Invalidate current sessions for the affected user/IP
        user_id = event.details.get('user_id')
        source_ip = event.details.get('source_ip')
        
        if user_id:
            self._invalidate_user_sessions(user_id)
        elif source_ip:
            self._invalidate_ip_sessions(source_ip)
        
        # Log the incident
        self._log_audit_event(
            'unauthorized_access_attempt',
            'blocked',
            {
                'user_id': user_id,
                'source_ip': source_ip,
                'details': event.details
            }
        )
    
    def _handle_rate_limit(self, event: SecurityEvent) -> None:
        """Handle rate limit violations."""
        source = event.details.get('source')
        if not source:
            return
            
        # Track rate limit violations
        if source not in self.rate_limits:
            self.rate_limits[source] = []
            
        now = datetime.utcnow()
        window = now - timedelta(seconds=60)  # 1-minute window
        
        # Remove old entries
        self.rate_limits[source] = [t for t in self.rate_limits[source] if t > window]
        
        # Add current timestamp
        self.rate_limits[source].append(now)
        
        # Check if we've exceeded the maximum allowed requests
        max_requests = self.policy.get_policy('network', 'max_requests_per_minute', 100)
        if len(self.rate_limits[source]) > max_requests:
            # Block this source
            blacklist_duration = self.policy.get_policy('network', 'blacklist_duration', 3600)
            self.blacklisted_ips.add(source)
            self.locked_accounts[source] = now + timedelta(seconds=blacklist_duration)
            
            logger.warning(f"Rate limit exceeded for {source}, blacklisted for {blacklist_duration} seconds")
            self._log_audit_event(
                'rate_limit_exceeded',
                'blocked',
                {
                    'source': source,
                    'request_count': len(self.rate_limits[source]),
                    'blacklist_until': self.locked_accounts[source].isoformat()
                }
            )
    
    def _handle_anomaly(self, event: SecurityEvent) -> None:
        """Handle detected anomalies."""
        # Analyze the anomaly using AI orchestrator
        gate_id = event.details.get('gate_id')
        if gate_id is not None:
            self.ai_orchestrator.analyze_gate_performance(
                gate_id=gate_id,
                metrics=event.details.get('metrics', {})
            )
        
        # Adjust security policies if needed
        if event.severity in [SecurityLevel.HIGH, SecurityLevel.PARANOID]:
            self.increase_security_level()
            
            # If this is a gate-related anomaly, consider rotating the affected gate
            if 'gate_id' in event.details:
                self._rotate_gate(event.details['gate_id'])
        
        # Log the anomaly
        self._log_audit_event(
            'anomaly_detected',
            'detected',
            {
                'gate_id': event.details.get('gate_id'),
                'severity': event.severity.name,
                'details': event.details
            }
        )
    
    def _handle_compromise(self, event: SecurityEvent) -> None:
        """Handle system compromise events."""
        # Go to maximum security level
        self.security_level = SecurityLevel.PARANOID
        
        # Rotate all encryption keys
        self._rotate_all_keys()
        
        # Invalidate all sessions
        self._invalidate_all_sessions()
        
        # Disable non-essential services
        self._disable_non_essential_services()
        
        # Alert administrators
        self._send_security_alert("SYSTEM COMPROMISE DETECTED", event.description)
        
        # Log the incident
        self._log_audit_event(
            'system_compromise',
            'critical',
            {
                'severity': 'critical',
                'action_taken': 'elevated_security_rotated_keys_invalidated_sessions',
                'details': event.details
            }
        )
    
    def _handle_session_hijack(self, event: SecurityEvent) -> None:
        """Handle session hijacking attempts."""
        session_id = event.details.get('session_id')
        user_id = event.details.get('user_id')
        
        # Invalidate the compromised session
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        
        # Invalidate all sessions for this user
        if user_id:
            self._invalidate_user_sessions(user_id)
        
        # Log the incident
        self._log_audit_event(
            'session_hijack_attempt',
            'mitigated',
            {
                'session_id': session_id,
                'user_id': user_id,
                'source_ip': event.details.get('source_ip')
            }
        )
        
        # Increase security level
        self.increase_security_level()
    
    def _handle_key_rotation(self, event: SecurityEvent) -> None:
        """Handle key rotation events."""
        key_type = event.details.get('key_type', 'all')
        
        if key_type == 'all':
            self._rotate_all_keys()
        else:
            self._rotate_keys_of_type(key_type)
        
        # Log the key rotation
        self._log_audit_event(
            'key_rotation',
            'success',
            {
                'key_type': key_type,
                'initiated_by': event.details.get('initiated_by', 'system')
            }
        )
    
    def increase_security_level(self) -> None:
        """Increase the current security level."""
        if self.security_level == SecurityLevel.LOW:
            self.security_level = SecurityLevel.MEDIUM
        elif self.security_level == SecurityLevel.MEDIUM:
            self.security_level = SecurityLevel.HIGH
        elif self.security_level == SecurityLevel.HIGH:
            self.security_level = SecurityLevel.PARANOID
        
        logger.info(f"Security level increased to {self.security_level.name}")
        
        # Update crypto engine with new security level
        self.crypto_engine.set_security_level(self.security_level)
        
        # Log the security level change
        self._log_audit_event(
            'security_level_change',
            'success',
            {'new_level': self.security_level.name}
        )
    
    def _rotate_affected_keys(self, identifier: str) -> None:
        """Rotate keys affected by a security event."""
        # In a real implementation, this would rotate keys associated with the identifier
        logger.info(f"Rotating keys for {identifier}")
        
        # For now, we'll just log the rotation
        self._log_audit_event(
            'key_rotation',
            'initiated',
            {'reason': 'security_event', 'identifier': identifier}
        )
    
    def _rotate_all_keys(self) -> None:
        """Rotate all encryption keys in the system."""
        logger.warning("Initiating full key rotation")
        
        # In a real implementation, this would rotate all keys
        self._log_audit_event(
            'full_key_rotation',
            'initiated',
            {'reason': 'security_policy'}
        )
    
    def _rotate_keys_of_type(self, key_type: str) -> None:
        """Rotate keys of a specific type."""
        logger.info(f"Rotating {key_type} keys")
        
        # In a real implementation, this would rotate the specified keys
        self._log_audit_event(
            'key_rotation',
            'initiated',
            {'key_type': key_type, 'reason': 'security_policy'}
        )
    
    def _rotate_gate(self, gate_id: int) -> None:
        """Rotate the configuration of a specific gate."""
        logger.info(f"Rotating gate {gate_id}")
        
        # In a real implementation, this would regenerate the gate's keys and parameters
        self._log_audit_event(
            'gate_rotation',
            'initiated',
            {'gate_id': gate_id, 'reason': 'anomaly_detected'}
        )
    
    def _invalidate_user_sessions(self, user_id: str) -> None:
        """Invalidate all sessions for a specific user."""
        sessions_to_remove = [
            session_id for session_id, session in self.active_sessions.items()
            if session.get('user_id') == user_id
        ]
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
        
        logger.info(f"Invalidated {len(sessions_to_remove)} sessions for user {user_id}")
    
    def _invalidate_ip_sessions(self, ip_address: str) -> None:
        """Invalidate all sessions from a specific IP address."""
        sessions_to_remove = [
            session_id for session_id, session in self.active_sessions.items()
            if session.get('ip_address') == ip_address
        ]
        
        for session_id in sessions_to_remove:
            del self.active_sessions[session_id]
        
        logger.info(f"Invalidated {len(sessions_to_remove)} sessions from IP {ip_address}")
    
    def _invalidate_all_sessions(self) -> None:
        """Invalidate all active sessions."""
        session_count = len(self.active_sessions)
        self.active_sessions.clear()
        
        logger.warning(f"Invalidated all {session_count} active sessions")
        
        self._log_audit_event(
            'session_invalidation',
            'success',
            {'sessions_invalidated': session_count, 'reason': 'security_breach'}
        )
    
    def _disable_non_essential_services(self) -> None:
        """Disable non-essential services in case of a breach."""
        logger.warning("Disabling non-essential services")
        
        # In a real implementation, this would disable non-critical services
        self._log_audit_event(
            'service_control',
            'success',
            {'action': 'disable_non_essential', 'reason': 'security_breach'}
        )
    
    def _send_security_alert(self, subject: str, message: str) -> None:
        """Send a security alert to administrators."""
        logger.critical(f"SECURITY ALERT: {subject} - {message}")
        
        # In a real implementation, this would send an email or notification
        self._log_audit_event(
            'security_alert',
            'sent',
            {'subject': subject, 'message': message}
        )
    
    def check_rate_limit(self, identifier: str) -> bool:
        """Check if a request is within rate limits."""
        now = datetime.utcnow()
        
        # Check if this identifier is blacklisted
        if identifier in self.blacklisted_ips:
            # Check if the blacklist has expired
            if identifier in self.locked_accounts:
                if now < self.locked_accounts[identifier]:
                    return False
                else:
                    # Blacklist expired, remove it
                    self.blacklisted_ips.remove(identifier)
                    del self.locked_accounts[identifier]
                    del self.failed_attempts[identifier]
            else:
                # No expiration time, keep it blacklisted
                return False
        
        # Initialize rate limit tracking if needed
        if identifier not in self.rate_limits:
            self.rate_limits[identifier] = []
        
        # Clean up old timestamps
        window = now - timedelta(seconds=60)  # 1-minute window
        self.rate_limits[identifier] = [t for t in self.rate_limits[identifier] if t > window]
        
        # Check if under rate limit
        max_requests = self.policy.get_policy('network', 'max_requests_per_minute', 100)
        if len(self.rate_limits[identifier]) >= max_requests:
            # Log the rate limit event
            self.handle_event(SecurityEvent(
                event_type=SecurityEventType.RATE_LIMIT_EXCEEDED,
                severity=SecurityLevel.MEDIUM,
                source=identifier,
                description=f"Rate limit exceeded for {identifier}",
                details={
                    'count': len(self.rate_limits[identifier]),
                    'limit': max_requests
                }
            ))
            return False
        
        # Record this request
        self.rate_limits[identifier].append(now)
        return True
    
    def get_security_status(self) -> Dict[str, Any]:
        """Get the current security status."""
        return {
            'security_level': self.security_level.name,
            'active_events': len([e for e in self.security_events if not e.resolved]),
            'blacklisted_ips': len(self.blacklisted_ips),
            'active_sessions': len(self.active_sessions),
            'failed_login_attempts': sum(self.failed_attempts.values()),
            'metrics': self.metrics,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def save_state(self, filepath: str) -> None:
        """Save security manager state to a file."""
        state = {
            'security_level': self.security_level.value,
            'blacklisted_ips': list(self.blacklisted_ips),
            'failed_attempts': self.failed_attempts,
            'locked_accounts': {
                k: v.isoformat() for k, v in self.locked_accounts.items()
            },
            'active_sessions': self.active_sessions,
            'security_events': [e.to_dict() for e in self.security_events],
            'audit_log': self.audit_log,
            'metrics': self.metrics,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        # In a real implementation, this would encrypt the state before saving
        with open(filepath, 'w') as f:
            json.dump(state, f, indent=2)
    
    @classmethod
    def load_state(cls, filepath: str, crypto_engine: CryptoEngine, gate_system: GateSystem) -> 'SecurityManager':
        """Load security manager state from a file."""
        try:
            with open(filepath, 'r') as f:
                state = json.load(f)
            
            manager = cls(crypto_engine, gate_system)
            manager.security_level = SecurityLevel(state['security_level'])
            manager.blacklisted_ips = set(state['blacklisted_ips'])
            manager.failed_attempts = state.get('failed_attempts', {})
            
            # Convert string timestamps back to datetime objects
            manager.locked_accounts = {
                k: datetime.fromisoformat(v) 
                for k, v in state.get('locked_accounts', {}).items()
            }
            
            manager.active_sessions = state.get('active_sessions', {})
            
            # Convert event dictionaries back to SecurityEvent objects
            manager.security_events = [
                SecurityEvent.from_dict(e) 
                for e in state.get('security_events', [])
            ]
            
            manager.audit_log = state.get('audit_log', [])
            manager.metrics = state.get('metrics', {})
            
            return manager
            
        except FileNotFoundError:
            # Return a new instance if no saved state exists
            return cls(crypto_engine, gate_system)
        except Exception as e:
            logger.error(f"Error loading security state: {str(e)}")
            # Return a new instance on error
            return cls(crypto_engine, gate_system)
