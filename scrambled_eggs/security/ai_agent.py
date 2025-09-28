"""
AI Security Agent for analyzing threats and responding to security events.
"""
import logging
import time
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum, auto
import random
import json

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

class ThreatType(Enum):
    BRUTE_FORCE = "Brute Force Attempt"
    TIMING_ATTACK = "Timing Attack"
    REPLAY_ATTACK = "Replay Attack"
    KEY_COMPROMISE = "Possible Key Compromise"
    UNKNOWN = "Unknown Threat"

@dataclass
class ThreatAssessment:
    threat_type: ThreatType
    confidence: float  # 0.0 to 1.0
    recommended_actions: List[str]
    description: str
    timestamp: float = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'threat_type': self.threat_type.value,
            'confidence': self.confidence,
            'recommended_actions': self.recommended_actions,
            'description': self.description,
            'timestamp': self.timestamp
        }

class AISecurityAgent:
    """AI-powered security agent for threat analysis and response."""
    
    def __init__(self, response_callback: Optional[Callable] = None):
        self.response_callback = response_callback
        self.threat_history = []
        self.learning_rate = 0.1  # How quickly the AI adapts to new threats
        self.threat_patterns = self._initialize_threat_patterns()
        self.last_analysis = {}
        
        logger.info("AI Security Agent initialized")
    
    def _initialize_threat_patterns(self) -> Dict[ThreatType, Dict]:
        """Initialize known threat patterns and responses."""
        return {
            ThreatType.BRUTE_FORCE: {
                'indicators': [
                    'repeated_failures',
                    'high_frequency_attempts',
                    'similar_passwords'
                ],
                'responses': [
                    'add_encryption_layer',
                    'temporarily_block_ip',
                    'require_captcha'
                ],
                'base_confidence': 0.7
            },
            ThreatType.TIMING_ATTACK: {
                'indicators': [
                    'varying_response_times',
                    'small_timing_differences',
                    'repeated_similar_operations'
                ],
                'responses': [
                    'add_timing_noise',
                    'add_encryption_layer',
                    'require_reauth'
                ],
                'base_confidence': 0.6
            },
            ThreatType.REPLAY_ATTACK: {
                'indicators': [
                    'duplicate_messages',
                    'old_timestamps',
                    'sequence_anomalies'
                ],
                'responses': [
                    'invalidate_session',
                    'require_reauth',
                    'rotate_encryption_keys'
                ],
                'base_confidence': 0.8
            }
        }
    
    def analyze_threat(self, event_data: Dict[str, Any]) -> ThreatAssessment:
        """Analyze a security event and assess the threat level."""
        logger.info(f"Analyzing potential threat: {event_data.get('event_type', 'unknown')}")
        
        # Simple pattern matching (in a real system, this would use ML)
        threat_type = self._classify_threat(event_data)
        confidence = self._calculate_confidence(threat_type, event_data)
        
        # Generate recommended actions
        recommended_actions = self._generate_actions(threat_type, confidence, event_data)
        
        # Create assessment
        assessment = ThreatAssessment(
            threat_type=threat_type,
            confidence=confidence,
            recommended_actions=recommended_actions,
            description=f"Detected {threat_type.value} with {confidence*100:.1f}% confidence"
        )
        
        # Store in history
        self.threat_history.append(assessment)
        self.last_analysis = assessment.to_dict()
        
        # Trigger response if callback is available
        if self.response_callback:
            try:
                self.response_callback(assessment)
            except Exception as e:
                logger.error(f"Error in response callback: {e}")
        
        return assessment
    
    def _classify_threat(self, event_data: Dict[str, Any]) -> ThreatType:
        """Classify the type of threat based on event data."""
        event_type = event_data.get('event_type', '').lower()
        
        # Simple rule-based classification
        if 'brute_force' in event_type:
            return ThreatType.BRUTE_FORCE
        elif 'timing' in event_type:
            return ThreatType.TIMING_ATTACK
        elif 'replay' in event_type:
            return ThreatType.REPLAY_ATTACK
        elif 'key' in event_type and 'compromise' in event_type:
            return ThreatType.KEY_COMPROMISE
        else:
            return ThreatType.UNKNOWN
    
    def _calculate_confidence(self, threat_type: ThreatType, event_data: Dict[str, Any]) -> float:
        """Calculate confidence level for the threat assessment."""
        if threat_type == ThreatType.UNKNOWN:
            return 0.3  # Low confidence for unknown threats
            
        # Base confidence from the threat pattern
        base_confidence = self.threat_patterns.get(threat_type, {}).get('base_confidence', 0.5)
        
        # Adjust based on event data (simplified)
        confidence = base_confidence
        
        # Increase confidence if we've seen similar threats recently
        recent_similar = sum(1 for t in self.threat_history[-10:] 
                            if t.threat_type == threat_type and 
                            time.time() - t.timestamp < 3600)  # Last hour
        
        if recent_similar > 0:
            confidence = min(0.95, confidence + (recent_similar * 0.1))
        
        return round(confidence, 2)
    
    def _generate_actions(self, threat_type: ThreatType, 
                         confidence: float, 
                         event_data: Dict[str, Any]) -> List[str]:
        """Generate recommended actions based on threat type and confidence."""
        actions = []
        
        # Base actions from threat pattern
        if threat_type in self.threat_patterns:
            actions.extend(self.threat_patterns[threat_type]['responses'])
        
        # Add confidence-based actions
        if confidence > 0.7:
            actions.append('notify_admin')
        if confidence > 0.8:
            actions.append('enable_enhanced_logging')
        if confidence > 0.9:
            actions.append('lockdown_sensitive_resources')
        
        return actions
    
    def learn_from_feedback(self, assessment: ThreatAssessment, was_correct: bool):
        """Update the AI's knowledge based on feedback."""
        if was_correct:
            # Reinforce this pattern
            if assessment.threat_type in self.threat_patterns:
                # Slightly increase base confidence
                self.threat_patterns[assessment.threat_type]['base_confidence'] = min(
                    0.95,
                    self.threat_patterns[assessment.threat_type]['base_confidence'] + self.learning_rate
                )
        else:
            # Learn from mistake
            if assessment.threat_type in self.threat_patterns:
                # Slightly decrease base confidence
                self.threat_patterns[assessment.threat_type]['base_confidence'] = max(
                    0.1,
                    self.threat_patterns[assessment.threat_type]['base_confidence'] - self.learning_rate
                )
        
        logger.info(f"AI learned from feedback. New confidence for {assessment.threat_type}: "
                   f"{self.threat_patterns[assessment.threat_type]['base_confidence']:.2f}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current status of the AI agent."""
        return {
            'status': 'active',
            'threats_analyzed': len(self.threat_history),
            'recent_threats': [t.to_dict() for t in self.threat_history[-5:]],
            'learning_rate': self.learning_rate,
            'last_analysis': self.last_analysis
        }
