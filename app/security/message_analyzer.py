""
Message Analysis for Security

This module provides AI-powered analysis of messages for security purposes,
including detection of sensitive information, malicious content, and anomalies.
"""

import re
import json
import torch
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum, auto

# Import the model manager
from ..ai.model_manager import ModelManager

class RiskLevel(Enum):
    """Enumeration of risk levels for message analysis."""
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

@dataclass
class SecurityFinding:
    """Represents a security finding in message analysis."""
    type: str
    description: str
    risk_level: RiskLevel
    confidence: float
    location: Optional[Tuple[int, int]] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the finding to a dictionary."""
        result = asdict(self)
        result['risk_level'] = self.risk_level.name
        return result

class MessageAnalyzer:
    """Analyzes messages for security and privacy concerns."""
    
    def __init__(self, model_manager: Optional[ModelManager] = None):
        """Initialize the message analyzer."""
        self.model_manager = model_manager or ModelManager()
        self._load_models()
        self._load_patterns()
    
    def _load_models(self):
        """Load the required AI models."""
        # Load the security analysis model
        self.security_model = self.model_manager.load_model("security_analysis")
        
        # Load the anomaly detection model if available
        self.anomaly_model = self.model_manager.load_model("anomaly_detection")
        
        # Set device (GPU if available)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        if self.security_model and 'model' in self.security_model:
            self.security_model['model'] = self.security_model['model'].to(self.device)
        if self.anomaly_model and 'model' in self.anomaly_model:
            self.anomaly_model['model'] = self.anomaly_model['model'].to(self.device)
    
    def _load_patterns(self):
        """Load patterns for rule-based detection."""
        # Common patterns for sensitive information
        self.patterns = {
            'credit_card': {
                'regex': r'\b(?:\d[ -]*?){13,16}\b',
                'description': 'Potential credit card number',
                'risk_level': RiskLevel.HIGH
            },
            'ssn': {
                'regex': r'\b\d{3}[-\.]?\d{2}[-\.]?\d{4}\b',
                'description': 'Potential Social Security Number',
                'risk_level': RiskLevel.HIGH
            },
            'email': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Email address',
                'risk_level': RiskLevel.MEDIUM
            },
            'phone': {
                'regex': r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                'description': 'Phone number',
                'risk_level': RiskLevel.MEDIUM
            },
            'ip_address': {
                'regex': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'description': 'IP address',
                'risk_level': RiskLevel.MEDIUM
            },
            'url': {
                'regex': r'https?:\/\/(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)',
                'description': 'URL',
                'risk_level': RiskLevel.LOW
            },
            'api_key': {
                'regex': r'\b(?:[A-Za-z0-9+/=]{40,}|[A-Za-z0-9_\-]{20,})\b',
                'description': 'Potential API key or token',
                'risk_level': RiskLevel.HIGH
            }
        }
    
    def _analyze_with_ai(self, message: str) -> List[SecurityFinding]:
        """Analyze the message using AI models."""
        findings = []
        
        # Check if we have the security model loaded
        if not self.security_model or 'model' not in self.security_model:
            return findings
        
        try:
            # Tokenize the message
            inputs = self.security_model["tokenizer"](
                message,
                return_tensors="pt",
                truncation=True,
                max_length=512
            ).to(self.device)
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.security_model["model"](**inputs)
            
            # Process outputs (example - adjust based on your model)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            confidence, predicted = torch.max(probabilities, dim=1)
            
            # Map model output to risk levels (example mapping)
            risk_mapping = {
                0: RiskLevel.LOW,
                1: RiskLevel.MEDIUM,
                2: RiskLevel.HIGH,
                3: RiskLevel.CRITICAL
            }
            
            risk_level = risk_mapping.get(predicted.item(), RiskLevel.MEDIUM)
            confidence = confidence.item()
            
            if risk_level != RiskLevel.LOW or confidence > 0.7:
                findings.append(SecurityFinding(
                    type="ai_analysis",
                    description=f"AI-detected {risk_level.name.lower()} risk content",
                    risk_level=risk_level,
                    confidence=confidence,
                    metadata={
                        "class_probabilities": probabilities.cpu().numpy().tolist()[0]
                    }
                ))
                
        except Exception as e:
            print(f"Error in AI analysis: {e}")
        
        return findings
    
    def _check_for_anomalies(self, message: str) -> List[SecurityFinding]:
        """Check for anomalies in the message."""
        findings = []
        
        if not self.anomaly_model or 'model' not in self.anomaly_model:
            return findings
        
        try:
            # Tokenize the message
            inputs = self.anomaly_model["tokenizer"](message, return_tensors="pt")
            
            # Get model predictions
            with torch.no_grad():
                outputs = self.anomaly_model["model"](**inputs, output_hidden_states=True)
            
            # Calculate reconstruction error (example - adjust based on your model)
            # This is a simplified example - actual anomaly detection would be more sophisticated
            hidden_states = outputs.hidden_states[-1]
            mean_hidden = torch.mean(hidden_states, dim=1)
            reconstruction_error = torch.norm(mean_hidden, dim=1).item()
            
            # Threshold for anomaly detection (would be determined from training data)
            if reconstruction_error > 5.0:  # Example threshold
                findings.append(SecurityFinding(
                    type="anomaly_detection",
                    description=f"Unusual message pattern detected (anomaly score: {reconstruction_error:.2f})",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=min(1.0, reconstruction_error / 10.0),  # Scale to 0-1
                    metadata={
                        "anomaly_score": reconstruction_error,
                        "threshold": 5.0
                    }
                ))
                
        except Exception as e:
            print(f"Error in anomaly detection: {e}")
        
        return findings
    
    def _check_patterns(self, message: str) -> List[SecurityFinding]:
        """Check for sensitive patterns in the message."""
        findings = []
        
        for pattern_name, pattern_info in self.patterns.items():
            regex = re.compile(pattern_info['regex'], re.IGNORECASE)
            matches = list(regex.finditer(message))
            
            for match in matches:
                # Get the matched text and its position
                matched_text = match.group()
                start_pos, end_pos = match.span()
                
                # Skip false positives with some basic validation
                if pattern_name == 'credit_card' and not self._is_valid_credit_card(matched_text):
                    continue
                if pattern_name == 'ssn' and not self._is_valid_ssn(matched_text):
                    continue
                
                findings.append(SecurityFinding(
                    type=pattern_name,
                    description=f"{pattern_info['description']} detected: {matched_text}",
                    risk_level=pattern_info['risk_level'],
                    confidence=0.9,  # High confidence for pattern matches
                    location=(start_pos, end_pos),
                    metadata={
                        'matched_text': matched_text,
                        'pattern': pattern_name
                    }
                ))
        
        return findings
    
    def _is_valid_credit_card(self, number: str) -> bool:
        """Validate a credit card number using Luhn algorithm."""
        # Remove all non-digit characters
        number = ''.join(filter(str.isdigit, number))
        
        # Check if the number is too short or too long
        if len(number) < 13 or len(number) > 19:
            return False
        
        # Luhn algorithm
        total = 0
        reverse_digits = number[::-1]
        
        for i in range(len(reverse_digits)):
            digit = int(reverse_digits[i])
            if i % 2 == 1:  # Double every second digit
                digit *= 2
                if digit > 9:
                    digit = (digit // 10) + (digit % 10)
            total += digit
        
        return total % 10 == 0
    
    def _is_valid_ssn(self, ssn: str) -> bool:
        """Basic validation for SSN format."""
        # Remove non-digit characters
        ssn = ''.join(filter(str.isdigit, ssn))
        
        # Check length
        if len(ssn) != 9:
            return False
        
        # Check for invalid SSNs (e.g., 000-xx-xxxx, xxx-00-xxxx, xxx-xx-0000)
        if ssn.startswith('000') or ssn[3:5] == '00' or ssn[5:] == '0000':
            return False
        
        # Check for known test SSNs (e.g., 111-11-1111, 123-45-6789)
        if ssn == '111111111' or ssn == '123456789':
            return False
        
        return True
    
    def analyze(self, message: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze a message for security and privacy concerns.
        
        Args:
            message: The message to analyze
            context: Additional context for the analysis (e.g., sender info, message type)
            
        Returns:
            A dictionary containing the analysis results
        """
        if not context:
            context = {}
        
        # Start with basic information
        result = {
            'timestamp': datetime.utcnow().isoformat(),
            'message_length': len(message),
            'findings': [],
            'risk_score': 0.0,
            'risk_level': 'LOW',
            'context': context
        }
        
        # Skip analysis for very short messages
        if len(message.strip()) < 3:
            result['status'] = 'skipped_short_message'
            return result
        
        try:
            # Run all analysis methods
            findings = []
            
            # 1. Check for sensitive patterns
            findings.extend(self._check_patterns(message))
            
            # 2. AI-based analysis
            findings.extend(self._analyze_with_ai(message))
            
            # 3. Anomaly detection
            findings.extend(self._check_for_anomalies(message))
            
            # Calculate overall risk score (0-100)
            risk_score = 0.0
            risk_weights = {
                RiskLevel.LOW: 0.2,
                RiskLevel.MEDIUM: 0.5,
                RiskLevel.HIGH: 0.8,
                RiskLevel.CRITICAL: 1.0
            }
            
            for finding in findings:
                # Add weight based on risk level and confidence
                weight = risk_weights.get(finding.risk_level, 0.3)
                risk_score += weight * finding.confidence * 100
            
            # Cap the risk score at 100
            risk_score = min(100.0, risk_score)
            
            # Determine overall risk level
            if risk_score >= 80:
                risk_level = 'CRITICAL'
            elif risk_score >= 50:
                risk_level = 'HIGH'
            elif risk_score >= 20:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Update the result
            result.update({
                'status': 'completed',
                'findings': [finding.to_dict() for finding in findings],
                'risk_score': round(risk_score, 2),
                'risk_level': risk_level,
                'findings_count': len(findings)
            })
            
        except Exception as e:
            result.update({
                'status': 'error',
                'error': str(e)
            })
        
        return result

# Example usage
if __name__ == "__main__":
    # Initialize the analyzer
    analyzer = MessageAnalyzer()
    
    # Example messages
    messages = [
        "My credit card is 4111 1111 1111 1111 and my SSN is 123-45-6789.",
        "Hello, how are you doing today?",
        "Please send the API key to admin@example.com immediately!",
        "This is a test message with an IP address: 192.168.1.1",
        "My phone number is (555) 123-4567 if you need to reach me."
    ]
    
    # Analyze each message
    for i, message in enumerate(messages, 1):
        print(f"\n--- Analyzing Message {i} ---")
        print(f"Message: {message}")
        
        result = analyzer.analyze(message)
        
        print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']:.1f})")
        
        if result['findings']:
            print("\nFindings:")
            for j, finding in enumerate(result['findings'], 1):
                print(f"  {j}. [{finding['risk_level']}] {finding['description']} (Confidence: {finding['confidence']*100:.1f}%)")
        else:
            print("No security issues found.")
