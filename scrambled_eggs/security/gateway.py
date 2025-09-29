"""
Security Gateway - Integrates monitoring, dynamic encryption, and AI response.
"""

import logging
import time
from typing import Any, Callable, Dict, Optional

from .ai_agent import AISecurityAgent, ThreatAssessment, ThreatType
from .dynamic_encryption import DynamicEncryption, EncryptionLayer
from .monitor import BreachSeverity, SecurityEvent, SecurityMonitor

logger = logging.getLogger(__name__)


class SecurityGateway:
    """
    Main security gateway that integrates monitoring, encryption, and AI response.
    Handles gate breaching events and coordinates the security response.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        # Default configuration
        self.config = {
            "max_layers": 5,  # Maximum number of encryption layers to add
            "base_algorithm": "AES",  # Default encryption algorithm
            "base_key_size": 256,  # Base key size in bits
            "ai_enabled": True,  # Enable AI analysis
            "auto_respond": True,  # Allow automatic responses to threats
            "autonomous_mode": True,  # Enable fully autonomous operation
            "max_autonomous_layers": 3,  # Maximum layers to add autonomously
            "self_learning": True,  # Enable continuous learning
            "threat_response_level": 0.7,  # Confidence threshold for auto-response
            "adaptive_security": True,  # Adjust security based on threat level
        }

        # Update with provided config
        if config:
            self.config.update(config)

        # Initialize components
        self.encryption = DynamicEncryption(
            base_algorithm=self.config["base_algorithm"], base_key_size=self.config["base_key_size"]
        )

        # Initialize AI agent if enabled
        self.ai_agent = None
        if self.config["ai_enabled"]:
            self.ai_agent = AISecurityAgent(response_callback=self._handle_ai_response)

        # Initialize security monitor with AI callback
        self.monitor = SecurityMonitor(
            ai_alert_callback=self._handle_security_alert if self.ai_agent else None
        )

        # Track security state
        self.breach_detected = False
        self.last_breach_response = 0
        self.security_level = self.encryption.calculate_security_level()

        logger.info("Security Gateway initialized")

    def _handle_security_alert(self, event: SecurityEvent) -> bool:
        """Process a security alert from the monitor."""
        logger.warning(f"Security alert received: {event.event_type} (Severity: {event.severity})")

        # Update breach state
        self.breach_detected = True

        # If AI is enabled, let it analyze the threat
        if self.ai_agent:
            assessment = self.ai_agent.analyze_threat(
                {
                    "event_type": event.event_type,
                    "severity": event.severity.name,
                    "details": event.details,
                    "timestamp": event.timestamp,
                }
            )

            logger.info(f"AI Threat Assessment: {assessment.description}")

            # If auto-respond is enabled, handle the response
            if self.config["auto_respond"]:
                return self._handle_breach(assessment)

        return False

    def _handle_ai_response(self, assessment: ThreatAssessment) -> bool:
        """Handle AI's recommended response to a threat."""
        logger.info(f"AI recommended actions: {', '.join(assessment.recommended_actions)}")
        return self._handle_breach(assessment)

    def _handle_breach(self, assessment: ThreatAssessment) -> bool:
        """Handle a security breach with appropriate response in autonomous mode."""
        now = time.time()
        response_taken = False

        # Skip if we're in cooldown period
        cooldown = 30 if self.config["autonomous_mode"] else 60
        if now - self.last_breach_response < cooldown:
            logger.warning(
                f"Skipping breach response: Still in cooldown ({int(cooldown - (now - self.last_breach_response))}s remaining)"
            )
            return False

        # In autonomous mode, make decisions based on threat assessment
        if (
            self.config["autonomous_mode"]
            and assessment.confidence >= self.config["threat_response_level"]
        ):
            response_taken = self._autonomous_response(assessment)
        elif (
            not self.config["autonomous_mode"]
            and "add_encryption_layer" in assessment.recommended_actions
        ):
            # Manual mode - only add layers if explicitly recommended
            response_taken = self._add_encryption_layers(assessment)

        # Update security level and learning
        self.security_level = self.encryption.calculate_security_level()
        self.last_breach_response = now

        # Self-learning: Adjust response based on outcome
        if self.config["self_learning"] and self.ai_agent:
            self._update_learning(assessment, response_taken)

        return response_taken

    def _autonomous_response(self, assessment: ThreatAssessment) -> bool:
        """Autonomous response to security threats.

        When a breach is detected, adds a random number of encryption layers
        on top of the existing 1000 layers to make breaching virtually impossible.
        """
        response_taken = False
        current_layers = len(self.encryption.layers)

        # Calculate how many layers to add (exponential based on threat level)
        if assessment.confidence > 0.5:
            # Base number of layers to add (increases with threat level)
            base_layers = int(10 ** (assessment.confidence * 3))  # 10-1000 layers

            # Add random variation (50-150% of base)
            layers_to_add = random.randint(base_layers // 2, base_layers + (base_layers // 2))

            # Ensure we don't exceed max_layers
            layers_to_add = min(layers_to_add, self.config["max_layers"] - current_layers)

            if layers_to_add > 0:
                logger.info(
                    f"[AUTONOMOUS] Adding {layers_to_add} new encryption layers "
                    f"(Threat: {assessment.confidence:.1%}, "
                    f"Total layers: {current_layers + layers_to_add})"
                )

                # Add the layers with a progress indicator for large numbers
                if layers_to_add > 100:
                    print(f"\n🔒 Adding {layers_to_add} new encryption layers...")

                for i in range(layers_to_add):
                    self.encryption.add_random_layer()
                    if layers_to_add > 100 and (i + 1) % 100 == 0:
                        print(f"  - Added {i + 1}/{layers_to_add} layers...")

                response_taken = True

                # Log the enhanced security
                if layers_to_add > 0:
                    logger.critical(
                        f"🚨 CRITICAL: Added {layers_to_add} encryption layers in response to "
                        f"{assessment.threat_type.value} (Confidence: {assessment.confidence:.1%})"
                    )

        # 2. For critical threats, also rotate encryption parameters
        if assessment.confidence > 0.8:
            self._adjust_security_parameters(assessment)

            # For extremely high confidence threats, add additional protection
            if assessment.confidence > 0.95:
                self._activate_emergency_protocols(assessment)

        return response_taken

    def _add_encryption_layers(self, assessment: ThreatAssessment) -> bool:
        """Add encryption layers based on threat assessment."""
        layers_to_add = min(
            self.config["max_layers"] - len(self.encryption.layers),
            max(1, int(assessment.confidence * 3)),
        )

        for _ in range(layers_to_add):
            self.encryption.add_random_layer()

        logger.info(f"Added {layers_to_add} encryption layers in response to threat")
        return layers_to_add > 0

    def _adjust_security_parameters(self, assessment: ThreatAssessment):
        """Dynamically adjust security parameters based on threat level."""
        # For critical threats, significantly increase key size
        if assessment.confidence > 0.8:
            key_increase = random.randint(64, 256)  # Add 64-256 bits
            self.encryption.base_key_size = min(
                8192, self.encryption.base_key_size + key_increase  # Absolute maximum
            )
            logger.critical(
                f"🔐 CRITICAL: Increased encryption key size by {key_increase} bits "
                f"(New size: {self.encryption.base_key_size} bits)"
            )

        # For extreme threats, rotate to stronger algorithms
        if assessment.confidence > 0.9:
            # Ordered by strength (in our implementation)
            algorithms = ["AES-512-GCM", "ChaCha20-Poly1305", "AES-256-GCM", "Blowfish-448"]

            # Move to a stronger algorithm
            current_strength = 0
            if self.encryption.base_algorithm in algorithms:
                current_strength = algorithms.index(self.encryption.base_algorithm)

            # Select a stronger algorithm (if available)
            if current_strength > 0:
                new_algo = algorithms[current_strength - 1]
                self.encryption.base_algorithm = new_algo
                logger.critical(
                    f"🔄 CRITICAL: Upgraded encryption algorithm to {new_algo} "
                    f"in response to {assessment.threat_type.value}"
                )

    def _activate_emergency_protocols(self, assessment: ThreatAssessment):
        """Activate additional emergency security measures."""
        logger.critical("🚨 EMERGENCY: Activating maximum security protocols!")

        # Add emergency layers (bypassing normal limits)
        emergency_layers = random.randint(500, 2000)
        logger.critical(f"🚨 Adding EMERGENCY {emergency_layers} encryption layers!")

        for _ in range(emergency_layers):
            self.encryption.add_random_layer()

        # Switch to strongest possible settings
        self.encryption.base_algorithm = "AES-512-GCM"
        self.encryption.base_key_size = 8192

        logger.critical("✅ Maximum security protocols activated!")

    def _update_learning(self, assessment: ThreatAssessment, response_effective: bool):
        """Update AI learning based on response effectiveness."""
        # In a real system, this would use more sophisticated learning
        # Here we're just providing feedback to the AI agent
        self.ai_agent.learn_from_feedback(assessment, response_effective)

        # Adjust response threshold based on recent threat history
        if self.config["adaptive_security"]:
            recent_threats = [
                t for t in self.ai_agent.threat_history if time.time() - t.timestamp < 3600
            ]  # Last hour
            if len(recent_threats) > 3:
                # Increase sensitivity if seeing many threats
                new_threshold = max(0.5, self.config["threat_response_level"] * 0.9)
                if new_threshold != self.config["threat_response_level"]:
                    self.config["threat_response_level"] = round(new_threshold, 2)
                    logger.info(
                        f"[AUTONOMOUS] Adjusted threat response threshold to {new_threshold:.2f}"
                    )

    def get_security_status(self) -> Dict[str, Any]:
        """Get current security status with autonomous operation details."""
        status = {
            "breach_detected": self.breach_detected,
            "security_level": self.security_level,
            "active_layers": len(self.encryption.layers),
            "last_breach_response": self.last_breach_response,
            "autonomous_mode": self.config["autonomous_mode"],
            "self_learning": self.config["self_learning"],
            "threat_response_level": self.config["threat_response_level"],
            "ai_status": self.ai_agent.get_status() if self.ai_agent else "disabled",
            "encryption": {
                **self.encryption.get_encryption_parameters(),
                "base_algorithm": self.encryption.base_algorithm,
                "base_key_size": self.encryption.base_key_size,
            },
            "next_autonomous_action": self._predict_next_action(),
        }

        return status

    def _predict_next_action(self) -> Dict[str, Any]:
        """Predict the next autonomous action based on current state."""
        if not self.config["autonomous_mode"]:
            return {"action": "none", "reason": "Autonomous mode disabled"}

        # Simple prediction logic - in a real system this would use ML
        if self.breach_detected:
            return {
                "action": "enhance_encryption",
                "priority": "high",
                "estimated_time": "immediate",
            }

        # Check if we should rotate keys based on time since last rotation
        time_since_rotation = time.time() - (getattr(self, "_last_key_rotation", 0) or 0)
        if time_since_rotation > 86400:  # 24 hours
            return {
                "action": "rotate_keys",
                "priority": "medium",
                "reason": f"{int(time_since_rotation/3600)} hours since last rotation",
                "estimated_time": "next_maintenance_window",
            }

        return {"action": "monitor", "reason": "No immediate action required"}

    def reset_security(self, full_reset: bool = False):
        """
        Reset the security gateway.

        Args:
            full_reset: If True, also resets AI learning and configuration
        """
        # Reset encryption to base state
        self.encryption = DynamicEncryption(
            base_algorithm=self.config["base_algorithm"], base_key_size=self.config["base_key_size"]
        )

        # Reset monitoring
        self.monitor.reset()

        # Reset state
        self.breach_detected = False
        self.security_level = self.encryption.calculate_security_level()
        self.last_breach_response = 0

        # Reset AI if requested
        if full_reset and self.ai_agent:
            self.ai_agent = AISecurityAgent(response_callback=self._handle_ai_response)

        logger.info("Security Gateway has been reset" + (" (full reset)" if full_reset else ""))

    def set_autonomous_mode(self, enabled: bool = True):
        """Enable or disable autonomous security mode."""
        self.config["autonomous_mode"] = enabled
        status = "enabled" if enabled else "disabled"
        logger.info(f"Autonomous security mode {status}")

        # If enabling autonomous mode, do an initial security assessment
        if enabled and self.ai_agent:
            self._perform_security_assessment()

    def _perform_security_assessment(self):
        """Perform an initial security assessment in autonomous mode."""
        if not self.config["autonomous_mode"] or not self.ai_agent:
            return

        logger.info("Performing initial security assessment...")

        # Check current security level
        current_level = self.security_level

        # In a real system, this would be more sophisticated
        if current_level < 20:  # Arbitrary threshold
            logger.info("Security level below recommended threshold, enhancing...")
            self._add_encryption_layers(
                ThreatAssessment(
                    threat_type=ThreatType.UNKNOWN,
                    confidence=0.8,
                    recommended_actions=["add_encryption_layer"],
                    description="Initial security enhancement",
                )
            )

        logger.info(f"Security assessment complete. Current level: {self.security_level}")
