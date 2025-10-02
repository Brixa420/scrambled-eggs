"""
Command Feedback System for Clippy AI.

Provides feedback for voice commands using TTS and natural language processing.
"""

import random
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

from .tts import TextToSpeech

logger = logging.getLogger(__name__)

class FeedbackType(Enum):
    """Types of feedback that can be provided."""
    CONFIRMATION = auto()
    SUCCESS = auto()
    FAILURE = auto()
    PROGRESS = auto()
    HELP = auto()

@dataclass
class FeedbackTemplate:
    """Template for generating feedback messages."""
    confirm: list[str] = field(default_factory=lambda: [
        "I'll do that right away.",
        "On it!",
        "Consider it done.",
        "I'll take care of that.",
        "Got it, I'm on it."
    ])
    success: list[str] = field(default_factory=lambda: [
        "Successfully completed.",
        "All done!",
        "Task completed successfully.",
        "I've taken care of that for you.",
        "Operation completed as requested."
    ])
    failure: list[str] = field(default_factory=lambda: [
        "I couldn't complete that request.",
        "Sorry, I ran into a problem with that.",
        "I wasn't able to do that.",
        "Something went wrong with that request.",
        "I couldn't process that command."
    ])
    progress: list[str] = field(default_factory=lambda: [
        "Working on that for you.",
        "Let me take care of that.",
        "Processing your request.",
        "I'm on it.",
        "Just a moment, please."
    ])
    help: list[str] = field(default_factory=lambda: [
        "How can I assist you?",
        "What would you like me to do?",
        "I'm here to help. What do you need?",
        "How can I be of service?",
        "What can I do for you today?"
    ])

class CommandFeedback:
    """Handles feedback for voice commands using TTS."""
    
    def __init__(self, tts_engine: Optional[TextToSpeech] = None):
        """
        Initialize the command feedback system.
        
        Args:
            tts_engine: Optional TTS engine instance. If not provided, one will be created.
        """
        self.tts = tts_engine or TextToSpeech()
        self.templates = FeedbackTemplate()
        self.enabled = True
        self._callbacks: Dict[FeedbackType, list[Callable]] = {
            FeedbackType.CONFIRMATION: [],
            FeedbackType.SUCCESS: [],
            FeedbackType.FAILURE: [],
            FeedbackType.PROGRESS: [],
            FeedbackType.HELP: []
        }
    
    def add_callback(self, feedback_type: FeedbackType, callback: Callable[[str], None]):
        """Add a callback for a specific feedback type."""
        self._callbacks[feedback_type].append(callback)
    
    def _notify_callbacks(self, feedback_type: FeedbackType, message: str):
        """Notify all registered callbacks for the given feedback type."""
        for callback in self._callbacks[feedback_type]:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Error in feedback callback: {e}")
    
    def _get_template(self, feedback_type: FeedbackType) -> str:
        """Get a random template for the given feedback type."""
        templates = getattr(self.templates, feedback_type.name.lower(), [])
        return random.choice(templates) if templates else ""
    
    def speak(self, text: str, feedback_type: FeedbackType = None, wait: bool = False) -> bool:
        """
        Speak the given text and notify callbacks.
        
        Args:
            text: The text to speak
            feedback_type: Type of feedback (for callbacks)
            wait: Whether to wait for speech to complete
            
        Returns:
            bool: True if speech was initiated successfully
        """
        if not self.enabled or not text:
            return False
            
        try:
            # Notify callbacks first
            if feedback_type:
                self._notify_callbacks(feedback_type, text)
                
            # Speak the text
            return self.tts.speak(text, wait=wait) is not None
            
        except Exception as e:
            logger.error(f"Error in feedback.speak: {e}")
            return False
    
    def confirm(self, message: str = None, wait: bool = False) -> bool:
        """Provide confirmation feedback."""
        text = message or self._get_template(FeedbackType.CONFIRMATION)
        return self.speak(text, FeedbackType.CONFIRMATION, wait)
    
    def success(self, message: str = None, wait: bool = False) -> bool:
        """Provide success feedback."""
        text = message or self._get_template(FeedbackType.SUCCESS)
        return self.speak(text, FeedbackType.SUCCESS, wait)
    
    def failure(self, message: str = None, wait: bool = False) -> bool:
        """Provide failure feedback."""
        text = message or self._get_template(FeedbackType.FAILURE)
        return self.speak(text, FeedbackType.FAILURE, wait)
    
    def progress(self, message: str = None, wait: bool = False) -> bool:
        """Provide progress feedback."""
        text = message or self._get_template(FeedbackType.PROGRESS)
        return self.speak(text, FeedbackType.PROGRESS, wait)
    
    def help(self, message: str = None, wait: bool = False) -> bool:
        """Provide help feedback."""
        text = message or self._get_template(FeedbackType.HELP)
        return self.speak(text, FeedbackType.HELP, wait)

# Global instance for easy access
feedback = CommandFeedback()

def set_feedback_enabled(enabled: bool):
    """Enable or disable all feedback."""
    feedback.enabled = enabled

def add_feedback_callback(feedback_type: FeedbackType, callback: Callable[[str], None]):
    """Add a callback for a specific feedback type."""
    feedback.add_callback(feedback_type, callback)
