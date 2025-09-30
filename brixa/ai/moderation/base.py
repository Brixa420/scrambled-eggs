"""
Base classes for content moderation.
"""
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from enum import Enum, auto
import logging

logger = logging.getLogger(__name__)

class ContentType(Enum):
    """Supported content types for moderation."""
    TEXT = auto()
    IMAGE = auto()
    VIDEO = auto()
    AUDIO = auto()

class ModerationAction(Enum):
    """Possible actions to take based on moderation results."""
    ALLOW = auto()
    FLAG = auto()
    BLOCK = auto()
    QUARANTINE = auto()
    ESCALATE = auto()

@dataclass
class ModerationResult:
    """Result of a content moderation check."""
    action: ModerationAction
    confidence: float
    reasons: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'action': self.action.name,
            'confidence': self.confidence,
            'reasons': self.reasons,
            'metadata': self.metadata
        }

class ContentModerator(ABC):
    """Base class for all content moderators."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the moderator with optional configuration."""
        self.config = config or {}
        self._setup()
    
    @abstractmethod
    def _setup(self) -> None:
        """Set up the moderator with configuration."""
        pass
    
    @abstractmethod
    async def moderate(self, content: Any, context: Optional[Dict] = None) -> ModerationResult:
        """
        Moderate the given content.
        
        Args:
            content: The content to moderate (text, image bytes, video path, etc.)
            context: Additional context for moderation (e.g., user info, content metadata)
            
        Returns:
            ModerationResult with the decision and details
        """
        pass
    
    @property
    @abstractmethod
    def content_type(self) -> ContentType:
        """Return the type of content this moderator handles."""
        pass
    
    def _log_moderation(self, result: ModerationResult, content_id: str = None) -> None:
        """Log moderation results."""
        log_data = {
            'content_id': content_id,
            'action': result.action.name,
            'confidence': result.confidence,
            'reasons': result.reasons
        }
        
        if result.action in (ModerationAction.BLOCK, ModerationAction.QUARANTINE):
            logger.warning("Content blocked/quarantined: %s", log_data)
        elif result.action == ModerationAction.FLAG:
            logger.info("Content flagged for review: %s", log_data)
        else:
            logger.debug("Content allowed: %s", log_data)
