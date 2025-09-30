""
Factory for creating content moderators.
"""
from typing import Dict, Any, Optional, Type, Union
import logging
from .base import ContentModerator, ContentType
from .text import TextModerator
from .image import ImageModerator
from .video import VideoModerator
from .exceptions import UnsupportedContentType, ConfigurationError

logger = logging.getLogger(__name__)

class ModeratorFactory:
    """Factory for creating content moderators."""
    
    # Map of content types to their respective moderator classes
    _MODERATOR_CLASSES = {
        ContentType.TEXT: TextModerator,
        ContentType.IMAGE: ImageModerator,
        ContentType.VIDEO: VideoModerator,
    }
    
    # Default configuration for each content type
    _DEFAULT_CONFIGS = {
        'text': {
            'models': {
                'huggingface': {
                    'model': 'facebook/bart-large-mnli',
                    'threshold': 0.8
                }
            }
        },
        'image': {
            'models': {
                'huggingface': {
                    'model': 'google/vit-base-patch16-224',
                    'threshold': 0.75
                }
            }
        },
        'video': {
            'frame_interval': 10,
            'max_frames': 30,
            'image_config': {
                'models': {
                    'huggingface': {
                        'model': 'google/vit-base-patch16-224',
                        'threshold': 0.7
                    }
                }
            }
        }
    }
    
    @classmethod
    def create_moderator(
        cls, 
        content_type: Union[ContentType, str],
        config: Optional[Dict[str, Any]] = None
    ) -> ContentModerator:
        """
        Create a moderator for the specified content type.
        
        Args:
            content_type: The type of content to moderate (TEXT, IMAGE, or VIDEO)
            config: Configuration for the moderator (optional)
            
        Returns:
            An instance of the appropriate ContentModerator subclass
            
        Raises:
            UnsupportedContentType: If the content type is not supported
            ConfigurationError: If there's an error in the configuration
        """
        # Convert string content type to enum if needed
        if isinstance(content_type, str):
            try:
                content_type = ContentType[content_type.upper()]
            except KeyError as e:
                supported = list(ContentType.__members__.keys())
                raise UnsupportedContentType(
                    content_type=content_type,
                    supported_types=supported
                ) from e
        
        # Get the appropriate moderator class
        moderator_class = cls._MODERATOR_CLASSES.get(content_type)
        if not moderator_class:
            supported = [t.name.lower() for t in cls._MODERATOR_CLASSES.keys()]
            raise UnsupportedContentType(
                content_type=content_type.name,
                supported_types=supported
            )
        
        # Get default config for this content type
        default_config = cls._get_default_config(content_type)
        
        # Merge with provided config
        if config:
            import copy
            merged_config = copy.deepcopy(default_config)
            cls._deep_merge(merged_config, config)
        else:
            merged_config = default_config
        
        # Create and return the moderator
        try:
            return moderator_class(merged_config)
        except Exception as e:
            logger.error(f"Error creating {content_type.name} moderator: {e}")
            raise ConfigurationError(
                setting=content_type.name.lower(),
                reason=str(e)
            ) from e
    
    @classmethod
    def _get_default_config(cls, content_type: ContentType) -> Dict[str, Any]:
        """Get default configuration for a content type."""
        config_key = content_type.name.lower()
        return cls._DEFAULT_CONFIGS.get(config_key, {})
    
    @staticmethod
    def _deep_merge(base: Dict, update: Dict) -> Dict:
        """Recursively merge two dictionaries."""
        for key, value in update.items():
            if (key in base and isinstance(base[key], dict) and 
                    isinstance(value, dict)):
                ModeratorFactory._deep_merge(base[key], value)
            else:
                base[key] = value
        return base
    
    @classmethod
    def get_supported_content_types(cls) -> list:
        """Get a list of supported content types."""
        return [t.name.lower() for t in cls._MODERATOR_CLASSES.keys()]


def get_moderator(
    content_type: Union[ContentType, str],
    config: Optional[Dict[str, Any]] = None
) -> ContentModerator:
    """
    Convenience function to get a content moderator.
    
    Args:
        content_type: The type of content to moderate (TEXT, IMAGE, or VIDEO)
        config: Configuration for the moderator (optional)
        
    Returns:
        An instance of the appropriate ContentModerator subclass
    """
    return ModeratorFactory.create_moderator(content_type, config)
