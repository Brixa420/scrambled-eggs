""
Utility functions for content moderation.
"""
import base64
import io
import logging
import mimetypes
from typing import Optional, Tuple, Union, Dict, Any
from pathlib import Path

from PIL import Image, UnidentifiedImageError
import magic

from .base import ContentType
from .exceptions import UnsupportedContentType, ContentProcessingError

logger = logging.getLogger(__name__)

def detect_content_type(data: bytes, filename: Optional[str] = None) -> ContentType:
    """
    Detect the content type of the given data.
    
    Args:
        data: The content data as bytes
        filename: Optional filename for extension-based detection
        
    Returns:
        ContentType enum value
        
    Raises:
        UnsupportedContentType: If the content type is not supported
        ContentProcessingError: If there's an error processing the content
    """
    try:
        # Try libmagic for content-based detection
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(data[:1024])  # Only check first KB for performance
        
        # Map MIME types to our content types
        if mime_type.startswith('text/'):
            return ContentType.TEXT
        elif mime_type.startswith('image/'):
            return ContentType.IMAGE
        elif mime_type.startswith('video/'):
            return ContentType.VIDEO
        elif mime_type.startswith('audio/'):
            return ContentType.AUDIO
        
        # Fall back to file extension if MIME type is too generic
        if filename:
            ext = Path(filename).suffix.lower()
            if ext in ('.txt', '.md', '.csv', '.json', '.xml'):
                return ContentType.TEXT
            elif ext in ('.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'):
                return ContentType.IMAGE
            elif ext in ('.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm'):
                return ContentType.VIDEO
            elif ext in ('.mp3', '.wav', '.ogg', '.m4a'):
                return ContentType.AUDIO
        
        raise UnsupportedContentType(
            content_type=mime_type,
            supported_types=[t.name.lower() for t in ContentType]
        )
        
    except Exception as e:
        logger.error(f"Error detecting content type: {e}")
        raise ContentProcessingError("content", str(e)) from e

def load_image(data: Union[bytes, str]) -> Image.Image:
    """
    Load an image from bytes or base64 string.
    
    Args:
        data: Image data as bytes or base64 string
        
    Returns:
        PIL Image object
        
    Raises:
        ContentProcessingError: If the image cannot be loaded
    """
    try:
        if isinstance(data, str):
            # Handle base64 data URL
            if data.startswith('data:image'):
                # Extract base64 data from data URL
                data = data.split(',', 1)[1]
            # Decode base64
            data = base64.b64decode(data)
            
        if isinstance(data, bytes):
            # Convert bytes to PIL Image
            return Image.open(io.BytesIO(data)).convert('RGB')
            
        raise ValueError("Unsupported image data type")
        
    except (UnidentifiedImageError, ValueError, IOError) as e:
        raise ContentProcessingError("image", f"Failed to load image: {e}") from e

def get_media_metadata(data: bytes) -> Dict[str, Any]:
    """
    Extract basic metadata from media content.
    
    Args:
        data: Media content as bytes
        
    Returns:
        Dictionary with metadata (varies by content type)
    """
    metadata = {
        'size_bytes': len(data),
        'mime_type': magic.Magic(mime=True).from_buffer(data[:1024])
    }
    
    try:
        # Try to get image-specific metadata
        image = Image.open(io.BytesIO(data))
        metadata.update({
            'width': image.width,
            'height': image.height,
            'mode': image.mode,
            'format': image.format
        })
    except:
        pass
        
    return metadata

def validate_content_size(data: bytes, max_size_mb: float = 50.0) -> None:
    """
    Validate that content size is within limits.
    
    Args:
        data: Content data as bytes
        max_size_mb: Maximum allowed size in megabytes
        
    Raises:
        ContentTooLarge: If content exceeds size limit
    """
    max_size = int(max_size_mb * 1024 * 1024)  # Convert MB to bytes
    if len(data) > max_size:
        from .exceptions import ContentTooLarge
        raise ContentTooLarge(
            content_type=detect_content_type(data).name.lower(),
            size=len(data),
            max_size=max_size
        )

def normalize_text(text: str) -> str:
    """
    Normalize text for consistent processing.
    
    Args:
        text: Input text
        
    Returns:
        Normalized text
    """
    import unicodedata
    import re
    
    # Normalize unicode characters
    text = unicodedata.normalize('NFKC', text)
    
    # Replace multiple whitespace with single space
    text = re.sub(r'\s+', ' ', text)
    
    # Remove control characters
    text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')
    
    return text.strip()

def is_supported_media_type(file_path: Union[str, Path]) -> bool:
    """
    Check if a file's media type is supported for moderation.
    
    Args:
        file_path: Path to the file
        
    Returns:
        bool: True if the media type is supported, False otherwise
    """
    supported_types = [
        # Text
        'text/plain', 'text/markdown', 'application/json', 'application/xml',
        # Images
        'image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp',
        # Videos
        'video/mp4', 'video/avi', 'video/quicktime', 'video/x-ms-wmv',
        'video/x-flv', 'video/webm',
        # Audio
        'audio/mpeg', 'audio/wav', 'audio/ogg', 'audio/x-m4a'
    ]
    
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(str(file_path))
    
    return mime_type in supported_types

def get_file_extension(content_type: str) -> str:
    """
    Get a file extension for a given content type.
    
    Args:
        content_type: MIME type (e.g., 'image/jpeg')
        
    Returns:
        File extension with leading dot (e.g., '.jpg')
    """
    ext = mimetypes.guess_extension(content_type)
    if not ext:
        # Default to .bin for unknown types
        return '.bin'
    
    # Special cases
    if ext == '.jpe':
        return '.jpg'
    elif ext == '.tif':
        return '.tiff'
    
    return ext
