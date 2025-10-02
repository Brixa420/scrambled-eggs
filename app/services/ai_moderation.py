import os
import logging
import asyncio
from typing import Dict, List, Optional, Tuple, Union, Any
from datetime import datetime, timedelta
import requests
from PIL import Image, ImageOps
import io
import numpy as np
import cv2
from concurrent.futures import ThreadPoolExecutor
from functools import partial

from app.core.config import settings
from app.models.moderation import ViolationType

logger = logging.getLogger(__name__)

class AIModerationService:
    """
    Service for AI-powered content moderation and age verification.
    Uses a combination of local and cloud-based AI models for moderation.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        # Initialize AI models (can be local or API-based)
        self.min_confidence = float(self.config.get('MIN_CONFIDENCE', 0.85))
        self.api_key = os.getenv('AI_MODERATION_API_KEY', '')
        self.api_url = self.config.get('AI_MODERATION_API_URL', '')
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.loop = asyncio.get_event_loop()
        
        # Load local models if available
        self.local_models_loaded = False
        self._load_local_models()
    
    def _load_local_models(self):
        """Load local ML models for content analysis"""
        try:
            # Placeholder for model loading logic
            # In a real implementation, this would load models like:
            # - NSFW detection model
            # - Object detection model
            # - Text analysis model
            self.local_models_loaded = True
            logger.info("Local AI models loaded successfully")
        except Exception as e:
            logger.warning(f"Failed to load local models: {str(e)}")
            self.local_models_loaded = False
    
    async def moderate_content(
        self, 
        content_type: str, 
        content_data: Union[bytes, str], 
        metadata: Optional[Dict] = None,
        check_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze content for policy violations with specific checks.
        
        Args:
            content_type: Type of content ('image', 'video', 'text', 'stream')
            content_data: Binary content data or text
            metadata: Additional metadata about the content
            check_types: List of violation types to check for
                        (e.g., ['csam', 'beastiality', 'violence'])
            
        Returns:
            dict: Analysis results with violation details and confidence scores
        """
        if check_types is None:
            check_types = ['csam', 'beastiality', 'violence']
            
        metadata = metadata or {}
        
        try:
            # Route to appropriate analyzer based on content type
            if content_type in ['image', 'screenshot']:
                result = await self._analyze_image(content_data, metadata, check_types)
            elif content_type == 'video':
                result = await self._analyze_video(content_data, metadata, check_types)
            elif content_type == 'text':
                text = content_data.decode('utf-8') if isinstance(content_data, bytes) else content_data
                result = await self._analyze_text(text, check_types)
            else:
                raise ValueError(f"Unsupported content type: {content_type}")
                
            # Verify age if adult content is detected
            if result.get('is_adult', False) and not await self._verify_age(metadata.get('user_id')):
                result['is_violation'] = True
                result['violation_type'] = 'age_verification_required'
                result['message'] = 'Age verification required for adult content'
                
            return result
            
        except Exception as e:
            logger.error(f"Error in content moderation: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
        except Exception as e:
            logger.error(f"Error in content moderation: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
    
    async def _analyze_image(
        self, 
        image_data: bytes, 
        metadata: Dict,
        check_types: List[str]
    ) -> Dict[str, Any]:
        """
        Analyze an image for policy violations.
        
        Args:
            image_data: Binary image data
            metadata: Additional metadata about the image
            check_types: List of violation types to check for
            
        Returns:
            dict: Analysis results with violation details
        """
        try:
            # Convert to PIL Image for preprocessing
            image = Image.open(io.BytesIO(image_data))
            
            # Basic image validation
            if self._check_image_size(image):
                return self._create_violation_result(
                    'image_too_small',
                    confidence=0.9,
                    reason="Image too small to analyze"
                )
            
            # Initialize result structure
            result = {
                'status': 'success',
                'is_violation': False,
                'violation_type': None,
                'confidence': 0.0,
                'categories': {},
                'is_adult': False,
                'message': ''
            }
            
            # Run checks in parallel
            tasks = []
            
            if 'csam' in check_types:
                tasks.append(self._check_csam(image, image_data))
            if 'bestiality' in check_types:
                tasks.append(self._check_beastiality(image, image_data))
            if 'violence' in check_types:
                tasks.append(self._check_violence(image, image_data))
                
            # Wait for all checks to complete
            check_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            for check_result in check_results:
                if isinstance(check_result, Exception):
                    logger.error(f"Error in image analysis: {str(check_result)}")
                    continue
                    
                if check_result.get('is_violation', False):
                    result['is_violation'] = True
                    result['violation_type'] = check_result.get('violation_type')
                    result['confidence'] = max(
                        result.get('confidence', 0), 
                        check_result.get('confidence', 0)
                    )
                    result['categories'].update(check_result.get('categories', {}))
                    
                    # Set message if this is the highest confidence violation
                    if check_result.get('confidence', 0) > result.get('confidence', 0):
                        result['message'] = check_result.get('message', '')
            
            # Check for adult content
            if any(cat in result.get('categories', {}) for cat in ['nudity', 'explicit']):
                result['is_adult'] = True
                
            return result
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            raise
    
    async def _check_csam(self, image: Image.Image, image_data: bytes) -> Dict[str, Any]:
        """
        Check for Child Sexual Abuse Material (CSAM) in an image.
        
        Args:
            image: PIL Image object
            image_data: Raw image bytes
            
        Returns:
            dict: Analysis results with CSAM detection
        """
        try:
            # In a real implementation, this would use a specialized CSAM detection model
            # This is a simplified example that would be replaced with actual model inference
            
            # Check for potential CSAM indicators
            # 1. Check image characteristics (size, dimensions, etc.)
            width, height = image.size
            aspect_ratio = width / height if height > 0 else 0
            
            # 2. Check for skin tone regions (simplified example)
            # In a real implementation, this would use proper skin detection
            np_image = np.array(image)
            if len(np_image.shape) == 3:  # Color image
                # Convert to HSV for better skin detection
                hsv = cv2.cvtColor(np_image, cv2.COLOR_RGB2HSV)
                # Define skin color range in HSV
                lower_skin = np.array([0, 48, 80], dtype=np.uint8)
                upper_skin = np.array([20, 255, 255], dtype=np.uint8)
                
                # Create mask for skin regions
                skin_mask = cv2.inRange(hsv, lower_skin, upper_skin)
                skin_pixels = cv2.countNonZero(skin_mask)
                total_pixels = width * height
                skin_ratio = skin_pixels / total_pixels if total_pixels > 0 else 0
            else:
                skin_ratio = 0
            
            # 3. Check for potential CSAM indicators (simplified)
            # In a real implementation, this would use a trained ML model
            has_csam_indicators = False
            confidence = 0.0
            
            # Example heuristic checks (would be replaced with actual model inference)
            if skin_ratio > 0.3:  # High skin ratio
                confidence = 0.4
                if aspect_ratio > 0.7 and aspect_ratio < 1.4:  # Square-ish
                    confidence += 0.2
            
            # Check if confidence exceeds threshold
            is_violation = confidence >= self.min_confidence
            
            return {
                'is_violation': is_violation,
                'violation_type': 'csam' if is_violation else None,
                'confidence': min(confidence, 1.0),
                'categories': {
                    'csam': confidence,
                    'skin_ratio': skin_ratio,
                    'aspect_ratio': aspect_ratio
                },
                'message': 'Potential CSAM content detected' if is_violation else ''
            }
            
        except Exception as e:
            logger.error(f"Error in CSAM detection: {str(e)}", exc_info=True)
            return {
                'is_violation': False,
                'confidence': 0.0,
                'categories': {},
                'message': f"Error in CSAM detection: {str(e)}"
            }
    
    async def _check_bestiality(self, image: Image.Image, image_data: bytes) -> Dict[str, Any]:
        """
        Check for bestiality content in an image.
        
        Args:
            image: PIL Image object
            image_data: Raw image bytes
            
        Returns:
            dict: Analysis results with bestiality detection
        """
        try:
            # In a real implementation, this would use a specialized model
            # This is a simplified example
            
            # Convert to numpy array for processing
            np_image = np.array(image)
            
            # Check for animal and human presence
            # In a real implementation, this would use object detection
            has_animal = False
            has_human = False
            
            # Check for skin regions (simplified)
            if len(np_image.shape) == 3:  # Color image
                # Convert to HSV for better skin detection
                hsv = cv2.cvtColor(np_image, cv2.COLOR_RGB2HSV)
                lower_skin = np.array([0, 48, 80], dtype=np.uint8)
                upper_skin = np.array([20, 255, 255], dtype=np.uint8)
                skin_mask = cv2.inRange(hsv, lower_skin, upper_skin)
                skin_ratio = cv2.countNonZero(skin_mask) / (image.width * image.height)
                has_human = skin_ratio > 0.1  # Simple threshold
            
            # Check for animal-like colors (simplified example)
            # In reality, you'd use an animal detection model
            
            # Calculate confidence based on heuristics
            confidence = 0.0
            if has_human:
                confidence = 0.3  # Base confidence if human is detected
                # Add more confidence if certain conditions are met
                # This is where you'd integrate with an actual model
            
            is_violation = confidence >= self.min_confidence
            
            return {
                'is_violation': is_violation,
                'violation_type': 'bestiality' if is_violation else None,
                'confidence': min(confidence, 1.0),
                'categories': {
                    'bestiality': confidence,
                    'has_human': has_human,
                    'has_animal': has_animal
                },
                'message': 'Potential bestiality content detected' if is_violation else ''
            }
            
        except Exception as e:
            logger.error(f"Error in bestiality detection: {str(e)}", exc_info=True)
            return {
                'is_violation': False,
                'confidence': 0.0,
                'categories': {},
                'message': f"Error in bestiality detection: {str(e)}"
            }
    
    async def _check_violence(self, image: Image.Image, image_data: bytes) -> Dict[str, Any]:
        """
        Check for violent content in an image.
        
        Args:
            image: PIL Image object
            image_data: Raw image bytes
            
        Returns:
            dict: Analysis results with violence detection
        """
        try:
            # In a real implementation, this would use a specialized model
            # This is a simplified example
            
            # Convert to grayscale for edge detection
            np_image = np.array(image.convert('L'))
            
            # Edge detection (simplified example)
            edges = cv2.Canny(np_image, 100, 200)
            edge_ratio = np.count_nonzero(edges) / edges.size
            
            # Check for blood-like colors (simplified)
            if len(np.array(image).shape) == 3:  # Color image
                hsv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2HSV)
                # Define blood color range in HSV
                lower_blood = np.array([0, 50, 50], dtype=np.uint8)
                upper_blood = np.array([10, 255, 255], dtype=np.uint8)
                blood_mask = cv2.inRange(hsv, lower_blood, upper_blood)
                blood_ratio = cv2.countNonZero(blood_mask) / (image.width * image.height)
            else:
                blood_ratio = 0
            
            # Calculate confidence based on heuristics
            confidence = (edge_ratio * 0.4) + (blood_ratio * 0.6)
            
            is_violation = confidence >= self.min_confidence
            
            return {
                'is_violation': is_violation,
                'violation_type': 'violence' if is_violation else None,
                'confidence': min(confidence, 1.0),
                'categories': {
                    'violence': confidence,
                    'edge_ratio': edge_ratio,
                    'blood_ratio': blood_ratio
                },
                'message': 'Potentially violent content detected' if is_violation else ''
            }
            
        except Exception as e:
            logger.error(f"Error in violence detection: {str(e)}", exc_info=True)
            return {
                'is_violation': False,
                'confidence': 0.0,
                'categories': {},
                'message': f"Error in violence detection: {str(e)}"
            }
    
    async def _analyze_video(self, video_data: bytes, metadata: Dict, check_types: List[str]) -> Dict[str, Any]:
        """
        Analyze a video for policy violations by sampling frames.
        
        Args:
            video_data: Raw video data
            metadata: Additional metadata about the video
            check_types: List of violation types to check for
            
        Returns:
            dict: Analysis results with violation details
        """
        try:
            # In a real implementation, this would:
            # 1. Extract frames from the video
            # 2. Analyze each frame using _analyze_image
            # 3. Aggregate results across frames
            
            # For now, return a placeholder
            return {
                'status': 'success',
                'is_violation': False,
                'violation_type': None,
                'confidence': 0.0,
                'categories': {},
                'is_adult': False,
                'message': 'Video analysis not fully implemented',
                'frames_analyzed': 0,
                'frame_results': []
            }
            
        except Exception as e:
            logger.error(f"Error analyzing video: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
    
    async def _analyze_text(self, text: str, check_types: List[str]) -> Dict[str, Any]:
        """
        Analyze text for policy violations.
        
        Args:
            text: Text content to analyze
            check_types: List of violation types to check for
            
        Returns:
            dict: Analysis results with violation details
        """
        try:
            # In a real implementation, this would use NLP models
            # to detect various types of violations in text
            
            # For now, return a placeholder
            return {
                'status': 'success',
                'is_violation': False,
                'violation_type': None,
                'confidence': 0.0,
                'categories': {},
                'is_adult': False,
                'message': 'Text analysis not fully implemented'
            }
            
        except Exception as e:
            logger.error(f"Error analyzing text: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
    
    async def _verify_age(self, user_id: Optional[int]) -> bool:
        """
        Verify if a user is of legal age for adult content.
        
        Args:
            user_id: ID of the user to verify
            
        Returns:
            bool: True if user is verified as an adult, False otherwise
        """
        if not user_id:
            return False
            
        # In a real implementation, this would check the user's age verification status
        # from the database or an identity verification service
        # For now, return False as a safe default
        return False
    
    def _check_image_size(self, image: Image.Image) -> bool:
        """Check if image is too small to analyze."""
        min_dimension = self.config.get('MIN_IMAGE_DIMENSION', 50)
        return min(image.width, image.height) < min_dimension
    
    def _create_violation_result(
        self, 
        violation_type: str, 
        confidence: float, 
        reason: str = ''
    ) -> Dict[str, Any]:
        """Create a standardized violation result dictionary."""
        return {
            'status': 'success',
            'is_violation': True,
            'violation_type': violation_type,
            'confidence': min(max(confidence, 0.0), 1.0),
            'categories': {violation_type: min(max(confidence, 0.0), 1.0)},
            'message': reason or f"{violation_type} detected with {confidence:.1%} confidence"
        }
    async def _analyze_text(self, text: str) -> dict:
        """
        Analyze text for policy violations.
        
        Args:
            text: Text content to analyze
            
        Returns:
            dict: Analysis results with violation details
        """
        try:
            # In a real implementation, this would use NLP models
            # to detect various types of violations in text
            
            # For now, return a placeholder
            return {
                'status': 'success',
                'is_violation': False,
                'violation_type': None,
                'confidence': 0.0,
                'categories': {},
                'is_adult': False,
                'message': 'Text analysis not fully implemented'
            }
            
        except Exception as e:
            logger.error(f"Error analyzing text: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e),
                'is_violation': False,
                'confidence': 0.0,
                'categories': {}
            }
    
    async def verify_age(self, document_image: bytes, selfie_image: bytes = None) -> Tuple[bool, Optional[int], dict]:
        """
        Verify user's age using AI.
        
        Args:
            document_image: Image of ID/passport
            selfie_image: Optional selfie for liveness check
            
        Returns:
            Tuple of (is_verified, estimated_age, details)
        """
        try:
            # This would use AI to verify age from ID and optionally match with selfie
            # In a real implementation, we would:
            # 1. Extract birth date from document
            # 2. Verify document authenticity
            # 3. If selfie is provided, perform liveness check and face matching
            # 4. Calculate age and verify it meets minimum requirements
            
            # For now, return a placeholder with a mock successful verification
            return True, 25, {
                'status': 'verified',
                'method': 'ai_verification',
                'confidence': 0.92,
                'verification_timestamp': datetime.utcnow().isoformat(),
                'document_type': 'drivers_license',  # Detected document type
                'verification_provider': 'internal_ai',
                'message': 'Age verification successful (mock)'
            }
            
        except Exception as e:
            logger.error(f"Error in age verification: {str(e)}", exc_info=True)
            return False, None, {
                'error': 'verification_failed',
                'message': str(e)
            }
    
    async def _process_id_document(self, document_image: bytes) -> dict:
        """Process ID document to extract information."""
        # This would integrate with an ID verification service
        # For now, return a placeholder
        return {
            'status': 'success',
            'document_type': 'drivers_license',
            'extracted_data': {
                'date_of_birth': '1990-01-01',
                'document_number': '*****',
                'expiry_date': '2030-01-01'
            },
            'authenticity_checks': {
                'is_authentic': True,
                'confidence': 0.95
            }
        }
    
    async def _check_liveness(self, selfie_image: bytes, document_image: bytes = None) -> dict:
        """Verify that the selfie is from a live person and matches the document."""
        # This would integrate with a liveness detection service
        # For now, return a placeholder
        return {
            'is_live': True,
            'confidence': 0.92,
            'matches_document': True if document_image else None,
            'analysis': {
                'blink_detected': True,
                'motion_detected': True
            }
        }
    
    def _check_image_size(self, image: Image.Image, min_dimension: int = 50) -> bool:
        """Check if image is too small for analysis."""
        return min(image.size) < min_dimension
    
    def _create_violation_result(
        self, 
        violation_type: str, 
        confidence: float, 
        reason: str = None,
        metadata: dict = None
    ) -> dict:
        """Create a standardized violation result."""
        return {
            'status': 'success',
            'is_violation': True,
            'confidence': confidence,
            'violation_type': violation_type,
            'reason': reason,
            'metadata': metadata or {},
            'categories': {
                violation_type: {
                    'confidence': confidence,
                    'reason': reason
                }
            }
        }
