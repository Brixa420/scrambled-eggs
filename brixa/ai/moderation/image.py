"""
Image content moderation using various AI models.
"""
import asyncio
import base64
import io
import logging
from typing import Dict, List, Optional, Any, Union
from PIL import Image, UnidentifiedImageError
import numpy as np

from .base import ContentModerator, ModerationResult, ModerationAction, ContentType

logger = logging.getLogger(__name__)

class ImageModerator(ContentModerator):
    """Moderates image content for policy violations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the image moderator."""
        self.models = {}
        super().__init__(config)
    
    @property
    def content_type(self):
        return ContentType.IMAGE
    
    def _setup(self) -> None:
        """Set up image moderation models based on configuration."""
        try:
            model_configs = self.config.get('models', {})
            
            # Initialize image classification models
            if 'huggingface' in model_configs:
                self._setup_huggingface(model_configs['huggingface'])
                
            if 'google' in model_configs:
                self._setup_google_vision(model_configs['google'])
                
            if 'nsfw_detector' in model_configs:
                self._setup_nsfw_detector(model_configs['nsfw_detector'])
                
            if not self.models:
                logger.warning("No image moderation models configured. Using default setup.")
                self._setup_default_models()
                
        except Exception as e:
            logger.error(f"Error setting up image moderator: {e}")
            raise
    
    def _setup_huggingface(self, config: Dict[str, Any]) -> None:
        """Set up HuggingFace models for image classification."""
        try:
            from transformers import pipeline, AutoModelForImageClassification, AutoFeatureExtractor
            
            model_name = config.get('model', 'google/vit-base-patch16-224')
            threshold = float(config.get('threshold', 0.7))
            
            logger.info(f"Loading HuggingFace image model: {model_name}")
            
            # Load model and feature extractor
            model = AutoModelForImageClassification.from_pretrained(model_name)
            feature_extractor = AutoFeatureExtractor.from_pretrained(model_name)
            
            # Create image classification pipeline
            classifier = pipeline(
                "image-classification",
                model=model,
                feature_extractor=feature_extractor,
                device=0  # Use GPU if available
            )
            
            self.models['huggingface'] = {
                'pipeline': classifier,
                'threshold': threshold,
                'banned_categories': config.get('banned_categories', [
                    'nudity', 'porn', 'sex', 'adult', 'explicit',
                    'violence', 'weapon', 'drug', 'alcohol', 'tobacco'
                ])
            }
            
        except ImportError:
            logger.warning("HuggingFace transformers not installed. Install with: pip install transformers")
        except Exception as e:
            logger.error(f"Error setting up HuggingFace image model: {e}")
    
    def _setup_google_vision(self, config: Dict[str, Any]) -> None:
        """Set up Google Cloud Vision API for image analysis."""
        try:
            from google.cloud import vision
            
            credentials_path = config.get('credentials_path')
            if credentials_path:
                import os
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = credentials_path
            
            self.models['google_vision'] = {
                'client': vision.ImageAnnotatorClient(),
                'threshold': float(config.get('threshold', 0.7)),
                'features': [
                    vision.Feature(type_=vision.Feature.Type.SAFE_SEARCH_DETECTION),
                    vision.Feature(type_=vision.Feature.Type.LABEL_DETECTION)
                ]
            }
            
        except ImportError:
            logger.warning("Google Cloud Vision not installed. Install with: pip install google-cloud-vision")
        except Exception as e:
            logger.error(f"Error setting up Google Vision: {e}")
    
    def _setup_nsfw_detector(self, config: Dict[str, Any]) -> None:
        """Set up NSFW detection model."""
        try:
            from nsfw_detector import predict
            import tensorflow as tf
            
            model_path = config.get('model_path', 'nsfw.299x299.h5')
            threshold = float(config.get('threshold', 0.7))
            
            # Suppress TensorFlow logging
            tf.get_logger().setLevel('ERROR')
            
            self.models['nsfw_detector'] = {
                'model': predict.load_model(model_path),
                'threshold': threshold
            }
            
        except ImportError:
            logger.warning("NSFW detector not installed. Install with: pip install nsfw_detector")
        except Exception as e:
            logger.error(f"Error setting up NSFW detector: {e}")
    
    def _setup_default_models(self) -> None:
        """Set up default models if no configuration is provided."""
        try:
            # Try to use a simple NSFW detector as fallback
            self.models['nsfw_detector'] = {
                'threshold': 0.7
            }
        except Exception as e:
            logger.error(f"Error setting up default models: {e}")
    
    async def moderate(self, image_data: Union[bytes, str, Image.Image], 
                      context: Optional[Dict] = None) -> ModerationResult:
        """
        Moderate the given image content.
        
        Args:
            image_data: The image data (bytes, base64 string, or PIL Image)
            context: Additional context (e.g., user info, content metadata)
            
        Returns:
            ModerationResult with the decision and details
        """
        try:
            # Convert input to PIL Image
            image = await self._load_image(image_data)
            if image is None:
                return ModerationResult(
                    action=ModerationAction.BLOCK,
                    confidence=1.0,
                    reasons=["Invalid or corrupted image"]
                )
            
            # Run all available models in parallel
            tasks = []
            for model_name, model_config in self.models.items():
                if model_name == 'huggingface':
                    tasks.append(self._check_huggingface(image, model_config))
                elif model_name == 'google_vision':
                    tasks.append(self._check_google_vision(image, model_config))
                elif model_name == 'nsfw_detector':
                    tasks.append(self._check_nsfw(image, model_config))
            
            # Wait for all checks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results and make final decision
            return self._process_results(results, context)
            
        except Exception as e:
            logger.error(f"Error in image moderation: {e}", exc_info=True)
            return ModerationResult(
                action=ModerationAction.FLAG,
                confidence=0.0,
                reasons=[f"Error processing image: {str(e)}"]
            )
    
    async def _load_image(self, image_data: Union[bytes, str, Image.Image]) -> Optional[Image.Image]:
        """Load image from various input formats."""
        try:
            if isinstance(image_data, Image.Image):
                return image_data
                
            if isinstance(image_data, str):
                # Handle base64 encoded image
                if image_data.startswith('data:image'):
                    # Extract base64 data from data URL
                    image_data = image_data.split(',', 1)[1]
                # Decode base64
                image_data = base64.b64decode(image_data)
                
            if isinstance(image_data, bytes):
                # Convert bytes to PIL Image
                return Image.open(io.BytesIO(image_data)).convert('RGB')
                
            return None
            
        except (UnidentifiedImageError, ValueError, IOError) as e:
            logger.error(f"Error loading image: {e}")
            return None
    
    async def _check_huggingface(self, image: Image.Image, config: Dict) -> Dict:
        """Check image using HuggingFace model."""
        try:
            classifier = config['pipeline']
            threshold = config['threshold']
            banned_categories = config['banned_categories']
            
            # Run classification
            results = classifier(image)
            
            # Process results
            violations = []
            for result in results:
                if (result['score'] >= threshold and 
                    any(cat in result['label'].lower() for cat in banned_categories)):
                    violations.append({
                        'label': result['label'],
                        'score': float(result['score']),
                        'model': 'huggingface'
                    })
            
            return {
                'model': 'huggingface',
                'violations': violations,
                'confidence': max([v['score'] for v in violations], default=0.0)
            }
            
        except Exception as e:
            logger.error(f"Error in HuggingFace image moderation: {e}")
            return {'model': 'huggingface', 'error': str(e), 'violations': []}
    
    async def _check_google_vision(self, image: Image.Image, config: Dict) -> Dict:
        """Check image using Google Cloud Vision API."""
        try:
            from google.cloud import vision
            from google.cloud.vision_v1.types import Image as VisionImage
            
            client = config['client']
            threshold = config['threshold']
            
            # Convert PIL Image to bytes
            img_byte_arr = io.BytesIO()
            image.save(img_byte_arr, format='PNG')
            img_byte_arr = img_byte_arr.getvalue()
            
            # Create Vision Image
            vision_image = VisionImage(content=img_byte_arr)
            
            # Make API request
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: client.annotate_image({
                    'image': vision_image,
                    'features': config['features']
                })
            )
            
            # Process safe search results
            violations = []
            safe_search = response.safe_search_annotation
            
            # Check for adult, violence, etc.
            for attr in ['adult', 'violence', 'racy', 'medical', 'spoof']:
                likelihood = getattr(safe_search, attr)
                score = self._likelihood_to_score(likelihood)
                
                if score >= threshold:
                    violations.append({
                        'label': f'safe_search_{attr}',
                        'score': score,
                        'model': 'google_vision',
                        'likelihood': likelihood
                    })
            
            # Process label annotations if needed
            for label in response.label_annotations:
                if label.score >= threshold and 'porn' in label.description.lower():
                    violations.append({
                        'label': f'label_{label.description.lower()}',
                        'score': label.score,
                        'model': 'google_vision',
                        'description': label.description
                    })
            
            return {
                'model': 'google_vision',
                'violations': violations,
                'confidence': max([v['score'] for v in violations], default=0.0)
            }
            
        except Exception as e:
            logger.error(f"Error in Google Vision moderation: {e}")
            return {'model': 'google_vision', 'error': str(e), 'violations': []}
    
    async def _check_nsfw(self, image: Image.Image, config: Dict) -> Dict:
        """Check for NSFW content using NSFW detector."""
        try:
            from nsfw_detector import predict
            import tensorflow as tf
            
            model = config.get('model')
            threshold = config.get('threshold', 0.7)
            
            # Convert PIL Image to numpy array
            image = image.resize((299, 299))  # NSFW detector expects 299x299
            img_array = np.array(image)
            
            # Make prediction
            if model:
                predictions = predict.classify_nd(model, img_array)
            else:
                # Fallback to simple color analysis if model not available
                return self._simple_color_analysis(image, threshold)
            
            # Process results
            violations = []
            for label, score in predictions.items():
                if label != 'neutral' and score >= threshold:
                    violations.append({
                        'label': f'nsfw_{label}',
                        'score': float(score),
                        'model': 'nsfw_detector'
                    })
            
            return {
                'model': 'nsfw_detector',
                'violations': violations,
                'confidence': max([v['score'] for v in violations], default=0.0)
            }
            
        except Exception as e:
            logger.error(f"Error in NSFW detection: {e}")
            return {'model': 'nsfw_detector', 'error': str(e), 'violations': []}
    
    def _simple_color_analysis(self, image: Image.Image, threshold: float) -> Dict:
        """Simple color-based NSFW detection as fallback."""
        try:
            # Convert to HSV color space
            hsv_image = image.convert('HSV')
            h, s, v = hsv_image.split()
            
            # Calculate average saturation and value
            avg_saturation = np.mean(s) / 255.0
            avg_value = np.mean(v) / 255.0
            
            # Simple heuristic for NSFW content
            if avg_saturation > 0.5 and avg_value > 0.7:
                return {
                    'model': 'color_analysis',
                    'violations': [{
                        'label': 'high_saturation_brightness',
                        'score': 0.6,  # Medium confidence
                        'model': 'color_analysis'
                    }],
                    'confidence': 0.6
                }
                
            return {'model': 'color_analysis', 'violations': [], 'confidence': 0.0}
            
        except Exception as e:
            logger.error(f"Error in simple color analysis: {e}")
            return {'model': 'color_analysis', 'error': str(e), 'violations': []}
    
    def _likelihood_to_score(self, likelihood: int) -> float:
        """Convert Google Vision likelihood to a score between 0 and 1."""
        # Google Vision likelihood values:
        # UNKNOWN = 0, VERY_UNLIKELY = 1, UNLIKELY = 2, POSSIBLE = 3, 
        # LIKELY = 4, VERY_LIKELY = 5
        return likelihood / 5.0
    
    def _process_results(self, results: List[Dict], context: Optional[Dict]) -> ModerationResult:
        """Process results from all models and make final moderation decision."""
        all_violations = []
        max_confidence = 0.0
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Error in moderation model: {result}")
                continue
                
            if 'violations' in result:
                all_violations.extend(result['violations'])
                max_confidence = max(max_confidence, result.get('confidence', 0))
        
        # If no violations found, allow the content
        if not all_violations:
            return ModerationResult(
                action=ModerationAction.ALLOW,
                confidence=1.0,
                reasons=["No policy violations detected"]
            )
        
        # Sort violations by score (highest first)
        all_violations.sort(key=lambda x: x['score'], reverse=True)
        
        # Get unique violation types
        violation_types = {v['label'] for v in all_violations}
        
        # Determine action based on worst violation
        if any(v['score'] >= 0.9 for v in all_violations):
            action = ModerationAction.BLOCK
        elif any(v['score'] >= 0.7 for v in all_violations):
            action = ModerationAction.QUARANTINE
        else:
            action = ModerationAction.FLAG
        
        return ModerationResult(
            action=action,
            confidence=max_confidence,
            reasons=[f"Detected: {', '.join(violation_types)}"],
            metadata={
                'violations': all_violations,
                'violation_count': len(all_violations)
            }
        )
