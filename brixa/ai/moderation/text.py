"""
Text content moderation using various AI models.
"""
import asyncio
from typing import Dict, List, Optional, Any
import logging
from .base import ContentModerator, ModerationResult, ModerationAction, ContentType

logger = logging.getLogger(__name__)

class TextModerator(ContentModerator):
    """Moderates text content for policy violations."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the text moderator."""
        self.models = {}
        super().__init__(config)
    
    @property
    def content_type(self):
        return ContentType.TEXT
    
    def _setup(self) -> None:
        """Set up text moderation models based on configuration."""
        try:
            model_configs = self.config.get('models', {})
            
            # Initialize text classification models
            if 'huggingface' in model_configs:
                self._setup_huggingface(model_configs['huggingface'])
                
            if 'openai' in model_configs:
                self._setup_openai(model_configs['openai'])
                
            if not self.models:
                logger.warning("No text moderation models configured. Using default setup.")
                self._setup_default_models()
                
        except Exception as e:
            logger.error(f"Error setting up text moderator: {e}")
            raise
    
    def _setup_huggingface(self, config: Dict[str, Any]) -> None:
        """Set up HuggingFace models for text classification."""
        try:
            from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer
            
            model_name = config.get('model', 'facebook/bart-large-mnli')
            threshold = float(config.get('threshold', 0.8))
            
            logger.info(f"Loading HuggingFace model: {model_name}")
            
            # Load model and tokenizer
            model = AutoModelForSequenceClassification.from_pretrained(model_name)
            tokenizer = AutoTokenizer.from_pretrained(model_name)
            
            # Create text classification pipeline
            classifier = pipeline(
                "zero-shot-classification",
                model=model,
                tokenizer=tokenizer,
                device=0  # Use GPU if available
            )
            
            self.models['huggingface'] = {
                'pipeline': classifier,
                'threshold': threshold,
                'labels': config.get('labels', [
                    'hate', 'violence', 'harassment', 'self-harm',
                    'sexual', 'child_sexual_exploitation', 'shocking',
                    'hate_speech', 'spam', 'misinformation'
                ])
            }
            
        except ImportError:
            logger.warning("HuggingFace transformers not installed. Install with: pip install transformers")
        except Exception as e:
            logger.error(f"Error setting up HuggingFace model: {e}")
    
    def _setup_openai(self, config: Dict[str, Any]) -> None:
        """Set up OpenAI's moderation API."""
        try:
            import openai
            
            api_key = config.get('api_key') or os.getenv('OPENAI_API_KEY')
            if not api_key:
                logger.warning("OpenAI API key not provided. Skipping OpenAI setup.")
                return
                
            openai.api_key = api_key
            self.models['openai'] = {
                'client': openai,
                'threshold': float(config.get('threshold', 0.8))
            }
            
        except ImportError:
            logger.warning("OpenAI not installed. Install with: pip install openai")
        except Exception as e:
            logger.error(f"Error setting up OpenAI: {e}")
    
    def _setup_default_models(self) -> None:
        """Set up default models if no configuration is provided."""
        try:
            # Try to use a simple keyword-based matcher as fallback
            self.models['keyword'] = {
                'banned_phrases': [
                    'hate speech', 'racis', 'sexis', 'discriminat',
                    'kill you', 'hurt you', 'self-harm', 'suicid',
                    'porn', 'nude', 'naked', 'sex', 'fuck', 'shit', 'bitch', 'asshole'
                ],
                'threshold': 0.7
            }
        except Exception as e:
            logger.error(f"Error setting up default models: {e}")
    
    async def moderate(self, text: str, context: Optional[Dict] = None) -> ModerationResult:
        """
        Moderate the given text content.
        
        Args:
            text: The text content to moderate
            context: Additional context (e.g., user info, content metadata)
            
        Returns:
            ModerationResult with the decision and details
        """
        if not text or not isinstance(text, str):
            return ModerationResult(
                action=ModerationAction.ALLOW,
                confidence=1.0,
                reasons=["Empty or invalid text content"]
            )
        
        # Run all available models in parallel
        tasks = []
        for model_name, model_config in self.models.items():
            if model_name == 'huggingface':
                tasks.append(self._check_huggingface(text, model_config))
            elif model_name == 'openai':
                tasks.append(self._check_openai(text, model_config))
            elif model_name == 'keyword':
                tasks.append(self._check_keywords(text, model_config))
        
        # Wait for all checks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and make final decision
        return self._process_results(results, text, context)
    
    async def _check_huggingface(self, text: str, config: Dict) -> Dict:
        """Check text using HuggingFace model."""
        try:
            classifier = config['pipeline']
            labels = config['labels']
            threshold = config['threshold']
            
            # Run classification
            result = classifier(text, labels, multi_label=True)
            
            # Process results
            violations = []
            for label, score in zip(result['labels'], result['scores']):
                if score >= threshold:
                    violations.append({
                        'label': label,
                        'score': float(score),
                        'model': 'huggingface'
                    })
            
            return {
                'model': 'huggingface',
                'violations': violations,
                'confidence': max([v['score'] for v in violations], default=0.0)
            }
            
        except Exception as e:
            logger.error(f"Error in HuggingFace moderation: {e}")
            return {'model': 'huggingface', 'error': str(e), 'violations': []}
    
    async def _check_openai(self, text: str, config: Dict) -> Dict:
        """Check text using OpenAI's moderation API."""
        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.models['openai']['client'].Moderation.create(input=text)
            )
            
            result = response['results'][0]
            violations = []
            
            for category, flagged in result['categories'].items():
                if flagged and result['category_scores'][category] >= config['threshold']:
                    violations.append({
                        'label': category,
                        'score': float(result['category_scores'][category]),
                        'model': 'openai'
                    })
            
            return {
                'model': 'openai',
                'violations': violations,
                'confidence': result['scores']['overall']
            }
            
        except Exception as e:
            logger.error(f"Error in OpenAI moderation: {e}")
            return {'model': 'openai', 'error': str(e), 'violations': []}
    
    async def _check_keywords(self, text: str, config: Dict) -> Dict:
        """Check for banned keywords in text."""
        text_lower = text.lower()
        violations = []
        
        for phrase in config.get('banned_phrases', []):
            if phrase in text_lower:
                violations.append({
                    'label': 'banned_phrase',
                    'score': 0.9,  # High confidence for exact matches
                    'phrase': phrase,
                    'model': 'keyword'
                })
        
        return {
            'model': 'keyword',
            'violations': violations,
            'confidence': 0.9 if violations else 0.0
        }
    
    def _process_results(self, results: List[Dict], text: str, context: Optional[Dict]) -> ModerationResult:
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
            action = ModerationAction.FLAG
        else:
            action = ModerationAction.ALLOW
        
        return ModerationResult(
            action=action,
            confidence=max_confidence,
            reasons=[f"Detected: {', '.join(violation_types)}"],
            metadata={
                'violations': all_violations,
                'text_preview': text[:200] + ('...' if len(text) > 200 else '')
            }
        )
