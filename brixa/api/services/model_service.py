""
Model Service

This module handles loading and running inference with machine learning models.
"""
import os
import torch
import logging
from typing import Dict, Any, Optional
from pathlib import Path
import json

from ...ai.training import TrainingMetrics
from ...ai.registry import ModelRegistry
from ...config import settings

logger = logging.getLogger(__name__)

class ModelService:
    """Service for managing and running model inference."""
    
    def __init__(self):
        """Initialize the model service."""
        self.model = None
        self.tokenizer = None
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model_registry = ModelRegistry()
        self.current_model_version = None
        
    async def load_model(self, model_path: Optional[str] = None):
        """
        Load a trained model from disk or registry.
        
        Args:
            model_path: Path to the model file. If None, uses the default from config.
        """
        model_path = model_path or settings.MODEL_PATH
        
        try:
            logger.info(f"Loading model from {model_path}")
            
            # Check if model exists
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
                
            # Load model state dict
            checkpoint = torch.load(model_path, map_location=self.device)
            
            # Initialize model architecture (replace with your actual model class)
            from ...ai.models.sentiment import SentimentClassifier
            self.model = SentimentClassifier()
            self.model.load_state_dict(checkpoint['model_state_dict'])
            self.model.to(self.device)
            self.model.eval()
            
            # Load tokenizer (if needed)
            tokenizer_path = os.path.join(os.path.dirname(model_path), 'tokenizer.json')
            if os.path.exists(tokenizer_path):
                from transformers import AutoTokenizer
                self.tokenizer = AutoTokenizer.from_pretrained(os.path.dirname(tokenizer_path))
            
            self.current_model_version = checkpoint.get('version', 'unknown')
            logger.info(f"Model loaded successfully (version: {self.current_model_version})")
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            raise
    
    async def predict_sentiment(self, text: str) -> Dict[str, Any]:
        """
        Predict sentiment for the given text.
        
        Args:
            text: Input text to analyze.
            
        Returns:
            Dictionary containing sentiment prediction and confidence.
        """
        if self.model is None:
            await self.load_model()
            
        try:
            # Tokenize input
            if self.tokenizer:
                inputs = self.tokenizer(text, return_tensors="pt", padding=True, truncation=True, max_length=512)
                inputs = {k: v.to(self.device) for k, v in inputs.items()}
            else:
                # Fallback simple tokenization (example)
                import torch
                inputs = torch.tensor([[ord(c) for c in text[:512]]], device=self.device)
            
            # Run inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                
            # Process outputs (this is an example - adjust based on your model)
            if isinstance(outputs, dict):
                logits = outputs.get('logits', outputs.get('output'))
            else:
                logits = outputs
                
            if logits is not None:
                probs = torch.softmax(logits, dim=-1)
                confidence, predicted = torch.max(probs, dim=-1)
                sentiment = "positive" if predicted.item() == 1 else "negative"
                return {
                    "sentiment": sentiment,
                    "confidence": confidence.item(),
                    "model_version": self.current_model_version or "unknown"
                }
            
            # Fallback if model output format is unexpected
            return {
                "sentiment": "neutral",
                "confidence": 0.5,
                "model_version": self.current_model_version or "unknown"
            }
            
        except Exception as e:
            logger.error(f"Error during prediction: {str(e)}")
            raise
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Get information about the currently loaded model.
        
        Returns:
            Dictionary containing model information.
        """
        return {
            "version": self.current_model_version or "unknown",
            "device": str(self.device),
            "model_type": self.model.__class__.__name__ if self.model else None,
            "tokenizer_type": self.tokenizer.__class__.__name__ if self.tokenizer else None
        }

# Global instance of the model service
model_service = ModelService()

# Initialize the model service on import
import asyncio
asyncio.create_task(model_service.load_model())
