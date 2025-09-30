from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Dict, Any, Optional
import logging

from ...ai.registry.registry import ModelRegistry
from ...ai.models.sentiment import AdvancedSentimentModel
from ...core.config import settings

logger = logging.getLogger(__name__)

router = APIRouter()
api_key_header = APIKeyHeader(name="X-API-Key")

# Initialize model registry and load models
model_registry = ModelRegistry(storage_node=settings.STORAGE_NODE)

# In-memory model cache
_model_cache: Dict[str, Any] = {}

def get_model(model_name: str, version: Optional[str] = None):
    """Get a model from cache or load it from the registry."""
    cache_key = f"{model_name}:{version or 'latest'}"
    
    if cache_key not in _model_cache:
        model_metadata = model_registry.get_model(model_name, version)
        if not model_metadata:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model {model_name} not found"
            )
        
        # Load the model
        model = model_registry.load_model(model_name, version)
        if model is None:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to load model"
            )
        
        _model_cache[cache_key] = {
            'model': model,
            'metadata': model_metadata
        }
    
    return _model_cache[cache_key]

def verify_api_key(api_key: str = Depends(api_key_header)) -> bool:
    """Verify the API key."""
    if api_key != settings.API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key"
        )
    return True

@router.post("/predict/{model_name}")
async def predict(
    model_name: str,
    data: Dict[str, Any],
    version: Optional[str] = None,
    _: bool = Depends(verify_api_key)
):
    """Make a prediction using the specified model."""
    try:
        # Get the model from cache or load it
        model_info = get_model(model_name, version)
        model = model_info['model']
        
        # Make prediction
        # Note: You'll need to adapt this based on your model's input format
        input_text = data.get("text", "")
        
        # This is a simplified example - adapt based on your model's API
        if isinstance(model, AdvancedSentimentModel):
            # Tokenize input and make prediction
            # Note: You'll need to implement the tokenization logic
            # based on how your model was trained
            inputs = model_info['metadata'].input_schema.get("tokenizer").tokenize(input_text)
            outputs = model(**inputs)
            prediction = outputs["logits"].argmax().item()
            
            return {
                "prediction": prediction,
                "model": model_name,
                "version": str(model_info['metadata'].version)
            }
        else:
            # Generic prediction for other model types
            prediction = model.predict([input_text])
            return {
                "prediction": prediction[0],
                "model": model_name,
                "version": str(model_info['metadata'].version)
            }
            
    except Exception as e:
        logger.error(f"Prediction error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )

@router.get("/models/{model_name}")
async def get_model_info(
    model_name: str,
    version: Optional[str] = None,
    _: bool = Depends(verify_api_key)
):
    """Get information about a model."""
    try:
        model_info = get_model(model_name, version)
        return {
            "name": model_name,
            "version": str(model_info['metadata'].version),
            "model_type": model_info['metadata'].model_type,
            "framework": model_info['metadata'].framework,
            "description": model_info['metadata'].description,
            "created_at": model_info['metadata'].created_at.isoformat(),
            "is_production": model_info['metadata'].is_production,
            "metrics": model_info['metadata'].metrics
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting model info: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get model info: {str(e)}"
        )

@router.get("/models")
async def list_models(
    filter_by: Optional[Dict[str, str]] = None,
    _: bool = Depends(verify_api_key)
):
    """List all available models."""
    try:
        models = model_registry.list_models(filter_by)
        return [
            {
                "name": m.name,
                "version": str(m.version),
                "model_type": m.model_type,
                "framework": m.framework,
                "is_production": m.is_production,
                "created_at": m.created_at.isoformat()
            }
            for m in models
        ]
    except Exception as e:
        logger.error(f"Error listing models: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list models: {str(e)}"
        )
