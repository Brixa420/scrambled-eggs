"""
Monitoring API endpoints for model performance tracking.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json

from ....ai.monitoring.monitor import monitor, PerformanceMetrics, PredictionRecord
from ....core.config import settings

router = APIRouter(prefix="/monitoring", tags=["monitoring"])

# Reuse the API key header from app.py
from ..app import api_key_header

# Request/Response Models
class ModelMetricsResponse(PerformanceMetrics):
    """Response model for model metrics."""
    pass

class DriftDetectionRequest(BaseModel):
    """Request model for drift detection."""
    reference_metrics: Dict[str, float]
    threshold: float = 0.1

class DriftDetectionResponse(BaseModel):
    """Response model for drift detection."""
    drift_detected: bool
    metrics: Dict[str, Any]
    threshold: float

@router.get("/metrics/{model_name}", response_model=List[ModelMetricsResponse])
async def get_model_metrics(
    model_name: str,
    version: Optional[str] = None,
    _: str = Depends(api_key_header)
):
    """Get performance metrics for a model."""
    try:
        return monitor.get_metrics(model_name, version)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get metrics: {str(e)}"
        )

@router.post("/drift/{model_name}/{version}", response_model=DriftDetectionResponse)
async def detect_drift(
    model_name: str,
    version: str,
    request: DriftDetectionRequest,
    _: str = Depends(api_key_header)
):
    """Detect drift in model performance."""
    try:
        return monitor.detect_drift(
            model_name=model_name,
            model_version=version,
            reference_metrics=request.reference_metrics,
            threshold=request.threshold
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to detect drift: {str(e)}"
        )

@router.get("/predictions/recent", response_model=List[Dict[str, Any]])
async def get_recent_predictions(
    model_name: Optional[str] = None,
    version: Optional[str] = None,
    limit: int = 100,
    _: str = Depends(api_key_header)
):
    """Get recent predictions."""
    try:
        predictions = monitor.recent_predictions
        
        # Filter by model and version if specified
        if model_name:
            predictions = [
                p for p in predictions
                if p.model_name == model_name and (not version or p.model_version == version)
            ]
        
        # Limit the number of results
        predictions = predictions[-limit:]
        
        # Convert to dict and format for JSON serialization
        return [json.loads(p.json()) for p in predictions]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get recent predictions: {str(e)}"
        )

# Add monitoring middleware to track predictions
@app.middleware("http")
async def monitor_predictions(request: Request, call_next):
    """Middleware to monitor API predictions."""
    # Only monitor prediction endpoints
    if not request.url.path.startswith("/predict/"):
        return await call_next(request)
    
    # Get request body for logging
    try:
        body = await request.body()
        request_body = json.loads(body) if body else {}
        
        # Store the request body in the request state for later use
        request.state.request_body = request_body
    except Exception as e:
        logger.warning(f"Failed to parse request body: {str(e)}")
        request.state.request_body = {}
    
    # Process the request
    start_time = datetime.utcnow()
    response = await call_next(request)
    end_time = datetime.utcnow()
    
    # Only log successful predictions
    if response.status_code == 200 and hasattr(request.state, 'request_body'):
        try:
            response_body = json.loads(response.body)
            
            # Log the prediction
            monitor.log_prediction(
                model_name=request.path_params.get("model_name"),
                model_version=request.query_params.get("version", "latest"),
                input_data=request.state.request_body,
                prediction=response_body.get("prediction"),
                confidence=response_body.get("confidence"),
                metadata={
                    "endpoint": request.url.path,
                    "method": request.method,
                    "status_code": response.status_code,
                    "latency_ms": (end_time - start_time).total_seconds() * 1000
                }
            )
        except Exception as e:
            logger.error(f"Failed to log prediction: {str(e)}")
    
    return response
