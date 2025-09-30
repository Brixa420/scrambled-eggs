"""
FastAPI Application for Model Serving

This module contains the main FastAPI application for serving machine learning models.
"""
import os
from fastapi import FastAPI, HTTPException, Depends, Request, status, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, Dict, Any, List, Callable
import logging
from datetime import datetime
import json
import os
import time
from pathlib import Path

# Import metrics
from . import metrics

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Brixa AI Model Serving API",
    description="REST API for serving and managing Brixa AI models",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Import and include routers
from .routes import monitoring
app.include_router(monitoring.router)

# Add metrics endpoint
@app.get("/metrics")
async def get_metrics():
    """Return Prometheus metrics."""
    return await metrics.get_metrics()

# Configure monitoring
os.makedirs("monitoring/predictions", exist_ok=True)
os.makedirs("monitoring/metrics", exist_ok=True)

async def monitor_requests(request: Request, call_next):
    """Middleware to monitor requests and update metrics."""
    start_time = time.time()
    method = request.method
    endpoint = request.url.path
    
    try:
        response = await call_next(request)
        status_code = response.status_code
        
        # Update request metrics
        metrics.REQUEST_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        
        metrics.REQUEST_LATENCY.labels(
            method=method,
            endpoint=endpoint
        ).observe(time.time() - start_time)
        
        # Track errors
        if status_code >= 400:
            metrics.ERROR_COUNT.labels(
                method=method,
                endpoint=endpoint,
                status_code=status_code
            ).inc()
            
        return response
        
    except Exception as e:
        status_code = 500
        metrics.ERROR_COUNT.labels(
            method=method,
            endpoint=endpoint,
            status_code=status_code
        ).inc()
        raise

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=json.loads(os.getenv("ALLOWED_ORIGINS", "[\"*\"]")),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Key Security
API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# Request/Response Models
class ModelInfo(BaseModel):
    """Model information response."""
    name: str
    version: str
    description: Optional[str] = None
    framework: str
    created_at: str
    is_production: bool = False
    metrics: Dict[str, Any] = {}

class ModelListResponse(BaseModel):
    """Response model for listing models."""
    models: List[ModelInfo]
    count: int

class SentimentRequest(BaseModel):
    """Request model for sentiment analysis."""
    text: str = Field(..., description="Text to analyze")
    model_version: Optional[str] = Field("latest", description="Model version to use")
    return_tokens: bool = Field(False, description="Return tokenized input")

class SentimentResponse(BaseModel):
    """Response model for sentiment analysis."""
    sentiment: str
    confidence: float
    model_version: str
    timestamp: str
    tokens: Optional[List[str]] = None

class HealthCheck(BaseModel):
    """Health check response model."""
    status: str
    version: str
    timestamp: str

# Routes
@app.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "0.1.0",
        "timestamp": datetime.utcnow().isoformat(),
    }

@app.post("/api/v1/sentiment", response_model=SentimentResponse)
async def analyze_sentiment(request: SentimentRequest):
    """
    Analyze the sentiment of the provided text.
    
    Args:
        request: Sentiment analysis request containing the text to analyze.
        
    Returns:
        Sentiment analysis result with confidence score.
    """
    try:
        # TODO: Implement actual model inference
        # For now, return a mock response
        return {
            "sentiment": "positive",
            "confidence": 0.85,
            "model_version": "0.1.0",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error in sentiment analysis: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize resources when the application starts."""
    logger.info("Starting Brixa API server...")
    # TODO: Load models and other resources

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Clean up resources when the application shuts down."""
    logger.info("Shutting down Brixa API server...")
    # TODO: Clean up resources
