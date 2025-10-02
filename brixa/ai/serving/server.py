"""
Model Serving API

This module provides a FastAPI-based server for serving AI models.
"""
import os
import time
import logging
import asyncio
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import json
import uuid

from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
import uvicorn

from .predictor import ModelPredictor
from .schemas import (
    PredictionRequest,
    PredictionResponse,
    HealthResponse,
    ModelInfoResponse,
    ErrorResponse,
    ModelMetadata
)
from ..registry import ModelRegistry

logger = logging.getLogger(__name__)

class ModelServer:
    """FastAPI server for model serving."""
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8000,
        model_dir: str = "./models",
        registry_uri: Optional[str] = None,
        debug: bool = False,
        workers: int = 1,
    ):
        """Initialize the model server.
        
        Args:
            host: Host to bind to
            port: Port to listen on
            model_dir: Directory to store models
            registry_uri: URI of the model registry
            debug: Enable debug mode
            workers: Number of worker processes
        """
        self.host = host
        self.port = port
        self.model_dir = Path(model_dir)
        self.debug = debug
        self.workers = workers
        self.start_time = time.time()
        
        # Initialize model registry
        self.model_registry = None
        if registry_uri:
            self.model_registry = ModelRegistry(registry_uri=registry_uri)
        
        # Initialize model predictor
        self.predictor = ModelPredictor(
            model_registry=self.model_registry,
            model_dir=self.model_dir
        )
        
        # Create FastAPI app
        self.app = self._create_app()
    
    def _create_app(self) -> FastAPI:
        """Create and configure the FastAPI application."""
        app = FastAPI(
            title="Brixa AI Model Server",
            description="REST API for serving AI models",
            version="0.1.0",
            debug=self.debug,
        )
        
        # Add middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Add exception handlers
        app.add_exception_handler(HTTPException, self._http_exception_handler)
        app.add_exception_handler(Exception, self._unhandled_exception_handler)
        app.add_exception_handler(
            RequestValidationError, 
            self._validation_exception_handler
        )
        
        # Add startup and shutdown events
        @app.on_event("startup")
        async def startup():
            logger.info("Starting model server...")
            
            # Preload models if needed
            # await self._preload_models()
        
        @app.on_event("shutdown")
        async def shutdown():
            logger.info("Shutting down model server...")
            await self.predictor.close()
        
        # Add routes
        @app.post(
            "/predict",
            response_model=PredictionResponse,
            responses={
                400: {"model": ErrorResponse},
                500: {"model": ErrorResponse},
            }
        )
        async def predict(request: Request, data: PredictionRequest):
            """Make a prediction using a model."""
            return await self._predict(request, data)
        
        @app.get(
            "/health",
            response_model=HealthResponse,
            responses={500: {"model": ErrorResponse}}
        )
        async def health():
            """Health check endpoint."""
            return await self._health_check()
        
        @app.get(
            "/models",
            response_model=List[str],
            responses={500: {"model": ErrorResponse}}
        )
        async def list_models():
            """List all available models."""
            return await self._list_models()
        
        @app.get(
            "/models/{model_name}",
            response_model=ModelInfoResponse,
            responses={
                404: {"model": ErrorResponse},
                500: {"model": ErrorResponse},
            }
        )
        async def get_model_info(model_name: str, version: str = "latest"):
            """Get information about a specific model."""
            return await self._get_model_info(model_name, version)
        
        return app
    
    async def _predict(
        self, 
        request: Request, 
        data: PredictionRequest
    ) -> PredictionResponse:
        """Handle prediction requests."""
        # Add request ID if not provided
        if not data.request_id:
            data.request_id = str(uuid.uuid4())
        
        # Log the request
        logger.info(
            f"Prediction request: model={data.model_name} "
            f"version={data.model_version or 'latest'} "
            f"request_id={data.request_id}"
        )
        
        try:
            # Make prediction
            response = await self.predictor.predict(data)
            return response
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Prediction failed: {str(e)}"
            )
    
    async def _health_check(self) -> HealthResponse:
        """Perform health check."""
        # Check model registry connection
        registry_status = "healthy"
        if self.model_registry:
            try:
                await self.model_registry.ping()
            except Exception as e:
                logger.warning(f"Model registry health check failed: {str(e)}")
                registry_status = f"unhealthy: {str(e)}"
        
        # Check model status
        model_status = {}
        # TODO: Check status of loaded models
        
        return HealthResponse(
            status="healthy",
            model_status=model_status,
            uptime=time.time() - self.start_time,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            registry_status=registry_status
        )
    
    async def _list_models(self) -> List[str]:
        """List all available models."""
        if not self.model_registry:
            return []
        
        try:
            return await self.model_registry.list_models()
        except Exception as e:
            logger.error(f"Failed to list models: {str(e)}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to list models: {str(e)}"
            )
    
    async def _get_model_info(
        self, 
        model_name: str, 
        version: str = "latest"
    ) -> ModelInfoResponse:
        """Get information about a specific model."""
        if not self.model_registry:
            raise HTTPException(
                status_code=status.HTTP_501_NOT_IMPLEMENTED,
                detail="Model registry not configured"
            )
        
        try:
            # Get model metadata from registry
            model = await self.model_registry.get_model(model_name, version)
            
            # Convert to response model
            return ModelInfoResponse(
                name=model.name,
                versions=model.versions,
                default_version=model.default_version,
                platform=model.metadata.get("framework", "unknown"),
                inputs=model.metadata.get("input_schema", []),
                outputs=model.metadata.get("output_schema", []),
                metadata=model.metadata
            )
            
        except ValueError as e:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Model not found: {str(e)}"
            )
        except Exception as e:
            logger.error(
                f"Failed to get model info for {model_name}:{version}: {str(e)}",
                exc_info=True
            )
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to get model info: {str(e)}"
            )
    
    async def _http_exception_handler(
        self, 
        request: Request, 
        exc: HTTPException
    ) -> JSONResponse:
        """Handle HTTP exceptions."""
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": exc.detail,
                "code": exc.status_code,
                "request_id": request.headers.get("x-request-id", "unknown")
            }
        )
    
    async def _validation_exception_handler(
        self, 
        request: Request, 
        exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation exceptions."""
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation error",
                "code": status.HTTP_422_UNPROCESSABLE_ENTITY,
                "details": exc.errors(),
                "request_id": request.headers.get("x-request-id", "unknown")
            }
        )
    
    async def _unhandled_exception_handler(
        self, 
        request: Request, 
        exc: Exception
    ) -> JSONResponse:
        """Handle unhandled exceptions."""
        logger.error(
            f"Unhandled exception: {str(exc)}",
            exc_info=True,
            extra={
                "request_id": request.headers.get("x-request-id", "unknown"),
                "path": request.url.path,
                "method": request.method,
            }
        )
        
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal server error",
                "code": status.HTTP_500_INTERNAL_SERVER_ERROR,
                "request_id": request.headers.get("x-request-id", "unknown")
            }
        )
    
    def run(self):
        """Run the model server."""
        uvicorn.run(
            self.app,
            host=self.host,
            port=self.port,
            workers=self.workers,
            log_level="debug" if self.debug else "info",
        )


def main():
    """Run the model server."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Brixa AI Model Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on")
    parser.add_argument("--model-dir", type=str, default="./models", help="Directory to store models")
    parser.add_argument("--registry-uri", type=str, help="URI of the model registry")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Create and run the server
    server = ModelServer(
        host=args.host,
        port=args.port,
        model_dir=args.model_dir,
        registry_uri=args.registry_uri,
        debug=args.debug,
        workers=args.workers,
    )
    
    server.run()


if __name__ == "__main__":
    main()
