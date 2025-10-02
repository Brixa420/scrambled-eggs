"""
Main FastAPI application for Scrambled Eggs.
"""

from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.staticfiles import StaticFiles
from typing import Any, Dict, List, Optional, AsyncGenerator
import asyncio
import json
import logging
import os

from app.api.v1.endpoints import auth as auth_v1, moderation, blockchain as blockchain_v1
from app.api.endpoints import auth as auth_v2, two_factor, rbac, feedback
from app.api.admin import router as admin_router
from app.core.config import settings, get_config
from app.core.blockchain_config import init_blockchain_config, get_blockchain_config
from app.core.rbac_init import init_rbac
from app.services.blockchain_service import BlockchainService
from app.api.docs.setup import setup_api_docs

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global blockchain service instance
blockchain_service: Optional[BlockchainService] = None

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Handle application startup and shutdown events."""
    global blockchain_service
    
    # Load configuration
    config = get_config()
    
    try:
        # Initialize blockchain configuration
        blockchain_config = {
            'enable_mining': config.get('blockchain.enable_mining', False),
            'miner_address': config.get('blockchain.miner_address'),
            'enable_validation': config.get('blockchain.enable_validation', False),
            'validator_address': config.get('blockchain.validator_address'),
            'blockchain_data_dir': config.get('blockchain.data_dir', str(Path.home() / '.scrambled-eggs' / 'blockchain')),
        }
        init_blockchain_config(**blockchain_config)
        
        # Initialize blockchain service
        blockchain_service = BlockchainService()
        await blockchain_service.initialize()
        
        # Start blockchain services if enabled in config
        if blockchain_config['enable_mining'] or blockchain_config['enable_validation']:
            await blockchain_service.start()
            
        logger.info("Blockchain service initialized successfully")
        
        yield  # The application runs here
        
    except Exception as e:
        logger.error(f"Error initializing blockchain service: {e}", exc_info=True)
        raise
        
    finally:
        # Cleanup on shutdown
        if blockchain_service is not None:
            await blockchain_service.stop()
            logger.info("Blockchain service stopped")

app = FastAPI(
    title="Scrambled Eggs API",
    description="""
    ## Scrambled Eggs API
    
    Secure and private messaging platform with end-to-end encryption and blockchain integration.
    
    ### Features
    - User authentication and authorization
    - End-to-end encrypted messaging
    - Message moderation capabilities
    - Real-time notifications
    - Brixa blockchain integration
    - Cryptocurrency mining and validation
    
    ### Authentication
    Most endpoints require authentication. Use the `/auth` endpoints to get an access token.
    
    ### Rate Limiting
    API is rate limited to 1000 requests per hour per IP address.
    
    ### Blockchain
    - Mining and validation endpoints available under `/api/v1/blockchain`
    - Real-time status updates for blockchain operations
    """,
    version="1.0.0",
    docs_url=None,  # Disable default docs
    redoc_url=None,  # Disable default redoc
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan
)

# Mount static files for Swagger UI
app.mount("/static", StaticFiles(directory="static"), name="static")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(
    auth_v1.router,
    prefix=f"{settings.API_V1_STR}/auth",
    tags=["authentication"]
)

# Include moderation endpoints
app.include_router(
    moderation.router,
    prefix=f"{settings.API_V1_STR}/moderation",
    tags=["moderation"]
)

# Include blockchain endpoints
app.include_router(
    blockchain_v1.router,
    prefix=f"{settings.API_V1_STR}/blockchain",
    tags=["blockchain"]
)

# Include API v1 routers
app.include_router(auth_v1.router, prefix="/api/v1/auth", tags=["auth-v1"])
app.include_router(blockchain_v1.router, prefix="/api/v1/blockchain", tags=["blockchain-v1"])
app.include_router(moderation.router, prefix="/api/v1/moderation", tags=["moderation"])

# Include API v2 routers
app.include_router(auth_v2.router, prefix="/api/auth", tags=["auth"])
app.include_router(two_factor.router, prefix="/api/2fa", tags=["2fa"])
app.include_router(rbac.router, prefix="/api/rbac", tags=["rbac"])

# Include feedback and admin routes
app.include_router(feedback.router, prefix="/api/feedback", tags=["feedback"])
app.include_router(admin_router, prefix="/api/admin", tags=["admin"])

# Initialize RBAC system
init_rbac()

# Set up API documentation
setup_api_docs(app)


@app.get("/health", response_model=Dict[str, Any])
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint to verify API and blockchain services are running.
    """
    status = {
        "api": "ok",
        "message": "Scrambled Eggs API is running"
    }
    
    # Add blockchain status if available
    try:
        if blockchain_service is not None:
            status["blockchain"] = blockchain_service.get_status()
        else:
            status["blockchain"] = {"status": "not_initialized"}
    except Exception as e:
        logger.error(f"Error getting blockchain status: {e}", exc_info=True)
        status["blockchain"] = {"status": "error", "error": str(e)}
    
    return status


@app.get("/docs", include_in_schema=False)
async def get_swagger_ui():
    """Serve custom Swagger UI."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


# OpenAPI schema route
@app.get("/openapi.json", include_in_schema=False)
async def get_openapi_schema() -> Dict[str, Any]:
    """Return OpenAPI schema."""
    return get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
