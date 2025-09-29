"""
Main FastAPI application for Scrambled Eggs.
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from typing import Any, Dict, List, Optional
import json
import os

from app.api.v1.endpoints import auth, moderation
from app.api.endpoints import auth as auth_v2, two_factor
from app.core.config import settings
from app.api.docs.setup import setup_api_docs

app = FastAPI(
    title="Scrambled Eggs API",
    description="""
    ## Scrambled Eggs API
    
    Secure and private messaging platform with end-to-end encryption.
    
    ### Features
    - User authentication and authorization
    - End-to-end encrypted messaging
    - Message moderation capabilities
    - Real-time notifications
    
    ### Authentication
    Most endpoints require authentication. Use the `/auth` endpoints to get an access token.
    
    ### Rate Limiting
    API is rate limited to 1000 requests per hour per IP address.
    """,
    version="1.0.0",
    docs_url=None,  # Disable default docs
    redoc_url=None,  # Disable default redoc
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
# API v1
app.include_router(auth.router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(moderation.router, prefix=f"{settings.API_V1_STR}/moderation", tags=["moderation"])

# API v2 (new endpoints)
app.include_router(auth_v2.router, prefix=f"{settings.API_V1_STR}/v2/auth", tags=["auth_v2"])
app.include_router(two_factor.router, prefix=f"{settings.API_V1_STR}/v2/2fa", tags=["2fa"])

# Initialize API documentation
docs = setup_api_docs(app)

@app.get("/", include_in_schema=False)
async def read_root():
    """Root endpoint that redirects to API documentation."""
    return {
        "message": "Welcome to Scrambled Eggs API",
        "documentation": "/docs",
        "openapi_schema": "/openapi.json"
    }


@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint to verify API is running."""
    return {
        "status": "healthy",
        "version": app.version,
        "environment": settings.ENVIRONMENT
    }


# Custom Swagger UI route
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
