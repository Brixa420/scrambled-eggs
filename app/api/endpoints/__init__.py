"""
API endpoints package.
"""
from fastapi import APIRouter

# Import all endpoint modules here
from . import auth, two_factor

# Create a main router for all API v2 endpoints
router = APIRouter()

# Include all endpoint routers
router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(two_factor.router, prefix="/2fa", tags=["2fa"])
