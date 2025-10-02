"""
Admin API Router

This module imports and includes all admin API endpoints.
"""
from fastapi import APIRouter

# Import admin routers
from .feedback import router as feedback_router

# Create main admin router
router = APIRouter(
    prefix="/admin",
    tags=["admin"],
    responses={404: {"description": "Not found"}},
)

# Include admin sub-routers
router.include_router(feedback_router)
