""
Authentication Middleware

This module provides authentication middleware for the API.
"""
from fastapi import Request, HTTPException, status
from fastapi.security import APIKeyHeader
from typing import Optional
import logging

from ..config import settings

logger = logging.getLogger(__name__)

class APIKeyAuth(APIKeyHeader):
    """API Key authentication."""
    
    async def __call__(self, request: Request) -> Optional[str]:
        """Validate API key from request headers."""
        # Skip authentication if no API key is configured
        if not settings.API_KEY:
            return None
            
        api_key = await super().__call__(request)
        if api_key != settings.API_KEY:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid API Key",
            )
        return api_key

# Create an instance of the API key authenticator
api_key_auth = APIKeyAuth(name="X-API-Key", auto_error=True)

def get_api_key(api_key: str = Depends(api_key_auth)) -> str:
    ""
    Dependency to validate API key.
    
    Args:
        api_key: The API key from the request header.
        
    Returns:
        The validated API key.
        
    Raises:
        HTTPException: If the API key is invalid.
    """
    return api_key
