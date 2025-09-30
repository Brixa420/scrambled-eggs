""
API Configuration

This module contains configuration settings for the Brixa API.
"""
import os
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    """Application settings."""
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Brixa AI API"
    DEBUG: bool = os.getenv("DEBUG", "False").lower() in ("true", "1", "t")
    
    # CORS settings
    BACKEND_CORS_ORIGINS: List[str] = ["*"]  # In production, replace with specific origins
    
    # Model settings
    MODEL_PATH: str = os.getenv("MODEL_PATH", "models/sentiment_model.pt")
    MODEL_VERSION: str = os.getenv("MODEL_VERSION", "0.1.0")
    
    # Security
    API_KEY: Optional[str] = os.getenv("API_KEY")
    RATE_LIMIT: str = os.getenv("RATE_LIMIT", "100/minute")
    
    class Config:
        case_sensitive = True
        env_file = ".env"

# Initialize settings
settings = Settings()
