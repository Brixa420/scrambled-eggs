"""
Application settings and configuration.
"""
import os
from typing import List, Optional, Union
from pydantic import AnyHttpUrl, BaseSettings, validator

class Settings(BaseSettings):
    # API settings
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "Scrambled Eggs API"
    
    # Security
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 days
    
    # CORS
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = ["http://localhost:3000"]
    
    # Database
    DATABASE_URL: str = "sqlite:///./scrambled_eggs.db"
    
    # Security
    SECURITY_BCRYPT_ROUNDS: int = 12
    
    class Config:
        case_sensitive = True
        env_file = ".env"

# Create settings instance
settings = Settings()
