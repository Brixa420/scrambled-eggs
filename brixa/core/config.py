"""
Configuration settings for the AI pipeline.
"""
import os
from pathlib import Path
from typing import Optional, Dict, Any
from pydantic import BaseSettings, Field, validator
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings(BaseSettings):
    """Application settings."""
    
    # Application settings
    APP_NAME: str = "Brixa AI Pipeline"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # Server settings
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Security
    API_KEY: str = Field(..., env="API_KEY")
    SECRET_KEY: str = Field(..., env="SECRET_KEY")
    
    # Model registry
    MODEL_REGISTRY_PATH: str = "models/registry"
    MODEL_STORAGE_PATH: str = "models/storage"
    
    # Training
    DEFAULT_MODEL_NAME: str = "sentiment-analysis"
    DEFAULT_FRAMEWORK: str = "pytorch"
    
    # Paths
    BASE_DIR: Path = Path(__file__).parent.parent.parent
    DATA_DIR: Path = BASE_DIR / "data"
    LOGS_DIR: Path = BASE_DIR / "logs"
    
    # Create necessary directories
    def __init__(self, **values: Any) -> None:
        super().__init__(**values)
        self.DATA_DIR.mkdir(exist_ok=True)
        self.LOGS_DIR.mkdir(exist_ok=True)
        (self.BASE_DIR / self.MODEL_REGISTRY_PATH).parent.mkdir(parents=True, exist_ok=True)
        (self.BASE_DIR / self.MODEL_STORAGE_PATH).parent.mkdir(parents=True, exist_ok=True)
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True

# Global settings instance
settings = Settings()

# Configure logging
import logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(settings.LOGS_DIR / "app.log")
    ]
)

logger = logging.getLogger(__name__)

# Storage configuration
class StorageConfig:
    """Storage configuration for model artifacts."""
    
    @staticmethod
    def get_storage_config() -> Dict[str, Any]:
        """Get storage configuration based on environment."""
        return {
            "type": "local",
            "base_path": str(settings.BASE_DIR / settings.MODEL_STORAGE_PATH)
        }
