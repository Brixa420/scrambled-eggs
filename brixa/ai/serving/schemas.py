"""
Request/Response Schemas

This module defines the request and response schemas for the model serving API.
"""
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from enum import Enum


class ModelInputType(str, Enum):
    """Supported input types for model prediction."""
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    EMBEDDING = "embedding"
    TENSOR = "tensor"


class ModelOutputType(str, Enum):
    """Supported output types for model prediction."""
    CLASSIFICATION = "classification"
    DETECTION = "detection"
    SEGMENTATION = "segmentation"
    EMBEDDING = "embedding"
    REGRESSION = "regression"
    GENERATION = "generation"


class ModelInput(BaseModel):
    """Base class for model input data."""
    data: Any
    data_type: ModelInputType
    shape: Optional[List[int]] = None
    dtype: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ModelOutput(BaseModel):
    """Base class for model output data."""
    data: Any
    output_type: ModelOutputType
    shape: Optional[List[int]] = None
    dtype: Optional[str] = None
    confidence: Optional[float] = None
    label: Optional[Union[str, List[str]]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ModelMetadata(BaseModel):
    """Model metadata."""
    name: str
    version: str
    framework: str
    description: Optional[str] = None
    input_schema: Dict[str, Any] = Field(default_factory=dict)
    output_schema: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PredictionRequest(BaseModel):
    """Request schema for model prediction."""
    model_name: str
    model_version: Optional[str] = "latest"
    inputs: Union[ModelInput, List[ModelInput]]
    parameters: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None
    timeout: Optional[float] = None


class PredictionResponse(BaseModel):
    """Response schema for model prediction."""
    model_name: str
    model_version: str
    outputs: Union[ModelOutput, List[ModelOutput]]
    request_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, float] = Field(default_factory=dict)


class HealthResponse(BaseModel):
    """Health check response schema."""
    status: str
    model_status: Dict[str, str]
    uptime: float
    timestamp: str


class ErrorResponse(BaseModel):
    """Error response schema."""
    error: str
    code: int
    details: Optional[Dict[str, Any]] = None


class ModelInfoResponse(BaseModel):
    """Model information response schema."""
    name: str
    versions: List[str]
    default_version: str
    platform: str
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    metadata: Dict[str, Any] = Field(default_factory=dict)
