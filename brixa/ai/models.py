"""
Model Management for Brixa AI

This module handles the storage, retrieval, and versioning of AI models.
"""
import asyncio
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union

import numpy as np
import torch
from torch import nn

from ..storage import StorageNode, VersionedStorage


class ModelFormat(Enum):
    """Supported model formats."""
    PYTORCH = "pytorch"
    ONNX = "onnx"
    TENSORFLOW = "tensorflow"
    HUGGINGFACE = "huggingface"
    CUSTOM = "custom"


@dataclass
class ModelMetadata:
    """Metadata for a trained model."""
    model_id: str
    name: str
    format: ModelFormat
    architecture: str
    input_shape: Tuple[int, ...]
    output_shape: Tuple[int, ...]
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    metrics: Dict[str, float] = field(default_factory=dict)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    author: str = ""
    version: str = "1.0.0"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary."""
        return {
            "model_id": self.model_id,
            "name": self.name,
            "format": self.format.value,
            "architecture": self.architecture,
            "input_shape": list(self.input_shape),
            "output_shape": list(self.output_shape),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": self.tags,
            "metrics": self.metrics,
            "hyperparameters": self.hyperparameters,
            "description": self.description,
            "author": self.author,
            "version": self.version,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Create metadata from a dictionary."""
        return cls(
            model_id=data["model_id"],
            name=data["name"],
            format=ModelFormat(data["format"]),
            architecture=data["architecture"],
            input_shape=tuple(data["input_shape"]),
            output_shape=tuple(data["output_shape"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            tags=data.get("tags", []),
            metrics=data.get("metrics", {}),
            hyperparameters=data.get("hyperparameters", {}),
            description=data.get("description", ""),
            author=data.get("author", ""),
            version=data.get("version", "1.0.0"),
        )


class ModelManager:
    """
    Manages AI models in the Brixa system.
    
    Handles storage, retrieval, and versioning of AI models.
    """
    
    def __init__(self, storage_node: StorageNode):
        """
        Initialize the ModelManager.
        
        Args:
            storage_node: The storage node to use for model storage
        """
        self.storage_node = storage_node
        self.logger = logging.getLogger(__name__)
        self._model_cache: Dict[str, Any] = {}
    
    async def initialize(self):
        """Initialize the model manager."""
        self.logger.info("Initializing ModelManager...")
        # Initialize any required resources
        self.logger.info("ModelManager initialized")
    
    async def save_model(
        self,
        model: Union[nn.Module, Any],
        metadata: ModelMetadata,
        format: ModelFormat = ModelFormat.PYTORCH,
        **kwargs
    ) -> str:
        """
        Save a model to the storage system.
        
        Args:
            model: The model to save
            metadata: Model metadata
            format: The format to save the model in
            **kwargs: Additional save parameters
            
        Returns:
            str: The ID of the saved model
        """
        self.logger.info(f"Saving model {metadata.name}...")
        
        # Generate a unique ID if not provided
        if not metadata.model_id:
            metadata.model_id = self._generate_model_id(metadata.name)
        
        # Update timestamps
        metadata.updated_at = datetime.utcnow()
        
        # Save model based on format
        model_data = await self._serialize_model(model, format, **kwargs)
        
        # Save model data
        model_key = f"models/{metadata.model_id}/model"
        await self.storage_node.set(model_key, model_data)
        
        # Save metadata
        metadata_key = f"models/{metadata.model_id}/metadata"
        await self.storage_node.set(metadata_key, json.dumps(metadata.to_dict()).encode())
        
        self.logger.info(f"Saved model {metadata.name} with ID {metadata.model_id}")
        return metadata.model_id
    
    async def load_model(
        self,
        model_id: str,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ) -> Tuple[Any, ModelMetadata]:
        """
        Load a model from storage.
        
        Args:
            model_id: The ID of the model to load
            device: The device to load the model onto
            
        Returns:
            Tuple[Any, ModelMetadata]: The loaded model and its metadata
        """
        # Check cache first
        if model_id in self._model_cache:
            return self._model_cache[model_id]
        
        # Load metadata
        metadata = await self.get_model_metadata(model_id)
        
        # Load model data
        model_key = f"models/{model_id}/model"
        model_data = await self.storage_node.get(model_key)
        if not model_data:
            raise ValueError(f"Model {model_id} not found")
        
        # Deserialize model
        model = await self._deserialize_model(model_data, metadata.format, device=device)
        
        # Cache the model
        self._model_cache[model_id] = (model, metadata)
        
        return model, metadata
    
    async def get_model_metadata(self, model_id: str) -> ModelMetadata:
        """
        Get metadata for a model.
        
        Args:
            model_id: The ID of the model
            
        Returns:
            ModelMetadata: The model metadata
        """
        metadata_key = f"models/{model_id}/metadata"
        metadata_data = await self.storage_node.get(metadata_key)
        if not metadata_data:
            raise ValueError(f"Metadata for model {model_id} not found")
        
        return ModelMetadata.from_dict(json.loads(metadata_data.decode()))
    
    async def list_models(
        self,
        filter_by: Optional[Dict[str, Any]] = None
    ) -> List[ModelMetadata]:
        """
        List all available models.
        
        Args:
            filter_by: Optional filters to apply
            
        Returns:
            List[ModelMetadata]: List of model metadata
        """
        # In a real implementation, this would query the storage system
        # For now, we'll just return an empty list
        return []
    
    async def delete_model(self, model_id: str) -> bool:
        """
        Delete a model.
        
        Args:
            model_id: The ID of the model to delete
            
        Returns:
            bool: True if the model was deleted, False otherwise
        """
        # Delete model data
        model_key = f"models/{model_id}/model"
        metadata_key = f"models/{model_id}/metadata"
        
        await self.storage_node.delete(model_key)
        await self.storage_node.delete(metadata_key)
        
        # Remove from cache
        self._model_cache.pop(model_id, None)
        
        return True
    
    async def _serialize_model(
        self,
        model: Any,
        format: ModelFormat,
        **kwargs
    ) -> bytes:
        """
        Serialize a model to bytes.
        
        Args:
            model: The model to serialize
            format: The format to serialize to
            **kwargs: Additional serialization parameters
            
        Returns:
            bytes: The serialized model
        """
        if format == ModelFormat.PYTORCH and isinstance(model, nn.Module):
            buffer = io.BytesIO()
            torch.save(model.state_dict(), buffer)
            return buffer.getvalue()
        elif format == ModelFormat.ONNX:
            # ONNX export would go here
            raise NotImplementedError("ONNX export not implemented")
        else:
            # For other formats, use pickle as a fallback
            import pickle
            return pickle.dumps(model)
    
    async def _deserialize_model(
        self,
        data: bytes,
        format: ModelFormat,
        **kwargs
    ) -> Any:
        """
        Deserialize a model from bytes.
        
        Args:
            data: The serialized model data
            format: The format of the serialized data
            **kwargs: Additional deserialization parameters
            
        Returns:
            Any: The deserialized model
        """
        device = kwargs.get("device", "cpu")
        
        if format == ModelFormat.PYTORCH:
            buffer = io.BytesIO(data)
            model = torch.load(buffer, map_location=device)
            if isinstance(model, nn.Module):
                model = model.to(device)
            return model
        else:
            # For other formats, use pickle as a fallback
            import pickle
            return pickle.loads(data)
    
    def _generate_model_id(self, name: str) -> str:
        """Generate a unique model ID."""
        timestamp = int(datetime.utcnow().timestamp() * 1000)
        random_str = hashlib.md5(os.urandom(16)).hexdigest()[:8]
        name_slug = "".join(c if c.isalnum() else "_" for c in name.lower())
        return f"{name_slug}_{timestamp}_{random_str}"
