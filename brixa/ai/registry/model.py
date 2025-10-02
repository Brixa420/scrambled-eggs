"""
Model metadata and artifact management for the Brixa AI platform.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Dict, Any, Optional, List, Union, BinaryIO
import json
import hashlib
import shutil

class ModelFormat(Enum):
    """Supported model serialization formats."""
    PYTORCH = "pytorch"
    TENSORFLOW = "tensorflow"
    ONNX = "onnx"
    HUGGINGFACE = "huggingface"
    PICKLE = "pickle"
    JOBLIB = "joblib"
    CUSTOM = "custom"

class ModelTask(Enum):
    """Supported model tasks."""
    CLASSIFICATION = "classification"
    REGRESSION = "regression"
    GENERATION = "generation"
    EMBEDDING = "embedding"
    CLUSTERING = "clustering"
    ANOMALY_DETECTION = "anomaly_detection"
    RECOMMENDATION = "recommendation"
    COMPUTER_VISION = "computer_vision"
    NLP = "nlp"
    AUDIO = "audio"
    OTHER = "other"

@dataclass
class ModelMetadata:
    """Metadata for a machine learning model."""
    name: str
    version: str
    format: ModelFormat
    task: ModelTask
    description: str = ""
    framework: str = ""
    framework_version: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    hyperparameters: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, float] = field(default_factory=dict)
    input_schema: Dict[str, Any] = field(default_factory=dict)
    output_schema: Dict[str, Any] = field(default_factory=dict)
    dependencies: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to a dictionary."""
        data = asdict(self)
        data['format'] = self.format.value
        data['task'] = self.task.value
        data['created_at'] = self.created_at.isoformat()
        data['updated_at'] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ModelMetadata':
        """Create metadata from a dictionary."""
        # Convert string enums back to enum values
        data = data.copy()
        data['format'] = ModelFormat(data['format'])
        data['task'] = ModelTask(data['task'])
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        data['updated_at'] = datetime.fromisoformat(data['updated_at'])
        return cls(**data)

class ModelArtifact:
    """Manages model artifacts and their storage."""
    
    def __init__(self, model_dir: Union[str, Path]):
        """Initialize with a directory to store model artifacts."""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_file = self.model_dir / "metadata.json"
        self.weights_file = self.model_dir / "weights"
        self.vocab_file = self.model_dir / "vocab.json"
        self.config_file = self.model_dir / "config.json"
    
    def save_model(
        self,
        model: Any,
        metadata: ModelMetadata,
        weights_only: bool = False
    ) -> None:
        """Save a model with its metadata."""
        # Update timestamps
        metadata.updated_at = datetime.utcnow()
        
        # Save metadata
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata.to_dict(), f, indent=2)
        
        # Save model weights
        self._save_weights(model, weights_only)
    
    def _save_weights(self, model: Any, weights_only: bool) -> None:
        """Save model weights in the appropriate format."""
        # Implementation depends on the framework
        # This is a placeholder - actual implementation would handle different frameworks
        if hasattr(model, 'save_pretrained'):  # HuggingFace models
            model.save_pretrained(str(self.model_dir))
        elif hasattr(model, 'save_weights'):  # Keras/TensorFlow
            model.save_weights(str(self.weights_file))
        elif hasattr(model, 'save'):  # PyTorch
            import torch
            torch.save(model.state_dict() if weights_only else model, self.weights_file)
        else:
            # Fallback to pickle for other models
            import pickle
            with open(self.weights_file, 'wb') as f:
                pickle.dump(model, f)
    
    def load_metadata(self) -> ModelMetadata:
        """Load model metadata."""
        with open(self.metadata_file, 'r') as f:
            return ModelMetadata.from_dict(json.load(f))
    
    def load_model(self, **kwargs):
        """Load a model from disk."""
        metadata = self.load_metadata()
        
        # Load model based on format
        if metadata.format == ModelFormat.HUGGINGFACE:
            from transformers import AutoModel
            return AutoModel.from_pretrained(str(self.model_dir), **kwargs)
        elif metadata.framework.lower() == 'tensorflow':
            import tensorflow as tf
            if self.weights_file.exists():
                model = self._create_model_from_metadata(metadata)
                model.load_weights(self.weights_file)
                return model
            return tf.saved_model.load(str(self.model_dir), **kwargs)
        elif metadata.framework.lower() == 'pytorch':
            import torch
            if self.weights_file.exists():
                model = self._create_model_from_metadata(metadata)
                model.load_state_dict(torch.load(self.weights_file, **kwargs))
                return model
            return torch.load(self.weights_file, **kwargs)
        else:
            # Fallback to pickle
            import pickle
            with open(self.weights_file, 'rb') as f:
                return pickle.load(f, **kwargs)
    
    def _create_model_from_metadata(self, metadata: ModelMetadata):
        """Create a model instance from metadata."""
        # This would be implemented based on your model architecture registry
        raise NotImplementedError("Model creation from metadata not implemented")
    
    def delete(self) -> None:
        """Delete all model artifacts."""
        if self.model_dir.exists():
            shutil.rmtree(self.model_dir)
    
    def get_file_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the SHA-256 hash of a file."""
        file_path = self.model_dir / file_path
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
            
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify the integrity of model artifacts."""
        if not self.metadata_file.exists():
            return False
            
        try:
            metadata = self.load_metadata()
            # Check if required files exist based on format
            if metadata.format == ModelFormat.HUGGINGFACE:
                required_files = ["pytorch_model.bin", "config.json"]
                return all((self.model_dir / f).exists() for f in required_files)
            return self.weights_file.exists()
        except Exception:
            return False
