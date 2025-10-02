""
Utility functions for model serving.
"""
import os
import json
import logging
import hashlib
import shutil
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, Union, List

import torch
import numpy as np

logger = logging.getLogger(__name__)

def load_model_from_registry(
    model_name: str,
    version: str = "latest",
    model_dir: Union[str, Path] = "./models",
    registry_uri: Optional[str] = None,
    device: Optional[str] = None,
) -> Tuple[Any, Dict[str, Any]]:
    """Load a model from the model registry.
    
    Args:
        model_name: Name of the model to load
        version: Model version (default: 'latest')
        model_dir: Directory to store the model
        registry_uri: URI of the model registry
        device: Device to load the model on ('cuda', 'cpu', etc.)
        
    Returns:
        Tuple of (model, metadata)
    """
    model_dir = Path(model_dir)
    model_path = model_dir / model_name / version
    
    # Create model directory if it doesn't exist
    model_path.mkdir(parents=True, exist_ok=True)
    
    # Check if model is already downloaded
    metadata_path = model_path / "metadata.json"
    if not metadata_path.exists():
        if not registry_uri:
            raise ValueError(
                f"Model {model_name}:{version} not found locally and no registry URI provided"
        )
        
        # Download the model from the registry
        logger.info(f"Downloading model {model_name}:{version} from registry...")
        _download_model_from_registry(
            model_name=model_name,
            version=version,
            target_dir=model_path,
            registry_uri=registry_uri
        )
    
    # Load metadata
    with open(metadata_path, 'r') as f:
        metadata = json.load(f)
    
    # Load the model
    model = _load_model(model_path, metadata, device)
    
    return model, metadata

def _download_model_from_registry(
    model_name: str,
    version: str,
    target_dir: Path,
    registry_uri: str
) -> None:
    """Download a model from the registry.
    
    Args:
        model_name: Name of the model to download
        version: Model version
        target_dir: Directory to save the model
        registry_uri: URI of the model registry
    """
    # This is a simplified implementation
    # In a real system, you would use the registry client to download the model
    
    # Create target directory
    target_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Simulate downloading model files
        # In a real implementation, you would use the registry client
        # to download the actual model files
        
        # Create dummy model file
        model_file = target_dir / "model.pt"
        model_file.touch()
        
        # Create metadata
        metadata = {
            "name": model_name,
            "version": version,
            "framework": "pytorch",
            "description": f"{model_name} model",
            "input_schema": {
                "type": "tensor",
                "shape": [1, 3, 224, 224],
                "dtype": "float32"
            },
            "output_schema": {
                "type": "tensor",
                "shape": [1, 1000],
                "dtype": "float32"
            },
            "created_at": "2023-01-01T00:00:00Z",
            "updated_at": "2023-01-01T00:00:00Z"
        }
        
        # Save metadata
        with open(target_dir / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
            
        logger.info(f"Successfully downloaded model {model_name}:{version}")
        
    except Exception as e:
        # Clean up on error
        if target_dir.exists():
            shutil.rmtree(target_dir)
        raise RuntimeError(f"Failed to download model: {str(e)}")

def _load_model(
    model_path: Path,
    metadata: Dict[str, Any],
    device: Optional[str] = None
) -> Any:
    """Load a model from disk.
    
    Args:
        model_path: Path to the model directory
        metadata: Model metadata
        device: Device to load the model on
        
    Returns:
        Loaded model
    """
    if device is None:
        device = 'cuda' if torch.cuda.is_available() else 'cpu'
    
    framework = metadata.get("framework", "pytorch").lower()
    
    if framework == "pytorch":
        return _load_pytorch_model(model_path, metadata, device)
    elif framework == "onnx":
        return _load_onnx_model(model_path, metadata, device)
    else:
        raise ValueError(f"Unsupported framework: {framework}")

def _load_pytorch_model(
    model_path: Path,
    metadata: Dict[str, Any],
    device: str
) -> torch.nn.Module:
    """Load a PyTorch model."""
    model_file = model_path / "model.pt"
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    
    # Load the model
    try:
        model = torch.jit.load(model_file, map_location=device)
        model.eval()
        return model
    except Exception as e:
        raise RuntimeError(f"Failed to load PyTorch model: {str(e)}")

def _load_onnx_model(
    model_path: Path,
    metadata: Dict[str, Any],
    device: str
) -> Any:
    """Load an ONNX model."""
    try:
        import onnxruntime as ort
    except ImportError:
        raise ImportError(
            "ONNX Runtime is required for loading ONNX models. "
            "Install with: pip install onnxruntime"
        )
    
    model_file = model_path / "model.onnx"
    if not model_file.exists():
        raise FileNotFoundError(f"Model file not found: {model_file}")
    
    # Set up ONNX Runtime session options
    sess_options = ort.SessionOptions()
    
    # Configure execution providers based on device
    providers = []
    if device.startswith("cuda"):
        providers = ["CUDAExecutionProvider", "CPUExecutionProvider"]
    else:
        providers = ["CPUExecutionProvider"]
    
    # Create the ONNX Runtime session
    try:
        session = ort.InferenceSession(
            str(model_file),
            sess_options,
            providers=providers
        )
        return session
    except Exception as e:
        raise RuntimeError(f"Failed to load ONNX model: {str(e)}")

def calculate_sha256(file_path: Union[str, Path]) -> str:
    """Calculate the SHA-256 hash of a file."""
    file_path = Path(file_path)
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

def get_model_size(model_path: Union[str, Path]) -> int:
    """Get the size of a model in bytes."""
    model_path = Path(model_path)
    
    if model_path.is_file():
        return model_path.stat().st_size
    
    # If it's a directory, calculate total size of all files
    total_size = 0
    for file_path in model_path.rglob("*"):
        if file_path.is_file():
            total_size += file_path.stat().st_size
    
    return total_size

def format_model_size(size_bytes: int) -> str:
    """Format model size in a human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"

def get_available_devices() -> List[Dict[str, Any]]:
    """Get information about available devices."""
    devices = []
    
    # CPU
    cpu_info = {
        "device_type": "cpu",
        "name": "CPU",
        "memory": None,
        "available": True
    }
    devices.append(cpu_info)
    
    # Check for CUDA devices
    if torch.cuda.is_available():
        for i in range(torch.cuda.device_count()):
            props = torch.cuda.get_device_properties(i)
            
            device_info = {
                "device_type": "cuda",
                "index": i,
                "name": props.name,
                "capability": f"{props.major}.{props.minor}",
                "memory": {
                    "total": props.total_memory,
                    "free": torch.cuda.memory_reserved(i) - torch.cuda.memory_allocated(i),
                    "used": torch.cuda.memory_allocated(i)
                },
                "available": True
            }
            devices.append(device_info)
    
    return devices

def move_to_device(
    data: Any, 
    device: Union[str, torch.device]
) -> Any:
    """Move data to the specified device.
    
    Args:
        data: Data to move (tensor, dict, list, etc.)
        device: Target device
        
    Returns:
        Data on the target device
    """
    if isinstance(data, (list, tuple)):
        return type(data)(move_to_device(x, device) for x in data)
    elif isinstance(data, dict):
        return {k: move_to_device(v, device) for k, v in data.items()}
    elif hasattr(data, 'to'):
        return data.to(device)
    return data
