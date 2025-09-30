"""
Model Predictor

This module handles model loading and inference for the model serving API.
"""
import os
import time
import logging
import asyncio
from typing import Dict, List, Any, Optional, Union, Tuple
from pathlib import Path
import json
import importlib

import torch
import numpy as np
from pydantic import ValidationError

from .schemas import ModelInput, ModelOutput, PredictionRequest, PredictionResponse, ModelMetadata
from ..registry import ModelRegistry

logger = logging.getLogger(__name__)

class ModelPredictor:
    """Handles model loading, caching, and prediction."""
    
    def __init__(
        self,
        model_registry: Optional[ModelRegistry] = None,
        model_dir: str = "./models",
        device: Optional[str] = None,
        max_batch_size: int = 32,
        max_wait_time: float = 0.1,
    ):
        """Initialize the model predictor.
        
        Args:
            model_registry: Optional model registry for model discovery
            model_dir: Directory to store downloaded models
            device: Device to run inference on ('cuda', 'cpu', etc.)
            max_batch_size: Maximum batch size for inference
            max_wait_time: Maximum time to wait for batching (seconds)
        """
        self.model_registry = model_registry
        self.model_dir = Path(model_dir)
        self.max_batch_size = max_batch_size
        self.max_wait_time = max_wait_time
        
        # Set device
        self.device = device or ('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Model cache
        self.models: Dict[str, Any] = {}
        self.model_metadata: Dict[str, ModelMetadata] = {}
        
        # Batching state
        self.batch_queue = asyncio.Queue()
        self.batch_processor_task = asyncio.create_task(self._process_batches())
        
        # Create model directory if it doesn't exist
        self.model_dir.mkdir(parents=True, exist_ok=True)
    
    async def predict(self, request: PredictionRequest) -> PredictionResponse:
        """Make a prediction using the specified model.
        
        Args:
            request: Prediction request
            
        Returns:
            Prediction response
        """
        try:
            # Get or load the model
            model, metadata = await self.get_model(request.model_name, request.model_version)
            
            # Prepare inputs
            inputs = self._prepare_inputs(request.inputs, metadata)
            
            # Make prediction
            start_time = time.time()
            outputs = await self._predict_batch(model, inputs, request.parameters)
            inference_time = time.time() - start_time
            
            # Prepare response
            return self._prepare_response(
                request=request,
                outputs=outputs,
                metadata=metadata,
                metrics={"inference_time": inference_time}
            )
            
        except Exception as e:
            logger.error(f"Prediction failed: {str(e)}", exc_info=True)
            raise
    
    async def get_model(
        self, 
        model_name: str, 
        version: str = "latest"
    ) -> Tuple[Any, ModelMetadata]:
        """Get a model from the cache or load it if not found.
        
        Args:
            model_name: Name of the model
            version: Model version (default: 'latest')
            
        Returns:
            Tuple of (model, metadata)
        """
        cache_key = f"{model_name}:{version}"
        
        # Check if model is already loaded
        if cache_key in self.models:
            return self.models[cache_key], self.model_metadata[cache_key]
        
        # Load the model
        return await self._load_model(model_name, version)
    
    async def _load_model(self, model_name: str, version: str) -> Tuple[Any, ModelMetadata]:
        """Load a model from the registry or disk.
        
        Args:
            model_name: Name of the model
            version: Model version
            
        Returns:
            Tuple of (model, metadata)
        """
        cache_key = f"{model_name}:{version}"
        model_path = self.model_dir / model_name / version
        
        # Download model from registry if needed
        if self.model_registry is not None:
            model_path = await self._download_model(model_name, version, model_path)
        
        # Load model metadata
        metadata_path = model_path / "metadata.json"
        if not metadata_path.exists():
            raise ValueError(f"Metadata not found for model {model_name}:{version}")
        
        with open(metadata_path, 'r') as f:
            metadata = ModelMetadata(**json.load(f))
        
        # Load the model
        model = self._load_model_from_disk(model_path, metadata)
        
        # Cache the model
        self.models[cache_key] = model
        self.model_metadata[cache_key] = metadata
        
        return model, metadata
    
    async def _download_model(
        self, 
        model_name: str, 
        version: str, 
        target_dir: Path
    ) -> Path:
        """Download a model from the registry.
        
        Args:
            model_name: Name of the model
            version: Model version
            target_dir: Directory to save the model
            
        Returns:
            Path to the downloaded model
        """
        if self.model_registry is None:
            raise RuntimeError("Model registry not configured")
        
        # Check if model is already downloaded
        if target_dir.exists():
            return target_dir
        
        # Download the model
        logger.info(f"Downloading model {model_name}:{version}...")
        target_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            # This would be implemented based on your model registry
            # For example, downloading files from a remote storage
            model_data = self.model_registry.get_model(model_name, version)
            
            # Save model files
            for filename, content in model_data.files.items():
                filepath = target_dir / filename
                filepath.parent.mkdir(parents=True, exist_ok=True)
                
                if isinstance(content, str):
                    filepath.write_text(content)
                else:
                    filepath.write_bytes(content)
            
            return target_dir
            
        except Exception as e:
            # Clean up on error
            if target_dir.exists():
                shutil.rmtree(target_dir)
            raise RuntimeError(f"Failed to download model: {str(e)}")
    
    def _load_model_from_disk(self, model_path: Path, metadata: ModelMetadata):
        """Load a model from disk based on its metadata."""
        # This is a simplified implementation
        # In a real system, you would handle different model types and frameworks
        
        # Check if the model is a PyTorch model
        if metadata.framework.lower() == 'pytorch':
            model_file = model_path / "model.pt"
            if not model_file.exists():
                raise FileNotFoundError(f"Model file not found: {model_file}")
            
            # Load the model
            model = torch.jit.load(model_file, map_location=self.device)
            model.eval()
            return model
        
        # Add support for other frameworks (TensorFlow, ONNX, etc.)
        raise ValueError(f"Unsupported model framework: {metadata.framework}")
    
    def _prepare_inputs(
        self, 
        inputs: Union[ModelInput, List[ModelInput]],
        metadata: ModelMetadata
    ) -> Dict[str, Any]:
        """Prepare model inputs from the request."""
        if not isinstance(inputs, list):
            inputs = [inputs]
        
        # This is a simplified implementation
        # In a real system, you would handle different input types and preprocess them
        
        batch = {}
        for i, inp in enumerate(inputs):
            # Convert input data to the expected format
            if inp.data_type == "tensor":
                if isinstance(inp.data, (list, np.ndarray)):
                    data = torch.tensor(inp.data, device=self.device)
                else:
                    data = torch.tensor([inp.data], device=self.device)
            else:
                # Handle other input types (text, image, etc.)
                data = inp.data
            
            # Add to batch
            if i == 0:
                batch = {k: [] for k in data.keys()} if isinstance(data, dict) else []
            
            if isinstance(data, dict):
                for k, v in data.items():
                    batch[k].append(v)
            else:
                batch.append(data)
        
        # Convert lists to tensors
        if isinstance(batch, dict):
            return {k: torch.stack(v) if isinstance(v[0], torch.Tensor) else v 
                   for k, v in batch.items()}
        else:
            return torch.stack(batch) if isinstance(batch[0], torch.Tensor) else batch
    
    async def _predict_batch(
        self, 
        model: Any, 
        inputs: Dict[str, Any], 
        parameters: Dict[str, Any]
    ) -> Any:
        """Run batch prediction."""
        with torch.no_grad():
            if isinstance(inputs, dict):
                inputs = {k: v.to(self.device) if hasattr(v, 'to') else v 
                         for k, v in inputs.items()}
                outputs = model(**inputs, **parameters)
            else:
                inputs = inputs.to(self.device) if hasattr(inputs, 'to') else inputs
                outputs = model(inputs, **parameters)
        
        return outputs
    
    def _prepare_response(
        self,
        request: PredictionRequest,
        outputs: Any,
        metadata: ModelMetadata,
        metrics: Dict[str, float]
    ) -> PredictionResponse:
        """Prepare the prediction response."""
        # Convert model outputs to the expected format
        if isinstance(outputs, torch.Tensor):
            outputs = outputs.cpu().numpy()
        
        # Create output objects
        if isinstance(outputs, dict):
            output_objs = []
            for name, data in outputs.items():
                output_objs.append(ModelOutput(
                    data=data,
                    output_type=metadata.output_schema.get(name, {}).get("type", "tensor"),
                    shape=list(data.shape) if hasattr(data, 'shape') else None,
                    dtype=str(data.dtype) if hasattr(data, 'dtype') else None,
                ))
        else:
            output_objs = ModelOutput(
                data=outputs,
                output_type=metadata.output_schema.get("type", "tensor"),
                shape=list(outputs.shape) if hasattr(outputs, 'shape') else None,
                dtype=str(outputs.dtype) if hasattr(outputs, 'dtype') else None,
            )
        
        return PredictionResponse(
            model_name=request.model_name,
            model_version=metadata.version,
            outputs=output_objs,
            request_id=request.request_id,
            metrics=metrics
        )
    
    async def _process_batches(self) -> None:
        """Background task to process batched predictions."""
        while True:
            try:
                # Wait for the first request in the batch
                first_item = await self.batch_queue.get()
                if first_item is None:  # Shutdown signal
                    break
                    
                # Get more items if available
                batch = [first_item]
                start_time = time.time()
                
                # Wait for more items or timeout
                while len(batch) < self.max_batch_size:
                    try:
                        timeout = self.max_wait_time - (time.time() - start_time)
                        if timeout <= 0:
                            break
                            
                        item = await asyncio.wait_for(
                            self.batch_queue.get(),
                            timeout=timeout
                        )
                        batch.append(item)
                    except asyncio.TimeoutError:
                        break
                
                # Process the batch
                await self._process_single_batch(batch)
                
            except Exception as e:
                logger.error(f"Error processing batch: {str(e)}", exc_info=True)
    
    async def _process_single_batch(self, batch: List[Any]) -> None:
        """Process a single batch of prediction requests."""
        # This is a simplified implementation
        # In a real system, you would batch the inputs and run a single forward pass
        
        for item in batch:
            request, future = item
            try:
                response = await self.predict(request)
                future.set_result(response)
            except Exception as e:
                future.set_exception(e)
    
    async def close(self) -> None:
        """Clean up resources."""
        # Signal the batch processor to stop
        if hasattr(self, 'batch_processor_task'):
            await self.batch_queue.put(None)
            await self.batch_processor_task
        
        # Clear model cache
        self.models.clear()
        self.model_metadata.clear()
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
