"""
Inference Service for Brixa AI

This module handles model serving and inference in a distributed environment.
"""
import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Callable, Union

import numpy as np
import torch
from torch import nn

from ..storage import StorageNode
from .models import ModelManager, ModelMetadata, ModelFormat


class InferenceRequest:
    """Represents an inference request."""
    
    def __init__(
        self,
        model_id: str,
        input_data: Any,
        request_id: Optional[str] = None,
        priority: int = 0,
        timeout: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize an inference request.
        
        Args:
            model_id: ID of the model to use for inference
            input_data: Input data for the model
            request_id: Optional request ID (auto-generated if not provided)
            priority: Priority of the request (higher = higher priority)
            timeout: Optional timeout in seconds
            metadata: Additional metadata for the request
        """
        self.request_id = request_id or f"req_{int(time.time() * 1000)}_{hash(str(input_data)) % 10000:04d}"
        self.model_id = model_id
        self.input_data = input_data
        self.priority = priority
        self.timeout = timeout
        self.metadata = metadata or {}
        self.created_at = time.time()
        self.started_at: Optional[float] = None
        self.completed_at: Optional[float] = None
        self.result: Optional[Any] = None
        self.error: Optional[str] = None
        self._event = asyncio.Event()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert the request to a dictionary."""
        return {
            "request_id": self.request_id,
            "model_id": self.model_id,
            "priority": self.priority,
            "timeout": self.timeout,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'InferenceRequest':
        """Create a request from a dictionary."""
        request = cls(
            model_id=data["model_id"],
            input_data=data.get("input_data"),
            request_id=data.get("request_id"),
            priority=data.get("priority", 0),
            timeout=data.get("timeout"),
            metadata=data.get("metadata", {})
        )
        
        request.started_at = data.get("started_at")
        request.completed_at = data.get("completed_at")
        request.result = data.get("result")
        request.error = data.get("error")
        
        return request
    
    async def wait(self, timeout: Optional[float] = None) -> Any:
        """
        Wait for the request to complete.
        
        Args:
            timeout: Maximum time to wait in seconds
            
        Returns:
            The inference result
            
        Raises:
            asyncio.TimeoutError: If the timeout is reached
            Exception: If an error occurred during inference
        """
        try:
            await asyncio.wait_for(self._event.wait(), timeout=timeout or self.timeout)
            
            if self.error:
                raise Exception(f"Inference failed: {self.error}")
                
            return self.result
        except asyncio.TimeoutError:
            raise asyncio.TimeoutError("Inference request timed out")
    
    def set_result(self, result: Any):
        """Set the result of the request."""
        self.result = result
        self.completed_at = time.time()
        self._event.set()
    
    def set_error(self, error: str):
        """Set an error for the request."""
        self.error = error
        self.completed_at = time.time()
        self._event.set()


class InferenceMetrics:
    """Metrics for inference operations."""
    
    def __init__(self):
        """Initialize metrics."""
        self.start_time = time.time()
        self.total_requests = 0
        self.failed_requests = 0
        self.total_latency = 0.0
        self.requests_per_second = 0.0
        self.last_update = self.start_time
        
        # Per-model metrics
        self.model_metrics: Dict[str, Dict[str, Any]] = {}
    
    def record_request(
        self,
        model_id: str,
        latency: float,
        success: bool = True
    ):
        """
        Record an inference request.
        
        Args:
            model_id: ID of the model
            latency: Request latency in seconds
            success: Whether the request was successful
        """
        self.total_requests += 1
        self.total_latency += latency
        
        if not success:
            self.failed_requests += 1
        
        # Update model-specific metrics
        if model_id not in self.model_metrics:
            self.model_metrics[model_id] = {
                "total_requests": 0,
                "failed_requests": 0,
                "total_latency": 0.0,
                "last_latency": 0.0,
                "avg_latency": 0.0
            }
        
        model_metric = self.model_metrics[model_id]
        model_metric["total_requests"] += 1
        model_metric["total_latency"] += latency
        model_metric["last_latency"] = latency
        model_metric["avg_latency"] = (
            model_metric["total_latency"] / model_metric["total_requests"]
        )
        
        if not success:
            model_metric["failed_requests"] += 1
        
        # Update RPS
        now = time.time()
        elapsed = now - self.last_update
        
        if elapsed >= 1.0:  # Update RPS every second
            self.requests_per_second = self.total_requests / (now - self.start_time)
            self.last_update = now
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get a summary of the metrics.
        
        Returns:
            Dict containing the metrics summary
        """
        now = time.time()
        uptime = now - self.start_time
        
        return {
            "uptime": uptime,
            "total_requests": self.total_requests,
            "failed_requests": self.failed_requests,
            "success_rate": (
                1.0 - (self.failed_requests / self.total_requests)
                if self.total_requests > 0 else 1.0
            ),
            "avg_latency": (
                self.total_latency / self.total_requests
                if self.total_requests > 0 else 0.0
            ),
            "requests_per_second": self.requests_per_second,
            "models": {
                model_id: {
                    "total_requests": metrics["total_requests"],
                    "failed_requests": metrics["failed_requests"],
                    "avg_latency": metrics["avg_latency"],
                    "last_latency": metrics["last_latency"]
                }
                for model_id, metrics in self.model_metrics.items()
            }
        }


class InferenceService:
    """
    Service for performing inference using trained models.
    
    Handles model loading, request queuing, and batching.
    """
    
    def __init__(
        self,
        storage_node: StorageNode,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the InferenceService.
        
        Args:
            storage_node: The storage node to use for model storage
            config: Configuration dictionary
        """
        self.storage_node = storage_node
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Model management
        self.model_manager = ModelManager(storage_node)
        self.loaded_models: Dict[str, Any] = {}
        self.model_metadata: Dict[str, ModelMetadata] = {}
        
        # Request queue
        self.request_queue = asyncio.PriorityQueue()
        self.active_requests: Dict[str, InferenceRequest] = {}
        
        # Metrics
        self.metrics = InferenceMetrics()
        
        # Background tasks
        self._inference_task: Optional[asyncio.Task] = None
        self._metrics_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
    
    async def initialize(self):
        """Initialize the inference service."""
        self.logger.info("Initializing InferenceService...")
        
        # Start background tasks
        self._inference_task = asyncio.create_task(self._process_requests())
        self._metrics_task = asyncio.create_task(self._log_metrics())
        
        self.logger.info("InferenceService initialized")
    
    async def stop(self):
        """Stop the inference service and clean up resources."""
        self.logger.info("Stopping InferenceService...")
        
        # Signal background tasks to stop
        self._stop_event.set()
        
        # Cancel tasks
        if self._inference_task:
            self._inference_task.cancel()
        if self._metrics_task:
            self._metrics_task.cancel()
        
        # Wait for tasks to complete
        if self._inference_task or self._metrics_task:
            await asyncio.gather(
                self._inference_task or asyncio.sleep(0),
                self._metrics_task or asyncio.sleep(0),
                return_exceptions=True
            )
        
        # Unload all models
        for model_id in list(self.loaded_models.keys()):
            await self.unload_model(model_id)
        
        self.logger.info("InferenceService stopped")
    
    async def predict(
        self,
        model_id: str,
        input_data: Any,
        request_id: Optional[str] = None,
        priority: int = 0,
        timeout: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Make a prediction using a model.
        
        Args:
            model_id: ID of the model to use
            input_data: Input data for the model
            request_id: Optional request ID
            priority: Priority of the request (higher = higher priority)
            timeout: Optional timeout in seconds
            metadata: Additional metadata for the request
            
        Returns:
            The model's prediction
            
        Raises:
            ValueError: If the model is not found or failed to load
            Exception: If inference fails
        """
        # Create and enqueue the request
        request = InferenceRequest(
            model_id=model_id,
            input_data=input_data,
            request_id=request_id,
            priority=priority,
            timeout=timeout,
            metadata=metadata or {}
        )
        
        # Add to active requests
        self.active_requests[request.request_id] = request
        
        # Add to priority queue (priority is inverted because queue is min-heap)
        await self.request_queue.put((-priority, request.request_id))
        
        try:
            # Wait for the request to complete
            result = await request.wait(timeout=timeout)
            return result
        finally:
            # Clean up
            self.active_requests.pop(request.request_id, None)
    
    async def load_model(self, model_id: str) -> bool:
        """
        Load a model into memory.
        
        Args:
            model_id: ID of the model to load
            
        Returns:
            bool: True if the model was loaded successfully, False otherwise
        """
        if model_id in self.loaded_models:
            return True
        
        try:
            # Load model and metadata
            model, metadata = await self.model_manager.load_model(model_id)
            
            # Move model to GPU if available
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            if isinstance(model, nn.Module):
                model = model.to(device)
                model.eval()  # Set to evaluation mode
            
            # Store in cache
            self.loaded_models[model_id] = model
            self.model_metadata[model_id] = metadata
            
            self.logger.info(f"Loaded model {model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load model {model_id}: {e}", exc_info=True)
            return False
    
    async def unload_model(self, model_id: str) -> bool:
        """
        Unload a model from memory.
        
        Args:
            model_id: ID of the model to unload
            
        Returns:
            bool: True if the model was unloaded successfully, False otherwise
        """
        if model_id not in self.loaded_models:
            return True
        
        try:
            # Clean up model resources
            model = self.loaded_models.pop(model_id)
            self.model_metadata.pop(model_id, None)
            
            # If it's a PyTorch model, clean up GPU memory
            if isinstance(model, nn.Module):
                del model
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
            
            self.logger.info(f"Unloaded model {model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload model {model_id}: {e}", exc_info=True)
            return False
    
    async def _process_requests(self):
        """Process inference requests from the queue."""
        while not self._stop_event.is_set():
            try:
                # Get the next request (with timeout to allow for clean shutdown)
                try:
                    _, request_id = await asyncio.wait_for(
                        self.request_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                request = self.active_requests.get(request_id)
                if not request:
                    continue
                
                # Mark request as started
                request.started_at = time.time()
                
                try:
                    # Ensure model is loaded
                    if not await self.load_model(request.model_id):
                        raise ValueError(f"Failed to load model {request.model_id}")
                    
                    # Get model and metadata
                    model = self.loaded_models[request.model_id]
                    metadata = self.model_metadata[request.model_id]
                    
                    # Preprocess input
                    input_tensor = self._preprocess_input(request.input_data, metadata)
                    
                    # Move to device
                    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
                    if isinstance(input_tensor, torch.Tensor):
                        input_tensor = input_tensor.to(device)
                    
                    # Run inference
                    with torch.no_grad():
                        start_time = time.time()
                        
                        if isinstance(model, nn.Module):
                            output = model(input_tensor)
                        else:
                            # For non-PyTorch models
                            output = model(input_tensor)
                        
                        # Convert output to CPU and numpy if needed
                        if torch.is_tensor(output):
                            output = output.cpu().numpy()
                        
                        inference_time = time.time() - start_time
                        
                        # Record metrics
                        self.metrics.record_request(
                            model_id=request.model_id,
                            latency=inference_time,
                            success=True
                        )
                        
                        # Set result
                        request.set_result(output)
                
                except Exception as e:
                    # Record error
                    error_msg = str(e)
                    self.logger.error(
                        f"Inference failed for request {request.request_id}: {error_msg}",
                        exc_info=True
                    )
                    
                    self.metrics.record_request(
                        model_id=request.model_id,
                        latency=time.time() - (request.started_at or time.time()),
                        success=False
                    )
                    
                    request.set_error(error_msg)
                
                finally:
                    # Mark as processed
                    self.request_queue.task_done()
            
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                self.logger.error(
                    f"Error in inference processing loop: {e}",
                    exc_info=True
                )
                await asyncio.sleep(1)  # Prevent tight loop on errors
    
    async def _log_metrics(self):
        """Log metrics periodically."""
        while not self._stop_event.is_set():
            try:
                await asyncio.sleep(60)  # Log every minute
                
                summary = self.metrics.get_summary()
                self.logger.info(
                    "Inference metrics: "
                    f"{summary['total_requests']} requests, "
                    f"{summary['requests_per_second']:.2f} RPS, "
                    f"{summary['avg_latency']*1000:.2f}ms avg latency, "
                    f"{summary['success_rate']*100:.1f}% success rate"
                )
                
            except asyncio.CancelledError:
                break
            
            except Exception as e:
                self.logger.error(f"Error logging metrics: {e}", exc_info=True)
                await asyncio.sleep(5)  # Prevent tight loop on errors
    
    def _preprocess_input(
        self,
        input_data: Any,
        metadata: ModelMetadata
    ) -> Any:
        """
        Preprocess input data for the model.
        
        Args:
            input_data: Raw input data
            metadata: Model metadata
            
        Returns:
            Preprocessed input suitable for the model
        """
        # This is a simplified implementation
        # In a real system, this would handle various input types and formats
        
        if isinstance(input_data, (list, np.ndarray)):
            # Convert to tensor if needed
            if not isinstance(input_data, torch.Tensor):
                return torch.tensor(input_data, dtype=torch.float32)
        
        return input_data
