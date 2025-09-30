"""
Training Coordinator for Brixa AI

This module handles the training of AI models in a distributed environment.
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
from torch import nn, optim
from torch.utils.data import DataLoader, Dataset

from ..storage import StorageNode
from .models import ModelManager, ModelMetadata, ModelFormat


class TrainingStatus(Enum):
    """Status of a training job."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TrainingMetrics:
    """Metrics collected during training."""
    epoch: int = 0
    step: int = 0
    loss: float = 0.0
    accuracy: float = 0.0
    learning_rate: float = 0.0
    timestamp: float = field(default_factory=time.time)
    custom_metrics: Dict[str, float] = field(default_factory=dict)


@dataclass
class TrainingConfig:
    """Configuration for a training job."""
    epochs: int = 10
    batch_size: int = 32
    learning_rate: float = 0.001
    optimizer: str = "adam"
    loss_function: str = "cross_entropy"
    metrics: List[str] = field(default_factory=lambda: ["accuracy"])
    checkpoint_freq: int = 1  # Save checkpoint every N epochs
    use_gpu: bool = torch.cuda.is_available()
    num_workers: int = 4
    early_stopping_patience: int = 5  # Stop if no improvement for N epochs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to a dictionary."""
        return {
            "epochs": self.epochs,
            "batch_size": self.batch_size,
            "learning_rate": self.learning_rate,
            "optimizer": self.optimizer,
            "loss_function": self.loss_function,
            "metrics": self.metrics,
            "checkpoint_freq": self.checkpoint_freq,
            "use_gpu": self.use_gpu,
            "num_workers": self.num_workers,
            "early_stopping_patience": self.early_stopping_patience,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrainingConfig':
        """Create config from a dictionary."""
        return cls(**data)


@dataclass
class TrainingJob:
    """Represents a training job."""
    job_id: str
    model_metadata: ModelMetadata
    config: TrainingConfig
    status: TrainingStatus = TrainingStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    metrics: List[TrainingMetrics] = field(default_factory=list)
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to a dictionary."""
        return {
            "job_id": self.job_id,
            "model_metadata": self.model_metadata.to_dict(),
            "config": self.config.to_dict(),
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metrics": [{
                "epoch": m.epoch,
                "step": m.step,
                "loss": m.loss,
                "accuracy": m.accuracy,
                "learning_rate": m.learning_rate,
                "timestamp": m.timestamp,
                "custom_metrics": m.custom_metrics,
            } for m in self.metrics],
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrainingJob':
        """Create job from a dictionary."""
        job = cls(
            job_id=data["job_id"],
            model_metadata=ModelMetadata.from_dict(data["model_metadata"]),
            config=TrainingConfig.from_dict(data["config"]),
            status=TrainingStatus(data["status"]),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            error=data.get("error"),
        )
        
        # Add metrics
        for metric_data in data.get("metrics", []):
            job.metrics.append(TrainingMetrics(
                epoch=metric_data["epoch"],
                step=metric_data["step"],
                loss=metric_data["loss"],
                accuracy=metric_data["accuracy"],
                learning_rate=metric_data["learning_rate"],
                timestamp=metric_data["timestamp"],
                custom_metrics=metric_data.get("custom_metrics", {}),
            ))
        
        return job


class TrainingCoordinator:
    """
    Coordinates the training of AI models.
    
    Handles distributed training, checkpointing, and monitoring.
    """
    
    def __init__(
        self,
        storage_node: StorageNode,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the TrainingCoordinator.
        
        Args:
            storage_node: The storage node to use for checkpoints
            config: Configuration dictionary
        """
        self.storage_node = storage_node
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.model_manager = ModelManager(storage_node)
        
        # Track active training jobs
        self.active_jobs: Dict[str, TrainingJob] = {}
        self._job_tasks: Dict[str, asyncio.Task] = {}
    
    async def initialize(self):
        """Initialize the training coordinator."""
        self.logger.info("Initializing TrainingCoordinator...")
        # Initialize any required resources
        self.logger.info("TrainingCoordinator initialized")
    
    async def train_model(
        self,
        model_config: Dict[str, Any],
        training_data: Any,
        validation_data: Optional[Any] = None,
        callbacks: Optional[List[Callable]] = None,
        **kwargs
    ) -> str:
        """
        Start a new training job.
        
        Args:
            model_config: Configuration for the model
            training_data: Training dataset or data loader
            validation_data: Optional validation dataset or data loader
            callbacks: List of callback functions
            **kwargs: Additional training parameters
            
        Returns:
            str: ID of the training job
        """
        # Create a new training job
        job_id = self._generate_job_id()
        
        # Create model metadata
        model_metadata = ModelMetadata(
            model_id=f"{job_id}_model",
            name=model_config.get("name", f"model_{job_id[:8]}"),
            format=ModelFormat.PYTORCH,
            architecture=model_config.get("architecture", "custom"),
            input_shape=model_config.get("input_shape", (1,)),
            output_shape=model_config.get("output_shape", (1,)),
            hyperparameters=model_config.get("hyperparameters", {})
        )
        
        # Create training config
        training_config = TrainingConfig(
            epochs=model_config.get("epochs", 10),
            batch_size=model_config.get("batch_size", 32),
            learning_rate=model_config.get("learning_rate", 0.001),
            optimizer=model_config.get("optimizer", "adam"),
            loss_function=model_config.get("loss_function", "cross_entropy"),
            metrics=model_config.get("metrics", ["accuracy"]),
            use_gpu=model_config.get("use_gpu", torch.cuda.is_available()),
        )
        
        # Create and store the job
        job = TrainingJob(
            job_id=job_id,
            model_metadata=model_metadata,
            config=training_config,
            status=TrainingStatus.PENDING
        )
        
        self.active_jobs[job_id] = job
        
        # Start the training task
        task = asyncio.create_task(
            self._run_training(job, training_data, validation_data, callbacks)
        )
        self._job_tasks[job_id] = task
        
        # Clean up completed tasks
        self._cleanup_completed_jobs()
        
        return job_id
    
    async def get_job_status(self, job_id: str) -> Optional[TrainingJob]:
        """
        Get the status of a training job.
        
        Args:
            job_id: The ID of the job
            
        Returns:
            Optional[TrainingJob]: The job status, or None if not found
        """
        # Check active jobs first
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]
        
        # Try to load from storage
        try:
            job_data = await self.storage_node.get(f"training/jobs/{job_id}")
            if job_data:
                return TrainingJob.from_dict(json.loads(job_data.decode()))
        except Exception as e:
            self.logger.error(f"Error loading job {job_id}: {e}")
        
        return None
    
    async def cancel_job(self, job_id: str) -> bool:
        """
        Cancel a running training job.
        
        Args:
            job_id: The ID of the job to cancel
            
        Returns:
            bool: True if the job was cancelled, False otherwise
        """
        if job_id not in self.active_jobs:
            return False
        
        job = self.active_jobs[job_id]
        if job.status != TrainingStatus.RUNNING:
            return False
        
        # Cancel the task
        task = self._job_tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        
        # Update job status
        job.status = TrainingStatus.CANCELLED
        job.end_time = time.time()
        
        # Save the final state
        await self._save_job(job)
        
        # Clean up
        self._cleanup_job(job_id)
        
        return True
    
    async def _run_training(
        self,
        job: TrainingJob,
        training_data: Any,
        validation_data: Optional[Any] = None,
        callbacks: Optional[List[Callable]] = None
    ):
        """
        Run the training loop for a job.
        
        Args:
            job: The training job
            training_data: Training dataset or data loader
            validation_data: Optional validation dataset or data loader
            callbacks: List of callback functions
        """
        try:
            # Update job status
            job.status = TrainingStatus.RUNNING
            job.start_time = time.time()
            await self._save_job(job)
            
            # Initialize model
            model = self._create_model(job.model_metadata)
            
            # Set up training
            device = torch.device("cuda" if job.config.use_gpu and torch.cuda.is_available() else "cpu")
            model = model.to(device)
            
            # Set up optimizer and loss function
            optimizer = self._create_optimizer(model, job.config)
            criterion = self._create_loss_function(job.config.loss_function)
            
            # Set up data loaders
            train_loader = self._create_data_loader(training_data, job.config.batch_size, shuffle=True)
            val_loader = None
            if validation_data is not None:
                val_loader = self._create_data_loader(validation_data, job.config.batch_size, shuffle=False)
            
            # Training loop
            best_val_loss = float('inf')
            epochs_without_improvement = 0
            
            for epoch in range(job.config.epochs):
                # Train for one epoch
                train_metrics = await self._train_epoch(
                    model, train_loader, criterion, optimizer, device, epoch, job
                )
                job.metrics.append(train_metrics)
                
                # Validate
                if val_loader is not None:
                    val_metrics = await self._validate_epoch(
                        model, val_loader, criterion, device, epoch, job
                    )
                    job.metrics.append(val_metrics)
                    
                    # Check for improvement
                    if val_metrics.loss < best_val_loss:
                        best_val_loss = val_metrics.loss
                        epochs_without_improvement = 0
                        
                        # Save the best model
                        await self.model_manager.save_model(
                            model,
                            job.model_metadata,
                            format=ModelFormat.PYTORCH
                        )
                    else:
                        epochs_without_improvement += 1
                        
                        # Early stopping
                        if (job.config.early_stopping_patience > 0 and 
                                epochs_without_improvement >= job.config.early_stopping_patience):
                            self.logger.info(f"Early stopping at epoch {epoch}")
                            break
                
                # Save checkpoint
                if epoch % job.config.checkpoint_freq == 0:
                    await self._save_job(job)
                
                # Call callbacks
                if callbacks:
                    for callback in callbacks:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback(job)
                            else:
                                callback(job)
                        except Exception as e:
                            self.logger.error(f"Error in callback: {e}")
            
            # Training completed
            job.status = TrainingStatus.COMPLETED
            job.end_time = time.time()
            
            # Save the final model and job state
            await self.model_manager.save_model(
                model,
                job.model_metadata,
                format=ModelFormat.PYTORCH
            )
            await self._save_job(job)
            
            self.logger.info(f"Training job {job.job_id} completed successfully")
            
        except asyncio.CancelledError:
            # Training was cancelled
            job.status = TrainingStatus.CANCELLED
            job.end_time = time.time()
            await self._save_job(job)
            self.logger.info(f"Training job {job.job_id} was cancelled")
            
        except Exception as e:
            # Training failed
            job.status = TrainingStatus.FAILED
            job.error = str(e)
            job.end_time = time.time()
            await self._save_job(job)
            self.logger.error(f"Training job {job.job_id} failed: {e}", exc_info=True)
            
        finally:
            # Clean up
            self._cleanup_job(job.job_id)
    
    async def _train_epoch(
        self,
        model: nn.Module,
        data_loader: DataLoader,
        criterion: Callable,
        optimizer: optim.Optimizer,
        device: torch.device,
        epoch: int,
        job: TrainingJob
    ) -> TrainingMetrics:
        """Train the model for one epoch."""
        model.train()
        total_loss = 0.0
        correct = 0
        total = 0
        
        for batch_idx, (inputs, targets) in enumerate(data_loader):
            inputs, targets = inputs.to(device), targets.to(device)
            
            # Zero gradients
            optimizer.zero_grad()
            
            # Forward pass
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            
            # Backward pass and optimize
            loss.backward()
            optimizer.step()
            
            # Update metrics
            total_loss += loss.item() * inputs.size(0)
            _, predicted = outputs.max(1)
            total += targets.size(0)
            correct += predicted.eq(targets).sum().item()
            
            # Log progress
            if batch_idx % 10 == 0:
                self.logger.info(
                    f"Epoch: {epoch} | Batch: {batch_idx}/{len(data_loader)} | "
                    f"Loss: {loss.item():.4f} | Acc: {100. * correct / total:.2f}%"
                )
        
        # Calculate epoch metrics
        avg_loss = total_loss / len(data_loader.dataset)
        accuracy = 100. * correct / total
        
        return TrainingMetrics(
            epoch=epoch,
            step=epoch * len(data_loader),
            loss=avg_loss,
            accuracy=accuracy,
            learning_rate=optimizer.param_groups[0]['lr']
        )
    
    async def _validate_epoch(
        self,
        model: nn.Module,
        data_loader: DataLoader,
        criterion: Callable,
        device: torch.device,
        epoch: int,
        job: TrainingJob
    ) -> TrainingMetrics:
        """Validate the model for one epoch."""
        model.eval()
        total_loss = 0.0
        correct = 0
        total = 0
        
        with torch.no_grad():
            for inputs, targets in data_loader:
                inputs, targets = inputs.to(device), targets.to(device)
                
                # Forward pass
                outputs = model(inputs)
                loss = criterion(outputs, targets)
                
                # Update metrics
                total_loss += loss.item() * inputs.size(0)
                _, predicted = outputs.max(1)
                total += targets.size(0)
                correct += predicted.eq(targets).sum().item()
        
        # Calculate epoch metrics
        avg_loss = total_loss / len(data_loader.dataset)
        accuracy = 100. * correct / total
        
        self.logger.info(
            f"Validation | Epoch: {epoch} | "
            f"Loss: {avg_loss:.4f} | Acc: {accuracy:.2f}%"
        )
        
        return TrainingMetrics(
            epoch=epoch,
            step=epoch * len(data_loader),
            loss=avg_loss,
            accuracy=accuracy,
            learning_rate=0.0  # Not applicable for validation
        )
    
    def _create_model(self, metadata: ModelMetadata) -> nn.Module:
        """Create a model from metadata."""
        # This is a placeholder - in a real implementation, you would create
        # the appropriate model based on the metadata
        return nn.Sequential(
            nn.Linear(metadata.input_shape[0], 64),
            nn.ReLU(),
            nn.Linear(64, metadata.output_shape[0])
        )
    
    def _create_optimizer(
        self,
        model: nn.Module,
        config: TrainingConfig
    ) -> optim.Optimizer:
        """Create an optimizer from config."""
        if config.optimizer.lower() == "adam":
            return optim.Adam(model.parameters(), lr=config.learning_rate)
        elif config.optimizer.lower() == "sgd":
            return optim.SGD(model.parameters(), lr=config.learning_rate, momentum=0.9)
        else:
            raise ValueError(f"Unsupported optimizer: {config.optimizer}")
    
    def _create_loss_function(self, loss_name: str) -> Callable:
        """Create a loss function from name."""
        if loss_name == "cross_entropy":
            return nn.CrossEntropyLoss()
        elif loss_name == "mse":
            return nn.MSELoss()
        else:
            raise ValueError(f"Unsupported loss function: {loss_name}")
    
    def _create_data_loader(
        self,
        data: Any,
        batch_size: int,
        shuffle: bool = True
    ) -> DataLoader:
        """Create a data loader from data."""
        if isinstance(data, DataLoader):
            return data
        elif isinstance(data, Dataset):
            return DataLoader(
                data,
                batch_size=batch_size,
                shuffle=shuffle,
                num_workers=self.config.get("num_workers", 4)
            )
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
    
    async def _save_job(self, job: TrainingJob):
        """Save a job to storage."""
        try:
            job_data = json.dumps(job.to_dict()).encode()
            await self.storage_node.set(f"training/jobs/{job.job_id}", job_data)
        except Exception as e:
            self.logger.error(f"Error saving job {job.job_id}: {e}")
    
    def _cleanup_job(self, job_id: str):
        """Clean up resources for a completed job."""
        if job_id in self._job_tasks:
            del self._job_tasks[job_id]
        if job_id in self.active_jobs:
            del self.active_jobs[job_id]
    
    def _cleanup_completed_jobs(self):
        """Clean up completed jobs."""
        completed = []
        for job_id, task in list(self._job_tasks.items()):
            if task.done():
                completed.append(job_id)
        
        for job_id in completed:
            self._cleanup_job(job_id)
    
    def _generate_job_id(self) -> str:
        """Generate a unique job ID."""
        import uuid
        return f"job_{uuid.uuid4().hex[:8]}"
