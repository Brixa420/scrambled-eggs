"""
Distributed Trainer

This module provides distributed training functionality for AI models.
"""
import os
import torch
import torch.distributed as dist
import torch.multiprocessing as mp
from torch.nn.parallel import DistributedDataParallel as DDP
from torch.utils.data.distributed import DistributedSampler
from torch.optim import Optimizer
from torch.optim.lr_scheduler import _LRScheduler
from typing import Dict, Any, Optional, Callable, Union, List
from dataclasses import dataclass, field, asdict
import logging
from datetime import datetime
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
import numpy as np

from ..registry import ModelRegistry
from .experiment import ExperimentTracker


@dataclass
class TrainingMetrics:
    """Class to track training metrics."""
    loss: List[float] = field(default_factory=list)
    accuracy: List[float] = field(default_factory=list)
    val_loss: List[float] = field(default_factory=list)
    val_accuracy: List[float] = field(default_factory=list)
    learning_rates: List[float] = field(default_factory=list)
    timestamps: List[datetime] = field(default_factory=list)
    
    def update(
        self,
        loss: Optional[float] = None,
        accuracy: Optional[float] = None,
        val_loss: Optional[float] = None,
        val_accuracy: Optional[float] = None,
        lr: Optional[float] = None
    ) -> None:
        """Update metrics with new values."""
        if loss is not None:
            self.loss.append(loss)
        if accuracy is not None:
            self.accuracy.append(accuracy)
        if val_loss is not None:
            self.val_loss.append(val_loss)
        if val_accuracy is not None:
            self.val_accuracy.append(val_accuracy)
        if lr is not None:
            self.learning_rates.append(lr)
        self.timestamps.append(datetime.now())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to a dictionary."""
        return {
            'loss': self.loss,
            'accuracy': self.accuracy,
            'val_loss': self.val_loss,
            'val_accuracy': self.val_accuracy,
            'learning_rates': self.learning_rates,
            'timestamps': [ts.isoformat() for ts in self.timestamps]
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TrainingMetrics':
        """Create a TrainingMetrics instance from a dictionary."""
        metrics = cls()
        metrics.loss = data.get('loss', [])
        metrics.accuracy = data.get('accuracy', [])
        metrics.val_loss = data.get('val_loss', [])
        metrics.val_accuracy = data.get('val_accuracy', [])
        metrics.learning_rates = data.get('learning_rates', [])
        metrics.timestamps = [
            datetime.fromisoformat(ts) if isinstance(ts, str) else ts 
            for ts in data.get('timestamps', [])
        ]
        return metrics
    
    def get_latest(self) -> Dict[str, Any]:
        """Get the latest metrics."""
        return {
            'loss': self.loss[-1] if self.loss else None,
            'accuracy': self.accuracy[-1] if self.accuracy else None,
            'val_loss': self.val_loss[-1] if self.val_loss else None,
            'val_accuracy': self.val_accuracy[-1] if self.val_accuracy else None,
            'learning_rate': self.learning_rates[-1] if self.learning_rates else None,
            'timestamp': self.timestamps[-1].isoformat() if self.timestamps else None
        }

logger = logging.getLogger(__name__)

@dataclass
class TrainingConfig:
    """Configuration for model training."""
    batch_size: int = 32
    num_epochs: int = 10
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    gradient_accumulation_steps: int = 1
    max_grad_norm: float = 1.0
    warmup_steps: int = 0
    log_interval: int = 10
    save_interval: int = 1000
    eval_interval: int = 1000
    checkpoint_dir: str = "./checkpoints"
    use_amp: bool = True
    device: str = "cuda" if torch.cuda.is_available() else "cpu"
    num_workers: int = 4
    seed: int = 42
    metrics: List[str] = field(default_factory=lambda: ["loss", "accuracy"])

class DistributedTrainer:
    """Handles distributed training of AI models."""
    
    def __init__(
        self,
        model: torch.nn.Module,
        train_loader: 'DataLoader',
        val_loader: Optional['DataLoader'] = None,
        config: Optional[TrainingConfig] = None,
        optimizer: Optional[Optimizer] = None,
        scheduler: Optional[_LRScheduler] = None,
        experiment: Optional[ExperimentTracker] = None,
        model_registry: Optional[ModelRegistry] = None,
    ):
        """Initialize the distributed trainer.
        
        Args:
            model: The model to train
            train_loader: DataLoader for training data
            val_loader: Optional DataLoader for validation data
            config: Training configuration
            optimizer: Optional optimizer (will be created if None)
            scheduler: Optional learning rate scheduler
            experiment: Optional experiment tracker
            model_registry: Optional model registry for saving models
        """
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.config = config or TrainingConfig()
        self.experiment = experiment
        self.model_registry = model_registry
        
        # Setup distributed training
        self.rank = int(os.environ.get("RANK", 0))
        self.world_size = int(os.environ.get("WORLD_SIZE", 1))
        self.device = torch.device(f"cuda:{self.rank}" if torch.cuda.is_available() else "cpu")
        
        # Move model to device and wrap with DDP
        self.model = model.to(self.device)
        if self.world_size > 1:
            self.model = DDP(self.model, device_ids=[self.rank])
        
        # Setup optimizer and scheduler
        self.optimizer = optimizer or torch.optim.AdamW(
            model.parameters(),
            lr=self.config.learning_rate,
            weight_decay=self.config.weight_decay
        )
        
        self.scheduler = scheduler
        self.scaler = torch.cuda.amp.GradScaler(enabled=self.config.use_amp)
        
        # Create checkpoint directory
        self.checkpoint_dir = Path(self.config.checkpoint_dir)
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        
        # Training state
        self.global_step = 0
        self.epoch = 0
        self.best_metric = float('inf')
    
    def train_epoch(self) -> Dict[str, float]:
        """Train the model for one epoch."""
        self.model.train()
        total_loss = 0.0
        metrics = {name: 0.0 for name in self.config.metrics}
        
        if isinstance(self.train_loader.sampler, DistributedSampler):
            self.train_loader.sampler.set_epoch(self.epoch)
        
        for batch_idx, batch in enumerate(self.train_loader):
            # Move batch to device
            batch = {k: v.to(self.device) if hasattr(v, 'to') else v 
                    for k, v in batch.items()}
            
            # Forward pass with mixed precision
            with torch.cuda.amp.autocast(enabled=self.config.use_amp):
                outputs = self.model(**batch)
                loss = outputs.loss / self.config.gradient_accumulation_steps
            
            # Backward pass
            self.scaler.scale(loss).backward()
            
            # Gradient accumulation
            if (batch_idx + 1) % self.config.gradient_accumulation_steps == 0:
                # Gradient clipping
                self.scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(), 
                    self.config.max_grad_norm
                )
                
                # Optimizer step
                self.scaler.step(self.optimizer)
                self.scaler.update()
                self.optimizer.zero_grad()
                
                # Update learning rate
                if self.scheduler is not None:
                    self.scheduler.step()
                
                self.global_step += 1
                
                # Log metrics
                total_loss += loss.item() * self.config.gradient_accumulation_steps
                for name in metrics:
                    if hasattr(outputs, name):
                        metrics[name] += getattr(outputs, name).item()
                
                # Log progress
                if self.rank == 0 and self.global_step % self.config.log_interval == 0:
                    self._log_metrics(metrics, prefix='train')
                
                # Save checkpoint
                if self.rank == 0 and self.global_step % self.config.save_interval == 0:
                    self.save_checkpoint()
                
                # Evaluate
                if (self.val_loader is not None and 
                    self.global_step % self.config.eval_interval == 0):
                    eval_metrics = self.evaluate()
                    if self.rank == 0:
                        self._log_metrics(eval_metrics, prefix='eval')
        
        # Average metrics
        num_batches = len(self.train_loader) // self.config.gradient_accumulation_steps
        metrics = {k: v / num_batches for k, v in metrics.items()}
        metrics['loss'] = total_loss / num_batches
        
        self.epoch += 1
        return metrics
    
    @torch.no_grad()
    def evaluate(self) -> Dict[str, float]:
        """Evaluate the model on the validation set."""
        if self.val_loader is None:
            return {}
            
        self.model.eval()
        metrics = {name: 0.0 for name in self.config.metrics}
        total_loss = 0.0
        
        for batch in self.val_loader:
            # Move batch to device
            batch = {k: v.to(self.device) if hasattr(v, 'to') else v 
                    for k, v in batch.items()}
            
            # Forward pass
            with torch.cuda.amp.autocast(enabled=self.config.use_amp):
                outputs = self.model(**batch)
                loss = outputs.loss
            
            # Update metrics
            total_loss += loss.item()
            for name in metrics:
                if hasattr(outputs, name):
                    metrics[name] += getattr(outputs, name).item()
        
        # Average metrics
        metrics = {k: v / len(self.val_loader) for k, v in metrics.items()}
        metrics['loss'] = total_loss / len(self.val_loader)
        
        # Update best model
        if metrics['loss'] < self.best_metric:
            self.best_metric = metrics['loss']
            if self.rank == 0:
                self.save_checkpoint(is_best=True)
        
        return metrics
    
    def train(self) -> None:
        """Train the model for the specified number of epochs."""
        for epoch in range(self.config.num_epochs):
            metrics = self.train_epoch()
            if self.rank == 0:
                logger.info(f"Epoch {epoch+1}/{self.config.num_epochs} - "
                          f"loss: {metrics['loss']:.4f}")
    
    def save_checkpoint(self, is_best: bool = False) -> None:
        """Save a checkpoint of the model."""
        if self.rank != 0:
            return
            
        checkpoint = {
            'epoch': self.epoch,
            'global_step': self.global_step,
            'model_state_dict': self.model.module.state_dict() if hasattr(self.model, 'module') else self.model.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'scheduler_state_dict': self.scheduler.state_dict() if self.scheduler else None,
            'best_metric': self.best_metric,
            'config': self.config.__dict__,
        }
        
        # Save checkpoint
        checkpoint_path = self.checkpoint_dir / f"checkpoint_step_{self.global_step}.pt"
        torch.save(checkpoint, checkpoint_path)
        
        # Save best model
        if is_best:
            best_path = self.checkpoint_dir / "best_model.pt"
            torch.save(checkpoint, best_path)
        
        # Save to model registry if available
        if self.model_registry is not None:
            self._save_to_registry(checkpoint_path, is_best=is_best)
    
    def _save_to_registry(self, checkpoint_path: str, is_best: bool = False) -> None:
        """Save the model to the model registry."""
        if self.model_registry is None:
            return
            
        metadata = {
            'epoch': self.epoch,
            'global_step': self.global_step,
            'metrics': {'loss': self.best_metric},
            'framework': 'pytorch',
            'training_config': self.config.__dict__,
            'is_best': is_best,
        }
        
        # Register the model
        model_name = f"{self.model.__class__.__name__.lower()}"
        self.model_registry.register_model(
            name=model_name,
            version=f"v{self.epoch}.{self.global_step}",
            model_path=str(checkpoint_path),
            metadata=metadata
        )
    
    def _log_metrics(self, metrics: Dict[str, float], prefix: str = '') -> None:
        """Log metrics to the experiment tracker and console."""
        if self.rank != 0:
            return
            
        # Format metrics
        log_str = f"[{prefix.upper()}] Step {self.global_step} - "
        log_str += " - ".join([f"{k}: {v:.4f}" for k, v in metrics.items()])
        
        # Log to console
        logger.info(log_str)
        
        # Log to experiment tracker
        if self.experiment is not None:
            self.experiment.log_metrics(metrics, step=self.global_step, prefix=prefix)

def setup_distributed(backend: str = 'nccl') -> None:
    """Initialize distributed training."""
    if 'RANK' in os.environ and 'WORLD_SIZE' in os.environ:
        rank = int(os.environ['RANK'])
        world_size = int(os.environ['WORLD_SIZE'])
        local_rank = int(os.environ['LOCAL_RANK'])
        
        torch.cuda.set_device(local_rank)
        dist.init_process_group(
            backend=backend,
            init_method='env://',
            world_size=world_size,
            rank=rank
        )
        
        # Set device
        device = torch.device('cuda', local_rank)
        torch.cuda.set_device(device)
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO if rank == 0 else logging.WARN,
            format=f'[%(asctime)s] [RANK {rank}] %(levelname)s: %(message)s'
        )
        
        return rank, world_size, device
    
    return 0, 1, torch.device('cuda' if torch.cuda.is_available() else 'cpu')
