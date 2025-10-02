"""
Experiment Tracking

This module provides functionality for tracking experiments, logging metrics,
and visualizing training progress.
"""
import os
import json
import logging
import time

logger = logging.getLogger(__name__)
import numpy as np
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
import torch
import torch.nn as nn
from datetime import datetime
import shutil

from ..registry import ModelRegistry

logger = logging.getLogger(__name__)

class ExperimentTracker:
    """Tracks experiments, logs metrics, and saves checkpoints."""
    
    def __init__(
        self,
        experiment_name: str,
        log_dir: str = "./experiments",
        model: Optional[nn.Module] = None,
        model_registry: Optional[ModelRegistry] = None,
        config: Optional[Dict[str, Any]] = None,
        enabled: bool = True
    ):
        """Initialize the experiment tracker.
        
        Args:
            experiment_name: Name of the experiment
            log_dir: Directory to save experiment logs
            model: Optional model to track
            model_registry: Optional model registry for saving models
            config: Optional configuration dictionary
            enabled: Whether tracking is enabled
        """
        self.experiment_name = experiment_name
        self.enabled = enabled
        self.model_registry = model_registry
        self.config = config or {}
        self.start_time = time.time()
        
        # Setup logging directory
        self.log_dir = Path(log_dir) / self._get_experiment_id()
        self.checkpoint_dir = self.log_dir / "checkpoints"
        self.metrics_file = self.log_dir / "metrics.json"
        self.config_file = self.log_dir / "config.json"
        self.tensorboard_dir = self.log_dir / "tensorboard"
        
        if self.enabled:
            self._setup_directories()
            self._save_config()
        
        # Initialize metrics storage
        self.metrics = {
            'train': {},
            'val': {},
            'test': {}
        }
        
        # Initialize TensorBoard if available
        self.tensorboard_writer = None
        if self.enabled:
            try:
                from torch.utils.tensorboard import SummaryWriter
                self.tensorboard_writer = SummaryWriter(log_dir=str(self.tensorboard_dir))
            except ImportError:
                logger.warning("TensorBoard not available. Install with: pip install tensorboard")
    
    def _get_experiment_id(self) -> str:
        """Generate a unique experiment ID."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{self.experiment_name}_{timestamp}"
    
    def _setup_directories(self) -> None:
        """Create necessary directories for the experiment."""
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_dir.mkdir(exist_ok=True)
        self.tensorboard_dir.mkdir(exist_ok=True)
    
    def _save_config(self) -> None:
        """Save the experiment configuration."""
        config = {
            'experiment_name': self.experiment_name,
            'start_time': datetime.now().isoformat(),
            'config': self.config,
            'git_hash': self._get_git_hash(),
            'hostname': os.uname().nodename if hasattr(os, 'uname') else 'unknown'
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=2)
    
    def _get_git_hash(self) -> str:
        """Get the current git commit hash."""
        try:
            import subprocess
            return subprocess.check_output(
                ['git', 'rev-parse', '--short', 'HEAD']
            ).decode('ascii').strip()
        except Exception:
            return "unknown"
    
    def log_metrics(
        self, 
        metrics: Dict[str, Union[float, int]], 
        step: int, 
        prefix: str = ''
    ) -> None:
        """Log metrics to the experiment tracker.
        
        Args:
            metrics: Dictionary of metrics to log
            step: Current step or epoch
            prefix: Optional prefix for the metrics (e.g., 'train', 'val')
        """
        if not self.enabled:
            return
        
        # Update metrics storage
        prefix = prefix.lower()
        if prefix not in self.metrics:
            self.metrics[prefix] = {}
        
        for name, value in metrics.items():
            full_name = f"{prefix}/{name}" if prefix else name
            
            # Update metrics storage
            if full_name not in self.metrics[prefix]:
                self.metrics[prefix][full_name] = []
            self.metrics[prefix][full_name].append((step, value))
            
            # Log to TensorBoard
            if self.tensorboard_writer is not None:
                self.tensorboard_writer.add_scalar(full_name, value, step)
            
            # Log to console
            logger.info(f"{full_name} at step {step}: {value:.4f}")
        
        # Save metrics to disk
        self._save_metrics()
    
    def log_model_summary(self, model: nn.Module, input_size: tuple) -> None:
        """Log a summary of the model architecture.
        
        Args:
            model: The model to summarize
            input_size: Input size for the model
        """
        if not self.enabled:
            return
            
        try:
            from torchsummary import summary
            
            # Create a dummy input
            device = next(model.parameters()).device
            dummy_input = torch.randn(1, *input_size).to(device)
            
            # Save model summary to file
            with open(self.log_dir / "model_summary.txt", 'w') as f:
                f.write(str(model) + "\n\n")
                f.write("-" * 80 + "\n")
                f.write("Model Summary:\n")
                f.write("-" * 80 + "\n")
                
                # Redirect stdout to capture the summary
                import sys
                from io import StringIO
                
                old_stdout = sys.stdout
                sys.stdout = StringIO()
                
                try:
                    summary(model, input_size, device=device.type)
                    summary_str = sys.stdout.getvalue()
                finally:
                    sys.stdout = old_stdout
                
                f.write(summary_str)
                
        except ImportError:
            logger.warning("torchsummary not available. Install with: pip install torchsummary")
    
    def save_checkpoint(
        self,
        model: nn.Module,
        optimizer: torch.optim.Optimizer,
        epoch: int,
        step: int,
        metrics: Optional[Dict[str, float]] = None,
        is_best: bool = False,
        filename: str = "checkpoint.pth"
    ) -> str:
        """Save a checkpoint of the model.
        
        Args:
            model: The model to save
            optimizer: The optimizer state to save
            epoch: Current epoch
            step: Current step
            metrics: Optional metrics to log
            is_best: Whether this is the best model so far
            filename: Name of the checkpoint file
            
        Returns:
            Path to the saved checkpoint
        """
        if not self.enabled:
            return ""
        
        # Prepare checkpoint
        checkpoint = {
            'epoch': epoch,
            'step': step,
            'model_state_dict': model.state_dict(),
            'optimizer_state_dict': optimizer.state_dict(),
            'metrics': metrics or {},
            'config': self.config,
        }
        
        # Save checkpoint
        checkpoint_path = self.checkpoint_dir / filename
        torch.save(checkpoint, checkpoint_path)
        
        # Save best model
        if is_best:
            best_path = self.checkpoint_dir / "model_best.pth"
            shutil.copyfile(checkpoint_path, best_path)
            
            # Save to model registry if available
            if self.model_registry is not None:
                self._save_to_registry(best_path, metrics, is_best=True)
        
        return str(checkpoint_path)
    
    def _save_to_registry(
        self, 
        checkpoint_path: str, 
        metrics: Optional[Dict[str, float]] = None,
        is_best: bool = False
    ) -> None:
        """Save the model to the model registry.
        
        Args:
            checkpoint_path: Path to the model checkpoint
            metrics: Optional metrics to include in metadata
            is_best: Whether this is the best model so far
        """
        if self.model_registry is None:
            return
            
        metadata = {
            'experiment_name': self.experiment_name,
            'checkpoint_path': checkpoint_path,
            'metrics': metrics or {},
            'is_best': is_best,
            'timestamp': datetime.now().isoformat(),
            'config': self.config,
        }
        
        # Register the model
        model_name = f"{self.experiment_name.lower().replace(' ', '_')}"
        version = f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.model_registry.register_model(
            name=model_name,
            version=version,
            model_path=checkpoint_path,
            metadata=metadata
        )
    
    def _save_metrics(self) -> None:
        """Save metrics to disk."""
        if not self.enabled:
            return
            
        with open(self.metrics_file, 'w') as f:
            json.dump(self.metrics, f, indent=2)
    
    def close(self) -> None:
        """Close the experiment and clean up resources."""
        if self.tensorboard_writer is not None:
            self.tensorboard_writer.close()
        
        # Save final metrics
        if self.enabled:
            self._save_metrics()
            
            # Log completion
            duration = time.time() - self.start_time
            logger.info(f"Experiment '{self.experiment_name}' completed in {duration:.2f} seconds")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
