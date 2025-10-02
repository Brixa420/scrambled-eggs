"""
Training Coordinator

This module provides a coordinator for managing distributed training processes.
"""
import os
import torch
import logging
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field

from .trainer import DistributedTrainer, TrainingConfig
from .experiment import ExperimentTracker

logger = logging.getLogger(__name__)

@dataclass
class TrainingCoordinator:
    """
    Coordinates distributed training across multiple processes.
    """
    config: TrainingConfig
    experiment: Optional[ExperimentTracker] = None
    model: Optional[torch.nn.Module] = None
    train_loader: Optional[torch.utils.data.DataLoader] = None
    val_loader: Optional[torch.utils.data.DataLoader] = None
    
    def __post_init__(self):
        """Initialize the training coordinator."""
        self.trainer = DistributedTrainer(
            model=self.model,
            train_loader=self.train_loader,
            val_loader=self.val_loader,
            config=self.config,
            experiment=self.experiment
        )
    
    def setup_distributed(self, backend: str = 'nccl'):
        """Set up distributed training."""
        if not torch.distributed.is_available():
            logger.warning("Distributed training is not available. Running in single-process mode.")
            return False
            
        if torch.distributed.is_initialized():
            logger.warning("Distributed is already initialized.")
            return True
            
        # Initialize the process group
        torch.distributed.init_process_group(backend=backend)
        return True
    
    def train(self):
        """Run the training process."""
        try:
            self.trainer.train()
            return True
        except Exception as e:
            logger.error(f"Training failed: {str(e)}")
            return False
    
    def evaluate(self):
        """Run evaluation on the validation set."""
        try:
            metrics = self.trainer.evaluate()
            return metrics
        except Exception as e:
            logger.error(f"Evaluation failed: {str(e)}")
            return None
    
    def save_checkpoint(self, is_best: bool = False):
        """Save a checkpoint of the model."""
        try:
            self.trainer.save_checkpoint(is_best=is_best)
            return True
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {str(e)}")
            return False
    
    def cleanup(self):
        """Clean up resources."""
        if torch.distributed.is_initialized():
            torch.distributed.destroy_process_group()
        
        if hasattr(self, 'trainer') and self.trainer is not None:
            if hasattr(self.trainer, 'experiment') and self.trainer.experiment is not None:
                self.trainer.experiment.close()
