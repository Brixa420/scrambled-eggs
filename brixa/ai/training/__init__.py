"""
Training Module

This module provides distributed training infrastructure for AI models.
"""

# Import core components
from .trainer import DistributedTrainer, TrainingConfig, TrainingMetrics
from .experiment import ExperimentTracker
from .coordinator import TrainingCoordinator

# Import data-related components with lazy imports to avoid circular dependencies
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .data import DataLoader, DistributedSampler
else:
    # These will be imported on first use
    DataLoader = None
    DistributedSampler = None

__all__ = [
    'DistributedTrainer',
    'TrainingConfig',
    'TrainingMetrics',
    'ExperimentTracker',
    'TrainingCoordinator',
    'DataLoader',
    'DistributedSampler'
]

def __getattr__(name):
    # Lazy load data modules to avoid circular imports
    if name in ['DataLoader', 'DistributedSampler']:
        from . import data
        globals()['DataLoader'] = data.DataLoader
        globals()['DistributedSampler'] = data.DistributedSampler
        return getattr(data, name)
    raise AttributeError(f"module {__name__} has no attribute {name}")
