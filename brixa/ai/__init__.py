"""
Brixa AI Module

This module provides AI capabilities for the Brixa platform, including:
- Distributed model training
- Federated learning
- Model serving
- Privacy-preserving AI
"""

from .core import AIEngine
from .models import ModelManager
from .training import TrainingCoordinator
from .inference import InferenceService
from .federated import FederatedLearningManager

__all__ = [
    'AIEngine',
    'ModelManager',
    'TrainingCoordinator',
    'InferenceService',
    'FederatedLearningManager'
]
