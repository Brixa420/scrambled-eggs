"""
Core AI Engine for Brixa

This module implements the main AI engine that coordinates between different
AI components and provides a unified interface for AI operations.
"""
import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Callable, Union

from ..storage import StorageNode
from .models import ModelManager
from .training import TrainingCoordinator
from .inference import InferenceService
from .federated import FederatedLearningManager


class AIEngine:
    """
    Main AI engine for Brixa that coordinates all AI operations.
    
    This class serves as the main entry point for all AI-related functionality,
    including model training, inference, and federated learning.
    """
    
    def __init__(
        self,
        storage_node: StorageNode,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the AI Engine.
        
        Args:
            storage_node: The storage node to use for model storage
            config: Configuration dictionary
        """
        self.storage_node = storage_node
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.model_manager = ModelManager(storage_node)
        self.training_coordinator = TrainingCoordinator(storage_node, self.config.get('training', {}))
        self.inference_service = InferenceService(storage_node, self.config.get('inference', {}))
        self.federated_learning = FederatedLearningManager(
            storage_node,
            self.config.get('federated', {})
        )
        
        # Track running tasks
        self._tasks: List[asyncio.Task] = []
    
    async def initialize(self):
        """Initialize the AI engine and its components."""
        self.logger.info("Initializing AI Engine...")
        
        # Initialize components
        await self.model_manager.initialize()
        await self.training_coordinator.initialize()
        await self.inference_service.initialize()
        await self.federated_learning.initialize()
        
        self.logger.info("AI Engine initialized")
    
    async def train_model(
        self,
        model_config: Dict[str, Any],
        training_data: Any,
        **kwargs
    ) -> str:
        """
        Train a new model.
        
        Args:
            model_config: Configuration for the model
            training_data: Training data
            **kwargs: Additional training parameters
            
        Returns:
            str: ID of the trained model
        """
        return await self.training_coordinator.train_model(model_config, training_data, **kwargs)
    
    async def predict(
        self,
        model_id: str,
        input_data: Any,
        **kwargs
    ) -> Any:
        """
        Make a prediction using a trained model.
        
        Args:
            model_id: ID of the model to use
            input_data: Input data for prediction
            **kwargs: Additional prediction parameters
            
        Returns:
            The model's prediction
        """
        return await self.inference_service.predict(model_id, input_data, **kwargs)
    
    async def start_federated_learning(
        self,
        model_config: Dict[str, Any],
        participants: List[str],
        **kwargs
    ) -> str:
        """
        Start a federated learning session.
        
        Args:
            model_config: Configuration for the federated model
            participants: List of participant node IDs
            **kwargs: Additional federated learning parameters
            
        Returns:
            str: ID of the federated learning session
        """
        return await self.federated_learning.start_session(model_config, participants, **kwargs)
    
    async def stop(self):
        """Stop the AI engine and clean up resources."""
        self.logger.info("Stopping AI Engine...")
        
        # Cancel all running tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        # Stop components
        await self.training_coordinator.stop()
        await self.inference_service.stop()
        await self.federated_learning.stop()
        
        self.logger.info("AI Engine stopped")
    
    def _run_background(self, coro):
        """Run a coroutine in the background."""
        task = asyncio.create_task(coro)
        self._tasks.append(task)
        
        # Clean up completed tasks
        self._tasks = [t for t in self._tasks if not t.done()]
        
        return task
