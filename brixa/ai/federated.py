"""
Federated Learning for Brixa AI

This module implements federated learning capabilities, allowing models to be
trained across multiple nodes while keeping data decentralized.
"""
import asyncio
import copy
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

from ..storage import StorageNode
from .models import ModelManager, ModelMetadata, ModelFormat
from .training import TrainingConfig, TrainingMetrics


class FederatedLearningRoundStatus(Enum):
    """Status of a federated learning round."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class FederatedLearningStatus(Enum):
    """Status of a federated learning session."""
    CREATED = "created"
    TRAINING = "training"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class FederatedLearningConfig:
    """Configuration for federated learning."""
    # Training configuration
    training_config: TrainingConfig = field(default_factory=TrainingConfig)
    
    # Federated learning parameters
    num_rounds: int = 10
    clients_per_round: int = 3
    min_clients: int = 1
    eval_every: int = 1  # Evaluate global model every N rounds
    save_every: int = 1  # Save global model every N rounds
    aggregation_method: str = "fedavg"  # Options: fedavg, fedprox, etc.
    
    # Model selection
    model_architecture: str = "simple_cnn"  # Or other architecture names
    input_shape: Tuple[int, ...] = (1, 28, 28)  # Example for MNIST
    output_shape: int = 10  # Number of classes
    
    # Privacy parameters
    use_differential_privacy: bool = False
    noise_multiplier: float = 1.0
    max_grad_norm: float = 1.0
    
    # Secure aggregation
    use_secure_aggregation: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert config to a dictionary."""
        return {
            "training_config": self.training_config.to_dict(),
            "num_rounds": self.num_rounds,
            "clients_per_round": self.clients_per_round,
            "min_clients": self.min_clients,
            "eval_every": self.eval_every,
            "save_every": self.save_every,
            "aggregation_method": self.aggregation_method,
            "model_architecture": self.model_architecture,
            "input_shape": list(self.input_shape),
            "output_shape": self.output_shape,
            "use_differential_privacy": self.use_differential_privacy,
            "noise_multiplier": self.noise_multiplier,
            "max_grad_norm": self.max_grad_norm,
            "use_secure_aggregation": self.use_secure_aggregation,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FederatedLearningConfig':
        """Create config from a dictionary."""
        config = cls()
        
        # Update training config
        if "training_config" in data:
            config.training_config = TrainingConfig.from_dict(data["training_config"])
        
        # Update other parameters
        for key, value in data.items():
            if key == "training_config":
                continue
            if hasattr(config, key):
                if key in ["input_shape"] and isinstance(value, list):
                    setattr(config, key, tuple(value))
                else:
                    setattr(config, key, value)
        
        return config


@dataclass
class FederatedLearningRound:
    """Represents a round of federated learning."""
    round_num: int
    status: FederatedLearningRoundStatus = FederatedLearningRoundStatus.PENDING
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    metrics: Dict[str, float] = field(default_factory=dict)
    participants: List[str] = field(default_factory=list)  # List of client IDs
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert round to a dictionary."""
        return {
            "round_num": self.round_num,
            "status": self.status.value,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "metrics": self.metrics,
            "participants": self.participants,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FederatedLearningRound':
        """Create round from a dictionary."""
        round_obj = cls(
            round_num=data["round_num"],
            status=FederatedLearningRoundStatus(data["status"]),
            start_time=data.get("start_time"),
            end_time=data.get("end_time"),
            metrics=data.get("metrics", {}),
            participants=data.get("participants", []),
        )
        return round_obj


@dataclass
class FederatedLearningSession:
    """Represents a federated learning session."""
    session_id: str
    config: FederatedLearningConfig
    status: FederatedLearningStatus = FederatedLearningStatus.CREATED
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    current_round: int = 0
    rounds: List[FederatedLearningRound] = field(default_factory=list)
    global_model_id: Optional[str] = None
    best_model_id: Optional[str] = None
    best_metric: float = 0.0
    metrics: Dict[str, List[float]] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to a dictionary."""
        return {
            "session_id": self.session_id,
            "config": self.config.to_dict(),
            "status": self.status.value,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "current_round": self.current_round,
            "rounds": [r.to_dict() for r in self.rounds],
            "global_model_id": self.global_model_id,
            "best_model_id": self.best_model_id,
            "best_metric": self.best_metric,
            "metrics": self.metrics,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FederatedLearningSession':
        """Create session from a dictionary."""
        session = cls(
            session_id=data["session_id"],
            config=FederatedLearningConfig.from_dict(data["config"]),
            status=FederatedLearningStatus(data["status"]),
            created_at=data.get("created_at", time.time()),
            started_at=data.get("started_at"),
            completed_at=data.get("completed_at"),
            current_round=data.get("current_round", 0),
            global_model_id=data.get("global_model_id"),
            best_model_id=data.get("best_model_id"),
            best_metric=data.get("best_metric", 0.0),
            metrics=data.get("metrics", {}),
        )
        
        # Add rounds
        for round_data in data.get("rounds", []):
            session.rounds.append(FederatedLearningRound.from_dict(round_data))
        
        return session
    
    def add_round(self, round_num: int) -> 'FederatedLearningRound':
        """Add a new round to the session."""
        round_obj = FederatedLearningRound(round_num=round_num)
        self.rounds.append(round_obj)
        return round_obj
    
    def get_round(self, round_num: int) -> Optional['FederatedLearningRound']:
        """Get a round by number."""
        for r in self.rounds:
            if r.round_num == round_num:
                return r
        return None
    
    def get_current_round(self) -> Optional['FederatedLearningRound']:
        """Get the current round."""
        return self.get_round(self.current_round)
    
    def update_metrics(self, metrics: Dict[str, float], round_num: Optional[int] = None):
        """Update metrics for a round."""
        if round_num is None:
            round_num = self.current_round
        
        round_obj = self.get_round(round_num)
        if round_obj is None:
            round_obj = self.add_round(round_num)
        
        round_obj.metrics.update(metrics)
        
        # Update global metrics
        for key, value in metrics.items():
            if key not in self.metrics:
                self.metrics[key] = []
            
            # Ensure we have enough space in the metrics list
            while len(self.metrics[key]) <= round_num:
                self.metrics[key].append(None)
            
            self.metrics[key][round_num] = value
            
            # Update best model if this is a better metric
            if key == "val_accuracy" and value > self.best_metric:
                self.best_metric = value
                # Note: The actual model saving is handled by the federated learning manager


class FederatedLearningManager:
    """
    Manages federated learning sessions across multiple nodes.
    
    This class coordinates the federated learning process, including:
    - Session management
    - Client selection
    - Model aggregation
    - Secure aggregation (optional)
    - Differential privacy (optional)
    """
    
    def __init__(
        self,
        storage_node: StorageNode,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the FederatedLearningManager.
        
        Args:
            storage_node: The storage node to use for model storage
            config: Configuration dictionary
        """
        self.storage_node = storage_node
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Model and training management
        self.model_manager = ModelManager(storage_node)
        
        # Active sessions
        self.active_sessions: Dict[str, FederatedLearningSession] = {}
        
        # Background tasks
        self._background_tasks: List[asyncio.Task] = []
        self._stop_event = asyncio.Event()
    
    async def initialize(self):
        """Initialize the federated learning manager."""
        self.logger.info("Initializing FederatedLearningManager...")
        
        # Load any active sessions from storage
        await self._load_active_sessions()
        
        # Start background tasks
        self._background_tasks.append(
            asyncio.create_task(self._monitor_sessions())
        )
        
        self.logger.info("FederatedLearningManager initialized")
    
    async def stop(self):
        """Stop the federated learning manager and clean up resources."""
        self.logger.info("Stopping FederatedLearningManager...")
        
        # Signal background tasks to stop
        self._stop_event.set()
        
        # Cancel background tasks
        for task in self._background_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for tasks to complete
        if self._background_tasks:
            await asyncio.gather(*self._background_tasks, return_exceptions=True)
        
        # Save session states
        await self._save_active_sessions()
        
        self.logger.info("FederatedLearningManager stopped")
    
    async def start_session(
        self,
        config: Union[FederatedLearningConfig, Dict[str, Any]],
        participants: List[str],
        session_id: Optional[str] = None
    ) -> str:
        """
        Start a new federated learning session.
        
        Args:
            config: Federated learning configuration
            participants: List of participant node IDs
            session_id: Optional session ID (auto-generated if not provided)
            
        Returns:
            str: The session ID
        """
        # Generate session ID if not provided
        if session_id is None:
            session_id = f"fl_{int(time.time())}_{hash(tuple(participants)) % 10000:04d}"
        
        # Convert config if needed
        if isinstance(config, dict):
            config = FederatedLearningConfig.from_dict(config)
        
        # Create a new session
        session = FederatedLearningSession(
            session_id=session_id,
            config=config,
            status=FederatedLearningStatus.CREATED,
        )
        
        # Initialize the global model
        global_model = self._create_model(config)
        
        # Save the initial model
        model_metadata = ModelMetadata(
            model_id=f"{session_id}_global_initial",
            name=f"{session_id}_global_initial",
            format=ModelFormat.PYTORCH,
            architecture=config.model_architecture,
            input_shape=config.input_shape,
            output_shape=config.output_shape,
            hyperparameters={
                "learning_rate": config.training_config.learning_rate,
                "batch_size": config.training_config.batch_size,
                "epochs": config.training_config.epochs,
            },
            description=f"Initial global model for federated learning session {session_id}",
        )
        
        # Save the model
        model_id = await self.model_manager.save_model(
            global_model,
            model_metadata,
            format=ModelFormat.PYTORCH
        )
        
        # Update session with model ID
        session.global_model_id = model_id
        session.best_model_id = model_id
        
        # Store the session
        self.active_sessions[session_id] = session
        await self._save_session(session)
        
        # Start the training process in the background
        self._background_tasks.append(
            asyncio.create_task(self._run_federated_learning(session, participants))
        )
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[FederatedLearningSession]:
        """
        Get a federated learning session by ID.
        
        Args:
            session_id: The session ID
            
        Returns:
            Optional[FederatedLearningSession]: The session, or None if not found
        """
        # Check active sessions first
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]
        
        # Try to load from storage
        try:
            session_data = await self.storage_node.get(f"fl_sessions/{session_id}")
            if session_data:
                return FederatedLearningSession.from_dict(json.loads(session_data.decode()))
        except Exception as e:
            self.logger.error(f"Error loading session {session_id}: {e}")
        
        return None
    
    async def stop_session(self, session_id: str) -> bool:
        """
        Stop a federated learning session.
        
        Args:
            session_id: The session ID
            
        Returns:
            bool: True if the session was stopped, False otherwise
        """
        session = await self.get_session(session_id)
        if not session:
            return False
        
        # Update session status
        session.status = FederatedLearningStatus.STOPPED
        session.completed_at = time.time()
        
        # Save the session
        await self._save_session(session)
        
        # Remove from active sessions
        self.active_sessions.pop(session_id, None)
        
        return True
    
    async def _run_federated_learning(
        self,
        session: FederatedLearningSession,
        participants: List[str]
    ):
        """
        Run the federated learning process.
        
        Args:
            session: The federated learning session
            participants: List of participant node IDs
        """
        try:
            # Update session status
            session.status = FederatedLearningStatus.TRAINING
            session.started_at = time.time()
            await self._save_session(session)
            
            self.logger.info(f"Starting federated learning session {session.session_id}")
            
            # Run federated learning rounds
            for round_num in range(session.config.num_rounds):
                if self._stop_event.is_set():
                    break
                
                # Update current round
                session.current_round = round_num
                
                # Create a new round
                round_obj = session.add_round(round_num)
                round_obj.status = FederatedLearningRoundStatus.RUNNING
                round_obj.start_time = time.time()
                
                # Select clients for this round
                selected_clients = self._select_clients(participants, session.config.clients_per_round)
                round_obj.participants = selected_clients
                
                self.logger.info(
                    f"Round {round_num + 1}/{session.config.num_rounds} | "
                    f"Selected clients: {', '.join(selected_clients)}"
                )
                
                # Train on selected clients (in parallel)
                client_tasks = []
                for client_id in selected_clients:
                    task = asyncio.create_task(
                        self._train_on_client(client_id, session, round_num)
                    )
                    client_tasks.append(task)
                
                # Wait for all clients to complete
                client_results = await asyncio.gather(*client_tasks, return_exceptions=True)
                
                # Process results
                successful_updates = []
                for result in client_results:
                    if isinstance(result, Exception):
                        self.logger.error(f"Client training failed: {result}")
                    else:
                        successful_updates.append(result)
                
                if not successful_updates:
                    self.logger.warning(f"No successful client updates in round {round_num}")
                    continue
                
                # Aggregate model updates
                await self._aggregate_updates(session, successful_updates, round_num)
                
                # Update round status
                round_obj.status = FederatedLearningRoundStatus.COMPLETED
                round_obj.end_time = time.time()
                
                # Evaluate global model (if needed)
                if (round_num + 1) % session.config.eval_every == 0:
                    await self._evaluate_global_model(session, round_num)
                
                # Save model checkpoint (if needed)
                if (round_num + 1) % session.config.save_every == 0:
                    await self._save_model_checkpoint(session, round_num)
                
                # Save session state
                await self._save_session(session)
            
            # Training completed
            session.status = FederatedLearningStatus.COMPLETED
            session.completed_at = time.time()
            
            self.logger.info(
                f"Federated learning session {session.session_id} completed successfully. "
                f"Best validation accuracy: {session.best_metric:.4f}"
            )
            
        except Exception as e:
            self.logger.error(
                f"Federated learning session {session.session_id} failed: {e}",
                exc_info=True
            )
            
            session.status = FederatedLearningStatus.FAILED
            session.completed_at = time.time()
        
        finally:
            # Save final session state
            await self._save_session(session)
            
            # Remove from active sessions
            self.active_sessions.pop(session.session_id, None)
    
    async def _train_on_client(
        self,
        client_id: str,
        session: FederatedLearningSession,
        round_num: int
    ) -> Dict[str, Any]:
        """
        Train the model on a client.
        
        Args:
            client_id: The client ID
            session: The federated learning session
            round_num: The current round number
            
        Returns:
            Dict containing the client update
        """
        try:
            self.logger.debug(f"Training on client {client_id} for round {round_num}")
            
            # In a real implementation, this would communicate with the client
            # For now, we'll simulate the training locally
            
            # Load the global model
            global_model_data = await self.storage_node.get(f"models/{session.global_model_id}")
            if not global_model_data:
                raise ValueError(f"Global model {session.global_model_id} not found")
            
            # Deserialize the model
            model = await self.model_manager.load_model(session.global_model_id)
            
            # Set up training
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model.to(device)
            model.train()
            
            # Set up optimizer and loss function
            optimizer = optim.SGD(
                model.parameters(),
                lr=session.config.training_config.learning_rate,
                momentum=0.9
            )
            criterion = nn.CrossEntropyLoss()
            
            # In a real implementation, we would load the client's data here
            # For now, we'll use a dummy dataset
            train_loader = self._get_dummy_dataloader(
                batch_size=session.config.training_config.batch_size,
                train=True
            )
            
            # Train for one epoch
            for epoch in range(session.config.training_config.epochs):
                for inputs, targets in train_loader:
                    inputs, targets = inputs.to(device), targets.to(device)
                    
                    # Forward pass
                    outputs = model(inputs)
                    loss = criterion(outputs, targets)
                    
                    # Backward pass and optimize
                    optimizer.zero_grad()
                    loss.backward()
                    
                    # Apply differential privacy if enabled
                    if session.config.use_differential_privacy:
                        self._apply_dp_sgd(
                            model,
                            session.config.max_grad_norm,
                            session.config.noise_multiplier
                        )
                    
                    optimizer.step()
            
            # Get model updates (difference between global and local model)
            global_model = await self.model_manager.load_model(session.global_model_id)
            updates = self._get_model_updates(global_model, model)
            
            # Calculate metrics
            metrics = {
                "train_loss": loss.item(),
                "train_accuracy": 0.0,  # Would calculate this in a real implementation
            }
            
            self.logger.debug(
                f"Client {client_id} completed training for round {round_num}. "
                f"Loss: {metrics['train_loss']:.4f}"
            )
            
            return {
                "client_id": client_id,
                "round_num": round_num,
                "updates": updates,
                "num_samples": len(train_loader.dataset),  # Number of training samples
                "metrics": metrics,
            }
            
        except Exception as e:
            self.logger.error(
                f"Error training on client {client_id} for round {round_num}: {e}",
                exc_info=True
            )
            raise
    
    async def _aggregate_updates(
        self,
        session: FederatedLearningSession,
        client_updates: List[Dict[str, Any]],
        round_num: int
    ) -> bool:
        """
        Aggregate client updates to update the global model.
        
        Args:
            session: The federated learning session
            client_updates: List of client updates
            round_num: The current round number
            
        Returns:
            bool: True if aggregation was successful, False otherwise
        """
        try:
            self.logger.debug(
                f"Aggregating {len(client_updates)} client updates for round {round_num}"
            )
            
            # Load the current global model
            global_model = await self.model_manager.load_model(session.global_model_id)
            
            # Apply aggregation method
            if session.config.aggregation_method == "fedavg":
                self._fedavg_aggregation(global_model, client_updates)
            else:
                self.logger.warning(
                    f"Unknown aggregation method: {session.config.aggregation_method}. "
                    "Using FedAvg as fallback."
                )
                self._fedavg_aggregation(global_model, client_updates)
            
            # Save the updated global model
            model_metadata = await self.model_manager.get_model_metadata(session.global_model_id)
            new_model_id = await self.model_manager.save_model(
                global_model,
                model_metadata,
                format=ModelFormat.PYTORCH
            )
            
            # Update session with new global model
            session.global_model_id = new_model_id
            
            # Log metrics
            session.update_metrics({
                "round": round_num,
                "num_clients": len(client_updates),
                # Add other metrics as needed
            })
            
            self.logger.info(
                f"Round {round_num} completed. Global model updated: {new_model_id}"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                f"Error aggregating updates for round {round_num}: {e}",
                exc_info=True
            )
            return False
    
    def _fedavg_aggregation(
        self,
        global_model: nn.Module,
        client_updates: List[Dict[str, Any]]
    ) -> None:
        """
        Perform Federated Averaging (FedAvg) aggregation.
        
        Args:
            global_model: The global model to update
            client_updates: List of client updates
        """
        # Get total number of samples across all clients
        total_samples = sum(update["num_samples"] for update in client_updates)
        
        # Initialize a zero model for aggregation
        aggregated_updates = {
            name: torch.zeros_like(param)
            for name, param in global_model.named_parameters()
        }
        
        # Aggregate updates
        for update in client_updates:
            weight = update["num_samples"] / total_samples
            
            for name, param in update["updates"].items():
                if name in aggregated_updates:
                    aggregated_updates[name] += param * weight
        
        # Update global model
        with torch.no_grad():
            for name, param in global_model.named_parameters():
                if name in aggregated_updates:
                    param.data = aggregated_updates[name]
    
    async def _evaluate_global_model(
        self,
        session: FederatedLearningSession,
        round_num: int
    ) -> Dict[str, float]:
        """
        Evaluate the global model on a validation set.
        
        Args:
            session: The federated learning session
            round_num: The current round number
            
        Returns:
            Dict containing evaluation metrics
        """
        try:
            self.logger.debug(f"Evaluating global model for round {round_num}")
            
            # Load the global model
            model = await self.model_manager.load_model(session.global_model_id)
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            model = model.to(device)
            model.eval()
            
            # In a real implementation, we would use a validation dataset
            # For now, we'll use a dummy dataset
            val_loader = self._get_dummy_dataloader(batch_size=64, train=False)
            
            # Evaluate
            criterion = nn.CrossEntropyLoss()
            total_loss = 0.0
            correct = 0
            total = 0
            
            with torch.no_grad():
                for inputs, targets in val_loader:
                    inputs, targets = inputs.to(device), targets.to(device)
                    
                    # Forward pass
                    outputs = model(inputs)
                    loss = criterion(outputs, targets)
                    
                    # Calculate accuracy
                    _, predicted = torch.max(outputs.data, 1)
                    total += targets.size(0)
                    correct += (predicted == targets).sum().item()
                    total_loss += loss.item() * inputs.size(0)
            
            # Calculate metrics
            avg_loss = total_loss / len(val_loader.dataset)
            accuracy = 100.0 * correct / total
            
            metrics = {
                "val_loss": avg_loss,
                "val_accuracy": accuracy,
            }
            
            # Update session metrics
            session.update_metrics(metrics, round_num)
            
            # Update best model if this is the best accuracy so far
            if accuracy > session.best_metric:
                session.best_metric = accuracy
                
                # Save the best model
                model_metadata = await self.model_manager.get_model_metadata(session.global_model_id)
                best_model_id = await self.model_manager.save_model(
                    model,
                    model_metadata,
                    format=ModelFormat.PYTORCH
                )
                session.best_model_id = best_model_id
                
                self.logger.info(
                    f"New best model at round {round_num} with accuracy: {accuracy:.2f}%"
                )
            
            self.logger.info(
                f"Round {round_num} evaluation - Loss: {avg_loss:.4f}, "
                f"Accuracy: {accuracy:.2f}%"
            )
            
            return metrics
            
        except Exception as e:
            self.logger.error(
                f"Error evaluating global model for round {round_num}: {e}",
                exc_info=True
            )
            return {}
    
    async def _save_model_checkpoint(
        self,
        session: FederatedLearningSession,
        round_num: int
    ) -> None:
        """
        Save a checkpoint of the global model.
        
        Args:
            session: The federated learning session
            round_num: The current round number
        """
        try:
            # Load the global model
            model = await self.model_manager.load_model(session.global_model_id)
            
            # Save checkpoint
            checkpoint_metadata = await self.model_manager.get_model_metadata(session.global_model_id)
            checkpoint_metadata.name = f"{session.session_id}_round_{round_num}"
            checkpoint_metadata.description = (
                f"Checkpoint for federated learning session {session.session_id}, round {round_num}"
            )
            
            await self.model_manager.save_model(
                model,
                checkpoint_metadata,
                format=ModelFormat.PYTORCH
            )
            
            self.logger.debug(f"Saved checkpoint for round {round_num}")
            
        except Exception as e:
            self.logger.error(
                f"Error saving checkpoint for round {round_num}: {e}",
                exc_info=True
            )
    
    def _create_model(self, config: FederatedLearningConfig) -> nn.Module:
        """
        Create a new model based on the configuration.
        
        Args:
            config: Federated learning configuration
            
        Returns:
            A new PyTorch model
        """
        # This is a simple model for demonstration
        # In a real implementation, you would support different architectures
        if config.model_architecture == "simple_cnn":
            return self._create_simple_cnn(config)
        else:
            raise ValueError(f"Unsupported model architecture: {config.model_architecture}")
    
    def _create_simple_cnn(self, config: FederatedLearningConfig) -> nn.Module:
        """Create a simple CNN model."""
        # This is a simple CNN for demonstration
        # In a real implementation, you would use a more sophisticated architecture
        class SimpleCNN(nn.Module):
            def __init__(self, input_shape, num_classes):
                super(SimpleCNN, self).__init__()
                self.conv1 = nn.Conv2d(input_shape[0], 32, kernel_size=3, padding=1)
                self.conv2 = nn.Conv2d(32, 64, kernel_size=3, padding=1)
                self.pool = nn.MaxPool2d(2, 2)
                self.fc1 = nn.Linear(64 * (input_shape[1] // 4) * (input_shape[2] // 4), 128)
                self.fc2 = nn.Linear(128, num_classes)
            
            def forward(self, x):
                x = self.pool(torch.relu(self.conv1(x)))
                x = self.pool(torch.relu(self.conv2(x)))
                x = x.view(x.size(0), -1)
                x = torch.relu(self.fc1(x))
                x = self.fc2(x)
                return x
        
        return SimpleCNN(config.input_shape, config.output_shape)
    
    def _select_clients(
        self,
        all_clients: List[str],
        num_clients: int
    ) -> List[str]:
        """
        Select clients for the next round of federated learning.
        
        Args:
            all_clients: List of all available client IDs
            num_clients: Number of clients to select
            
        Returns:
            List of selected client IDs
        """
        # Simple random selection
        # In a real implementation, you might want to use a more sophisticated strategy
        return np.random.choice(all_clients, size=min(num_clients, len(all_clients)), replace=False).tolist()
    
    def _get_model_updates(
        self,
        global_model: nn.Module,
        local_model: nn.Module
    ) -> Dict[str, torch.Tensor]:
        """
        Get the difference between a local model and the global model.
        
        Args:
            global_model: The global model
            local_model: The local model
            
        Returns:
            Dictionary of parameter updates
        """
        updates = {}
        
        for (name, global_param), (_, local_param) in zip(
            global_model.named_parameters(),
            local_model.named_parameters()
        ):
            updates[name] = local_param.data - global_param.data
        
        return updates
    
    def _apply_dp_sgd(
        self,
        model: nn.Module,
        max_grad_norm: float,
        noise_multiplier: float
    ) -> None:
        """
        Apply differential privacy using the DP-SGD algorithm.
        
        Args:
            model: The model to apply DP to
            max_grad_norm: Maximum L2 norm for gradient clipping
            noise_multiplier: Noise multiplier for differential privacy
        """
        # This is a simplified implementation
        # In a real implementation, you would use a library like Opacus
        
        # Clip gradients
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_grad_norm)
        
        # Add noise to gradients
        for param in model.parameters():
            if param.grad is not None:
                noise = torch.randn_like(param.grad) * noise_multiplier * max_grad_norm
                param.grad += noise
    
    def _get_dummy_dataloader(
        self,
        batch_size: int,
        train: bool = True
    ) -> torch.utils.data.DataLoader:
        """
        Create a dummy dataloader for testing.
        
        Args:
            batch_size: Batch size
            train: Whether to create training or test data
            
        Returns:
            A PyTorch DataLoader with dummy data
        """
        # This is just for testing
        # In a real implementation, you would load real data
        from torch.utils.data import TensorDataset, DataLoader
        
        # Create random data
        num_samples = 100 if train else 20
        x = torch.randn(num_samples, 1, 28, 28)  # MNIST-like data
        y = torch.randint(0, 10, (num_samples,))  # 10 classes
        
        dataset = TensorDataset(x, y)
        return DataLoader(dataset, batch_size=batch_size, shuffle=train)
    
    async def _save_session(self, session: FederatedLearningSession) -> None:
        """
        Save a federated learning session to storage.
        
        Args:
            session: The session to save
        """
        try:
            session_data = json.dumps(session.to_dict()).encode()
            await self.storage_node.set(f"fl_sessions/{session.session_id}", session_data)
        except Exception as e:
            self.logger.error(f"Error saving session {session.session_id}: {e}")
    
    async def _load_active_sessions(self) -> None:
        """Load active federated learning sessions from storage."""
        try:
            # In a real implementation, we would list and load all active sessions
            # For now, we'll just initialize with an empty dict
            self.active_sessions = {}
        except Exception as e:
            self.logger.error(f"Error loading active sessions: {e}")
            self.active_sessions = {}
    
    async def _save_active_sessions(self) -> None:
        """Save all active federated learning sessions to storage."""
        try:
            for session in self.active_sessions.values():
                await self._save_session(session)
        except Exception as e:
            self.logger.error(f"Error saving active sessions: {e}")
    
    async def _monitor_sessions(self) -> None:
        """Monitor active federated learning sessions."""
        while not self._stop_event.is_set():
            try:
                # Periodically save session states
                await asyncio.sleep(60)  # Save every minute
                await self._save_active_sessions()
                
                # Log status of active sessions
                if self.active_sessions:
                    self.logger.info(
                        f"Active federated learning sessions: {len(self.active_sessions)}"
                    )
                    
                    for session_id, session in list(self.active_sessions.items()):
                        self.logger.info(
                            f"Session {session_id}: {session.status.value}, "
                            f"Round {session.current_round + 1}/{session.config.num_rounds}, "
                            f"Best accuracy: {session.best_metric:.2f}%"
                        )
                
            except asyncio.CancelledError:
                break
                
            except Exception as e:
                self.logger.error(f"Error in session monitoring: {e}", exc_info=True)
                await asyncio.sleep(5)  # Prevent tight loop on errors
