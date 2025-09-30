"""
Reinforcement Learning Agent with Continuous Learning

This module implements a neural network-based reinforcement learning agent
with continuous learning capabilities and feedback mechanisms.
"""
import os
import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import numpy as np
import random
from collections import deque, namedtuple
import copy
from typing import List, Tuple, Dict, Any, Optional, Union
import json
from pathlib import Path
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
import hashlib

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
BUFFER_SIZE = int(1e6)  # Replay buffer size
BATCH_SIZE = 128        # Batch size for training
GAMMA = 0.99            # Discount factor
TAU = 1e-3              # For soft update of target parameters
LR_ACTOR = 1e-4         # Learning rate for actor
LR_CRITIC = 1e-3        # Learning rate for critic
WEIGHT_DECAY = 0.0      # L2 weight decay
UPDATE_EVERY = 4        # How often to update the network
LEARN_NUM = 4           # Number of learning passes

# Experience replay buffer
Experience = namedtuple('Experience', 
    field_names=['state', 'action', 'reward', 'next_state', 'done', 'feedback'])

class FeedbackType(Enum):
    """Types of feedback that can be provided to the agent."""
    POSITIVE = 1
    NEGATIVE = -1
    NEUTRAL = 0
    CORRECTION = 2
    DEMONSTRATION = 3

@dataclass
class TrainingStats:
    """Tracks training statistics."""
    episode: int = 0
    total_steps: int = 0
    episode_reward: float = 0.0
    episode_steps: int = 0
    losses: Dict[str, List[float]] = field(default_factory=lambda: {
        'actor': [], 'critic': [], 'total': []
    })
    rewards: List[float] = field(default_factory=list)
    feedback_stats: Dict[str, int] = field(default_factory=lambda: {
        'positive': 0, 'negative': 0, 'neutral': 0, 'correction': 0, 'demonstration': 0
    })
    
    def update_loss(self, actor_loss: float, critic_loss: float):
        """Update loss statistics."""
        self.losses['actor'].append(actor_loss)
        self.losses['critic'].append(critic_loss)
        self.losses['total'].append(actor_loss + critic_loss)
    
    def update_feedback(self, feedback_type: FeedbackType):
        """Update feedback statistics."""
        self.feedback_stats[feedback_type.name.lower()] += 1

class ReplayBuffer:
    """Fixed-size buffer to store experience tuples."""
    
    def __init__(self, action_size: int, buffer_size: int = BUFFER_SIZE, 
                 batch_size: int = BATCH_SIZE, seed: int = 42):
        """Initialize a ReplayBuffer object.
        
        Args:
            action_size: Dimension of each action
            buffer_size: Maximum size of buffer
            batch_size: Size of each training batch
            seed: Random seed
        """
        self.action_size = action_size
        self.memory = deque(maxlen=buffer_size)
        self.batch_size = batch_size
        self.experience = Experience
        self.seed = random.seed(seed)
        
        # Prioritized experience replay parameters
        self.priorities = deque(maxlen=buffer_size)
        self.alpha = 0.6  # Controls how much prioritization is used
        self.beta = 0.4   # Importance-sampling weight
        self.beta_increment_per_sampling = 0.001
        self.max_priority = 1.0
        self.epsilon = 1e-5  # Small constant to prevent zero probabilities
    
    def add(self, state: np.ndarray, action: np.ndarray, reward: float, 
            next_state: np.ndarray, done: bool, feedback: Optional[FeedbackType] = None):
        """Add a new experience to memory."""
        if feedback is None:
            feedback = FeedbackType.NEUTRAL
            
        e = self.experience(state, action, reward, next_state, done, feedback)
        self.memory.append(e)
        
        # Add initial priority
        self.priorities.append(self.max_priority)
    
    def sample(self) -> Tuple[list, np.ndarray, list]:
        """Randomly sample a batch of experiences from memory."""
        # Convert to numpy array for efficient operations
        priorities = np.array(self.priorities, dtype=np.float32)
        
        # Calculate sampling probabilities
        probs = priorities ** self.alpha
        probs = probs / probs.sum()
        
        # Sample indices based on probabilities
        indices = np.random.choice(len(self.memory), size=self.batch_size, p=probs)
        
        # Calculate importance sampling weights
        weights = (len(self.memory) * probs[indices]) ** (-self.beta)
        weights = weights / weights.max()
        
        # Get the experiences
        experiences = [self.memory[idx] for idx in indices]
        
        # Update beta for next time
        self.beta = min(1.0, self.beta + self.beta_increment_per_sampling)
        
        return experiences, indices, weights
    
    def update_priorities(self, indices: list, errors: np.ndarray):
        """Update priorities of sampled experiences."""
        for idx, error in zip(indices, errors):
            # Convert error to priority
            priority = (abs(error) + self.epsilon) ** self.alpha
            self.priorities[idx] = priority
            
            # Update max priority
            self.max_priority = max(self.max_priority, priority)
    
    def __len__(self) -> int:
        """Return the current size of internal memory."""
        return len(self.memory)

class Actor(nn.Module):
    """Actor (Policy) Model."""
    
    def __init__(self, state_size: int, action_size: int, 
                 hidden_layers: List[int] = [256, 128], seed: int = 42):
        """Initialize parameters and build model.
        
        Args:
            state_size: Dimension of each state
            action_size: Dimension of each action
            hidden_layers: List of hidden layer sizes
            seed: Random seed
        """
        super(Actor, self).__init__()
        self.seed = torch.manual_seed(seed)
        
        # Input layer
        self.layers = nn.ModuleList([nn.Linear(state_size, hidden_layers[0])])
        
        # Hidden layers
        layer_sizes = zip(hidden_layers[:-1], hidden_layers[1:])
        self.layers.extend([nn.Linear(h1, h2) for h1, h2 in layer_sizes])
        
        # Output layer
        self.output = nn.Linear(hidden_layers[-1], action_size)
        
        # Initialize weights
        self.reset_parameters()
    
    def reset_parameters(self):
        """Initialize weights with He initialization."""
        for layer in self.layers:
            if isinstance(layer, nn.Linear):
                nn.init.kaiming_normal_(layer.weight.data, nonlinearity='relu')
                nn.init.constant_(layer.bias.data, 0.1)
        
        # Initialize output layer weights to be small
        nn.init.uniform_(self.output.weight.data, -3e-3, 3e-3)
        nn.init.constant_(self.output.bias.data, 0.1)
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Build an actor (policy) network that maps states -> actions."""
        x = state
        
        # Apply hidden layers with ReLU activation
        for layer in self.layers:
            x = F.relu(layer(x))
        
        # Output layer with tanh activation for bounded action space
        return torch.tanh(self.output(x))

class Critic(nn.Module):
    """Critic (Value) Model."""
    
    def __init__(self, state_size: int, action_size: int, 
                 hidden_layers: List[int] = [256, 256, 128], seed: int = 42):
        """Initialize parameters and build model.
        
        Args:
            state_size: Dimension of each state
            action_size: Dimension of each action
            hidden_layers: List of hidden layer sizes
            seed: Random seed
        """
        super(Critic, self).__init__()
        self.seed = torch.manual_seed(seed)
        
        # First hidden layer (state only)
        self.layers = nn.ModuleList([nn.Linear(state_size, hidden_layers[0])])
        
        # Second hidden layer (state + action)
        self.layers.append(nn.Linear(hidden_layers[0] + action_size, hidden_layers[1]))
        
        # Additional hidden layers
        for i in range(2, len(hidden_layers)):
            self.layers.append(nn.Linear(hidden_layers[i-1], hidden_layers[i]))
        
        # Output layer
        self.output = nn.Linear(hidden_layers[-1], 1)
        
        # Initialize weights
        self.reset_parameters()
    
    def reset_parameters(self):
        """Initialize weights with He initialization."""
        for layer in self.layers:
            if isinstance(layer, nn.Linear):
                nn.init.kaiming_normal_(layer.weight.data, nonlinearity='relu')
                nn.init.constant_(layer.bias.data, 0.1)
        
        # Initialize output layer weights to be small
        nn.init.uniform_(self.output.weight.data, -3e-4, 3e-4)
        nn.init.constant_(self.output.bias.data, 0.1)
    
    def forward(self, state: torch.Tensor, action: torch.Tensor) -> torch.Tensor:
        """Build a critic (value) network that maps (state, action) pairs -> Q-values."""
        # First hidden layer (state only)
        x = F.relu(self.layers[0](state))
        
        # Second hidden layer (state + action)
        x = torch.cat((x, action), dim=1)
        x = F.relu(self.layers[1](x))
        
        # Additional hidden layers
        for layer in self.layers[2:]:
            x = F.relu(layer(x))
        
        # Output layer (no activation)
        return self.output(x)

class Noise:
    """Ornstein-Uhlenbeck process for exploration noise."""
    
    def __init__(self, size: int, seed: int = 42, mu: float = 0.0, 
                 theta: float = 0.15, sigma: float = 0.2):
        """Initialize parameters and noise process."""
        self.mu = mu * np.ones(size)
        self.theta = theta
        self.sigma = sigma
        self.seed = random.seed(seed)
        self.reset()
    
    def reset(self):
        """Reset the internal state to mean (mu)."""
        self.state = copy.copy(self.mu)
        # Gradually reduce sigma over time for adaptive exploration
        self.sigma = max(0.01, self.sigma * 0.9999)
    
    def sample(self) -> np.ndarray:
        """Update internal state and return it as a noise sample."""
        dx = self.theta * (self.mu - self.state) + \
             self.sigma * np.random.standard_normal(len(self.state))
        self.state += dx
        return self.state

class RLLearner:
    """Reinforcement Learning agent with continuous learning and feedback mechanisms."""
    
    def __init__(
        self,
        state_size: int,
        action_size: int,
        hidden_layers_actor: List[int] = [256, 128],
        hidden_layers_critic: List[int] = [256, 256, 128],
        buffer_size: int = BUFFER_SIZE,
        batch_size: int = BATCH_SIZE,
        gamma: float = GAMMA,
        tau: float = TAU,
        lr_actor: float = LR_ACTOR,
        lr_critic: float = LR_CRITIC,
        weight_decay: float = WEIGHT_DECAY,
        update_every: int = UPDATE_EVERY,
        learn_num: int = LEARN_NUM,
        seed: int = 42,
        model_dir: str = "models",
        load_model: bool = False
    ):
        """Initialize an Agent object.
        
        Args:
            state_size: Dimension of each state
            action_size: Dimension of each action
            hidden_layers_actor: List of hidden layer sizes for actor network
            hidden_layers_critic: List of hidden layer sizes for critic network
            buffer_size: Replay buffer size
            batch_size: Minibatch size
            gamma: Discount factor
            tau: For soft update of target parameters
            lr_actor: Learning rate for actor
            lr_critic: Learning rate for critic
            weight_decay: L2 weight decay
            update_every: How often to update the network
            learn_num: Number of learning passes
            seed: Random seed
            model_dir: Directory to save/load models
            load_model: Whether to load a saved model if available
        """
        self.state_size = state_size
        self.action_size = action_size
        self.buffer_size = buffer_size
        self.batch_size = batch_size
        self.gamma = gamma
        self.tau = tau
        self.lr_actor = lr_actor
        self.lr_critic = lr_critic
        self.weight_decay = weight_decay
        self.update_every = update_every
        self.learn_num = learn_num
        self.seed = random.seed(seed)
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize statistics
        self.stats = TrainingStats()
        
        # Actor Network (w/ Target Network)
        self.actor_local = Actor(state_size, action_size, hidden_layers_actor, seed).to(DEVICE)
        self.actor_target = Actor(state_size, action_size, hidden_layers_actor, seed).to(DEVICE)
        self.actor_optimizer = optim.Adam(
            self.actor_local.parameters(), 
            lr=lr_actor,
            weight_decay=weight_decay
        )
        
        # Critic Network (w/ Target Network)
        self.critic_local = Critic(state_size, action_size, hidden_layers_critic, seed).to(DEVICE)
        self.critic_target = Critic(state_size, action_size, hidden_layers_critic, seed).to(DEVICE)
        self.critic_optimizer = optim.Adam(
            self.critic_local.parameters(), 
            lr=lr_critic,
            weight_decay=weight_decay
        )
        
        # Initialize target networks with same weights as local networks
        self.soft_update(self.actor_local, self.actor_target, 1.0)
        self.soft_update(self.critic_local, self.critic_target, 1.0)
        
        # Noise process for exploration
        self.noise = Noise(action_size, seed)
        
        # Replay memory
        self.memory = ReplayBuffer(action_size, buffer_size, batch_size, seed)
        
        # Initialize time step (for updating every UPDATE_EVERY steps)
        self.t_step = 0
        
        # Load model if requested
        if load_model:
            self.load_checkpoint()
    
    def step(self, state: np.ndarray, action: np.ndarray, reward: float, 
             next_state: np.ndarray, done: bool, feedback: Optional[FeedbackType] = None):
        """Save experience in replay memory, and use random sample from buffer to learn."""
        # Save experience in replay memory
        self.memory.add(state, action, reward, next_state, done, feedback)
        
        # Update feedback statistics
        if feedback is not None:
            self.stats.update_feedback(feedback)
        
        # Learn every UPDATE_EVERY time steps
        self.t_step = (self.t_step + 1) % self.update_every
        if self.t_step == 0 and len(self.memory) > self.batch_size:
            for _ in range(self.learn_num):
                experiences = self.memory.sample()
                self.learn(experiences, self.gamma)
    
    def act(self, state: np.ndarray, add_noise: bool = True) -> np.ndarray:
        """Returns actions for given state as per current policy."""
        state = torch.from_numpy(state).float().to(DEVICE)
        
        # Set the model to evaluation mode
        self.actor_local.eval()
        
        with torch.no_grad():
            action = self.actor_local(state).cpu().data.numpy()
        
        # Set the model back to training mode
        self.actor_local.train()
        
        # Add noise for exploration
        if add_noise:
            action += self.noise.sample()
        
        # Clip the action to be within valid bounds
        return np.clip(action, -1, 1)
    
    def learn(self, experiences: Tuple, gamma: float):
        """Update policy and value parameters using given batch of experience tuples.
        
        Q_targets = r + γ * critic_target(next_state, actor_target(next_state))
        where:
            actor_target(state) -> action
            critic_target(state, action) -> Q-value
        
        Args:
            experiences: Tuple of (s, a, r, s', done, feedback) tuples
            gamma: Discount factor
        """
        states, actions, rewards, next_states, dones, feedbacks = experiences
        
        # Convert to PyTorch tensors
        states = torch.FloatTensor(np.array(states)).to(DEVICE)
        actions = torch.FloatTensor(np.array(actions)).to(DEVICE)
        rewards = torch.FloatTensor(np.array(rewards)).unsqueeze(1).to(DEVICE)
        next_states = torch.FloatTensor(np.array(next_states)).to(DEVICE)
        dones = torch.FloatTensor(np.array(dones).astype(np.uint8)).unsqueeze(1).to(DEVICE)
        
        # ---------------------------- update critic ---------------------------- #
        # Get predicted next-state actions and Q values from target models
        actions_next = self.actor_target(next_states)
        Q_targets_next = self.critic_target(next_states, actions_next)
        
        # Compute Q targets for current states (y_i)
        Q_targets = rewards + (gamma * Q_targets_next * (1 - dones))
        
        # Compute critic loss
        Q_expected = self.critic_local(states, actions)
        critic_loss = F.mse_loss(Q_expected, Q_targets.detach())
        
        # Minimize the loss
        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.critic_local.parameters(), 1.0)  # Gradient clipping
        self.critic_optimizer.step()
        
        # ---------------------------- update actor ---------------------------- #
        # Compute actor loss
        actions_pred = self.actor_local(states)
        actor_loss = -self.critic_local(states, actions_pred).mean()
        
        # Add entropy regularization for exploration
        entropy = -torch.mean(torch.log(1 - actions_pred.pow(2) + 1e-6))
        actor_loss -= 0.01 * entropy
        
        # Minimize the loss
        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        torch.nn.utils.clip_grad_norm_(self.actor_local.parameters(), 1.0)  # Gradient clipping
        self.actor_optimizer.step()
        
        # ----------------------- update target networks ----------------------- #
        self.soft_update(self.critic_local, self.critic_target, self.tau)
        self.soft_update(self.actor_local, self.actor_target, self.tau)
        
        # Update statistics
        self.stats.update_loss(actor_loss.item(), critic_loss.item())
    
    def soft_update(self, local_model: nn.Module, target_model: nn.Module, tau: float):
        """Soft update model parameters.
        θ_target = τ*θ_local + (1 - τ)*θ_target
        
        Args:
            local_model: PyTorch model (weights will be copied from)
            target_model: PyTorch model (weights will be copied to)
            tau: Interpolation parameter (usually small)
        """
        for target_param, local_param in zip(target_model.parameters(), local_model.parameters()):
            target_param.data.copy_(tau*local_param.data + (1.0-tau)*target_param.data)
    
    def save_checkpoint(self, filename: str = "checkpoint.pth"):
        """Save model parameters to file."""
        checkpoint = {
            'state_dict_actor': self.actor_local.state_dict(),
            'state_dict_critic': self.critic_local.state_dict(),
            'optimizer_actor': self.actor_optimizer.state_dict(),
            'optimizer_critic': self.critic_optimizer.state_dict(),
            'stats': self.stats.__dict__,
            'noise_state': self.noise.state,
            'noise_sigma': self.noise.sigma,
            't_step': self.t_step,
            'seed': self.seed
        }
        
        # Save to file
        torch.save(checkpoint, self.model_dir / filename)
        logger.info(f"Saved checkpoint to {self.model_dir / filename}")
    
    def load_checkpoint(self, filename: str = "checkpoint.pth"):
        """Load model parameters from file."""
        try:
            checkpoint = torch.load(self.model_dir / filename, map_location=DEVICE)
            
            # Load model parameters
            self.actor_local.load_state_dict(checkpoint['state_dict_actor'])
            self.critic_local.load_state_dict(checkpoint['state_dict_critic'])
            self.actor_optimizer.load_state_dict(checkpoint['optimizer_actor'])
            self.critic_optimizer.load_state_dict(checkpoint['optimizer_critic'])
            
            # Load statistics
            self.stats = TrainingStats()
            self.stats.__dict__.update(checkpoint['stats'])
            
            # Load noise state
            self.noise.state = checkpoint['noise_state']
            self.noise.sigma = checkpoint['noise_sigma']
            
            # Load other parameters
            self.t_step = checkpoint['t_step']
            self.seed = checkpoint['seed']
            
            # Update target networks
            self.soft_update(self.actor_local, self.actor_target, 1.0)
            self.soft_update(self.critic_local, self.critic_target, 1.0)
            
            logger.info(f"Loaded checkpoint from {self.model_dir / filename}")
            return True
            
        except FileNotFoundError:
            logger.warning(f"No checkpoint found at {self.model_dir / filename}")
            return False
        except Exception as e:
            logger.error(f"Error loading checkpoint: {e}")
            return False
    
    def get_action_with_uncertainty(self, state: np.ndarray, num_samples: int = 10) -> Tuple[np.ndarray, float]:
        """Get action with uncertainty estimation using dropout at test time.
        
        Args:
            state: Current state
            num_samples: Number of forward passes for uncertainty estimation
            
        Returns:
            Tuple of (mean_action, uncertainty)
        """
        # Enable dropout at test time
        self.actor_local.train()
        
        # Get multiple action samples
        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(DEVICE)
        state_tensor = state_tensor.repeat(num_samples, 1)
        
        with torch.no_grad():
            actions = self.actor_local(state_tensor).cpu().numpy()
        
        # Calculate mean and standard deviation
        mean_action = np.mean(actions, axis=0)
        uncertainty = np.mean(np.std(actions, axis=0))
        
        # Set back to eval mode
        self.actor_local.eval()
        
        return mean_action, uncertainty
    
    def provide_feedback(self, state: np.ndarray, action: np.ndarray, 
                        feedback_type: FeedbackType, correction: Optional[np.ndarray] = None):
        """Provide feedback on an action taken in a given state.
        
        Args:
            state: The state where the action was taken
            action: The action that was taken
            feedback_type: Type of feedback (positive, negative, correction, etc.)
            correction: The corrected action (only used for CORRECTION feedback)
        """
        # Update feedback statistics
        self.stats.update_feedback(feedback_type)
        
        # Handle different types of feedback
        if feedback_type == FeedbackType.POSITIVE:
            # Positive feedback: reinforce this action
            reward = 1.0
            
        elif feedback_type == FeedbackType.NEGATIVE:
            # Negative feedback: penalize this action
            reward = -1.0
            
        elif feedback_type == FeedbackType.CORRECTION and correction is not None:
            # Corrective feedback: use the corrected action
            # Add the correction as a demonstration
            self.memory.add(state, correction, 1.0, state, True, FeedbackType.CORRECTION)
            return
            
        elif feedback_type == FeedbackType.DEMONSTRATION:
            # Demonstration: add as a perfect example
            reward = 1.0
            
        else:
            # Neutral feedback: no specific reward
            reward = 0.0
        
        # Add the feedback to the replay buffer
        self.memory.add(state, action, reward, state, True, feedback_type)
        
        # If we have enough samples, do a learning step with the feedback
        if len(self.memory) > self.batch_size:
            experiences = self.memory.sample()
            self.learn(experiences, self.gamma)
    
    def train_mode(self):
        """Set the model to training mode."""
        self.actor_local.train()
        self.critic_local.train()
    
    def eval_mode(self):
        """Set the model to evaluation mode."""
        self.actor_local.eval()
        self.critic_local.eval()

# Example usage
def example_usage():
    # Environment parameters
    state_size = 24
    action_size = 4
    
    # Create the agent
    agent = RLLearner(
        state_size=state_size,
        action_size=action_size,
        hidden_layers_actor=[256, 128],
        hidden_layers_critic=[256, 256, 128],
        buffer_size=1000000,
        batch_size=128,
        gamma=0.99,
        tau=0.001,
        lr_actor=1e-4,
        lr_critic=1e-3,
        weight_decay=0.0,
        update_every=4,
        learn_num=4,
        seed=42,
        model_dir="models",
        load_model=False
    )
    
    # Training loop
    num_episodes = 1000
    max_steps = 1000
    
    for episode in range(1, num_episodes + 1):
        # Reset the environment
        state = np.random.randn(state_size)  # Replace with actual environment reset
        episode_reward = 0
        
        for step in range(max_steps):
            # Select an action
            action = agent.act(state)
            
            # Take a step in the environment (replace with actual environment step)
            next_state = np.random.randn(state_size)  # Replace with actual environment step
            reward = np.random.randn()  # Replace with actual reward
            done = np.random.random() < 0.01  # Replace with actual done condition
            
            # Store the experience in replay memory
            agent.step(state, action, reward, next_state, done)
            
            # Update state and reward
            state = next_state
            episode_reward += reward
            
            if done:
                break
        
        # Print episode statistics
        print(f"Episode: {episode}, Reward: {episode_reward:.2f}, "
              f"Steps: {step + 1}, "
              f"Avg Loss: {np.mean(agent.stats.losses['total'][-10:]):.4f}")
        
        # Save checkpoint every 100 episodes
        if episode % 100 == 0:
            agent.save_checkpoint(f"checkpoint_ep{episode}.pth")
    
    # Save final model
    agent.save_checkpoint("final_model.pth")
    print("Training completed!")

if __name__ == "__main__":
    example_usage()
