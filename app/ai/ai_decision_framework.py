"""
AI Decision Framework

This module implements the neural network architecture and reinforcement learning
components for the AI decision framework in the Scrambled Eggs encryption system.
"""

import logging
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque
import random

logger = logging.getLogger(__name__)

class NeuralNetwork(nn.Module):
    """Neural network architecture for the AI decision framework."""
    
    def __init__(self, input_size: int, hidden_sizes: List[int], output_size: int):
        super(NeuralNetwork, self).__init__()
        
        # Input layer
        layers = [nn.Linear(input_size, hidden_sizes[0]), nn.ReLU()]
        
        # Hidden layers
        for i in range(len(hidden_sizes) - 1):
            layers.append(nn.Linear(hidden_sizes[i], hidden_sizes[i+1]))
            layers.append(nn.ReLU())
        
        # Output layer
        layers.append(nn.Linear(hidden_sizes[-1], output_size))
        layers.append(nn.Softmax(dim=1))
        
        self.model = nn.Sequential(*layers)
    
    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.model(x)

@dataclass
class Experience:
    """Represents a single experience in the reinforcement learning memory."""
    state: np.ndarray
    action: int
    reward: float
    next_state: np.ndarray
    done: bool
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

class ReplayBuffer:
    """Experience replay buffer for reinforcement learning."""
    
    def __init__(self, capacity: int = 10000):
        self.buffer = deque(maxlen=capacity)
    
    def add(self, experience: Experience) -> None:
        """Add a new experience to the buffer."""
        self.buffer.append(experience)
    
    def sample(self, batch_size: int) -> List[Experience]:
        """Sample a batch of experiences from the buffer."""
        return random.sample(self.buffer, min(len(self.buffer), batch_size))
    
    def __len__(self) -> int:
        return len(self.buffer)

class AIDecisionFramework:
    """AI Decision Framework for the Scrambled Eggs encryption system."""
    
    def __init__(
        self,
        input_size: int = 64,  # Size of the state vector
        hidden_sizes: List[int] = [128, 128],
        output_size: int = 10,  # Number of possible actions
        learning_rate: float = 0.001,
        gamma: float = 0.99,  # Discount factor
        epsilon: float = 1.0,  # Exploration rate
        epsilon_min: float = 0.01,
        epsilon_decay: float = 0.995,
        batch_size: int = 64,
        memory_size: int = 10000,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.input_size = input_size
        self.output_size = output_size
        self.gamma = gamma
        self.epsilon = epsilon
        self.epsilon_min = epsilon_min
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.device = device
        
        # Initialize neural networks
        self.policy_net = NeuralNetwork(input_size, hidden_sizes, output_size).to(device)
        self.target_net = NeuralNetwork(input_size, hidden_sizes, output_size).to(device)
        self.target_net.load_state_dict(self.policy_net.state_dict())
        self.target_net.eval()
        
        # Initialize optimizer and loss function
        self.optimizer = optim.Adam(self.policy_net.parameters(), lr=learning_rate)
        self.criterion = nn.MSELoss()
        
        # Initialize replay buffer
        self.memory = ReplayBuffer(memory_size)
        
        # Track training metrics
        self.training_metrics = {
            'episode_rewards': [],
            'episode_losses': [],
            'exploration_rate': [],
            'episode_lengths': []
        }
    
    def get_action(self, state: np.ndarray, training: bool = True) -> int:
        """Select an action using an epsilon-greedy policy."""
        if training and random.random() < self.epsilon:
            return random.randint(0, self.output_size - 1)
        
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_tensor)
            return torch.argmax(q_values).item()
    
    def remember(self, state: np.ndarray, action: int, reward: float, next_state: np.ndarray, done: bool) -> None:
        """Store experience in replay memory."""
        experience = Experience(state, action, reward, next_state, done)
        self.memory.add(experience)
    
    def replay(self) -> Optional[float]:
        """Train the neural network on a batch of experiences."""
        if len(self.memory) < self.batch_size:
            return None
        
        # Sample a batch of experiences
        batch = self.memory.sample(self.batch_size)
        
        # Convert batch to tensors
        states = torch.FloatTensor(np.array([e.state for e in batch])).to(self.device)
        actions = torch.LongTensor([e.action for e in batch]).to(self.device)
        rewards = torch.FloatTensor([e.reward for e in batch]).to(self.device)
        next_states = torch.FloatTensor(np.array([e.next_state for e in batch])).to(self.device)
        dones = torch.FloatTensor([e.done for e in batch]).to(self.device)
        
        # Compute Q(s_t, a)
        current_q_values = self.policy_net(states).gather(1, actions.unsqueeze(1))
        
        # Compute V(s_{t+1}) for all next states
        with torch.no_grad():
            next_q_values = self.target_net(next_states).max(1)[0].detach()
            expected_q_values = rewards + (1 - dones) * self.gamma * next_q_values
        
        # Compute loss
        loss = self.criterion(current_q_values.squeeze(), expected_q_values)
        
        # Optimize the model
        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        
        # Update epsilon
        self.epsilon = max(self.epsilon_min, self.epsilon * self.epsilon_decay)
        
        return loss.item()
    
    def update_target_network(self) -> None:
        """Update the target network with the policy network's weights."""
        self.target_net.load_state_dict(self.policy_net.state_dict())
    
    def save_model(self, path: str) -> None:
        """Save the model to a file."""
        torch.save({
            'policy_net_state_dict': self.policy_net.state_dict(),
            'target_net_state_dict': self.target_net.state_dict(),
            'optimizer_state_dict': self.optimizer.state_dict(),
            'epsilon': self.epsilon,
            'training_metrics': self.training_metrics
        }, path)
    
    def load_model(self, path: str) -> None:
        """Load the model from a file."""
        checkpoint = torch.load(path, map_location=self.device)
        self.policy_net.load_state_dict(checkpoint['policy_net_state_dict'])
        self.target_net.load_state_dict(checkpoint['target_net_state_dict'])
        self.optimizer.load_state_dict(checkpoint['optimizer_state_dict'])
        self.epsilon = checkpoint.get('epsilon', self.epsilon_min)
        self.training_metrics = checkpoint.get('training_metrics', self.training_metrics)
        self.target_net.eval()
    
    def explain_decision(self, state: np.ndarray, action: int) -> Dict[str, Any]:
        """
        Provide an explanation for the AI's decision.
        
        This is a simplified explanation mechanism. In a production system,
        you would implement more sophisticated explainability techniques.
        """
        with torch.no_grad():
            state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            q_values = self.policy_net(state_tensor).squeeze().cpu().numpy()
            
            # Get the top 3 actions and their confidence scores
            top_actions = np.argsort(q_values)[::-1][:3]
            top_confidences = q_values[top_actions]
            
            return {
                "chosen_action": int(action),
                "action_confidence": float(q_values[action]),
                "top_alternative_actions": [int(a) for a in top_actions if a != action][:2],
                "top_alternative_confidences": [float(c) for i, c in enumerate(top_confidences) if top_actions[i] != action][:2],
                "explanation": self._generate_explanation(state, action, q_values)
            }
    
    def _generate_explanation(self, state: np.ndarray, action: int, q_values: np.ndarray) -> str:
        """Generate a human-readable explanation for the decision."""
        # This is a simple example. In a real system, you would implement
        # more sophisticated explanation generation based on the state and action.
        confidence = q_values[action]
        
        if confidence > 0.8:
            return "The AI is highly confident in this decision based on clear patterns in the input."
        elif confidence > 0.5:
            return "The AI is moderately confident in this decision, but there is some uncertainty."
        else:
            return "The AI has low confidence in this decision and is making a best guess."

# Example usage
if __name__ == "__main__":
    # Initialize the AI decision framework
    framework = AIDecisionFramework(
        input_size=64,
        hidden_sizes=[128, 128],
        output_size=10,
        learning_rate=0.001,
        gamma=0.99,
        epsilon=1.0,
        epsilon_min=0.01,
        epsilon_decay=0.995,
        batch_size=64,
        memory_size=10000
    )
    
    # Example training loop
    for episode in range(1000):
        state = np.random.randn(64)  # Example state
        total_reward = 0
        done = False
        
        while not done:
            # Select an action
            action = framework.get_action(state)
            
            # Take the action and observe the result
            next_state = np.random.randn(64)  # Example next state
            reward = random.random()  # Example reward
            done = random.random() < 0.1  # 10% chance of episode ending
            
            # Store the experience
            framework.remember(state, action, reward, next_state, done)
            
            # Train the model
            loss = framework.replay()
            
            # Update the target network periodically
            if episode % 10 == 0:
                framework.update_target_network()
            
            state = next_state
            total_reward += reward
        
        # Log metrics
        print(f"Episode {episode + 1}, Total Reward: {total_reward:.2f}, Epsilon: {framework.epsilon:.4f}")
