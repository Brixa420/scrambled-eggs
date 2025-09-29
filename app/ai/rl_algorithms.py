"""
Reinforcement Learning Algorithms

This module implements various reinforcement learning algorithms that can be used
with the AI decision framework, including PPO, SAC, and DDPG.
"""

import torch
import torch.nn as nn
import torch.optim as optim
import torch.nn.functional as F
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
import random
from collections import deque
import copy

# Common components
class ReplayBuffer:
    """Experience replay buffer for reinforcement learning."""
    
    def __init__(self, capacity: int = 100000):
        self.buffer = deque(maxlen=capacity)
    
    def add(self, experience: Dict[str, Any]) -> None:
        """Add a new experience to the buffer."""
        self.buffer.append(experience)
    
    def sample(self, batch_size: int) -> List[Dict[str, Any]]:
        """Sample a batch of experiences from the buffer."""
        return random.sample(self.buffer, min(len(self.buffer), batch_size))
    
    def __len__(self) -> int:
        return len(self.buffer)

class Actor(nn.Module):
    """Base actor network for policy-based methods."""
    
    def __init__(self, state_dim: int, action_dim: int, hidden_dims: List[int] = [256, 256]):
        super().__init__()
        
        layers = []
        prev_dim = state_dim
        
        # Hidden layers
        for dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, dim))
            layers.append(nn.ReLU())
            prev_dim = dim
        
        # Output layer
        self.net = nn.Sequential(*layers)
        self.mu = nn.Linear(prev_dim, action_dim)
        self.log_std = nn.Parameter(torch.zeros(action_dim) - 1, requires_grad=True)
    
    def forward(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        """Forward pass."""
        x = self.net(state)
        mu = torch.tanh(self.mu(x))  # Bound actions to [-1, 1]
        std = self.log_std.exp().expand_as(mu)
        return mu, std
    
    def sample(self, state: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        """Sample action from the policy."""
        mu, std = self.forward(state)
        dist = torch.distributions.Normal(mu, std)
        action = dist.rsample()
        log_prob = dist.log_prob(action).sum(dim=-1, keepdim=True)
        return action, log_prob, dist.entropy().sum(dim=-1, keepdim=True)

class Critic(nn.Module):
    """Base critic network for value-based methods."""
    
    def __init__(self, state_dim: int, hidden_dims: List[int] = [256, 256]):
        super().__init__()
        
        layers = []
        prev_dim = state_dim
        
        # Hidden layers
        for dim in hidden_dims:
            layers.append(nn.Linear(prev_dim, dim))
            layers.append(nn.ReLU())
            prev_dim = dim
        
        # Output layer
        layers.append(nn.Linear(prev_dim, 1))
        self.net = nn.Sequential(*layers)
    
    def forward(self, state: torch.Tensor) -> torch.Tensor:
        """Forward pass."""
        return self.net(state)

# PPO (Proximal Policy Optimization)
class PPO:
    """Proximal Policy Optimization algorithm."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dims: List[int] = [256, 256],
        lr_actor: float = 3e-4,
        lr_critic: float = 1e-3,
        gamma: float = 0.99,
        gae_lambda: float = 0.95,
        clip_ratio: float = 0.2,
        target_kl: float = 0.01,
        train_iters: int = 80,
        train_batch_size: int = 64,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.device = device
        self.gamma = gamma
        self.gae_lambda = gae_lambda
        self.clip_ratio = clip_ratio
        self.target_kl = target_kl
        self.train_iters = train_iters
        self.train_batch_size = train_batch_size
        
        # Initialize actor and critic networks
        self.actor = Actor(state_dim, action_dim, hidden_dims).to(device)
        self.critic = Critic(state_dim, hidden_dims).to(device)
        
        # Initialize optimizers
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=lr_actor)
        self.critic_optimizer = optim.Adam(self.critic.parameters(), lr=lr_critic)
        
        # Initialize old actor for policy updates
        self.actor_old = Actor(state_dim, action_dim, hidden_dims).to(device)
        self.actor_old.load_state_dict(self.actor.state_dict())
    
    def update(self, batch: Dict[str, torch.Tensor]) -> Dict[str, float]:
        """Update the policy and value networks."""
        # Move batch to device
        states = batch['states'].to(self.device)
        actions = batch['actions'].to(self.device)
        old_log_probs = batch['log_probs'].to(self.device)
        advantages = batch['advantages'].to(self.device)
        returns = batch['returns'].to(self.device)
        
        # Normalize advantages
        advantages = (advantages - advantages.mean()) / (advantages.std() + 1e-8)
        
        # Update actor and critic for several epochs
        actor_losses, critic_losses, kl_divs = [], [], []
        
        for _ in range(self.train_iters):
            # Get current policy's action probabilities
            _, log_probs, _ = self.actor.sample(states)
            log_ratio = log_probs - old_log_probs
            ratio = torch.exp(log_ratio)
            
            # Calculate surrogate loss
            surr1 = ratio * advantages
            surr2 = torch.clamp(ratio, 1.0 - self.clip_ratio, 1.0 + self.clip_ratio) * advantages
            actor_loss = -torch.min(surr1, surr2).mean()
            
            # Calculate KL divergence
            with torch.no_grad():
                _, old_log_probs_old, _ = self.actor_old.sample(states)
                kl = (old_log_probs - old_log_probs_old).mean()
                kl_divs.append(kl.item())
            
            # Early stopping if KL divergence is too large
            if kl > self.target_kl * 1.5:
                break
            
            # Update actor
            self.actor_optimizer.zero_grad()
            actor_loss.backward()
            self.actor_optimizer.step()
            
            # Update critic
            values = self.critic(states)
            critic_loss = F.mse_loss(values, returns)
            
            self.critic_optimizer.zero_grad()
            critic_loss.backward()
            self.critic_optimizer.step()
            
            # Store losses
            actor_losses.append(actor_loss.item())
            critic_losses.append(critic_loss.item())
        
        # Update old actor
        self.actor_old.load_state_dict(self.actor.state_dict())
        
        return {
            'actor_loss': np.mean(actor_losses),
            'critic_loss': np.mean(critic_losses),
            'kl_divergence': np.mean(kl_divs)
        }
    
    def act(self, state: np.ndarray, deterministic: bool = False) -> Tuple[np.ndarray, np.ndarray]:
        """Select an action using the current policy."""
        with torch.no_grad():
            state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            
            if deterministic:
                mu, _ = self.actor(state)
                action = mu
            else:
                action, log_prob, _ = self.actor.sample(state)
                log_prob = log_prob.squeeze(0).cpu().numpy()
            
            value = self.critic(state).squeeze(0).cpu().numpy()
            action = action.squeeze(0).cpu().numpy()
            
            if not deterministic:
                return action, log_prob, value
            return action, value
    
    def save(self, path: str) -> None:
        """Save the model to a file."""
        torch.save({
            'actor_state_dict': self.actor.state_dict(),
            'critic_state_dict': self.critic.state_dict(),
            'actor_optimizer_state_dict': self.actor_optimizer.state_dict(),
            'critic_optimizer_state_dict': self.critic_optimizer.state_dict(),
        }, path)
    
    def load(self, path: str) -> None:
        """Load the model from a file."""
        checkpoint = torch.load(path, map_location=self.device)
        self.actor.load_state_dict(checkpoint['actor_state_dict'])
        self.critic.load_state_dict(checkpoint['critic_state_dict'])
        self.actor_optimizer.load_state_dict(checkpoint['actor_optimizer_state_dict'])
        self.critic_optimizer.load_state_dict(checkpoint['critic_optimizer_state_dict'])
        self.actor_old.load_state_dict(self.actor.state_dict())

# SAC (Soft Actor-Critic)
class SAC:
    """Soft Actor-Critic algorithm."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dims: List[int] = [256, 256],
        lr_actor: float = 3e-4,
        lr_critic: float = 3e-4,
        lr_alpha: float = 3e-4,
        gamma: float = 0.99,
        tau: float = 0.005,
        alpha: float = 0.2,
        automatic_entropy_tuning: bool = True,
        target_update_interval: int = 1,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.device = device
        self.gamma = gamma
        self.tau = tau
        self.target_update_interval = target_update_interval
        self.automatic_entropy_tuning = automatic_entropy_tuning
        
        # Initialize networks
        self.actor = Actor(state_dim, action_dim, hidden_dims).to(device)
        self.critic1 = Critic(state_dim + action_dim, hidden_dims).to(device)
        self.critic2 = Critic(state_dim + action_dim, hidden_dims).to(device)
        self.critic1_target = Critic(state_dim + action_dim, hidden_dims).to(device)
        self.critic2_target = Critic(state_dim + action_dim, hidden_dims).to(device)
        
        # Initialize target networks
        self.critic1_target.load_state_dict(self.critic1.state_dict())
        self.critic2_target.load_state_dict(self.critic2.state_dict())
        
        # Initialize optimizers
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=lr_actor)
        self.critic1_optimizer = optim.Adam(self.critic1.parameters(), lr=lr_critic)
        self.critic2_optimizer = optim.Adam(self.critic2.parameters(), lr=lr_critic)
        
        # Entropy tuning
        if self.automatic_entropy_tuning:
            self.target_entropy = -torch.prod(torch.Tensor((action_dim,)).to(device)).item()
            self.log_alpha = torch.zeros(1, requires_grad=True, device=device)
            self.alpha_optimizer = optim.Adam([self.log_alpha], lr=lr_alpha)
            self.alpha = self.log_alpha.exp()
        else:
            self.alpha = alpha
        
        self.total_it = 0
    
    def update(self, batch: Dict[str, torch.Tensor]) -> Dict[str, float]:
        """Update the policy and value networks."""
        self.total_it += 1
        
        # Unpack batch
        states = batch['states'].to(self.device)
        actions = batch['actions'].to(self.device)
        next_states = batch['next_states'].to(self.device)
        rewards = batch['rewards'].to(self.device)
        dones = batch['dones'].to(self.device)
        
        with torch.no_grad():
            # Sample next actions and compute target Q values
            next_actions, next_log_probs, _ = self.actor.sample(next_states)
            next_q1 = self.critic1_target(torch.cat([next_states, next_actions], 1))
            next_q2 = self.critic2_target(torch.cat([next_states, next_actions], 1))
            next_q = torch.min(next_q1, next_q2) - self.alpha * next_log_probs
            target_q = rewards + (1 - dones) * self.gamma * next_q
        
        # Update critics
        current_q1 = self.critic1(torch.cat([states, actions], 1))
        current_q2 = self.critic2(torch.cat([states, actions], 1))
        
        critic1_loss = F.mse_loss(current_q1, target_q)
        critic2_loss = F.mse_loss(current_q2, target_q)
        
        self.critic1_optimizer.zero_grad()
        critic1_loss.backward()
        self.critic1_optimizer.step()
        
        self.critic2_optimizer.zero_grad()
        critic2_loss.backward()
        self.critic2_optimizer.step()
        
        # Update actor
        actions_pred, log_probs, _ = self.actor.sample(states)
        q1_pi = self.critic1(torch.cat([states, actions_pred], 1))
        q2_pi = self.critic2(torch.cat([states, actions_pred], 1))
        q_pi = torch.min(q1_pi, q2_pi)
        
        actor_loss = (self.alpha * log_probs - q_pi).mean()
        
        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        self.actor_optimizer.step()
        
        # Update alpha
        if self.automatic_entropy_tuning:
            alpha_loss = -(self.log_alpha * (log_probs + self.target_entropy).detach()).mean()
            
            self.alpha_optimizer.zero_grad()
            alpha_loss.backward()
            self.alpha_optimizer.step()
            
            self.alpha = self.log_alpha.exp()
        
        # Update target networks
        if self.total_it % self.target_update_interval == 0:
            self._update_target_network()
        
        return {
            'actor_loss': actor_loss.item(),
            'critic1_loss': critic1_loss.item(),
            'critic2_loss': critic2_loss.item(),
            'alpha': self.alpha.item()
        }
    
    def _update_target_network(self) -> None:
        """Update the target networks using soft updates."""
        for param, target_param in zip(self.critic1.parameters(), self.critic1_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)
        
        for param, target_param in zip(self.critic2.parameters(), self.critic2_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)
    
    def act(self, state: np.ndarray, evaluate: bool = False) -> np.ndarray:
        """Select an action using the current policy."""
        with torch.no_grad():
            state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            
            if evaluate:
                action, _, _ = self.actor.sample(state)
            else:
                action, _, _ = self.actor.sample(state)
            
            return action.squeeze(0).cpu().numpy()
    
    def save(self, path: str) -> None:
        """Save the model to a file."""
        torch.save({
            'actor_state_dict': self.actor.state_dict(),
            'critic1_state_dict': self.critic1.state_dict(),
            'critic2_state_dict': self.critic2.state_dict(),
            'critic1_target_state_dict': self.critic1_target.state_dict(),
            'critic2_target_state_dict': self.critic2_target.state_dict(),
            'actor_optimizer_state_dict': self.actor_optimizer.state_dict(),
            'critic1_optimizer_state_dict': self.critic1_optimizer.state_dict(),
            'critic2_optimizer_state_dict': self.critic2_optimizer.state_dict(),
            'log_alpha': self.log_alpha if self.automatic_entropy_tuning else None,
            'alpha_optimizer_state_dict': self.alpha_optimizer.state_dict() if self.automatic_entropy_tuning else None,
            'total_it': self.total_it
        }, path)
    
    def load(self, path: str) -> None:
        """Load the model from a file."""
        checkpoint = torch.load(path, map_location=self.device)
        
        self.actor.load_state_dict(checkpoint['actor_state_dict'])
        self.critic1.load_state_dict(checkpoint['critic1_state_dict'])
        self.critic2.load_state_dict(checkpoint['critic2_state_dict'])
        self.critic1_target.load_state_dict(checkpoint['critic1_target_state_dict'])
        self.critic2_target.load_state_dict(checkpoint['critic2_target_state_dict'])
        
        self.actor_optimizer.load_state_dict(checkpoint['actor_optimizer_state_dict'])
        self.critic1_optimizer.load_state_dict(checkpoint['critic1_optimizer_state_dict'])
        self.critic2_optimizer.load_state_dict(checkpoint['critic2_optimizer_state_dict'])
        
        if self.automatic_entropy_tuning and checkpoint['log_alpha'] is not None:
            self.log_alpha = checkpoint['log_alpha'].to(self.device)
            self.alpha_optimizer.load_state_dict(checkpoint['alpha_optimizer_state_dict'])
        
        self.total_it = checkpoint.get('total_it', 0)

# DDPG (Deep Deterministic Policy Gradient)
class DDPG:
    """Deep Deterministic Policy Gradient algorithm."""
    
    def __init__(
        self,
        state_dim: int,
        action_dim: int,
        hidden_dims: List[int] = [400, 300],
        lr_actor: float = 1e-4,
        lr_critic: float = 1e-3,
        gamma: float = 0.99,
        tau: float = 0.001,
        noise_std: float = 0.1,
        noise_decay: float = 0.999,
        noise_min: float = 0.01,
        device: str = "cuda" if torch.cuda.is_available() else "cpu"
    ):
        self.device = device
        self.gamma = gamma
        self.tau = tau
        self.noise_std = noise_std
        self.noise_decay = noise_decay
        self.noise_min = noise_min
        
        # Initialize networks
        self.actor = Actor(state_dim, action_dim, hidden_dims).to(device)
        self.actor_target = Actor(state_dim, action_dim, hidden_dims).to(device)
        self.actor_target.load_state_dict(self.actor.state_dict())
        
        self.critic = Critic(state_dim + action_dim, hidden_dims).to(device)
        self.critic_target = Critic(state_dim + action_dim, hidden_dims).to(device)
        self.critic_target.load_state_dict(self.critic.state_dict())
        
        # Initialize optimizers
        self.actor_optimizer = optim.Adam(self.actor.parameters(), lr=lr_actor)
        self.critic_optimizer = optim.Adam(self.critic.parameters(), lr=lr_critic)
        
        # Action noise for exploration
        self.action_noise = ActionNoise(
            mean=np.zeros(action_dim),
            std_dev=float(noise_std) * np.ones(action_dim)
        )
    
    def update(self, batch: Dict[str, torch.Tensor]) -> Dict[str, float]:
        """Update the policy and value networks."""
        # Unpack batch
        states = batch['states'].to(self.device)
        actions = batch['actions'].to(self.device)
        next_states = batch['next_states'].to(self.device)
        rewards = batch['rewards'].to(self.device)
        dones = batch['dones'].to(self.device)
        
        # Update critic
        with torch.no_grad():
            next_actions = self.actor_target(next_states)[0]  # Get mu only
            target_q = self.critic_target(torch.cat([next_states, next_actions], 1))
            target_q = rewards + (1 - dones) * self.gamma * target_q
        
        current_q = self.critic(torch.cat([states, actions], 1))
        critic_loss = F.mse_loss(current_q, target_q)
        
        self.critic_optimizer.zero_grad()
        critic_loss.backward()
        self.critic_optimizer.step()
        
        # Update actor
        pred_actions = self.actor(states)[0]  # Get mu only
        actor_loss = -self.critic(torch.cat([states, pred_actions], 1)).mean()
        
        self.actor_optimizer.zero_grad()
        actor_loss.backward()
        self.actor_optimizer.step()
        
        # Update target networks
        self._update_target_network()
        
        # Decay noise
        self.action_noise.decay_noise()
        
        return {
            'actor_loss': actor_loss.item(),
            'critic_loss': critic_loss.item(),
            'noise_std': self.action_noise.std_dev[0]
        }
    
    def _update_target_network(self) -> None:
        """Update the target networks using soft updates."""
        for param, target_param in zip(self.actor.parameters(), self.actor_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)
        
        for param, target_param in zip(self.critic.parameters(), self.critic_target.parameters()):
            target_param.data.copy_(self.tau * param.data + (1 - self.tau) * target_param.data)
    
    def act(self, state: np.ndarray, add_noise: bool = True) -> np.ndarray:
        """Select an action using the current policy."""
        with torch.no_grad():
            state = torch.FloatTensor(state).unsqueeze(0).to(self.device)
            action = self.actor(state)[0].cpu().numpy()  # Get mu only
            
            if add_noise:
                noise = self.action_noise()
                action = np.clip(action + noise, -1.0, 1.0)
            
            return action.squeeze(0)
    
    def save(self, path: str) -> None:
        """Save the model to a file."""
        torch.save({
            'actor_state_dict': self.actor.state_dict(),
            'critic_state_dict': self.critic.state_dict(),
            'actor_target_state_dict': self.actor_target.state_dict(),
            'critic_target_state_dict': self.critic_target.state_dict(),
            'actor_optimizer_state_dict': self.actor_optimizer.state_dict(),
            'critic_optimizer_state_dict': self.critic_optimizer.state_dict(),
            'action_noise_std': self.action_noise.std_dev[0]
        }, path)
    
    def load(self, path: str) -> None:
        """Load the model from a file."""
        checkpoint = torch.load(path, map_location=self.device)
        
        self.actor.load_state_dict(checkpoint['actor_state_dict'])
        self.critic.load_state_dict(checkpoint['critic_state_dict'])
        self.actor_target.load_state_dict(checkpoint['actor_target_state_dict'])
        self.critic_target.load_state_dict(checkpoint['critic_target_state_dict'])
        
        self.actor_optimizer.load_state_dict(checkpoint['actor_optimizer_state_dict'])
        self.critic_optimizer.load_state_dict(checkpoint['critic_optimizer_state_dict'])
        
        # Update action noise
        if 'action_noise_std' in checkpoint:
            self.action_noise = ActionNoise(
                mean=np.zeros_like(self.action_noise.mean),
                std_dev=checkpoint['action_noise_std'] * np.ones_like(self.action_noise.std_dev)
            )

class ActionNoise:
    """Action noise for exploration in DDPG."""
    
    def __init__(self, mean: np.ndarray, std_dev: np.ndarray):
        self.mean = mean
        self.std_dev = std_dev
        self.original_std = std_dev.copy()
    
    def __call__(self) -> np.ndarray:
        """Generate noise."""
        return np.random.normal(self.mean, self.std_dev).astype(np.float32)
    
    def decay_noise(self) -> None:
        """Decay the noise standard deviation."""
        self.std_dev = np.maximum(
            self.noise_min,
            self.std_dev * self.noise_decay
        )
    
    def reset(self) -> None:
        """Reset the noise standard deviation to its original value."""
        self.std_dev = self.original_std.copy()

# Example usage
if __name__ == "__main__":
    import gym
    
    # Hyperparameters
    env_name = "Pendulum-v1"
    state_dim = 3
    action_dim = 1
    max_episodes = 1000
    max_steps = 200
    batch_size = 64
    
    # Initialize environment and agent
    env = gym.make(env_name)
    agent = PPO(state_dim, action_dim)
    
    # Training loop
    for episode in range(max_episodes):
        state = env.reset()
        episode_reward = 0
        
        for step in range(max_steps):
            # Select action
            action, log_prob, _ = agent.act(state)
            
            # Take action
            next_state, reward, done, _ = env.step(action)
            
            # Store experience
            agent.memory.add({
                'state': state,
                'action': action,
                'reward': reward,
                'next_state': next_state,
                'done': done,
                'log_prob': log_prob
            })
            
            # Update agent
            if len(agent.memory) >= batch_size:
                agent.update(agent.memory.sample(batch_size))
            
            state = next_state
            episode_reward += reward
            
            if done:
                break
        
        print(f"Episode {episode + 1}, Reward: {episode_reward:.2f}")
    
    env.close()
