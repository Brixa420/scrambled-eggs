""
Scrambled Eggs AI Integration Example

This module demonstrates how to integrate the AI decision framework with the
Scrambled Eggs encryption system, including reinforcement learning and explainability.
"""

import os
import sys
import torch
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
import json
from datetime import datetime

# Add the project root to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.ai.ai_decision_framework import AIDecisionFramework
from app.ai.explainability import AIExplainer
from app.ai.rl_algorithms import PPO, SAC, DDPG
from app.core.security import SecurityManager
from app.services.scrambled_eggs_crypto import ScrambledEggsCrypto

class ScrambledEggsAI:
    """AI integration for the Scrambled Eggs encryption system."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the Scrambled Eggs AI system."""
        self.config = config
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        # Initialize security components
        self.security_manager = SecurityManager()
        self.crypto_service = ScrambledEggsCrypto(self.security_manager)
        
        # Initialize AI components
        self._init_ai_components()
        
        # Load or initialize models
        self._load_or_initialize_models()
    
    def _init_ai_components(self) -> None:
        """Initialize AI components based on configuration."""
        # State and action dimensions
        self.state_dim = self.config.get('state_dim', 64)
        self.action_dim = self.config.get('action_dim', 10)
        
        # Initialize the decision framework
        self.decision_framework = AIDecisionFramework(
            input_size=self.state_dim,
            hidden_sizes=[128, 128],
            output_size=self.action_dim,
            learning_rate=0.001,
            gamma=0.99,
            epsilon=1.0,
            epsilon_min=0.01,
            epsilon_decay=0.995,
            batch_size=64,
            memory_size=10000,
            device=self.device
        )
        
        # Initialize the explainer
        self.explainer = AIExplainer(
            model=self.decision_framework.policy_net,
            feature_names=[f"feature_{i}" for i in range(self.state_dim)],
            class_names=[f"action_{i}" for i in range(self.action_dim)]
        )
        
        # Initialize RL algorithms
        self.rl_algorithms = {
            'ppo': PPO(
                state_dim=self.state_dim,
                action_dim=self.action_dim,
                hidden_dims=[128, 128],
                device=self.device
            ),
            'sac': SAC(
                state_dim=self.state_dim,
                action_dim=self.action_dim,
                hidden_dims=[128, 128],
                device=self.device
            ),
            'ddpg': DDPG(
                state_dim=self.state_dim,
                action_dim=self.action_dim,
                hidden_dims=[128, 128],
                device=self.device
            )
        }
    
    def _load_or_initialize_models(self) -> None:
        """Load saved models or initialize new ones."""
        model_dir = os.path.join(os.path.dirname(__file__), 'saved_models')
        os.makedirs(model_dir, exist_ok=True)
        
        # Define model paths
        self.model_paths = {
            'decision_framework': os.path.join(model_dir, 'decision_framework.pt'),
            'ppo': os.path.join(model_dir, 'ppo.pt'),
            'sac': os.path.join(model_dir, 'sac.pt'),
            'ddpg': os.path.join(model_dir, 'ddpg.pt')
        }
        
        # Load or initialize models
        if os.path.exists(self.model_paths['decision_framework']):
            self.decision_framework.load_model(self.model_paths['decision_framework'])
            print("Loaded decision framework model from", self.model_paths['decision_framework'])
        
        for algo_name, algo in self.rl_algorithms.items():
            if os.path.exists(self.model_paths[algo_name]):
                algo.load(self.model_paths[algo_name])
                print(f"Loaded {algo_name.upper()} model from", self.model_paths[algo_name])
    
    def save_models(self) -> None:
        """Save all models to disk."""
        # Save decision framework
        self.decision_framework.save_model(self.model_paths['decision_framework'])
        
        # Save RL algorithms
        for algo_name, algo in self.rl_algorithms.items():
            algo.save(self.model_paths[algo_name])
        
        print("All models saved successfully.")
    
    def process_encryption_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process an encryption request using the AI decision framework."""
        # Extract and preprocess input data
        input_data = self._preprocess_input(request_data)
        
        # Get action from the decision framework
        action, confidence = self._get_ai_decision(input_data)
        
        # Generate explanation
        explanation = self.explain_decision(input_data, action)
        
        # Apply the action (e.g., select encryption parameters)
        result = self._apply_action(action, request_data)
        
        # Update the model based on feedback (if available)
        if 'feedback' in request_data:
            self._update_models(input_data, action, request_data['feedback'])
        
        return {
            'action': int(action),
            'confidence': float(confidence),
            'explanation': explanation,
            'result': result,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def _preprocess_input(self, request_data: Dict[str, Any]) -> np.ndarray:
        """Preprocess input data for the AI model."""
        # In a real implementation, this would extract and normalize features
        # from the request_data dictionary
        
        # For demonstration, create a random feature vector
        return np.random.randn(self.state_dim).astype(np.float32)
    
    def _get_ai_decision(self, input_data: np.ndarray) -> Tuple[int, float]:
        """Get a decision from the AI framework."""
        # Convert input to tensor
        state_tensor = torch.FloatTensor(input_data).unsqueeze(0).to(self.device)
        
        # Get action probabilities
        with torch.no_grad():
            action_probs = self.decision_framework.policy_net(state_tensor).squeeze()
        
        # Sample an action
        action = torch.multinomial(action_probs, 1).item()
        confidence = action_probs[action].item()
        
        return action, confidence
    
    def explain_decision(self, input_data: np.ndarray, action: int) -> Dict[str, Any]:
        """Generate an explanation for the AI's decision."""
        # Get SHAP explanation
        shap_exp = self.explainer.explain_with_shap(input_data.reshape(1, -1))
        
        # Get LIME explanation
        lime_exp = self.explainer.explain_with_lime(input_data)
        
        # Generate counterfactual explanation
        target_class = (action + 1) % self.action_dim  # Just for demonstration
        cf_input = input_data.reshape(1, -1)
        cf, cf_exp = self.explainer.generate_counterfactual(cf_input, target_class)
        
        return {
            'shap': {
                'feature_importances': shap_exp['feature_importances'],
                'top_features': shap_exp['explanations'][f'action_{action}']['top_features'][:5]
            },
            'lime': {
                'explanation': lime_exp['explanation'][action] if lime_exp['explanation'] else {}
            },
            'counterfactual': cf_exp
        }
    
    def _apply_action(self, action: int, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply the selected action to the encryption process."""
        # In a real implementation, this would apply the action to the encryption process
        # For example, adjusting encryption parameters based on the action
        
        return {
            'status': 'success',
            'action_applied': action,
            'encryption_params': {
                'algorithm': 'AES-256',
                'mode': 'GCM',
                'key_size': 256,
                'iv_size': 96,
                'additional_data': f"ai_action_{action}"
            },
            'metadata': {
                'model_used': 'decision_framework',
                'model_version': '1.0.0',
                'processing_time_ms': 42.0
            }
        }
    
    def _update_models(self, state: np.ndarray, action: int, feedback: Dict[str, Any]) -> None:
        """Update the AI models based on feedback."""
        # Extract reward from feedback
        reward = feedback.get('reward', 0.0)
        
        # Update decision framework
        next_state = np.random.randn(self.state_dim)  # In a real system, this would be the next state
        done = feedback.get('done', False)
        
        self.decision_framework.remember(state, action, reward, next_state, done)
        loss = self.decision_framework.replay()
        
        # Periodically update target network
        if np.random.random() < 0.1:  # 10% chance to update target network
            self.decision_framework.update_target_network()
        
        # Update RL algorithms (for demonstration, using the same experience)
        for algo_name, algo in self.rl_algorithms.items():
            if algo_name == 'ppo':
                # PPO requires advantages and old log probs
                with torch.no_grad():
                    state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                    _, log_prob, _ = algo.actor.sample(state_tensor)
                
                # In a real implementation, you would compute advantages using GAE
                advantage = reward  # Simplified
                
                algo.memory.add({
                    'states': state_tensor,
                    'actions': torch.LongTensor([action]).to(self.device),
                    'log_probs': log_prob.detach(),
                    'advantages': torch.FloatTensor([advantage]).to(self.device),
                    'returns': torch.FloatTensor([reward]).to(self.device)
                })
                
                if len(algo.memory) >= algo.train_batch_size:
                    algo.update(algo.memory.sample(algo.train_batch_size))
            
            elif algo_name == 'sac':
                # SAC uses (state, action, reward, next_state, done) tuples
                algo.memory.add({
                    'states': torch.FloatTensor(state).unsqueeze(0).to(self.device),
                    'actions': torch.FloatTensor([action]).to(self.device),
                    'rewards': torch.FloatTensor([reward]).to(self.device),
                    'next_states': torch.FloatTensor(next_state).unsqueeze(0).to(self.device),
                    'dones': torch.FloatTensor([float(done)]).to(self.device)
                })
                
                if len(algo.memory) >= algo.batch_size:
                    algo.update(algo.memory.sample(algo.batch_size))
            
            elif algo_name == 'ddpg':
                # DDPG also uses (state, action, reward, next_state, done) tuples
                algo.memory.add({
                    'states': torch.FloatTensor(state).unsqueeze(0).to(self.device),
                    'actions': torch.FloatTensor([action]).to(self.device),
                    'rewards': torch.FloatTensor([reward]).to(self.device),
                    'next_states': torch.FloatTensor(next_state).unsqueeze(0).to(self.device),
                    'dones': torch.FloatTensor([float(done)]).to(self.device)
                })
                
                if len(algo.memory) >= algo.batch_size:
                    algo.update(algo.memory.sample(algo.batch_size))
        
        # Periodically save models
        if np.random.random() < 0.05:  # 5% chance to save models
            self.save_models()
    
    def train_rl_agent(self, algo_name: str, env: Any, num_episodes: int = 1000) -> List[float]:
        """Train an RL agent using the specified algorithm."""
        if algo_name not in self.rl_algorithms:
            raise ValueError(f"Unknown algorithm: {algo_name}. Available: {list(self.rl_algorithms.keys())}")
        
        algo = self.rl_algorithms[algo_name]
        episode_rewards = []
        
        for episode in range(num_episodes):
            state = env.reset()
            episode_reward = 0
            done = False
            
            while not done:
                # Select action
                if algo_name == 'ppo':
                    action, _, _ = algo.act(state)
                else:
                    action = algo.act(state)
                
                # Take action in the environment
                next_state, reward, done, _ = env.step(action)
                
                # Store experience
                if algo_name == 'ppo':
                    # PPO requires advantages and old log probs
                    with torch.no_grad():
                        state_tensor = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                        _, log_prob, _ = algo.actor.sample(state_tensor)
                    
                    # In a real implementation, you would compute advantages using GAE
                    advantage = reward  # Simplified
                    
                    algo.memory.add({
                        'states': state_tensor,
                        'actions': torch.LongTensor([action]).to(self.device),
                        'log_probs': log_prob.detach(),
                        'advantages': torch.FloatTensor([advantage]).to(self.device),
                        'returns': torch.FloatTensor([reward]).to(self.device)
                    })
                else:
                    algo.memory.add({
                        'states': torch.FloatTensor(state).unsqueeze(0).to(self.device),
                        'actions': torch.FloatTensor([action]).to(self.device),
                        'rewards': torch.FloatTensor([reward]).to(self.device),
                        'next_states': torch.FloatTensor(next_state).unsqueeze(0).to(self.device),
                        'dones': torch.FloatTensor([float(done)]).to(self.device)
                    })
                
                # Update the agent
                if len(algo.memory) >= algo.batch_size:
                    if algo_name == 'ppo':
                        algo.update(algo.memory.sample(algo.batch_size))
                    else:
                        algo.update(algo.memory.sample(algo.batch_size))
                
                state = next_state
                episode_reward += reward
                
                if done:
                    break
            
            episode_rewards.append(episode_reward)
            print(f"Episode {episode + 1}/{num_episodes}, Reward: {episode_reward:.2f}")
            
            # Save the model periodically
            if (episode + 1) % 100 == 0:
                self.save_models()
        
        return episode_rewards

# Example usage
if __name__ == "__main__":
    # Configuration
    config = {
        'state_dim': 64,
        'action_dim': 10,
        'models_dir': 'saved_models'
    }
    
    # Initialize the Scrambled Eggs AI system
    ai_system = ScrambledEggsAI(config)
    
    # Example encryption request
    request_data = {
        'data': 'Sensitive information to encrypt',
        'metadata': {
            'sensitivity_level': 'high',
            'required_security': 'military_grade',
            'performance_requirements': 'low_latency'
        },
        'feedback': {
            'reward': 1.0,  # Positive feedback
            'done': False
        }
    }
    
    # Process the request
    result = ai_system.process_encryption_request(request_data)
    
    # Print the result
    print("\nEncryption Result:")
    print(json.dumps(result, indent=2))
    
    # Save the models
    ai_system.save_models()
    
    # Example of training an RL agent (requires a Gym environment)
    try:
        import gym
        
        print("\nTraining RL agent...")
        env = gym.make('Pendulum-v1')
        rewards = ai_system.train_rl_agent('ppo', env, num_episodes=10)
        print(f"Training completed. Average reward: {np.mean(rewards):.2f}")
    except ImportError:
        print("\nGym not installed. Skipping RL training example.")
    except Exception as e:
        print(f"\nError during RL training: {str(e)}")
