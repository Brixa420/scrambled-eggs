"""
Personalization Module for AI Instances
Handles user-specific behaviors, preferences, and learning.
"""
import json
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
from .instance import AIInstance

logger = logging.getLogger(__name__)

class PersonalizationEngine:
    """Handles personalization for AI instances."""
    
    def __init__(self, ai_instance: AIInstance):
        """Initialize with an AI instance.
        
        Args:
            ai_instance: The AI instance to personalize
        """
        self.ai_instance = ai_instance
        self.preferences_file = ai_instance.data_path / 'preferences.json'
        self.behavior_file = ai_instance.data_path / 'behavior.json'
        self._preferences: Dict[str, Any] = {}
        self._behavior: Dict[str, Any] = {}
        self._load_data()
    
    def _load_data(self) -> None:
        """Load personalization data from disk."""
        # Load preferences
        if self.preferences_file.exists():
            try:
                with open(self.preferences_file, 'r') as f:
                    self._preferences = json.load(f)
            except Exception as e:
                logger.error(f"Error loading preferences: {e}")
                self._preferences = {}
        
        # Initialize default preferences if none exist
        if not self._preferences:
            self._preferences = {
                'communication_style': 'friendly',
                'formality': 'neutral',
                'topics_of_interest': [],
                'learning_rate': 0.1,
                'last_updated': datetime.utcnow().isoformat()
            }
            self._save_preferences()
        
        # Load behavior data
        if self.behavior_file.exists():
            try:
                with open(self.behavior_file, 'r') as f:
                    self._behavior = json.load(f)
            except Exception as e:
                logger.error(f"Error loading behavior data: {e}")
                self._behavior = {}
        
        # Initialize default behavior if none exists
        if not self._behavior:
            self._behavior = {
                'interaction_count': 0,
                'common_phrases': {},
                'preferred_topics': {},
                'interaction_history': [],
                'last_updated': datetime.utcnow().isoformat()
            }
            self._save_behavior()
    
    def _save_preferences(self) -> None:
        """Save preferences to disk."""
        self._preferences['last_updated'] = datetime.utcnow().isoformat()
        with open(self.preferences_file, 'w') as f:
            json.dump(self._preferences, f, indent=2)
    
    def _save_behavior(self) -> None:
        """Save behavior data to disk."""
        self._behavior['last_updated'] = datetime.utcnow().isoformat()
        with open(self.behavior_file, 'w') as f:
            json.dump(self._behavior, f, indent=2)
    
    def update_communication_style(self, style: str) -> None:
        """Update the user's preferred communication style."""
        valid_styles = ['friendly', 'professional', 'casual', 'formal']
        if style not in valid_styles:
            raise ValueError(f"Invalid style. Must be one of: {', '.join(valid_styles)}")
        
        self._preferences['communication_style'] = style
        self._save_preferences()
    
    def add_topic_interest(self, topic: str, weight: float = 1.0) -> None:
        """Add or update a topic of interest."""
        if 'topics_of_interest' not in self._preferences:
            self._preferences['topics_of_interest'] = {}
        
        self._preferences['topics_of_interest'][topic] = weight
        self._save_preferences()
    
    def record_interaction(self, user_input: str, ai_response: str) -> None:
        """Record an interaction for learning."""
        # Update interaction count
        self._behavior['interaction_count'] += 1
        
        # Record interaction
        interaction = {
            'timestamp': datetime.utcnow().isoformat(),
            'user_input': user_input,
            'ai_response': ai_response
        }
        self._behavior['interaction_history'].append(interaction)
        
        # Keep only the last 100 interactions
        if len(self._behavior['interaction_history']) > 100:
            self._behavior['interaction_history'] = self._behavior['interaction_history'][-100:]
        
        self._save_behavior()
    
    def analyze_behavior(self) -> Dict[str, Any]:
        """Analyze user behavior patterns."""
        # Simple analysis - can be expanded
        return {
            'interaction_count': self._behavior.get('interaction_count', 0),
            'frequent_topics': sorted(
                self._preferences.get('topics_of_interest', {}).items(),
                key=lambda x: x[1],
                reverse=True
            )[:5],
            'preferred_style': self._preferences.get('communication_style', 'neutral')
        }
    
    def get_personalized_response(self, message: str) -> str:
        """Generate a personalized response based on user preferences."""
        # This is a simplified example - in practice, you'd use an LLM here
        style = self._preferences.get('communication_style', 'friendly')
        
        if style == 'friendly':
            return f"Hey there! I noticed you said: '{message}'. That's really interesting!"
        elif style == 'professional':
            return f"Thank you for your message: '{message}'. I'll address this professionally."
        else:
            return f"I received your message: {message}"


class PersonalizationManager:
    """Manages personalization for all AI instances."""
    
    def __init__(self, ai_instance: AIInstance):
        """Initialize with an AI instance."""
        self.engine = PersonalizationEngine(ai_instance)
    
    def process_message(self, user_id: str, message: str) -> str:
        """Process a message with personalization."""
        # Get a response based on user preferences
        response = self.engine.get_personalized_response(message)
        
        # Record the interaction
        self.engine.record_interaction(message, response)
        
        return response
    
    def update_preferences(self, preferences: Dict[str, Any]) -> None:
        """Update user preferences."""
        for key, value in preferences.items():
            if key == 'communication_style':
                self.engine.update_communication_style(value)
            elif key == 'topics_of_interest':
                for topic, weight in value.items():
                    self.engine.add_topic_interest(topic, weight)
