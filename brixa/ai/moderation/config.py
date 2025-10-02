""
Configuration for content moderation system.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union
import yaml
import os

@dataclass
class ModelConfig:
    """Configuration for a moderation model."""
    name: str
    provider: str  # e.g., 'openai', 'huggingface', 'custom'
    version: str = "latest"
    threshold: float = 0.8  # Confidence threshold for actions
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class PolicyRule:
    """A single moderation policy rule."""
    name: str
    description: str
    action: str  # 'allow', 'flag', 'block', 'quarantine', 'escalate'
    conditions: List[Dict[str, Any]]
    priority: int = 0
    enabled: bool = True

@dataclass
class ModerationConfig:
    """Main configuration for the moderation system."""
    models: Dict[str, ModelConfig]
    policies: Dict[str, PolicyRule]
    default_action: str = "allow"
    require_human_review: bool = True
    log_level: str = "INFO"
    
    @classmethod
    def from_yaml(cls, config_path: str) -> 'ModerationConfig':
        """Load configuration from a YAML file."""
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        return cls.from_dict(config_data)
    
    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'ModerationConfig':
        """Create config from a dictionary."""
        models = {
            name: ModelConfig(name=name, **data)
            for name, data in config_dict.get('models', {}).items()
        }
        
        policies = {
            name: PolicyRule(name=name, **data)
            for name, data in config_dict.get('policies', {}).items()
        }
        
        return cls(
            models=models,
            policies=policies,
            default_action=config_dict.get('default_action', 'allow'),
            require_human_review=config_dict.get('require_human_review', True),
            log_level=config_dict.get('log_level', 'INFO')
        )
    
    def to_dict(self) -> Dict:
        """Convert config to dictionary."""
        return {
            'models': {
                name: {
                    'provider': model.provider,
                    'version': model.version,
                    'threshold': model.threshold,
                    'enabled': model.enabled,
                    **model.params
                }
                for name, model in self.models.items()
            },
            'policies': {
                name: {
                    'description': policy.description,
                    'action': policy.action,
                    'conditions': policy.conditions,
                    'priority': policy.priority,
                    'enabled': policy.enabled
                }
                for name, policy in self.policies.items()
            },
            'default_action': self.default_action,
            'require_human_review': self.require_human_review,
            'log_level': self.log_level
        }

def load_default_config() -> ModerationConfig:
    """Load the default moderation configuration."""
    default_config = {
        'models': {
            'text-moderation': {
                'provider': 'huggingface',
                'model': 'facebook/bart-large-mnli',
                'threshold': 0.8,
                'enabled': True
            },
            'image-moderation': {
                'provider': 'huggingface',
                'model': 'google/vit-base-patch16-224',
                'threshold': 0.75,
                'enabled': True
            }
        },
        'policies': {
            'hate_speech': {
                'description': 'Block hate speech and offensive content',
                'action': 'block',
                'conditions': [
                    {'model': 'text-moderation', 'label': 'hate', 'threshold': 0.8}
                ],
                'priority': 100
            },
            'explicit_content': {
                'description': 'Flag explicit or adult content',
                'action': 'flag',
                'conditions': [
                    {'model': 'image-moderation', 'label': 'explicit', 'threshold': 0.7}
                ],
                'priority': 90
            }
        },
        'default_action': 'allow',
        'require_human_review': True,
        'log_level': 'INFO'
    }
    
    return ModerationConfig.from_dict(default_config)
