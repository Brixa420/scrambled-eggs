"""
Base Skill Module

This module defines the base Skill class that all Clippy skills should inherit from.
"""
from typing import Dict, Any, Optional, List
import logging
from dataclasses import dataclass, field

@dataclass
class Skill:
    """Base class for all Clippy skills.
    
    Attributes:
        name: The name of the skill (defaults to class name)
        description: A brief description of what the skill does
        version: The version of the skill
        enabled: Whether the skill is currently enabled
        config: Configuration options for the skill
    """
    name: str = ""
    description: str = ""
    version: str = "0.1.0"
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize the skill with a logger and set default name if not provided."""
        if not self.name:
            self.name = self.__class__.__name__.replace("Skill", "").lower()
        self.logger = logging.getLogger(f"clippy.skills.{self.name}")
    
    async def initialize(self, **kwargs) -> None:
        """Initialize the skill with any required resources."""
        self.logger.info(f"Initializing {self.name} skill (v{self.version})")
    
    async def cleanup(self) -> None:
        """Clean up any resources used by the skill."""
        self.logger.info(f"Cleaning up {self.name} skill")
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the skill with the given context.
        
        Args:
            context: A dictionary containing the execution context
            
        Returns:
            A dictionary containing the result of the skill execution
        """
        raise NotImplementedError("Subclasses must implement execute()")
