"""
Voice Command Recognition for Clippy AI.

This module provides voice command recognition capabilities for Clippy,
allowing users to control the assistant using natural language commands.
"""

import re
import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Callable, Optional, Any, Union, Type, TypeVar
from functools import wraps

from .command_feedback import FeedbackType, feedback

logger = logging.getLogger(__name__)

class CommandType(Enum):
    """Types of voice commands."""
    ACTION = auto()      # Commands that perform an action (e.g., "send message")
    QUERY = auto()       # Commands that ask for information (e.g., "what's the weather")
    NAVIGATION = auto()  # Commands that navigate the interface
    SYSTEM = auto()      # System-level commands (e.g., "turn off")
    MEDIA = auto()       # Media control commands (e.g., "play music")
    SMART_HOME = auto()  # Smart home device control
    PRODUCTIVITY = auto() # Productivity tools (calendar, reminders, etc.)

@dataclass
class CommandContext:
    """Context for command execution."""
    user_id: Optional[str] = None
    previous_command: Optional[str] = None
    last_modified: float = 0.0
    data: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Command:
    """Represents a voice command with its metadata and handler."""
    name: str
    patterns: List[str]
    handler: Callable[..., Any]
    command_type: CommandType = CommandType.ACTION
    description: str = ""
    requires_confirmation: bool = False
    confirmation_message: str = None
    success_message: str = None
    failure_message: str = None
    enabled: bool = True
    category: str = "general"
    requires_context: bool = False
    confirmation_phrases: List[str] = field(default_factory=lambda: [
        "yes", "sure", "ok", "confirm", "affirmative", "yep", "yeah"
    ])
    
    def get_confirmation_message(self) -> str:
        """Get the confirmation message for this command."""
        if self.confirmation_message:
            return self.confirmation_message
        return f"Are you sure you want to {self.name.replace('_', ' ')}?"
        
    def get_success_message(self) -> str:
        """Get the success message for this command."""
        if self.success_message:
            return self.success_message
        return f"Successfully completed {self.name.replace('_', ' ')}."
        
    def get_failure_message(self) -> str:
        """Get the failure message for this command."""
        if self.failure_message:
            return self.failure_message
        return f"I couldn't complete {self.name.replace('_', ' ')}. Please try again."
    
    def match(self, text: str) -> Optional[Dict[str, str]]:
        """Check if the command matches the given text.
        
        Args:
            text: The recognized speech text
            
        Returns:
            Dict with extracted parameters if matched, None otherwise
        """
        if not self.enabled:
            return None
            
        text = text.lower().strip()
        
        for pattern in self.patterns:
            # Convert our pattern to a regex pattern
            regex_pattern = self._pattern_to_regex(pattern)
            match = re.match(regex_pattern, text, re.IGNORECASE)
            
            if match:
                return match.groupdict()
                
        return None
    
    def _pattern_to_regex(self, pattern: str) -> str:
        """Convert a command pattern to a regex pattern with support for:
        - Optional words in [brackets]
        - Multiple alternatives (word1|word2)
        - Named parameters {param:type}
        - Wildcards (* for any word, ** for any text)
        """
        # Handle optional words in [brackets]
        pattern = re.sub(r'\[(.*?)\]', r'(?:\1)?', pattern)
        
        # Handle word alternatives (word1|word2)
        pattern = re.sub(r'\(([^)]+)\|([^)]+)\)', r'(\1|\2)', pattern)
        
        # Handle parameters with types
        def param_replacer(match):
            name, ptype = match.groups()
            if ptype == 'int':
                return f"(?P<{name}>\\d+)"
            elif ptype == 'float':
                return f"(?P<{name}>\\d+\\.\\d*|\\d*\\.\\d+|\\d+)"
            elif ptype == 'word':
                return f"(?P<{name}>\\w+)"
            else:  # default to any text
                return f"(?P<{name}>.+?)"
        
        pattern = re.sub(r'\{(\w+)(?::(\w+))?\}', param_replacer, pattern)
        
        # Replace wildcards
        pattern = pattern.replace('*', r'\w+')
        pattern = pattern.replace('**', r'.*?')
        
        # Add word boundaries and make case insensitive
        return f'^(?i){pattern}$'

class CommandRegistry:
    """Manages voice commands and their handlers with context support."""
    
    def __init__(self):
        self.commands: List[Command] = []
        self.contexts: Dict[str, CommandContext] = {}
        self._command_history: List[Dict[str, Any]] = []
        self._max_history = 20  # Keep last 20 commands in history
    
    def register(self, 
                patterns: Union[str, List[str]], 
                command_type: CommandType = CommandType.ACTION,
                description: str = "",
                requires_confirmation: bool = False,
                confirmation_message: str = None,
                success_message: str = None,
                failure_message: str = None,
                enabled: bool = True,
                category: str = "general",
                requires_context: bool = False):
        """Decorator to register a command handler with enhanced options.
        
        Args:
            patterns: Command pattern or list of patterns
            command_type: Type of command (ACTION, QUERY, etc.)
            description: Help text for the command
            requires_confirmation: Whether to ask for confirmation
            confirmation_message: Custom message to ask for confirmation
            success_message: Custom message for successful execution
            failure_message: Custom message for failed execution
            enabled: Whether the command is active
            category: Command category for organization
            requires_context: Whether the command needs context from previous commands
        """
        if isinstance(patterns, str):
            patterns = [patterns]
            
        def decorator(handler):
            command = Command(
                name=handler.__name__,
                patterns=patterns,
                handler=handler,
                command_type=command_type,
                description=description,
                requires_confirmation=requires_confirmation,
                confirmation_message=confirmation_message,
                success_message=success_message,
                failure_message=failure_message,
                enabled=enabled,
                category=category,
                requires_context=requires_context
            )
            self.commands.append(command)
            return handler
            
        return decorator
    
    def process_command(self, text: str, user_id: str = "default") -> Dict[str, Any]:
        """Process a voice command with context and return the result.
        
        Args:
            text: The recognized speech text
            user_id: ID of the user issuing the command
            
        Returns:
            Dict containing command result and metadata
        """
        text = text.lower().strip()
        context = self.get_context(user_id)
        
        # Check for confirmation first
        if context.previous_command and any(confirm in text for confirm in context.previous_command.confirmation_phrases):
            command = context.previous_command
            try:
                # Provide feedback that we're processing the confirmed command
                feedback.progress(f"Executing {command.name.replace('_', ' ')}...")
                
                # Execute the command
                result = command.handler(**command.params)
                
                # Log to history
                self.add_to_history(command.name, result, command.params)
                
                # Provide success feedback with command-specific message
                feedback.success(command.get_success_message())
                
                # Clear the previous command since it's now completed
                context.previous_command = None
                
                return {
                    'command': command.name,
                    'result': result,
                    'status': 'completed',
                    'params': command.params,
                    'message': command.get_success_message()
                }
            except Exception as e:
                error_msg = f"Error executing {command.name}: {str(e)}"
                logger.error(error_msg, exc_info=True)
                feedback.failure(command.get_failure_message())
                
                # Clear the previous command on failure
                context.previous_command = None
                
                return {
                    'command': command.name,
                    'error': error_msg,
                    'status': 'error',
                    'params': command.params,
                    'message': command.get_failure_message()
                }
        
        # Check if the command requires confirmation
        for command in self.commands:
            if not command.enabled:
                continue
                
            params = command.match(text)
            if params:
                try:
                    # If command requires confirmation, ask for it
                    if command.requires_confirmation:
                        # Store the command and params in context for confirmation
                        context.previous_command = command
                        context.previous_command.params = params
                        
                        # Ask for confirmation with command-specific message
                        feedback.speak(
                            command.get_confirmation_message(),
                            feedback_type=FeedbackType.CONFIRMATION
                        )
                        
                        return {
                            'command': command.name,
                            'status': 'needs_confirmation',
                            'params': params,
                            'message': 'Waiting for confirmation...'
                        }
                    
                    # For commands that don't require confirmation, execute immediately
                    feedback.progress(f"Processing {command.name.replace('_', ' ')}...")
                    result = command.handler(**params)
                    self.add_to_history(command.name, result, params)
                    
                    # Provide success feedback with command-specific message
                    feedback.success(command.get_success_message())
                    
                    return {
                        'command': command.name,
                        'result': result,
                        'status': 'completed',
                        'params': params,
                        'message': command.get_success_message()
                    }
                except Exception as e:
                    error_msg = f"Error executing {command.name}: {str(e)}"
                    logger.error(error_msg, exc_info=True)
                    
                    # Provide failure feedback with command-specific message
                    feedback.failure(command.get_failure_message())
                    
                    return {
                        'command': command.name,
                        'error': error_msg,
                        'status': 'error',
                        'params': params,
                        'message': command.get_failure_message()
                    }
        
        # No matching command found
        feedback.speak(
            "I'm not sure how to help with that. Can you rephrase or say 'help' for assistance?",
            feedback_type=FeedbackType.HELP
        )
        return {
            'status': 'no_match', 
            'input': text,
            'message': 'Command not recognized. Try rephrasing or say help.'
        }

# Global command registry instance
command_registry = CommandRegistry()

def register_command(*args, **kwargs):
    """Convenience decorator to register a command with the global registry."""
    return command_registry.register(*args, **kwargs)

# Example command handlers
@register_command(
    ["set volume to {level}", "volume {level}"],
    command_type=CommandType.SYSTEM,
    description="Set the system volume (0-100)",
    requires_confirmation=True,
    confirmation_message="I'll set the volume to {level} percent. Is that correct?",
    success_message="Volume set to {level} percent.",
    failure_message="I couldn't change the volume. Please try again."
)
def set_volume(level: str):
    """Set the system volume."""
    try:
        volume = int(level)
        if 0 <= volume <= 100:
            # In a real implementation, this would set the system volume
            logger.info(f"Setting volume to {volume}%")
            
            # Simulate volume change
            time.sleep(0.5)  # Simulate processing time
            
            return {
                "status": "success", 
                "volume": volume,
                "message": f"Volume set to {volume}%"
            }
        else:
            raise ValueError("Volume must be between 0 and 100")
            
    except ValueError as e:
        error_msg = f"Invalid volume level: {level}. {str(e)}"
        logger.error(error_msg)
        raise ValueError(error_msg)

@register_command(
    ["what time is it", "current time", "time please"],
    command_type=CommandType.QUERY,
    description="Get the current time",
    success_message="The current time is {time}"
)
def get_time() -> dict:
    """Get the current time."""
    from datetime import datetime
    current_time = datetime.now().strftime("%I:%M %p")
    return {
        "status": "success",
        "time": current_time,
        "message": f"The current time is {current_time}"
    }

@register_command(
    [
        "send message to {recipient} saying {message}",
        "text {recipient} {message}",
        "message {recipient} {message}"
    ],
    command_type=CommandType.ACTION,
    description="Send a message to a recipient",
    requires_confirmation=True,
    confirmation_message="I'll send \"{message}\" to {recipient}. Should I send it?",
    success_message="Message sent to {recipient}.",
    failure_message="I couldn't send the message to {recipient}. Please try again."
)
def send_message(recipient: str, message: str) -> dict:
    """Send a message to a recipient."""
    # In a real implementation, this would send the message
    logger.info(f"Sending message to {recipient}: {message}")
    
    # Simulate message sending
    time.sleep(1)  # Simulate network delay
    
    return {
        "status": "success", 
        "recipient": recipient, 
        "message": message,
        "timestamp": time.time()
    }

def process_voice_command(text: str, user_id: str = "default"):
    """Process a voice command from recognized speech.
    
    Args:
        text: The recognized speech text
        user_id: ID of the user issuing the command
        
    Returns:
        Dict with command result or None if no matching command
    """
    if not text or not text.strip():
        feedback.speak("I didn't catch that. Could you please repeat?")
        return None
        
    # Check for help request
    if any(help_word in text.lower() for help_word in ['help', 'what can you do', 'options']):
        feedback.help("I can help with various tasks. Here are some things you can ask me: "
                     "set volume, get time, send message, and more. Just tell me what you need!")
        return {'status': 'help', 'message': 'Displayed help information'}
        
    return command_registry.process_command(text.strip(), user_id=user_id)

if __name__ == "__main__":
    # Example usage
    import logging
    logging.basicConfig(level=logging.INFO)
    test_commands = [
        "set volume to 50",
        "what time is it",
        "send message to John saying hello there",
        "this is not a valid command"
    ]
    
    for cmd in test_commands:
        print(f"\nCommand: {cmd}")
        result = process_voice_command(cmd)
        if result:
            print(f"  Result: {result}")
        else:
            print("  No matching command found")
