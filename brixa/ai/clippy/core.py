"""
Clippy Core Module

This module contains the main Clippy class and core functionality for the AI assistant.
"""
import os
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any, Callable, Union, AsyncGenerator, TYPE_CHECKING
from dataclasses import dataclass, field
from datetime import datetime
import importlib
import importlib.util
import asyncio

# Import the response generator
from brixa.ai.response_generator import ResponseGenerator

# Import memory system
if TYPE_CHECKING:
    from brixa.ai.memory import MemoryManager, MemoryItem

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Message:
    """A message in the conversation."""
    role: str  # 'system', 'user', or 'assistant'
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to a dictionary."""
        return {
            'role': self.role,
            'content': self.content,
            'timestamp': self.timestamp.isoformat(),
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Message':
        """Create a message from a dictionary."""
        data = data.copy()
        if 'timestamp' in data and isinstance(data['timestamp'], str):
            data['timestamp'] = datetime.fromisoformat(data['timestamp'])
        return cls(**data)


class Skill:
    """Base class for Clippy skills."""
    
    def __init__(self, clippy: 'Clippy'):
        """Initialize the skill with a reference to the Clippy instance."""
        self.clippy = clippy
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the skill with the given context."""
        raise NotImplementedError("Subclasses must implement execute()")
    
    def get_help(self) -> str:
        """Return help text for this skill."""
        return "No help available for this skill."


class Clippy:
    """Main Clippy AI assistant class."""
    
    def __init__(
        self,
        name: str = "Clippy",
        model: str = "gpt-4",
        model_type: str = "openai",
        temperature: float = 0.7,
        max_tokens: int = 2000,
        skills: Optional[List[str]] = None,
        system_prompt: Optional[str] = None,
        memory_backend: Optional[Any] = None,
        **model_kwargs
    ):
        """Initialize Clippy.
        
        Args:
            name: Name of the assistant
            model: Name of the language model to use
            model_type: Type of model ('openai', 'local', etc.)
            temperature: Sampling temperature (0-2)
            max_tokens: Maximum number of tokens to generate
            skills: List of skill modules to load
            system_prompt: Custom system prompt to use
            **model_kwargs: Additional model-specific parameters
        """
        self.name = name
        self.model_name = model
        self.model_type = model_type
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.conversation: List[Message] = []
        self.skills: Dict[str, Skill] = {}
        self.model_kwargs = model_kwargs
        self.response_generator = None
        
        # Initialize memory
        from brixa.ai.memory import MemoryManager, InMemoryBackend
        self.memory_manager = MemoryManager(memory_backend or InMemoryBackend())
        
        # Initialize the response generator
        self._init_response_generator(system_prompt)
        
        # Load skills
        self._load_skills(skills or [])
        
        # Load core plugins
        self._load_core_plugins()
    
    def _init_response_generator(self, system_prompt: Optional[str] = None):
        """Initialize the response generator with the appropriate settings."""
        if system_prompt is None:
            system_prompt = f"""You are {self.name}, a helpful AI coding assistant. 
You can help with writing, debugging, and explaining code in multiple programming languages.
Be concise and to the point. Format your responses in Markdown.
Current date and time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

You have access to the following skills: {', '.join(self.skills.keys()) if self.skills else 'None'}
"""
            
        self.response_generator = ResponseGenerator(
            model_name=self.model_name,
            model_type=self.model_type,
            system_prompt=system_prompt,
            **self.model_kwargs
        )
        
    def _get_system_prompt(self) -> str:
        """Get the system prompt for the assistant."""
        return self.response_generator.system_prompt if self.response_generator else ""
        
    def update_system_prompt(self, prompt: str):
        """Update the system prompt used by the assistant."""
        if self.response_generator:
            self.response_generator.system_prompt = prompt
            
            # Update the system message in the conversation if it exists
            for i, msg in enumerate(self.conversation):
                if msg.role == 'system':
                    self.conversation[i] = Message('system', prompt)
                    break
            else:
                # If no system message exists, add one
                self.conversation.insert(0, Message('system', prompt))
    
    def _load_skills(self, skill_names: List[str]) -> None:
        """Load skills from the specified modules."""
        for skill_name in skill_names:
            try:
                # Try loading as a core plugin first
                try:
                    module = importlib.import_module(f"brixa.ai.clippy.plugins.{skill_name}_plugin")
                    plugin_class = getattr(module, f"{skill_name.capitalize()}Plugin")
                    skill_instance = plugin_class(self)
                    self.skills[skill_name] = skill_instance
                    logger.info(f"Loaded plugin: {skill_name}")
                    continue
                except (ImportError, AttributeError):
                    pass
                
                # Try loading as a regular skill
                module = importlib.import_module(f"brixa.ai.clippy.skills.{skill_name}")
                skill_class = getattr(module, f"{skill_name.capitalize()}Skill")
                skill_instance = skill_class(self)
                self.skills[skill_name] = skill_instance
                logger.info(f"Loaded skill: {skill_name}")
                
                # Initialize the skill if it has an async setup method
                if hasattr(skill_instance, 'on_startup'):
                    asyncio.create_task(skill_instance.on_startup())
                    
            except (ImportError, AttributeError) as e:
                logger.warning(f"Failed to load skill/plugin {skill_name}: {e}")
    
    def _load_core_plugins(self):
        """Load core plugins that should always be available."""
        core_plugins = ['memory']  # Add other core plugins here
        
        for plugin_name in core_plugins:
            if plugin_name not in self.skills:  # Don't override existing skills
                try:
                    module = importlib.import_module(f"brixa.ai.clippy.plugins.{plugin_name}_plugin")
                    plugin_class = getattr(module, f"{plugin_name.capitalize()}Plugin")
                    plugin_instance = plugin_class(self)
                    self.skills[plugin_name] = plugin_instance
                    logger.info(f"Loaded core plugin: {plugin_name}")
                    
                    # Initialize the plugin if it has an async setup method
                    if hasattr(plugin_instance, 'on_startup'):
                        asyncio.create_task(plugin_instance.on_startup())
                        
                except (ImportError, AttributeError) as e:
                    logger.warning(f"Failed to load core plugin {plugin_name}: {e}")
    
    def add_message(self, role: str, content: str, **metadata) -> None:
        """Add a message to the conversation."""
        self.conversation.append(Message(role, content, metadata=metadata))
    
    async def process_message(self, user_input: str) -> str:
        """Process a user message and generate a response."""
        # Add user message to conversation
        self.add_message("user", user_input)
        
        try:
            # Let plugins process the message first
            for skill in self.skills.values():
                if hasattr(skill, 'on_message'):
                    result = await skill.on_message(self.conversation[-1])
                    if result and isinstance(result, Message):
                        self.add_message(result.role, result.content, **result.metadata)
            
            # Check if this is a command
            if user_input.startswith('/'):
                return await self._handle_command(user_input[1:])
            
            # Get relevant context from memory
            context = await self._get_context()
            
            # Generate response using the response generator with context
            result = await self.response_generator.generate_response(
                messages=[
                    {"role": "system", "content": self._get_system_prompt(context)},
                    *[msg.to_dict() for msg in self.conversation[-10:]]  # Last 10 messages
                ],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            )
            
            response = result['response']
            
            # Add assistant response to conversation
            self.add_message("assistant", response)
            
            # Store relevant information in memory
            await self._update_memory(user_input, response)
            
            return response
            
        except Exception as e:
            error_msg = f"I'm sorry, I encountered an error while generating a response: {str(e)}"
            logger.exception("Error in process_message")
            self.add_message("system", f"Error: {str(e)}")
            return error_msg
            
    async def stream_message(self, user_input: str) -> AsyncGenerator[str, None]:
        """Process a user message and stream the response.
        
        Args:
            user_input: The user's message
            
        Yields:
            Response tokens as they are generated
        """
        # Add user message to conversation
        self.add_message("user", user_input)
        
        # Check if this is a command
        if user_input.startswith('/'):
            response = await self._handle_command(user_input[1:])
            yield response
            return
            
        try:
            # Prepare the response buffer
            full_response = ""
            
            # Stream the response
            async for token in self.response_generator.stream_response(
                messages=[msg.to_dict() for msg in self.conversation],
                max_tokens=self.max_tokens,
                temperature=self.temperature
            ):
                full_response += token
                yield token
                
            # Add the complete response to the conversation
            self.conversation.append(Message("assistant", full_response.strip()))
            
        except Exception as e:
            error_msg = f"I'm sorry, I encountered an error while generating a response: {str(e)}"
            logger.exception("Error in stream_message")
            self.add_message("assistant", error_msg)
            yield error_msg
    
    async def _handle_command(self, command: str) -> str:
        """Handle a command from the user."""
        parts = command.split(maxsplit=1)
        cmd = parts[0].lower()
        args = parts[1] if len(parts) > 1 else ""
        
        if cmd == "help":
            return self._get_help()
            
        elif cmd == "clear":
            self.conversation = [self.conversation[0]]  # Keep system message
            return "Conversation cleared."
            
        elif cmd == "skills":
            return self._list_skills()
            
        elif cmd == "memory":
            # Handle memory-specific commands
            mem_parts = args.split(maxsplit=1)
            mem_cmd = mem_parts[0] if mem_parts else ""
            mem_args = mem_parts[1] if len(mem_parts) > 1 else ""
            
            if mem_cmd == "list":
                return await self._list_memories(mem_args)
            elif mem_cmd == "forget":
                return await self._forget_memory(mem_args)
            else:
                return "Memory commands: /memory list [query], /memory forget [id]"
            
        elif cmd in self.skills:
            return await self._execute_skill(cmd, args)
            
        else:
            return f"Unknown command: {cmd}. Type '/help' for a list of commands."
    
    def _get_help(self) -> str:
        """Get help text for available commands and skills."""
        help_text = [
            f"# {self.name} Help",
            "",
            "## Available Commands:",
            "- `/help` - Show this help message",
            "- `/clear` - Clear the conversation history",
            "- `/skills` - List available skills",
            "- `/memory list [query]` - List memories matching query",
            "- `/memory forget [id]` - Forget a specific memory",
            f"- `/model` - Show current model: {self.model_name} (type: {self.model_type})",
            "- `/model <name>` - Change the language model",
            "",
            "## Model Information:",
            f"- **Model**: {self.model_name}",
            f"- **Type**: {self.model_type}",
            f"- **Temperature**: {self.temperature}",
            f"- **Max Tokens**: {self.max_tokens}",
            ""
        ]
        
        # Add skills section if any are available
        if self.skills:
            help_text.extend([
                "## Available Skills:",
                *[f"- `/{name}` - {skill.get_help().split('.')[0] if hasattr(skill, 'get_help') else 'No description'}" 
                  for name, skill in self.skills.items()],
                ""
            ])
            
        help_text.append("Type your message to chat with me!")
        return "\n".join(help_text)
    
    def _list_skills(self) -> str:
        """List all available skills."""
        if not self.skills:
            return "No skills are currently loaded."
            
        skills_list = ["## Available Skills:\n"]
        for name, skill in self.skills.items():
            help_text = skill.get_help()
            skills_list.append(f"- **{name}**: {help_text}")
        
        return "\n".join(skills_list)
    
    async def _get_context(self) -> Dict[str, Any]:
        """Get the current context for response generation."""
        context = {
            'user': {
                'name': "User",  # Would be replaced with actual user info
                'preferences': {}
            },
            'conversation': {
                'history': [msg.to_dict() for msg in self.conversation[-10:]],
                'summary': ""
            },
            'memory': {
                'relevant': []
            },
            'system': {
                'current_time': datetime.now().isoformat(),
                'model': self.model_name,
                'model_type': self.model_type
            }
        }
        
        # Get relevant memories if we have a memory manager
        if hasattr(self, 'memory_manager') and self.conversation:
            last_message = self.conversation[-1].content
            memories = await self.memory_manager.recall(last_message, limit=3)
            context['memory']['relevant'] = [m.content for m in memories]
        
        # Get context from plugins
        for skill in self.skills.values():
            if hasattr(skill, 'get_context'):
                try:
                    skill_context = await skill.get_context()
                    if skill_context:
                        # Merge the context, with later plugins potentially overriding earlier ones
                        context.update(skill_context)
                except Exception as e:
                    logger.warning(f"Error getting context from {skill.__class__.__name__}: {e}")
        
        return context
    
    async def _update_memory(self, user_input: str, assistant_response: str) -> None:
        """Update memory with information from the conversation."""
        if not hasattr(self, 'memory_manager'):
            return
            
        # Simple memory update - in a real implementation, this would be more sophisticated
        try:
            # Only remember important information
            if len(user_input.split()) > 5:  # Arbitrary threshold
                await self.memory_manager.remember(
                    content=user_input,
                    memory_type="conversation",
                    importance=0.3  # Lower importance for regular conversation
                )
                
            # Remember the assistant's responses that contain facts
            if any(keyword in assistant_response.lower() for keyword in 
                  ['is', 'are', 'was', 'were', 'has', 'have', 'had']):
                await self.memory_manager.remember(
                    content=assistant_response,
                    memory_type="fact",
                    importance=0.7
                )
                
        except Exception as e:
            logger.warning(f"Error updating memory: {e}")
    
    async def _list_memories(self, query: str) -> str:
        """List memories matching a query."""
        if not hasattr(self, 'memory_manager'):
            return "Memory system not available."
            
        try:
            memories = await self.memory_manager.recall(query or "recent", limit=5)
            if not memories:
                return "No relevant memories found."
                
            response = ["## Relevant Memories:"]
            for i, memory in enumerate(memories, 1):
                response.append(f"{i}. {memory.content} (relevance: {memory.importance:.2f})")
                
            return "\n".join(response)
            
        except Exception as e:
            return f"Error accessing memories: {e}"
    
    async def _forget_memory(self, memory_id: str) -> str:
        """Forget a specific memory by ID."""
        if not hasattr(self, 'memory_manager'):
            return "Memory system not available."
            
        try:
            if not memory_id:
                return "Please specify a memory ID to forget."
                
            success = await self.memory_manager.backend.delete(memory_id)
            if success:
                return f"Forgot memory: {memory_id}"
            else:
                return f"Could not find memory: {memory_id}"
                
        except Exception as e:
            return f"Error forgetting memory: {e}"
    
    async def _execute_skill(self, skill_name: str, args: str) -> str:
        """Execute a skill with the given arguments."""
        if skill_name not in self.skills:
            return f"Unknown skill: {skill_name}. Type '/skills' to see available skills."
            
        skill = self.skills[skill_name]
        try:
            # Prepare context with conversation history and memory
            context = {
                'command': '',
                'args': args,
                'conversation': [msg.to_dict() for msg in self.conversation],
                'skills': list(self.skills.keys()),
                'memory': await self._get_context()
            }
            
            # Check if this is a command with subcommands
            parts = args.split(maxsplit=1)
            if parts:
                context['command'] = parts[0]
                context['args'] = parts[1] if len(parts) > 1 else ""
            
            # Execute the skill
            if hasattr(skill, 'execute_async') and callable(skill.execute_async):
                result = await skill.execute_async(context)
            else:
                # Fall back to synchronous execution
                result = await asyncio.get_event_loop().run_in_executor(
                    None, 
                    lambda: skill.execute(context)
                )
            
            # Handle the result
            if isinstance(result, dict) and 'response' in result:
                response = result['response']
                
                # Store any new memories if the skill provided them
                if 'memories' in result and isinstance(result['memories'], list):
                    for memory in result['memories']:
                        if isinstance(memory, dict) and 'content' in memory:
                            await self.memory_manager.remember(
                                content=memory['content'],
                                memory_type=memory.get('type', 'fact'),
                                importance=memory.get('importance', 0.5),
                                **memory.get('metadata', {})
                            )
                
                return response
            
            return str(result) if result is not None else "Done."
            
        except Exception as e:
            error_msg = f"Error executing skill {skill_name}: {str(e)}"
            logger.exception(f"Error in _execute_skill: {error_msg}")
            self.add_message("system", f"Error: {error_msg}")
            return f"I couldn't execute the {skill_name} skill. {error_msg}"
    
    def _get_system_prompt(self, context: Optional[Dict[str, Any]] = None) -> str:
        """Get the system prompt with current context."""
        base_prompt = f"""You are {self.name}, a helpful AI coding assistant. 
You can help with writing, debugging, and explaining code in multiple programming languages.
Be concise and to the point. Format your responses in Markdown.
Current date and time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        if not context:
            return base_prompt
            
        # Add relevant context to the system prompt
        context_parts = []
        
        # Add user information
        if 'user' in context and context['user'].get('name'):
            context_parts.append(f"You are talking to {context['user']['name']}.")
        
        # Add memory context
        if 'memory' in context and context['memory'].get('relevant'):
            context_parts.append("\nRelevant context from previous conversations:")
            for i, memory in enumerate(context['memory']['relevant'], 1):
                context_parts.append(f"- {memory}")
        
        # Add any other relevant context
        if 'conversation' in context and context['conversation'].get('summary'):
            context_parts.append(f"\nConversation summary: {context['conversation']['summary']}")
        
        return base_prompt + "\n".join(context_parts)
    
    async def _generate_response(self) -> str:
        """Generate a response using the language model with context."""
        if not self.response_generator:
            await self._init_response_generator()
        
        # Get current context
        context = await self._get_context()
        
        # Prepare messages for the language model
        messages = [
            {"role": "system", "content": self._get_system_prompt(context)},
            *[{"role": msg.role, "content": msg.content, **msg.metadata}
              for msg in self.conversation[-10:]]  # Last 10 messages
        ]
        
        # Generate response
        result = await self.response_generator.generate(
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature
        )
        
        return result
    
    def save_conversation(self, filepath: str) -> bool:
        """Save the conversation to a file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump([msg.to_dict() for msg in self.conversation], f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save conversation: {e}")
            return False
    
    def load_conversation(self, filepath: str) -> bool:
        """Load a conversation from a file."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self.conversation = [Message.from_dict(msg) for msg in data]
            return True
        except Exception as e:
            logger.error(f"Failed to load conversation: {e}")
            return False
