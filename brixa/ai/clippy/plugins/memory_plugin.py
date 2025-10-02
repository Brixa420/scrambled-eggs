"""
Memory Plugin for Clippy

This plugin provides memory capabilities to the Clippy AI assistant,
allowing it to remember user preferences, conversation context, and other information.
"""
from typing import Dict, List, Any, Optional, Union
import json
import logging
from datetime import datetime

from brixa.ai.memory import MemoryManager, MemoryItem, InMemoryBackend, FileBackend
from ..core import Message, Skill

logger = logging.getLogger(__name__)

class MemoryPlugin(Skill):
    """Memory management plugin for Clippy."""
    
    def __init__(self, clippy):
        super().__init__(clippy)
        self.manager = MemoryManager()
        self.conversation_summary = ""
        self.user_preferences = {}
        
        # Try to load user preferences
        self._load_preferences()
    
    def _load_preferences(self):
        """Load user preferences from storage."""
        # In a real implementation, this would load from a file or database
        self.user_preferences = {
            'preferred_name': None,
            'language': 'en',
            'timezone': 'UTC',
            'preferred_topics': [],
            'do_not_track': False
        }
    
    async def on_startup(self):
        """Initialize the memory system when the plugin loads."""
        # Initialize with file-based backend for persistence
        self.manager = MemoryManager(FileBackend("clippy_memories.json"))
        logger.info("Memory plugin initialized")
    
    async def on_message(self, message: Message) -> Optional[Message]:
        """Process incoming messages to extract and store memories."""
        if message.role == 'user':
            # Extract and store important information from user messages
            await self._extract_memories(message.content)
            
            # Update conversation summary periodically
            if len(self.clippy.conversation) % 5 == 0:
                self.conversation_summary = await self.manager.summarize_conversation(
                    [msg.to_dict() for msg in self.clippy.conversation]
                )
        
        return None
    
    async def _extract_memories(self, text: str):
        """Extract and store important information from text."""
        # This is a simplified version - in reality, you'd use NLP to extract entities
        # and relationships
        
        # Example: Remember user's name if mentioned
        if 'my name is ' in text.lower():
            name = text.split('my name is ')[1].split()[0]
            await self.remember(f"User's name is {name}", "user_info", importance=0.9)
            if not self.user_preferences.get('preferred_name'):
                self.user_preferences['preferred_name'] = name
        
        # Example: Remember user preferences
        if 'i prefer ' in text.lower():
            preference = text.lower().split('i prefer ')[1].split('.')[0]
            await self.remember(f"User preference: {preference}", "preference")
    
    async def remember(self, content: str, memory_type: str = "fact", **kwargs) -> str:
        """Store a new memory."""
        return await self.manager.remember(content, memory_type, **kwargs)
    
    async def recall(self, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve relevant memories."""
        memories = await self.manager.recall(query, limit)
        return [{
            'content': m.content,
            'type': m.memory_type,
            'timestamp': m.last_accessed.isoformat(),
            'importance': m.importance
        } for m in memories]
    
    async def get_context(self) -> Dict[str, Any]:
        """Get relevant context for the current conversation."""
        # Get recent conversation history
        recent_messages = [
            f"{msg.role}: {msg.content}" 
            for msg in self.clippy.conversation[-5:]
        ]
        
        # Get relevant memories
        last_message = self.clippy.conversation[-1].content if self.clippy.conversation else ""
        relevant_memories = await self.recall(last_message, limit=3)
        
        return {
            'conversation_summary': self.conversation_summary,
            'recent_messages': recent_messages,
            'relevant_memories': relevant_memories,
            'user_preferences': self.user_preferences,
            'current_time': datetime.now().isoformat()
        }
    
    # Command handlers
    async def handle_remember(self, args: str) -> str:
        """Handle the /remember command."""
        if not args:
            return "Please specify what you'd like me to remember."
            
        memory_id = await self.remember(args, "user_reminder")
        return f"I'll remember that: {args}"
    
    async def handle_recall(self, args: str) -> str:
        """Handle the /recall command."""
        query = args or "recent"
        memories = await self.recall(query, limit=3)
        
        if not memories:
            return "I couldn't find any relevant memories."
            
        response = ["Here's what I remember:"]
        for i, memory in enumerate(memories, 1):
            response.append(f"{i}. {memory['content']}")
            
        return "\n".join(response)
    
    async def handle_preferences(self, args: str) -> str:
        """Handle the /preferences command."""
        if not args:
            # Show current preferences
            prefs = "\n".join(f"- {k}: {v}" for k, v in self.user_preferences.items())
            return f"Current preferences:\n{prefs}"
        
        # In a real implementation, parse and update preferences
        return "I'll update your preferences."
    
    async def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the memory plugin."""
        command = context.get('command', '')
        args = context.get('args', '')
        
        if command == 'remember':
            return {'response': await self.handle_remember(args)}
        elif command == 'recall':
            return {'response': await self.handle_recall(args)}
        elif command == 'preferences':
            return {'response': await self.handle_preferences(args)}
        else:
            return {'response': "Unknown memory command. Try /remember, /recall, or /preferences"}
    
    def get_help(self) -> str:
        """Return help text for this plugin."""
        return """Memory Plugin Commands:
- /remember <something> - Ask me to remember something
- /recall <query> - Recall information from memory
- /preferences - View or update your preferences"""
