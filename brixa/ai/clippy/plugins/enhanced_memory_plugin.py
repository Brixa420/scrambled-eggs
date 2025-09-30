"""
Enhanced Memory Plugin for Clippy

This plugin provides advanced memory capabilities to Clippy, including:
- Semantic memory search
- Memory summarization
- Memory management commands
- Automatic memory consolidation and cleanup
"""
from typing import Dict, List, Any, Optional, Union, AsyncGenerator
import json
import logging
from datetime import datetime, timedelta
import asyncio

from brixa.ai.memory.enhanced import (
    EnhancedMemoryManager,
    EnhancedMemoryItem,
    MemoryType
)
from ..core import Message, Skill, Clippy

logger = logging.getLogger(__name__)

class EnhancedMemoryPlugin(Skill):
    """Enhanced memory management plugin for Clippy."""
    
    def __init__(self, clippy: Optional[Clippy] = None):
        super().__init__(clippy)
        self.name = "enhanced_memory"
        self.description = "Advanced memory management with semantic search and summarization"
        self.manager = None
        self.consolidation_interval = 3600  # 1 hour in seconds
        self.cleanup_interval = 86400  # 24 hours in seconds
        self.maintenance_task = None
    
    async def on_startup(self):
        """Initialize the memory manager and start maintenance tasks."""
        if self.clippy and hasattr(self.clippy, 'memory_manager'):
            # Create an enhanced memory manager using the existing backend
            self.manager = EnhancedMemoryManager(self.clippy.memory_manager.backend)
            self.clippy.memory_manager = self.manager  # Replace the default manager
            
            # Start maintenance tasks
            self.maintenance_task = asyncio.create_task(self._maintenance_loop())
            logger.info("Enhanced memory plugin initialized with maintenance tasks")
    
    async def on_message(self, message: Message) -> Optional[Union[str, Dict[str, Any]]]:
        """Process messages to extract and store memories."""
        if not self.manager:
            return None
            
        # Don't process bot's own messages
        if message.role == "assistant":
            return None
            
        # Extract and store potential memories from user messages
        if message.role == "user":
            await self._extract_and_store_memories(message.content)
            
            # Check for memory-related commands
            if message.content.startswith("/memory"):
                return await self._handle_memory_command(message.content)
    
    async def _maintenance_loop(self):
        """Background task for memory maintenance."""
        while True:
            try:
                # Run consolidation and cleanup at different intervals
                await asyncio.sleep(60)  # Check every minute
                
                current_time = datetime.utcnow()
                
                # Run consolidation periodically
                if not hasattr(self, '_last_consolidation') or \
                   (current_time - self._last_consolidation).total_seconds() > self.consolidation_interval:
                    await self.manager.consolidate_memories()
                    self._last_consolidation = current_time
                
                # Run cleanup less frequently
                if not hasattr(self, '_last_cleanup') or \
                   (current_time - self._last_cleanup).total_seconds() > self.cleanup_interval:
                    await self.manager.cleanup_memories()
                    self._last_cleanup = current_time
                    
            except Exception as e:
                logger.error(f"Memory maintenance error: {e}")
    
    async def _extract_and_store_memories(self, text: str) -> List[str]:
        """Extract and store potential memories from text."""
        if not text.strip():
            return []
            
        memories = []
        
        # Simple pattern matching for now - could be enhanced with NLP
        memory_triggers = [
            ("my name is", "fact", ["user_info", "name"]),
            ("i like", "preference", []),
            ("i prefer", "preference", []),
            ("i need", "need", []),
            ("remember that", "fact", []),
        ]
        
        for trigger, mem_type, tags in memory_triggers:
            if trigger in text.lower():
                # Extract the relevant part after the trigger
                content = text[text.lower().find(trigger) + len(trigger):].strip()
                if content:
                    memory_id = await self.manager.remember(
                        content=content,
                        memory_type=mem_type,
                        tags=tags,
                        importance=0.7  # Medium importance for auto-extracted memories
                    )
                    memories.append(memory_id)
        
        return memories
    
    async def _handle_memory_command(self, command: str) -> str:
        """Handle memory-related commands."""
        parts = command.split(maxsplit=2)
        if len(parts) < 2:
            return self._get_help()
            
        cmd = parts[1].lower()
        args = parts[2] if len(parts) > 2 else ""
        
        if cmd == "remember":
            return await self._handle_remember(args)
        elif cmd == "recall":
            return await self._handle_recall(args)
        elif cmd == "forget":
            return await self._handle_forget(args)
        elif cmd == "list":
            return await self._handle_list(args)
        elif cmd == "summary":
            return await self._handle_summary(args)
        else:
            return f"Unknown memory command: {cmd}. Try '/memory help' for available commands."
    
    async def _handle_remember(self, content: str) -> str:
        """Handle the remember command."""
        if not content:
            return "Please provide something to remember. Usage: /memory remember [content]"
            
        memory_id = await self.manager.remember(
            content=content,
            memory_type="fact",
            importance=0.8
        )
        return f"I'll remember that: {content}"
    
    async def _handle_recall(self, query: str) -> str:
        """Handle the recall command."""
        if not query:
            return "Please provide a search query. Usage: /memory recall [query]"
            
        memories = await self.manager.recall(query, limit=3)
        if not memories:
            return f"I couldn't find any memories matching '{query}'."
            
        results = [f"- {mem.content} (relevance: {mem.importance:.2f})" for mem in memories]
        return "I found these memories:\n" + "\n".join(results)
    
    async def _handle_forget(self, memory_id: str) -> str:
        """Handle the forget command."""
        if not memory_id:
            return "Please provide a memory ID. Use '/memory list' to see all memories."
            
        # This is a simplified version - in a real implementation, you'd need to
        # map user-friendly IDs to actual memory IDs
        success = await self.manager.delete(memory_id)
        if success:
            return f"Memory {memory_id} has been forgotten."
        else:
            return f"Could not find memory with ID {memory_id}."
    
    async def _handle_list(self, query: str = "") -> str:
        """List all memories, optionally filtered by query."""
        memories = await self.manager.search(query, limit=10)
        if not memories:
            return "No memories found."
            
        results = []
        for i, mem in enumerate(memories, 1):
            results.append(
                f"{i}. {mem.content[:50]}... "
                f"(type: {mem.memory_type}, importance: {mem.importance:.2f})"
            )
            
        return "Memories:\n" + "\n".join(results)
    
    async def _handle_summary(self, query: str = "") -> str:
        """Generate a summary of relevant memories."""
        summary = await self.manager.generate_summary(query)
        return f"Memory Summary:\n{summary}"
    
    def _get_help(self) -> str:
        """Get help text for memory commands."""
        return """Memory Management Commands:
/memory remember [content] - Store a new memory
/memory recall [query] - Search for relevant memories
/memory forget [id] - Remove a specific memory
/memory list [query] - List all memories (optionally filtered)
/memory summary [query] - Get a summary of relevant memories
/memory help - Show this help message
"""
    
    async def get_context(self) -> Dict[str, Any]:
        """Get relevant context from memories for the current conversation."""
        if not self.clippy or not hasattr(self.clippy, 'conversation_history'):
            return {}
            
        # Get the last few messages for context
        context_messages = self.clippy.conversation_history[-3:]
        context_text = "\n".join(
            f"{msg['role']}: {msg['content']}" 
            for msg in context_messages
        )
        
        # Get relevant memories
        memories = await self.manager.recall(context_text, limit=5)
        
        # Format memories for context
        memory_context = [
            f"{mem.memory_type.upper()}: {mem.content}" 
            for mem in memories
        ]
        
        return {
            "relevant_memories": memory_context,
            "memory_count": len(memories)
        }
    
    async def execute(self, command: str, **kwargs) -> Any:
        """Execute a memory-related command."""
        if command == "get_context":
            return await self.get_context()
        elif command == "remember":
            return await self._handle_remember(kwargs.get("content", ""))
        elif command == "recall":
            return await self._handle_recall(kwargs.get("query", ""))
        elif command == "summary":
            return await self._handle_summary(kwargs.get("query", ""))
        else:
            return f"Unknown command: {command}"

# Example usage with Clippy
async def example_usage():
    from ..core import Clippy
    
    # Create a Clippy instance with the enhanced memory plugin
    clippy = Clippy()
    memory_plugin = EnhancedMemoryPlugin(clippy)
    clippy.register_plugin(memory_plugin)
    
    # Start Clippy (this would initialize the plugin)
    await clippy.initialize()
    
    # Test memory commands
    print(await clippy.process_message("/memory remember My favorite color is blue"))
    print(await clippy.process_message("/memory recall color"))
    print(await clippy.process_message("/memory summary"))

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
