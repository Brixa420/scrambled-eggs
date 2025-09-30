"""
Enhanced Memory System for Clippy AI

This module extends the basic memory system with advanced features:
- Semantic search using embeddings
- Memory summarization
- Relevance scoring
- Memory consolidation
- Automatic cleanup
- Memory importance decay
"""
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
import numpy as np
from numpy.linalg import norm
import logging
import asyncio
from dataclasses import dataclass, field
from enum import Enum
import json
import uuid

from . import MemoryItem, BaseMemoryBackend, InMemoryBackend

logger = logging.getLogger(__name__)

class MemoryType(str, Enum):
    FACT = "fact"
    EVENT = "event"
    PREFERENCE = "preference"
    SKILL = "skill"
    SUMMARY = "summary"

@dataclass
class MemoryEnhancements:
    """Additional fields for enhanced memory capabilities."""
    embedding: Optional[np.ndarray] = None
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    access_count: int = 1
    decay_rate: float = 0.95  # Per day decay rate

class EnhancedMemoryItem(MemoryItem):
    """Extended MemoryItem with additional capabilities."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enhancements = MemoryEnhancements()
    
    def update_importance(self, boost: float = 1.0):
        """Update memory importance based on access patterns and time."""
        age_days = (datetime.utcnow() - self.created_at).days
        recency_factor = max(0.1, 1.0 / (age_days + 1))
        
        # Boost importance based on access frequency and recency
        self.importance = min(1.0, (
            0.3 * self.importance +
            0.4 * recency_factor +
            0.3 * (self.enhancements.access_count / 10) * boost
        ))
        
        # Update last accessed time and increment counter
        self.enhancements.last_accessed = datetime.utcnow()
        self.enhancements.access_count += 1
        
        return self.importance

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary including enhancements."""
        data = super().to_dict()
        data.update({
            'embedding': self.enhancements.embedding.tolist() if self.enhancements.embedding is not None else None,
            'last_accessed': self.enhancements.last_accessed.isoformat(),
            'access_count': self.enhancements.access_count,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'EnhancedMemoryItem':
        """Create from dictionary including enhancements."""
        embedding = data.pop('embedding', None)
        last_accessed = data.pop('last_accessed', None)
        access_count = data.pop('access_count', 1)
        
        instance = super().from_dict(data)
        if not hasattr(instance, 'enhancements'):
            instance.enhancements = MemoryEnhancements()
            
        if embedding is not None:
            instance.enhancements.embedding = np.array(embedding)
        if last_accessed:
            if isinstance(last_accessed, str):
                last_accessed = datetime.fromisoformat(last_accessed)
            instance.enhancements.last_accessed = last_accessed
        instance.enhancements.access_count = access_count
        
        return instance

class EnhancedMemoryBackend(BaseMemoryBackend):
    """Enhanced memory backend with semantic search and memory management."""
    
    def __init__(self, base_backend: BaseMemoryBackend = None, embedding_model=None):
        self.backend = base_backend or InMemoryBackend()
        self.embedding_model = embedding_model
        self.embeddings_cache: Dict[str, np.ndarray] = {}
        self.maintenance_task = None
        self._setup_maintenance()
    
    def _setup_maintenance(self):
        """Setup periodic maintenance tasks."""
        async def maintenance_loop():
            while True:
                try:
                    await self._perform_maintenance()
                except Exception as e:
                    logger.error(f"Memory maintenance error: {e}")
                await asyncio.sleep(3600)  # Run hourly
        
        self.maintenance_task = asyncio.create_task(maintenance_loop())
    
    async def _perform_maintenance(self):
        """Perform memory maintenance tasks."""
        # Memory consolidation
        await self.consolidate_memories()
        
        # Clean up old/unimportant memories
        await self.cleanup_memories()
        
        # Update memory importance based on access patterns
        await self.update_memory_importance()
    
    async def store(self, memory: MemoryItem) -> str:
        """Store a memory with enhancements."""
        if not isinstance(memory, EnhancedMemoryItem):
            memory = EnhancedMemoryItem(**memory.__dict__)
        
        # Generate embedding if we have a model
        if self.embedding_model and not memory.enhancements.embedding:
            memory.enhancements.embedding = await self._get_embedding(memory.content)
        
        # Update importance
        memory.update_importance()
        
        # Store in backend
        memory_id = await self.backend.store(memory)
        
        # Cache the embedding
        if memory.enhancements.embedding is not None:
            self.embeddings_cache[memory_id] = memory.enhancements.embedding
            
        return memory_id
    
    async def retrieve(self, query: str, limit: int = 5, threshold: float = 0.7) -> List[MemoryItem]:
        """Retrieve relevant memories using semantic search."""
        # Get query embedding
        query_embedding = await self._get_embedding(query)
        
        # Get all memories with embeddings
        memories = await self.backend.search("", limit=1000)  # Get all memories
        
        # Score and sort by relevance
        scored_memories = []
        for mem in memories:
            if not hasattr(mem, 'enhancements') or mem.enhancements.embedding is None:
                continue
                
            # Calculate semantic similarity
            similarity = self._cosine_similarity(
                query_embedding, 
                mem.enhancements.embedding
            )
            
            # Apply importance and recency factors
            importance_factor = mem.importance
            recency = (datetime.utcnow() - mem.enhancements.last_accessed).days
            recency_factor = max(0.1, 1.0 / (recency + 1))
            
            # Combined score (weighted average)
            score = (
                0.6 * similarity +  # Semantic relevance
                0.3 * importance_factor +  # Importance
                0.1 * recency_factor  # Recency
            )
            
            if score >= threshold:
                scored_memories.append((score, mem))
        
        # Sort by score and return top results
        scored_memories.sort(key=lambda x: x[0], reverse=True)
        return [mem for score, mem in scored_memories[:limit]]
    
    async def search(self, query: str, limit: int = 5, **filters) -> List[MemoryItem]:
        """Enhanced search with filters and semantic search."""
        if query:
            # Use semantic search if there's a query
            return await self.retrieve(query, limit)
        else:
            # Fall back to filtered search
            return await self.backend.search(query, limit, **filters)
    
    async def update(self, memory_id: str, memory: MemoryItem) -> bool:
        """Update a memory with enhancements."""
        if not isinstance(memory, EnhancedMemoryItem):
            memory = EnhancedMemoryItem(**memory.__dict__)
        
        # Update embedding if content changed
        if self.embedding_model and memory_id in self.embeddings_cache:
            old_memory = await self.backend.retrieve(memory_id)
            if old_memory and old_memory.content != memory.content:
                memory.enhancements.embedding = await self._get_embedding(memory.content)
                self.embeddings_cache[memory_id] = memory.enhancements.embedding
        
        # Update importance
        memory.update_importance()
        
        return await self.backend.update(memory_id, memory)
    
    async def delete(self, memory_id: str) -> bool:
        """Delete a memory and its cached embedding."""
        if memory_id in self.embeddings_cache:
            del self.embeddings_cache[memory_id]
        return await self.backend.delete(memory_id)
    
    async def consolidate_memories(self):
        """Consolidate similar memories to reduce redundancy."""
        memories = await self.backend.search("", limit=1000)
        
        # Group memories by type and tags
        memory_groups: Dict[Tuple, List[MemoryItem]] = {}
        
        for mem in memories:
            if not hasattr(mem, 'enhancements') or mem.enhancements.embedding is None:
                continue
                
            # Create a key based on memory type and tags
            group_key = (mem.memory_type, tuple(sorted(mem.tags)))
            memory_groups.setdefault(group_key, []).append(mem)
        
        # Process each group
        for group_key, group_memories in memory_groups.items():
            if len(group_memories) < 2:
                continue
                
            # Sort by importance and recency
            group_memories.sort(
                key=lambda m: (
                    m.importance,
                    (datetime.utcnow() - m.enhancements.last_accessed).total_seconds()
                ),
                reverse=True
            )
            
            # Keep the most important memory and check others for consolidation
            primary_memory = group_memories[0]
            
            for memory in group_memories[1:]:
                similarity = self._cosine_similarity(
                    primary_memory.enhancements.embedding,
                    memory.enhancements.embedding
                )
                
                # If memories are very similar, merge them
                if similarity > 0.9:
                    # Merge content (simple concatenation, could be more sophisticated)
                    primary_memory.content = f"{primary_memory.content}\n{memory.content}"
                    
                    # Update importance based on both memories
                    primary_memory.importance = max(
                        primary_memory.importance,
                        memory.importance
                    )
                    
                    # Update last accessed to most recent
                    if memory.enhancements.last_accessed > primary_memory.enhancements.last_accessed:
                        primary_memory.enhancements.last_accessed = memory.enhancements.last_accessed
                    
                    # Delete the redundant memory
                    await self.backend.delete(memory.id)
    
    async def cleanup_memories(self, max_memories: int = 1000, min_importance: float = 0.1):
        """Clean up old or unimportant memories."""
        memories = await self.backend.search("", limit=max_memories * 2)
        
        if len(memories) <= max_memories:
            return
        
        # Sort by importance and recency
        memories.sort(
            key=lambda m: (
                m.importance,
                (datetime.utcnow() - m.enhancements.last_accessed).total_seconds()
            )
        )
        
        # Delete least important memories
        for memory in memories[:len(memories) - max_memories]:
            if memory.importance < min_importance:
                await self.backend.delete(memory.id)
    
    async def update_memory_importance(self):
        """Update memory importance based on access patterns and time."""
        memories = await self.backend.search("", limit=1000)
        
        for memory in memories:
            if not hasattr(memory, 'enhancements'):
                continue
                
            # Calculate time-based decay
            days_since_access = (datetime.utcnow() - memory.enhancements.last_accessed).days
            decay_factor = memory.enhancements.decay_rate ** days_since_access
            
            # Apply decay to importance
            memory.importance *= decay_factor
            
            # Ensure importance stays within bounds
            memory.importance = max(0.01, min(1.0, memory.importance))
            
            # Save updated memory
            await self.backend.update(memory.id, memory)
    
    async def summarize_memories(self, memories: List[MemoryItem]) -> str:
        """Generate a summary of a set of memories."""
        if not memories:
            return "No relevant memories found."
        
        # Group memories by type
        memory_groups: Dict[str, List[str]] = {}
        
        for mem in memories:
            memory_groups.setdefault(mem.memory_type, []).append(mem.content)
        
        # Create a summary for each group
        summary_parts = []
        
        for mem_type, contents in memory_groups.items():
            if len(contents) == 1:
                summary_parts.append(f"{mem_type.capitalize()}: {contents[0]}")
            else:
                summary = ", ".join(f"- {content}" for content in contents[:3])
                if len(contents) > 3:
                    summary += f" (and {len(contents) - 3} more)"
                summary_parts.append(f"{mem_type.capitalize()}s:\n{summary}")
        
        return "\n\n".join(summary_parts)
    
    async def _get_embedding(self, text: str) -> np.ndarray:
        """Get embedding for text using the configured model."""
        if self.embedding_model:
            try:
                # This is a placeholder - replace with actual embedding model call
                # Example: return await self.embedding_model.get_embedding(text)
                # For now, return a random embedding for demonstration
                return np.random.rand(768).astype(np.float32)
            except Exception as e:
                logger.error(f"Error getting embedding: {e}")
        
        # Fallback to a simple bag-of-words like representation
        words = text.lower().split()
        unique_words = list(set(words))
        embedding = np.zeros(len(unique_words) + 1)  # +1 for OOV
        
        for word in words:
            try:
                idx = unique_words.index(word)
                embedding[idx] += 1
            except ValueError:
                embedding[-1] += 1  # OOV bucket
        
        # Normalize
        norm = np.linalg.norm(embedding)
        if norm > 0:
            embedding = embedding / norm
            
        return embedding
    
    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        if a is None or b is None:
            return 0.0
            
        a_norm = norm(a)
        b_norm = norm(b)
        
        if a_norm == 0 or b_norm == 0:
            return 0.0
            
        return np.dot(a, b) / (a_norm * b_norm)

class EnhancedMemoryManager(MemoryManager):
    """Enhanced memory manager with advanced features."""
    
    def __init__(self, backend: Optional[BaseMemoryBackend] = None, embedding_model=None):
        """Initialize with an enhanced backend."""
        enhanced_backend = EnhancedMemoryBackend(backend, embedding_model)
        super().__init__(enhanced_backend)
    
    async def get_context_memories(self, query: str, limit: int = 5) -> List[MemoryItem]:
        """Get relevant memories for a given query context."""
        return await self.recall(query, limit=limit)
    
    async def generate_summary(self, query: str = "", limit: int = 10) -> str:
        """Generate a summary of relevant memories."""
        memories = await self.recall(query, limit=limit)
        return await self.backend.summarize_memories(memories)
    
    async def consolidate_memories(self):
        """Run memory consolidation."""
        if hasattr(self.backend, 'consolidate_memories'):
            await self.backend.consolidate_memories()
    
    async def cleanup_memories(self, max_memories: int = 1000, min_importance: float = 0.1):
        """Clean up old or unimportant memories."""
        if hasattr(self.backend, 'cleanup_memories'):
            await self.backend.cleanup_memories(max_memories, min_importance)
    
    async def update_memory_importance(self):
        """Update memory importance based on access patterns."""
        if hasattr(self.backend, 'update_memory_importance'):
            await self.backend.update_memory_importance()
            
    async def generate_suggestions(self, conversation_history: List[Dict[str, str]], limit: int = 3) -> List[Dict[str, Any]]:
        """
        Generate context-aware suggestions based on conversation history.
        
        Args:
            conversation_history: List of message dicts with 'role' and 'content' keys
            limit: Maximum number of suggestions to return
            
        Returns:
            List of suggestion dicts with 'text' and 'action' keys
        """
        if not conversation_history:
            # Default suggestions for new conversations
            return [
                {"text": "What can you do?", "action": "what_can_you_do"},
                {"text": "Tell me about yourself", "action": "self_intro"},
                {"text": "Help me with a task", "action": "task_assistance"}
            ]
            
        # Get the last few messages for context
        context = " ".join([msg["content"] for msg in conversation_history[-3:]])
        
        # Get relevant memories
        memories = await self.recall(context, limit=5)
        
        # Generate suggestions based on conversation context and memories
        suggestions = []
        
        # Add follow-up questions based on the last message
        last_message = conversation_history[-1]["content"].lower()
        
        if any(word in last_message for word in ["how", "what", "why", "when", "where", "who"]):
            suggestions.append({"text": "Can you explain more about that?", "action": "elaborate"})
            
        if "help" in last_message or "assist" in last_message:
            suggestions.append({"text": "I need help with something else", "action": "other_help"})
            
        # Add memory-based suggestions
        for memory in memories[:2]:
            if memory.memory_type == "preference":
                suggestions.append({
                    "text": f"Change {memory.content.split()[0]} settings",
                    "action": f"change_{memory.content.split()[0]}_settings"
                })
                
        # Add general suggestions if we don't have enough
        default_suggestions = [
            {"text": "Show me an example", "action": "show_example"},
            {"text": "What else can you do?", "action": "more_options"},
            {"text": "Never mind", "action": "dismiss"}
        ]
        
        # Combine and deduplicate suggestions
        seen = set()
        unique_suggestions = []
        for s in suggestions + default_suggestions:
            if s["text"] not in seen:
                seen.add(s["text"])
                unique_suggestions.append(s)
                if len(unique_suggestions) >= limit:
                    break
                    
        return unique_suggestions

# Example usage
async def example_usage():
    # Create an enhanced memory manager
    manager = EnhancedMemoryManager()
    
    # Store some memories
    await manager.remember("User prefers dark theme", "preference", tags=["ui", "theme"])
    await manager.remember("User's name is John", "fact", importance=0.9)
    
    # Retrieve relevant memories
    memories = await manager.recall("What theme does the user prefer?")
    print("Relevant memories:", [m.content for m in memories])
    
    # Generate a summary
    summary = await manager.generate_summary()
    print("Memory summary:", summary)
    
    # Run maintenance
    await manager.consolidate_memories()
    await manager.cleanup_memories()

if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
