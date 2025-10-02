"""
Memory System for Clippy AI

This module provides memory management capabilities for the Clippy AI assistant,
including short-term, long-term, and working memory components.
"""
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
from pathlib import Path
import uuid

logger = logging.getLogger(__name__)

@dataclass
class MemoryItem:
    """A single memory item with metadata."""
    content: str
    memory_type: str = "fact"
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_accessed: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    importance: float = 0.5  # 0.0 to 1.0 scale
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert memory item to a dictionary."""
        return {
            'content': self.content,
            'memory_type': self.memory_type,
            'created_at': self.created_at.isoformat(),
            'last_accessed': self.last_accessed.isoformat(),
            'tags': self.tags,
            'metadata': self.metadata,
            'importance': self.importance
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'MemoryItem':
        """Create a memory item from a dictionary."""
        data = data.copy()
        for time_field in ['created_at', 'last_accessed']:
            if time_field in data and isinstance(data[time_field], str):
                data[time_field] = datetime.fromisoformat(data[time_field])
        return cls(**data)


class BaseMemoryBackend:
    """Base class for memory storage backends."""
    
    async def store(self, memory: MemoryItem) -> str:
        """Store a memory item and return its ID."""
        raise NotImplementedError
    
    async def retrieve(self, query: str, limit: int = 5, threshold: float = 0.7) -> List[MemoryItem]:
        """Retrieve relevant memories based on a query."""
        raise NotImplementedError
    
    async def update(self, memory_id: str, memory: MemoryItem) -> bool:
        """Update an existing memory."""
        raise NotImplementedError
    
    async def delete(self, memory_id: str) -> bool:
        """Delete a memory by ID."""
        raise NotImplementedError
    
    async def search(self, query: str, limit: int = 5, **filters) -> List[MemoryItem]:
        """Search memories with filters."""
        raise NotImplementedError


class InMemoryBackend(BaseMemoryBackend):
    """In-memory storage backend for development and testing."""
    
    def __init__(self):
        self.memories: Dict[str, MemoryItem] = {}
    
    async def store(self, memory: MemoryItem) -> str:
        """Store a memory item in memory."""
        memory_id = str(uuid.uuid4())
        self.memories[memory_id] = memory
        return memory_id
    
    async def retrieve(self, query: str, limit: int = 5, threshold: float = 0.7) -> List[MemoryItem]:
        """Simple in-memory retrieval (basic implementation)."""
        # In a real implementation, this would use embeddings for semantic search
        return list(self.memories.values())[:limit]
    
    async def update(self, memory_id: str, memory: MemoryItem) -> bool:
        """Update a memory in the store."""
        if memory_id in self.memories:
            self.memories[memory_id] = memory
            return True
        return False
    
    async def delete(self, memory_id: str) -> bool:
        """Delete a memory from the store."""
        if memory_id in self.memories:
            del self.memories[memory_id]
            return True
        return False
    
    async def search(self, query: str, limit: int = 5, **filters) -> List[MemoryItem]:
        """Search memories with filters."""
        results = []
        for memory in self.memories.values():
            if all(getattr(memory, k) == v for k, v in filters.items()):
                results.append(memory)
                if len(results) >= limit:
                    break
        return results


class FileBackend(BaseMemoryBackend):
    """File-based storage backend for persistent memory."""
    
    def __init__(self, storage_path: Union[str, Path] = "memories.json"):
        self.storage_path = Path(storage_path)
        self.memories: Dict[str, MemoryItem] = {}
        self._load()
    
    def _load(self):
        """Load memories from file."""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.memories = {
                        k: MemoryItem.from_dict(v) 
                        for k, v in data.items()
                    }
            except Exception as e:
                logger.error(f"Error loading memories: {e}")
                self.memories = {}
    
    def _save(self):
        """Save memories to file."""
        try:
            with open(self.storage_path, 'w', encoding='utf-8') as f:
                json.dump(
                    {k: v.to_dict() for k, v in self.memories.items()},
                    f,
                    indent=2,
                    ensure_ascii=False
                )
        except Exception as e:
            logger.error(f"Error saving memories: {e}")
    
    async def store(self, memory: MemoryItem) -> str:
        """Store a memory item in the file."""
        memory_id = str(uuid.uuid4())
        self.memories[memory_id] = memory
        self._save()
        return memory_id
    
    async def retrieve(self, query: str, limit: int = 5, threshold: float = 0.7) -> List[MemoryItem]:
        """Retrieve relevant memories from the file."""
        # Simple implementation - would use embeddings in production
        return list(self.memories.values())[:limit]
    
    async def update(self, memory_id: str, memory: MemoryItem) -> bool:
        """Update a memory in the file."""
        if memory_id in self.memories:
            self.memories[memory_id] = memory
            self._save()
            return True
        return False
    
    async def delete(self, memory_id: str) -> bool:
        """Delete a memory from the file."""
        if memory_id in self.memories:
            del self.memories[memory_id]
            self._save()
            return True
        return False
    
    async def search(self, query: str, limit: int = 5, **filters) -> List[MemoryItem]:
        """Search memories with filters."""
        results = []
        for memory in self.memories.values():
            if all(getattr(memory, k) == v for k, v in filters.items()):
                results.append(memory)
                if len(results) >= limit:
                    break
        return results


class MemoryManager:
    """Manages different types of memories and their storage."""
    
    def __init__(self, backend: Optional[BaseMemoryBackend] = None):
        """Initialize the memory manager with a backend."""
        self.backend = backend or InMemoryBackend()
        self.working_memory: Dict[str, Any] = {}
    
    async def remember(self, content: str, memory_type: str = "fact", **kwargs) -> str:
        """Store a new memory."""
        memory = MemoryItem(
            content=content,
            memory_type=memory_type,
            **kwargs
        )
        return await self.backend.store(memory)
    
    async def recall(self, query: str, limit: int = 5, threshold: float = 0.7) -> List[MemoryItem]:
        """Retrieve relevant memories."""
        return await self.backend.retrieve(query, limit, threshold)
    
    async def search_memories(self, query: str, limit: int = 5, **filters) -> List[MemoryItem]:
        """Search memories with filters."""
        return await self.backend.search(query, limit, **filters)
    
    def set_working_memory(self, key: str, value: Any):
        """Set a value in working memory."""
        self.working_memory[key] = value
    
    def get_working_memory(self, key: str, default: Any = None) -> Any:
        """Get a value from working memory."""
        return self.working_memory.get(key, default)
    
    def clear_working_memory(self):
        """Clear all working memory."""
        self.working_memory.clear()
    
    async def summarize_conversation(self, conversation: List[Dict[str, str]]) -> str:
        """Generate a summary of the conversation."""
        # This would use an LLM to generate a summary in a real implementation
        summary = "\n".join(f"{msg['role']}: {msg['content']}" for msg in conversation[-5:])
        return f"Recent conversation summary:\n{summary}"
    
    async def update_memory_importance(self, memory_id: str, importance: float):
        """Update the importance of a memory."""
        # This would update the memory's importance in the backend
        pass
