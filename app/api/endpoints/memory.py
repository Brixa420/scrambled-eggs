"""
API endpoints for managing Clippy's memories using the blockchain.
"""
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.blockchain import get_blockchain, Block
from app.core.security import get_current_user
from app.models.user import User

router = APIRouter()

class MemoryCreate(BaseModel):
    """Schema for creating a new memory."""
    content: str = Field(..., min_length=1, max_length=10000)
    context: str = Field(..., min_length=1, max_length=100)
    memory_type: str = Field(default="general", max_length=50)
    metadata: Optional[dict] = None
    importance: float = Field(default=1.0, ge=0.0, le=1.0)

class MemoryResponse(MemoryCreate):
    """Schema for memory response."""
    id: str
    timestamp: float
    block_index: int
    
    class Config:
        orm_mode = True

class BlockResponse(BaseModel):
    """Schema for block response."""
    index: int
    timestamp: float
    hash: str
    previous_hash: str
    nonce: int
    difficulty: int
    memory_count: int

@router.post("/memories/", response_model=MemoryResponse, status_code=status.HTTP_201_CREATED)
async def create_memory(
    memory: MemoryCreate,
    current_user: User = Depends(get_current_user)
):
    """
    Add a new memory to the blockchain.
    
    The memory will be added to the pending memories and included in the next mined block.
    """
    blockchain = get_blockchain()
    
    # Create memory dict with additional metadata
    memory_dict = memory.dict()
    memory_dict['user_id'] = current_user.id
    memory_dict['app_id'] = "clippy"  # In a multi-app system, this would be dynamic
    
    # Add to pending memories
    blockchain.add_memory(memory_dict)
    
    # For demo purposes, mine a block immediately
    # In production, you might want to batch these
    block = blockchain.mine_pending_memories()
    
    # Find the memory in the new block
    for mem in block.memories:
        if mem.get('content') == memory.content:
            return {
                **mem,
                'block_index': block.index
            }
    
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Failed to create memory"
    )

@router.get("/memories/", response_model=List[MemoryResponse])
async def get_memories(
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user)
):
    """
    Get memories from the blockchain.
    
    Returns the most recent memories first.
    """
    blockchain = get_blockchain()
    
    # Get all memories (this is a simple implementation - in production, use pagination)
    all_memories = []
    for block in reversed(blockchain.chain):
        for memory in block.memories:
            # Skip system memories and memories from other users in a multi-user system
            if memory.get('user_id') == current_user.id:
                all_memories.append({
                    **memory,
                    'block_index': block.index
                })
    
    return all_memories[offset:offset+limit]

@router.get("/memories/{memory_id}", response_model=MemoryResponse)
async def get_memory(
    memory_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Get a specific memory by its ID.
    """
    blockchain = get_blockchain()
    memory = blockchain.get_memory_by_id(memory_id)
    
    if not memory:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Memory not found"
        )
    
    # Check if the current user has access to this memory
    if memory.get('user_id') != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this memory"
        )
    
    return memory

@router.get("/blocks/", response_model=List[BlockResponse])
async def get_blocks(
    limit: int = 10,
    current_user: User = Depends(get_current_user)
):
    """
    Get information about blocks in the blockchain.
    """
    blockchain = get_blockchain()
    
    blocks = []
    for block in reversed(blockchain.chain[-limit:]):
        blocks.append({
            'index': block.index,
            'timestamp': block.timestamp,
            'hash': block.hash,
            'previous_hash': block.previous_hash,
            'nonce': block.nonce,
            'difficulty': block.difficulty,
            'memory_count': len(block.memories)
        })
    
    return blocks

@router.get("/blocks/{block_index}", response_model=BlockResponse)
async def get_block(
    block_index: int,
    current_user: User = Depends(get_current_user)
):
    """
    Get information about a specific block.
    """
    blockchain = get_blockchain()
    block = blockchain.get_block_by_index(block_index)
    
    if not block:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Block not found"
        )
    
    return {
        'index': block.index,
        'timestamp': block.timestamp,
        'hash': block.hash,
        'previous_hash': block.previous_hash,
        'nonce': block.nonce,
        'difficulty': block.difficulty,
        'memory_count': len(block.memories)
    }

@router.get("/stats/")
async def get_blockchain_stats(
    current_user: User = Depends(get_current_user)
):
    """
    Get statistics about the blockchain.
    """
    blockchain = get_blockchain()
    
    return {
        'block_count': blockchain.get_chain_length(),
        'total_memories': blockchain.get_total_memories(),
        'pending_memories': len(blockchain.pending_memories),
        'difficulty': blockchain.difficulty,
        'is_valid': blockchain.is_chain_valid()
    }
