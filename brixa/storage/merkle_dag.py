"""
Merkle DAG (Directed Acyclic Graph) implementation for content-addressable storage.
"""
import hashlib
import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Any, Tuple
from datetime import datetime

from .interface import ContentAddressableStorage, VersionInfo


@dataclass
class DAGNode:
    """A node in the Merkle DAG."""
    # The content-addressable hash of this node
    cid: str
    # Links to other nodes in the DAG
    links: Dict[str, str] = field(default_factory=dict)
    # Size of the data in this node
    size: int = 0
    # Type of the node (file, directory, etc.)
    node_type: str = "file"
    # Custom metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Timestamp of creation
    created_at: float = field(default_factory=lambda: datetime.utcnow().timestamp())

    def to_dict(self) -> Dict[str, Any]:
        """Convert the node to a dictionary."""
        return {
            "cid": self.cid,
            "links": self.links,
            "size": self.size,
            "node_type": self.node_type,
            "metadata": self.metadata,
            "created_at": self.created_at
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DAGNode':
        """Create a DAGNode from a dictionary."""
        return cls(
            cid=data["cid"],
            links=data.get("links", {}),
            size=data.get("size", 0),
            node_type=data.get("node_type", "file"),
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.utcnow().timestamp())
        )


class MerkleDAG(ContentAddressableStorage):
    """
    A Merkle DAG implementation for content-addressable storage.
    """
    
    def __init__(self, storage: ContentAddressableStorage):
        """
        Initialize the Merkle DAG with a content-addressable storage backend.
        
        Args:
            storage: The underlying content-addressable storage
        """
        self._storage = storage
    
    async def _calculate_cid(self, data: bytes) -> str:
        """Calculate the content identifier for the given data."""
        # Using multihash for content addressing
        # This is a simplified version - in production, use a proper multihash implementation
        h = hashlib.sha256()
        h.update(data)
        return f"bafk{len(data):08x}{h.hexdigest()}"
    
    async def put(self, data: bytes, **metadata) -> str:
        """
        Store data in the DAG and return its CID.
        
        For large data, this will automatically split it into chunks and create
        a DAG of chunk nodes.
        """
        if len(data) <= 1024 * 1024:  # 1MB chunk size
            # Small enough to store as a single node
            node = DAGNode(
                cid=await self._calculate_cid(data),
                size=len(data),
                metadata=metadata
            )
            
            # Store the node data
            node_data = json.dumps(node.to_dict()).encode()
            node_cid = await self._calculate_cid(node_data)
            await self._storage.put(node_data, **{"type": "dag-node", **metadata})
            
            return node_cid
        else:
            # For large data, split into chunks and create a DAG
            chunk_size = 1024 * 1024  # 1MB chunks
            chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
            
            # Store each chunk
            chunk_cids = []
            for i, chunk in enumerate(chunks):
                chunk_cid = await self._storage.put(chunk, **{
                    "chunk_index": i,
                    "total_chunks": len(chunks),
                    **metadata
                })
                chunk_cids.append(chunk_cid)
            
            # Create a node that links to all chunks
            links = {str(i): cid for i, cid in enumerate(chunk_cids)}
            node = DAGNode(
                cid=await self._calculate_cid(b''.join(chunks)),
                links=links,
                size=len(data),
                node_type="file",
                metadata={
                    "chunks": len(chunks),
                    "original_size": len(data),
                    **metadata
                }
            )
            
            # Store the node
            node_data = json.dumps(node.to_dict()).encode()
            node_cid = await self._calculate_cid(node_data)
            await self._storage.put(node_data, **{"type": "dag-node", **metadata})
            
            return node_cid
    
    async def get(self, cid: str) -> Optional[bytes]:
        """
        Retrieve data by its CID.
        
        This will traverse the DAG and reassemble the data from its chunks if necessary.
        """
        # First, try to get the node data
        node_data = await self._storage.get(cid)
        if not node_data:
            return None
            
        try:
            node = DAGNode.from_dict(json.loads(node_data))
        except (json.JSONDecodeError, KeyError):
            # Not a DAG node, return the raw data
            return node_data
        
        # If it's a leaf node (no links), return its data
        if not node.links:
            return node_data
        
        # If it's an intermediate node, fetch and combine all chunks
        chunks = []
        for chunk_cid in sorted(node.links.values(), key=int):
            chunk_data = await self._storage.get(chunk_cid)
            if chunk_data:
                chunks.append(chunk_data)
            else:
                raise ValueError(f"Missing chunk {chunk_cid} for node {cid}")
        
        return b''.join(chunks)
    
    async def exists(self, cid: str) -> bool:
        """Check if a node exists in the DAG."""
        return await self._storage.exists(cid)
    
    async def get_node(self, cid: str) -> Optional[DAGNode]:
        """
        Retrieve a DAG node by its CID.
        
        Returns:
            Optional[DAGNode]: The deserialized DAG node, or None if not found
        """
        node_data = await self._storage.get(cid)
        if not node_data:
            return None
            
        try:
            return DAGNode.from_dict(json.loads(node_data))
        except (json.JSONDecodeError, KeyError):
            return None
    
    async def add_link(self, parent_cid: str, name: str, child_cid: str) -> str:
        """
        Add a link from a parent node to a child node.
        
        Args:
            parent_cid: The CID of the parent node
            name: The name of the link
            child_cid: The CID of the child node
            
        Returns:
            str: The CID of the updated parent node
        """
        # Get the parent node
        parent_node = await self.get_node(parent_cid)
        if not parent_node:
            raise ValueError(f"Parent node {parent_cid} not found")
        
        # Verify the child exists
        if not await self.exists(child_cid):
            raise ValueError(f"Child node {child_cid} not found")
        
        # Add the link
        parent_node.links[name] = child_cid
        
        # Update the parent node
        node_data = json.dumps(parent_node.to_dict()).encode()
        new_cid = await self._calculate_cid(node_data)
        await self._storage.put(node_data, **{"type": "dag-node"})
        
        return new_cid
