"""
Brixa Distributed Storage Module

This package provides a distributed, content-addressable storage system with versioning
built on top of a Merkle DAG (Directed Acyclic Graph).
"""

from .interface import KeyValueStore, ContentAddressableStorage, VersionedStorage
from .merkle_dag import MerkleDAG
from .storage_node import StorageNode

__all__ = [
    'KeyValueStore',
    'ContentAddressableStorage',
    'VersionedStorage',
    'MerkleDAG',
    'StorageNode'
]
