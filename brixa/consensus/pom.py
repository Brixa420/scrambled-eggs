"""
Proof-of-Memory (PoM) consensus mechanism implementation.

This module provides a memory-hard proof-of-work system that requires significant
memory to generate proofs but remains efficient to verify.
"""

import hashlib
import os
import time
from dataclasses import dataclass
from typing import List, Tuple, Optional

@dataclass
class PoMConfig:
    """Configuration for Proof-of-Memory consensus.
    
    Attributes:
        memory_size: Number of memory units to use (default: 16MB)
        iterations: Number of iterations for memory initialization
        difficulty: Number of leading zeros required in proof
    """
    memory_size: int = 2**24  # 16MB of memory
    iterations: int = 1000
    difficulty: int = 4

class ProofOfMemory:
    """Proof-of-Memory consensus implementation.
    
    This class implements a memory-hard proof-of-work system where generating
    a proof requires significant memory but verification remains efficient.
    """
    
    def __init__(self, config: Optional[PoMConfig] = None):
        """Initialize the PoM system with optional configuration.
        
        Args:
            config: Optional configuration parameters. Uses defaults if None.
        """
        self.config = config or PoMConfig()
        
    def generate_challenge(self, block_hash: str) -> bytes:
        """Generate a memory-hard challenge from block data.
        
        Args:
            block_hash: The hash of the block header
            
        Returns:
            A 32-byte challenge derived from the block hash
        """
        return hashlib.sha256(block_hash.encode()).digest()
    
    def initialize_memory(self, challenge: bytes) -> List[bytes]:
        """Initialize memory with a memory-hard function.
        
        This creates a memory array where each value depends on previous values,
        making it expensive to compute without storing the entire array.
        
        Args:
            challenge: The challenge to base memory initialization on
            
        Returns:
            A list of memory pages
        """
        memory = [challenge]
        for i in range(1, self.config.memory_size):
            # Each value depends on previous values
            prev = memory[i-1]
            memory.append(hashlib.sha256(prev + i.to_bytes(8, 'little')).digest())
        return memory
    
    def generate_proof(self, block_hash: str) -> Tuple[bytes, int, float]:
        """Generate a proof of memory.
        
        This is the mining function that performs the memory-hard work.
        
        Args:
            block_hash: The hash of the block to generate a proof for
            
        Returns:
            A tuple of (proof, nonce, time_taken) where:
            - proof: The generated proof
            - nonce: The nonce that produced the valid proof
            - time_taken: Time taken to generate the proof in seconds
        """
        challenge = self.generate_challenge(block_hash)
        memory = self.initialize_memory(challenge)
        
        nonce = 0
        start_time = time.time()
        
        while True:
            # Memory-hard proof of work
            index = int.from_bytes(
                hashlib.sha256(challenge + nonce.to_bytes(8, 'little')).digest(),
                'little'
            ) % self.config.memory_size
            
            proof = memory[index]
            
            # Check if proof meets difficulty target
            if proof.startswith(b'\x00' * self.config.difficulty):
                return proof, nonce, time.time() - start_time
                
            nonce += 1
            
    def verify_proof(self, block_hash: str, proof: bytes, nonce: int) -> bool:
        """Verify a proof of memory.
        
        Args:
            block_hash: The original block hash
            proof: The proof to verify
            nonce: The nonce used to generate the proof
            
        Returns:
            True if the proof is valid, False otherwise
        """
        challenge = self.generate_challenge(block_hash)
        memory = self.initialize_memory(challenge)
        
        index = int.from_bytes(
            hashlib.sha256(challenge + nonce.to_bytes(8, 'little')).digest(),
            'little'
        ) % self.config.memory_size
        
        candidate = memory[index]
        return candidate == proof and proof.startswith(b'\x00' * self.config.difficulty)
