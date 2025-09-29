"""
Chunked Data Processor

Handles in-memory chunked processing of data for efficient memory usage during
encryption/decryption operations.
"""
import asyncio
import math
import os
from typing import Any, Callable, List, Optional, Tuple, Union
import numpy as np

# Default chunk size (4MB)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024
# Minimum chunk size (64KB)
MIN_CHUNK_SIZE = 64 * 1024
# Maximum chunk size (64MB)
MAX_CHUNK_SIZE = 64 * 1024 * 1024

class ChunkedDataProcessor:
    """Process large in-memory data in chunks for better memory efficiency."""
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE, max_workers: Optional[int] = None):
        """Initialize the chunked data processor.
        
        Args:
            chunk_size: Size of each chunk in bytes
            max_workers: Maximum number of worker tasks (default: CPU count * 2)
        """
        self.chunk_size = self._validate_chunk_size(chunk_size)
        self.max_workers = max_workers or (os.cpu_count() or 4) * 2
        self.semaphore = asyncio.Semaphore(self.max_workers)
    
    @staticmethod
    def _validate_chunk_size(size: int) -> int:
        """Ensure chunk size is within reasonable bounds."""
        return max(MIN_CHUNK_SIZE, min(MAX_CHUNK_SIZE, size))
    
    async def process(
        self,
        data: Union[bytes, bytearray, memoryview],
        process_func: Callable[[bytes, dict], bytes],
        context: Optional[dict] = None
    ) -> bytes:
        """Process data in chunks using the provided processing function.
        
        Args:
            data: Input data to process
            process_func: Function to process each chunk
            context: Optional context dictionary passed to process_func
            
        Returns:
            Processed data
        """
        if not data:
            return b''
            
        context = context or {}
        chunks = self._split_into_chunks(data)
        processed_chunks = await self._process_chunks(chunks, process_func, context)
        return self._combine_chunks(processed_chunks)
    
    def _split_into_chunks(self, data: Union[bytes, bytearray, memoryview]) -> List[bytes]:
        """Split data into chunks of the configured size."""
        if isinstance(data, (bytearray, memoryview)):
            data = bytes(data)
        
        chunks = []
        total_chunks = math.ceil(len(data) / self.chunk_size)
        
        for i in range(total_chunks):
            start = i * self.chunk_size
            end = start + self.chunk_size
            chunks.append(data[start:end])
            
        return chunks
    
    async def _process_chunks(
        self,
        chunks: List[bytes],
        process_func: Callable[[bytes, dict], bytes],
        context: dict
    ) -> List[bytes]:
        """Process chunks in parallel with rate limiting."""
        async def process_chunk(chunk: bytes) -> bytes:
            async with self.semaphore:
                return await asyncio.get_event_loop().run_in_executor(
                    None,  # Use default executor
                    lambda: process_func(chunk, context)
                )
        
        tasks = [process_chunk(chunk) for chunk in chunks]
        return await asyncio.gather(*tasks)
    
    @staticmethod
    def _combine_chunks(chunks: List[bytes]) -> bytes:
        """Combine processed chunks back into a single bytestring."""
        return b''.join(chunks)
    
    def calculate_optimal_chunk_size(self, data_size: int) -> int:
        """Calculate optimal chunk size based on data size and system memory."""
        import psutil
        
        # Get available memory (leave 1GB free)
        available_mem = max(0, psutil.virtual_memory().available - (1024 ** 3))
        
        # Use at most 50% of available memory for chunks
        max_chunk_mem = available_mem // 2
        
        # Calculate based on number of workers and memory constraints
        chunk_size = min(
            max(
                MIN_CHUNK_SIZE,
                min(
                    data_size // (self.max_workers * 2),  # Keep workers busy
                    max_chunk_mem // max(1, self.max_workers)
                )
            ),
            MAX_CHUNK_SIZE
        )
        
        return self._validate_chunk_size(chunk_size)
    
    def auto_configure(self, data_size: int) -> None:
        """Automatically configure chunk size based on data size and system resources."""
        self.chunk_size = self.calculate_optimal_chunk_size(data_size)
        logger.info(f"Auto-configured chunk size: {self.chunk_size / (1024*1024):.2f}MB")


def get_chunked_processor(chunk_size: int = DEFAULT_CHUNK_SIZE) -> ChunkedDataProcessor:
    """Get a chunked data processor instance."""
    return ChunkedDataProcessor(chunk_size=chunk_size)

# Initialize logger
import logging
logger = logging.getLogger(__name__)
