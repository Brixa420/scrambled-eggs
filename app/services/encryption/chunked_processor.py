"""
Chunked Processing Module
Handles encryption/decryption of large files by processing them in chunks.
"""
import os
import asyncio
from typing import AsyncIterator, Tuple, Optional, Callable, Any
from dataclasses import dataclass
from .worker_pool import get_worker_pool

# Default chunk size (4MB)
DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024

@dataclass
class Chunk:
    """Represents a chunk of data being processed."""
    data: bytes
    index: int
    total_chunks: int
    metadata: dict = None

class ChunkedProcessor:
    """Handles chunked processing of encryption/decryption operations."""
    
    def __init__(self, chunk_size: int = DEFAULT_CHUNK_SIZE):
        """Initialize the chunked processor.
        
        Args:
            chunk_size: Size of each chunk in bytes
        """
        self.chunk_size = chunk_size
        self.worker_pool = get_worker_pool()
    
    async def process_file(
        self,
        input_path: str,
        output_path: str,
        process_func: Callable[[bytes, Any], Awaitable[bytes]],
        **kwargs
    ) -> None:
        """Process a file in chunks.
        
        Args:
            input_path: Path to input file
            output_path: Path to output file
            process_func: Async function to process each chunk
            **kwargs: Additional arguments to pass to process_func
        """
        # Get file size for progress tracking
        file_size = os.path.getsize(input_path)
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
        
        # Process chunks in parallel
        async with asyncio.TaskGroup() as tg:
            tasks = []
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                # Create a lock for thread-safe file writing
                write_lock = asyncio.Lock()
                
                # Process each chunk
                for chunk_idx in range(total_chunks):
                    # Read chunk
                    chunk_data = await self.worker_pool.submit(
                        self._read_chunk,
                        f_in,
                        chunk_idx,
                        self.chunk_size
                    )
                    
                    # Process chunk
                    task = tg.create_task(self._process_chunk(
                        chunk_data,
                        chunk_idx,
                        total_chunks,
                        process_func,
                        write_lock,
                        f_out,
                        **kwargs
                    ))
                    tasks.append(task)
                
                # Wait for all chunks to be processed
                await asyncio.gather(*tasks)
    
    @staticmethod
    def _read_chunk(file_obj, chunk_idx: int, chunk_size: int) -> bytes:
        """Read a chunk from the file."""
        file_obj.seek(chunk_idx * chunk_size)
        return file_obj.read(chunk_size)
    
    async def _process_chunk(
        self,
        chunk_data: bytes,
        chunk_idx: int,
        total_chunks: int,
        process_func: Callable,
        write_lock: asyncio.Lock,
        output_file,
        **kwargs
    ) -> None:
        """Process a single chunk and write the result."""
        try:
            # Process the chunk
            processed_data = await process_func(chunk_data, **kwargs)
            
            # Write the processed chunk
            async with write_lock:
                output_file.seek(chunk_idx * self.chunk_size)
                await self.worker_pool.submit(
                    output_file.write,
                    processed_data
                )
                output_file.flush()
                
        except Exception as e:
            logger.error(f"Error processing chunk {chunk_idx}: {str(e)}")
            raise

def get_chunk_processor() -> ChunkedProcessor:
    """Get a chunked processor instance."""
    return ChunkedProcessor()
