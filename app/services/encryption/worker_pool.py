"""
Worker pool for parallel encryption/decryption operations.
Handles thread management and task distribution for improved performance.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Callable, Any, TypeVar, Awaitable, List, Dict
import logging

T = TypeVar('T')

class WorkerPool:
    """Manages a pool of worker threads for CPU-bound operations."""
    
    def __init__(self, max_workers: int = None):
        """Initialize the worker pool.
        
        Args:
            max_workers: Maximum number of worker threads. If None, uses (CPU count + 4).
        """
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._futures: List[Future] = []
        self._loop = asyncio.get_event_loop()
        
    async def submit(self, func: Callable[..., T], *args, **kwargs) -> T:
        """Submit a task to the worker pool.
        
        Args:
            func: The function to execute in a worker thread.
            *args: Positional arguments to pass to the function.
            **kwargs: Keyword arguments to pass to the function.
            
        Returns:
            The result of the function call.
        """
        future = self._loop.run_in_executor(
            self._executor,
            lambda: func(*args, **kwargs)
        )
        self._futures.append(future)
        return await future
    
    async def map(self, func: Callable[..., T], *iterables) -> List[T]:
        """Map a function across multiple iterables in parallel.
        
        Args:
            func: The function to apply to each item.
            *iterables: One or more iterables of arguments.
            
        Returns:
            List of results in the same order as the input.
        """
        tasks = [self.submit(func, *args) for args in zip(*iterables)]
        return await asyncio.gather(*tasks)
    
    async def shutdown(self, wait: bool = True):
        """Shutdown the worker pool.
        
        Args:
            wait: If True, wait for all pending tasks to complete.
        """
        if wait:
            await asyncio.gather(*self._futures, return_exceptions=True)
        self._executor.shutdown(wait=wait)
        
    def __del__(self):
        """Ensure the executor is properly closed."""
        self._executor.shutdown(wait=False)

# Global worker pool instance
_worker_pool = None

def get_worker_pool() -> WorkerPool:
    """Get the global worker pool instance."""
    global _worker_pool
    if _worker_pool is None:
        _worker_pool = WorkerPool()
    return _worker_pool

async def shutdown_worker_pool():
    """Shutdown the global worker pool."""
    global _worker_pool
    if _worker_pool is not None:
        await _worker_pool.shutdown()
        _worker_pool = None
