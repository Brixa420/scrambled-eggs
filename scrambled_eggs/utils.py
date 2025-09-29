"""
Utility functions for Scrambled Eggs
"""

import logging
import logging.handlers
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar, cast

# Type variable for generic function wrapping
F = TypeVar("F", bound=Callable[..., Any])


def setup_logging(config: Optional[Dict[str, Any]] = None) -> None:
    """Set up logging configuration.

    Args:
        config: Optional logging configuration. If None, uses default config.
    """
    from .config import get_config

    if config is None:
        config = get_config().get("logging", {})

    log_level = getattr(logging, config.get("level", "INFO").upper(), logging.INFO)
    log_file = config.get("file")
    max_size = config.get("max_size", 10 * 1024 * 1024)  # 10MB
    backup_count = config.get("backup_count", 5)

    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Clear existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File handler if log file is specified
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_size, backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)


def timeit(func: F) -> F:
    """Decorator to measure function execution time."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        logger = logging.getLogger(func.__module__)
        logger.debug(f"Function {func.__name__} executed in {end_time - start_time:.4f} seconds")
        return result

    return cast(F, wrapper)


def secure_delete(file_path: str, passes: int = 3) -> None:
    """
    Securely delete a file by overwriting it before deletion.

    Args:
        file_path: Path to the file to delete
        passes: Number of overwrite passes (default: 3)
    """
    try:
        if not os.path.isfile(file_path):
            return

        file_size = os.path.getsize(file_path)

        with open(file_path, "r+b") as f:
            for _ in range(passes):
                # Move to start of file
                f.seek(0)

                # Overwrite with random data
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

                # Write all zeros
                f.seek(0)
                f.write(b"\x00" * file_size)
                f.flush()
                os.fsync(f.fileno())

                # Write 0xFF
                f.seek(0)
                f.write(b"\xff" * file_size)
                f.flush()
                os.fsync(f.fileno())

        # Remove the file
        os.unlink(file_path)

    except Exception as e:
        logging.error(f"Secure delete failed for {file_path}: {e}")
        try:
            os.unlink(file_path)
        except Exception as e:
            logging.error(f"Failed to delete {file_path}: {e}")


def get_file_checksum(file_path: str, algorithm: str = "sha256", chunk_size: int = 8192) -> str:
    """
    Calculate the checksum of a file.

    Args:
        file_path: Path to the file
        algorithm: Hash algorithm (default: 'sha256')
        chunk_size: Size of chunks to read at once in bytes (default: 8192)

    Returns:
        Hex-encoded checksum string
    """
    import hashlib  # Move import here to avoid circular imports

    hash_func = getattr(hashlib, algorithm.lower(), None)
    if not hash_func:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")

    hasher = hash_func()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


def parallel_process(
    items: List[Any],
    func: Callable[[Any], Any],
    max_workers: Optional[int] = None,
    chunk_size: int = 1,
) -> List[Any]:
    """
    Process items in parallel using ThreadPoolExecutor.

    Args:
        items: List of items to process
        func: Function to apply to each item
        max_workers: Maximum number of worker threads
        chunk_size: Number of items to process in each task

    Returns:
        List of results in the same order as input items
    """
    if not items:
        return []

    # Use all available cores if max_workers is not specified
    if max_workers is None:
        max_workers = min(32, (os.cpu_count() or 1) + 4)

    results = [None] * len(items)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit tasks in chunks
        futures = []
        for i in range(0, len(items), chunk_size):
            chunk = items[i : i + chunk_size]
            future = executor.submit(
                lambda chunk, indices: [(idx, func(item)) for idx, item in zip(indices, chunk)],
                chunk,
                range(i, min(i + chunk_size, len(items))),
            )
            futures.append(future)

        # Collect results
        for future in as_completed(futures):
            chunk_results = future.result()
            for idx, result in chunk_results:
                results[idx] = result

    return results


def get_file_size(file_path: str) -> int:
    """Get file size in bytes."""
    return os.path.getsize(file_path)


def human_readable_size(size_bytes: int) -> str:
    """Convert size in bytes to human-readable format."""
    if size_bytes == 0:
        return "0B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    i = 0
    while size_bytes >= 1024 and i < len(units) - 1:
        size_bytes /= 1024
        i += 1

    return f"{size_bytes:.2f}{units[i]}"
