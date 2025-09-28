"""
Encryption Monitoring Service

This module provides monitoring and metrics for encryption operations
and key management using Prometheus and structured logging.
"""
import time
import logging
from typing import Dict, Any, Optional, Callable, TypeVar, cast
from functools import wraps
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum

from prometheus_client import Counter, Gauge, Histogram, start_http_server

from app.config.encryption import config as encryption_config

logger = logging.getLogger(__name__)

# Type variable for generic function wrapping
F = TypeVar('F', bound=Callable[..., Any])

class EncryptionOperation(str, Enum):
    """Types of encryption operations that can be monitored."""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    KEY_GENERATE = "key_generate"
    KEY_ROTATE = "key_rotate"
    KEY_DERIVE = "key_derive"

@dataclass
class OperationMetrics:
    """Metrics for a single encryption operation."""
    operation: EncryptionOperation
    success: bool = False
    duration_seconds: float = 0.0
    key_id: Optional[str] = None
    key_size: Optional[int] = None
    data_size: Optional[int] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class EncryptionMonitor:
    """
    Monitors encryption operations and collects metrics.
    
    This class provides decorators and context managers to track encryption
    operations, including success/failure rates, operation duration, and
    resource usage.
    """
    
    def __init__(self, enable_metrics: bool = True):
        """Initialize the encryption monitor."""
        self.enable_metrics = enable_metrics
        self._init_metrics()
    
    def _init_metrics(self):
        """Initialize Prometheus metrics."""
        # Operation counters
        self.ops_total = Counter(
            'scrambled_eggs_encryption_operations_total',
            'Total number of encryption operations',
            ['operation', 'status']
        )
        
        # Operation duration histogram
        self.ops_duration = Histogram(
            'scrambled_eggs_encryption_duration_seconds',
            'Duration of encryption operations in seconds',
            ['operation'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
        )
        
        # Key metrics
        self.keys_total = Gauge(
            'scrambled_eggs_encryption_keys_total',
            'Total number of encryption keys',
            ['key_type', 'status']
        )
        
        # Key age histogram
        self.key_age_days = Gauge(
            'scrambled_eggs_encryption_key_age_days',
            'Age of encryption keys in days',
            ['key_type']
        )
        
        # Data size metrics
        self.data_size_bytes = Counter(
            'scrambled_eggs_encryption_data_size_bytes',
            'Total size of encrypted/decrypted data in bytes',
            ['operation']
        )
    
    def start_metrics_server(self, port: int = 8000):
        """Start the Prometheus metrics HTTP server."""
        if not self.enable_metrics:
            return
            
        try:
            start_http_server(port)
            logger.info(f"Started metrics server on port {port}")
        except Exception as e:
            logger.error(f"Failed to start metrics server: {e}")
    
    def track_operation(self, operation: EncryptionOperation) -> Callable[[F], F]:
        """
        Decorator to track an encryption operation.
        
        Example:
            @monitor.track_operation(EncryptionOperation.ENCRYPT)
            def encrypt_data(data: bytes, key: bytes) -> bytes:
                # encryption logic here
                pass
        """
        def decorator(func: F) -> F:
            @wraps(func)
            def wrapper(*args, **kwargs):
                start_time = time.monotonic()
                metrics = OperationMetrics(operation=operation)
                
                try:
                    # Extract key_id and data_size from function arguments if possible
                    if 'key_id' in kwargs:
                        metrics.key_id = kwargs['key_id']
                    elif len(args) > 1 and isinstance(args[1], str):
                        metrics.key_id = args[1]  # Assuming key_id is the second argument
                    
                    if 'data' in kwargs:
                        metrics.data_size = len(kwargs['data'])
                    elif len(args) > 0 and hasattr(args[0], '__len__'):
                        metrics.data_size = len(args[0])
                    
                    # Call the wrapped function
                    result = func(*args, **kwargs)
                    
                    # Update metrics on success
                    metrics.success = True
                    if hasattr(result, 'key') and hasattr(result.key, 'key_id'):
                        metrics.key_id = result.key.key_id
                    
                    return result
                    
                except Exception as e:
                    metrics.error = str(e)
                    metrics.success = False
                    logger.error(
                        f"Encryption operation failed: {operation.value}",
                        exc_info=True,
                        extra={
                            'operation': operation.value,
                            'error': str(e),
                            'key_id': metrics.key_id,
                            'data_size': metrics.data_size
                        }
                    )
                    raise
                finally:
                    # Calculate duration
                    metrics.duration_seconds = time.monotonic() - start_time
                    
                    # Record metrics
                    self._record_metrics(metrics)
                    
                    # Log the operation
                    self._log_operation(metrics)
            
            return cast(F, wrapper)
        return decorator
    
    def _record_metrics(self, metrics: OperationMetrics):
        """Record metrics for an operation."""
        if not self.enable_metrics:
            return
            
        status = 'success' if metrics.success else 'failure'
        
        # Update operation counters
        self.ops_total.labels(
            operation=metrics.operation.value,
            status=status
        ).inc()
        
        # Record operation duration
        if metrics.duration_seconds is not None:
            self.ops_duration.labels(
                operation=metrics.operation.value
            ).observe(metrics.duration_seconds)
        
        # Record data size if available
        if metrics.data_size is not None:
            self.data_size_bytes.labels(
                operation=metrics.operation.value
            ).inc(metrics.data_size)
    
    def _log_operation(self, metrics: OperationMetrics):
        """Log an encryption operation."""
        log_data = {
            'operation': metrics.operation.value,
            'success': metrics.success,
            'duration_seconds': metrics.duration_seconds,
            'key_id': metrics.key_id,
            'data_size': metrics.data_size
        }
        
        if metrics.error:
            log_data['error'] = metrics.error
        
        if metrics.success:
            logger.debug("Encryption operation completed", extra=log_data)
        else:
            logger.warning("Encryption operation failed", extra=log_data)
    
    def record_key_generated(self, key_id: str, key_type: str, key_size: int):
        """Record that a new encryption key was generated."""
        if not self.enable_metrics:
            return
            
        self.keys_total.labels(key_type=key_type, status='active').inc()
        
        logger.info("Encryption key generated", extra={
            'key_id': key_id,
            'key_type': key_type,
            'key_size': key_size
        })
    
    def record_key_rotated(self, old_key_id: str, new_key_id: str, key_type: str):
        """Record that an encryption key was rotated."""
        if not self.enable_metrics:
            return
            
        self.keys_total.labels(key_type=key_type, status='rotated').inc()
        
        logger.info("Encryption key rotated", extra={
            'old_key_id': old_key_id,
            'new_key_id': new_key_id,
            'key_type': key_type
        })
    
    def record_key_expired(self, key_id: str, key_type: str):
        """Record that an encryption key has expired."""
        if not self.enable_metrics:
            return
            
        self.keys_total.labels(key_type=key_type, status='expired').inc()
        
        logger.info("Encryption key expired", extra={
            'key_id': key_id,
            'key_type': key_type
        })

# Create a singleton instance of the monitor
monitor = EncryptionMonitor(enable_metrics=encryption_config.ENABLE_METRICS)
