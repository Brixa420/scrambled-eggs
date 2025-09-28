""
Monitoring service for encryption operations.
"""
import time
import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
from collections import defaultdict, deque
import statistics

from prometheus_client import Counter, Histogram, Gauge, start_http_server

from app.config.encryption import config

logger = logging.getLogger(__name__)

# Prometheus metrics
ENCRYPTION_OPS = Counter(
    'scrambled_eggs_encryption_operations_total',
    'Total number of encryption operations',
    ['operation', 'layer', 'status']
)

ENCRYPTION_DURATION = Histogram(
    'scrambled_eggs_encryption_duration_seconds',
    'Time spent processing encryption operations',
    ['operation', 'layer'],
    buckets=(0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
)

KEY_ROTATIONS = Counter(
    'scrambled_eggs_key_rotations_total',
    'Total number of key rotations',
    ['status']
)

ACTIVE_KEYS = Gauge(
    'scrambled_eggs_active_keys',
    'Number of active encryption keys'
)

@dataclass
class OperationStats:
    """Statistics for encryption operations."""
    operation: str
    layer: str
    count: int = 0
    total_duration: float = 0.0
    errors: int = 0
    last_error: Optional[str] = None
    
    @property
    def avg_duration(self) -> float:
        """Calculate average duration in milliseconds."""
        return (self.total_duration * 1000) / self.count if self.count else 0

class EncryptionMonitor:
    """Monitor encryption operations and collect metrics."""
    
    def __init__(self, enable_prometheus: bool = True):
        """Initialize the monitoring service."""
        self.stats: Dict[str, OperationStats] = {}
        self.enable_prometheus = enable_prometheus
        self._operation_history = defaultdict(lambda: deque(maxlen=1000))  # Store last 1000 operations
        
        if self.enable_prometheus:
            try:
                start_http_server(9090)  # Start Prometheus metrics server
                logger.info("Started Prometheus metrics server on port 9090")
            except Exception as e:
                logger.warning(f"Failed to start Prometheus metrics server: {e}")
    
    def record_operation(
        self,
        operation: str,
        layer: str,
        duration: float,
        success: bool = True,
        error: Optional[Exception] = None
    ) -> None:
        """
        Record an encryption operation.
        
        Args:
            operation: The operation name (e.g., 'encrypt', 'decrypt')
            layer: The encryption layer used
            duration: Operation duration in seconds
            success: Whether the operation was successful
            error: Any error that occurred
        """
        # Update stats
        key = f"{operation}:{layer}"
        if key not in self.stats:
            self.stats[key] = OperationStats(operation, layer)
        
        stats = self.stats[key]
        stats.count += 1
        stats.total_duration += duration
        
        if not success:
            stats.errors += 1
            if error:
                stats.last_error = str(error)
        
        # Update Prometheus metrics
        if self.enable_prometheus:
            status = 'success' if success else 'error'
            ENCRYPTION_OPS.labels(operation=operation, layer=layer, status=status).inc()
            if success:
                ENCRYPTION_DURATION.labels(operation=operation, layer=layer).observe(duration)
        
        # Add to operation history
        self._operation_history[key].append({
            'timestamp': datetime.utcnow(),
            'duration': duration,
            'success': success,
            'error': str(error) if error else None
        })
    
    def record_key_rotation(self, success: bool = True, error: Optional[Exception] = None) -> None:
        """Record a key rotation event."""
        if self.enable_prometheus:
            status = 'success' if success else 'error'
            KEY_ROTATIONS.labels(status=status).inc()
        
        if not success and error:
            logger.error(f"Key rotation failed: {error}", exc_info=error)
    
    def update_active_keys(self, count: int) -> None:
        """Update the active keys gauge."""
        if self.enable_prometheus:
            ACTIVE_KEYS.set(count)
    
    def get_operation_stats(self, operation: str, layer: str) -> Optional[OperationStats]:
        """Get statistics for a specific operation and layer."""
        return self.stats.get(f"{operation}:{layer}")
    
    def get_operation_history(
        self,
        operation: Optional[str] = None,
        layer: Optional[str] = None,
        time_window: Optional[timedelta] = None
    ) -> List[dict]:
        """
        Get operation history with optional filtering.
        
        Args:
            operation: Filter by operation name
            layer: Filter by encryption layer
            time_window: Filter by time window
            
        Returns:
            List of operation events
        """
        now = datetime.utcnow()
        result = []
        
        for op_key, events in self._operation_history.items():
            op, lyr = op_key.split(':', 1)
            
            # Apply filters
            if operation and op != operation:
                continue
            if layer and lyr != layer:
                continue
            
            for event in events:
                # Apply time window filter
                if time_window and (now - event['timestamp']) > time_window:
                    continue
                
                result.append({
                    'operation': op,
                    'layer': lyr,
                    **event
                })
        
        # Sort by timestamp
        return sorted(result, key=lambda x: x['timestamp'], reverse=True)
    
    def get_performance_metrics(self, time_window: timedelta = timedelta(hours=1)) -> dict:
        """
        Get performance metrics for all operations.
        
        Args:
            time_window: Time window to calculate metrics for
            
        Returns:
            Dictionary of performance metrics
        """
        now = datetime.utcnow()
        metrics = {}
        
        for op_key, stats in self.stats.items():
            op, layer = op_key.split(':', 1)
            
            # Get recent operations for this op/layer
            recent_ops = [
                e for e in self._operation_history.get(op_key, [])
                if (now - e['timestamp']) <= time_window
            ]
            
            if not recent_ops:
                continue
            
            # Calculate metrics
            durations = [op['duration'] for op in recent_ops if op['success']]
            errors = sum(1 for op in recent_ops if not op['success'])
            
            metrics[op_key] = {
                'operation': op,
                'layer': layer,
                'count': len(recent_ops),
                'errors': errors,
                'error_rate': errors / len(recent_ops) if recent_ops else 0,
                'avg_duration': statistics.mean(durations) if durations else 0,
                'p50': statistics.quantiles(durations, n=4)[1] if len(durations) >= 2 else 0,
                'p95': statistics.quantiles(durations, n=20)[18] if len(durations) >= 20 else 0,
                'p99': statistics.quantiles(durations, n=100)[98] if len(durations) >= 100 else 0,
            }
        
        return metrics

# Create a singleton instance
monitor = EncryptionMonitor(enable_prometheus=config.ENABLE_METRICS)

def monitor_operation(operation: str, layer: str):
    """Decorator to monitor encryption operations."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = time.monotonic()
            error = None
            
            try:
                result = func(*args, **kwargs)
                monitor.record_operation(
                    operation=operation,
                    layer=layer,
                    duration=time.monotonic() - start_time,
                    success=True
                )
                return result
            except Exception as e:
                error = e
                monitor.record_operation(
                    operation=operation,
                    layer=layer,
                    duration=time.monotonic() - start_time,
                    success=False,
                    error=e
                )
                raise
        return wrapper
    return decorator
