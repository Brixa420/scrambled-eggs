"""
Connection Health Monitoring

Implements connection health monitoring and failure detection for P2P connections.
"""
import asyncio
import logging
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Deque
from collections import deque

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class ConnectionStats:
    """Connection statistics and health metrics."""
    peer_id: str
    address: Tuple[str, int]
    
    # Connection metrics
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    last_message_sent: Optional[float] = None
    last_message_received: Optional[float] = None
    
    # Latency tracking (in seconds)
    latency_samples: Deque[float] = field(default_factory=lambda: deque(maxlen=100))
    average_latency: Optional[float] = None
    min_latency: Optional[float] = None
    max_latency: Optional[float] = None
    
    # Error tracking
    consecutive_errors: int = 0
    total_errors: int = 0
    last_error: Optional[Exception] = None
    
    # Connection state
    is_active: bool = False
    last_state_change: float = field(default_factory=time.time)
    
    def update_latency(self, latency: float) -> None:
        """Update latency statistics."""
        self.latency_samples.append(latency)
        self.average_latency = statistics.mean(self.latency_samples)
        self.min_latency = min(self.latency_samples) if self.latency_samples else None
        self.max_latency = max(self.latency_samples) if self.latency_samples else None
    
    def record_success(self, bytes_sent: int = 0, bytes_received: int = 0) -> None:
        """Record a successful message exchange."""
        self.consecutive_errors = 0
        self.total_bytes_sent += bytes_sent
        self.total_bytes_received += bytes_received
        self.last_message_sent = time.time()
        
        if not self.is_active:
            self.is_active = True
            self.last_state_change = time.time()
            logger.info(f"Connection to {self.peer_id} is now active")
    
    def record_error(self, error: Exception) -> None:
        """Record a connection error."""
        self.consecutive_errors += 1
        self.total_errors += 1
        self.last_error = error
        
        if self.is_active and self.consecutive_errors >= 3:
            self.is_active = False
            self.last_state_change = time.time()
            logger.warning(f"Connection to {self.peer_id} is now inactive")
    
    def get_health_score(self) -> float:
        """Calculate a health score between 0.0 (unhealthy) and 1.0 (healthy)."""
        if not self.is_active:
            return 0.0
            
        score = 1.0
        
        # Penalize for recent errors
        if self.consecutive_errors > 0:
            score *= 0.5 ** min(self.consecutive_errors, 5)
            
        # Penalize for high latency
        if self.average_latency is not None:
            if self.average_latency > 5.0:  # >5s average latency
                score *= 0.5
            elif self.average_latency > 1.0:  # >1s average latency
                score *= 0.8
                
        # Penalize for no recent activity
        if self.last_message_received:
            time_since_last_msg = time.time() - self.last_message_received
            if time_since_last_msg > 300:  # 5 minutes
                score *= 0.3
            elif time_since_last_msg > 60:  # 1 minute
                score *= 0.7
                
        return max(0.0, min(1.0, score))
    
    def get_summary(self) -> Dict[str, any]:
        """Get a summary of connection statistics."""
        return {
            "peer_id": self.peer_id,
            "address": f"{self.address[0]}:{self.address[1]}",
            "is_active": self.is_active,
            "uptime": time.time() - self.last_state_change if self.is_active else 0,
            "total_bytes_sent": self.total_bytes_sent,
            "total_bytes_received": self.total_bytes_received,
            "average_latency": self.average_latency,
            "min_latency": self.min_latency,
            "max_latency": self.max_latency,
            "total_errors": self.total_errors,
            "consecutive_errors": self.consecutive_errors,
            "health_score": self.get_health_score(),
            "last_error": str(self.last_error) if self.last_error else None,
            "last_message_sent": datetime.fromtimestamp(self.last_message_sent).isoformat() 
                                if self.last_message_sent else None,
            "last_message_received": datetime.fromtimestamp(self.last_message_received).isoformat() 
                                   if self.last_message_received else None,
        }

class ConnectionMonitor:
    """Monitors the health of P2P connections and manages reconnection logic."""
    
    def __init__(self, reconnect_interval: float = 30.0, 
                 health_check_interval: float = 60.0):
        self.connections: Dict[str, ConnectionStats] = {}
        self.reconnect_interval = reconnect_interval
        self.health_check_interval = health_check_interval
        self.monitor_task: Optional[asyncio.Task] = None
        self.is_running = False
        
    async def start(self) -> None:
        """Start the connection monitor."""
        if self.monitor_task and not self.monitor_task.done():
            logger.warning("Connection monitor is already running")
            return
            
        self.is_running = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Connection monitor started")
    
    async def stop(self) -> None:
        """Stop the connection monitor."""
        self.is_running = False
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
            self.monitor_task = None
        logger.info("Connection monitor stopped")
    
    def register_connection(self, peer_id: str, address: Tuple[str, int]) -> None:
        """Register a new connection to monitor."""
        if peer_id not in self.connections:
            self.connections[peer_id] = ConnectionStats(peer_id, address)
            logger.info(f"Started monitoring connection to {peer_id} at {address[0]}:{address[1]}")
    
    def unregister_connection(self, peer_id: str) -> None:
        """Stop monitoring a connection."""
        if peer_id in self.connections:
            del self.connections[peer_id]
            logger.info(f"Stopped monitoring connection to {peer_id}")
    
    def record_message_sent(self, peer_id: str, bytes_sent: int) -> None:
        """Record that a message was sent to a peer."""
        if peer_id in self.connections:
            self.connections[peer_id].record_success(bytes_sent=bytes_sent)
    
    def record_message_received(self, peer_id: str, bytes_received: int) -> None:
        """Record that a message was received from a peer."""
        if peer_id in self.connections:
            conn = self.connections[peer_id]
            conn.record_success(bytes_received=bytes_received)
            conn.last_message_received = time.time()
    
    def record_latency(self, peer_id: str, latency: float) -> None:
        """Record the latency for a message round-trip."""
        if peer_id in self.connections:
            self.connections[peer_id].update_latency(latency)
    
    def record_error(self, peer_id: str, error: Exception) -> None:
        """Record an error for a connection."""
        if peer_id in self.connections:
            self.connections[peer_id].record_error(error)
    
    def get_connection_health(self, peer_id: str) -> Optional[Dict[str, any]]:
        """Get health information for a connection."""
        if peer_id in self.connections:
            return self.connections[peer_id].get_summary()
        return None
    
    def get_all_connection_health(self) -> List[Dict[str, any]]:
        """Get health information for all connections."""
        return [conn.get_summary() for conn in self.connections.values()]
    
    def get_unhealthy_connections(self, threshold: float = 0.5) -> List[Dict[str, any]]:
        """Get a list of connections with health scores below the threshold."""
        return [
            conn.get_summary() 
            for conn in self.connections.values() 
            if conn.get_health_score() < threshold
        ]
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop that checks connection health."""
        last_reconnect_attempt = 0.0
        last_health_check = 0.0
        
        while self.is_running:
            current_time = time.time()
            
            # Periodically check connection health
            if current_time - last_health_check >= self.health_check_interval:
                await self._check_connection_health()
                last_health_check = current_time
            
            # Attempt to reconnect to failed connections
            if current_time - last_reconnect_attempt >= self.reconnect_interval:
                await self._attempt_reconnects()
                last_reconnect_attempt = current_time
            
            # Sleep to prevent busy-waiting
            await asyncio.sleep(1)
    
    async def _check_connection_health(self) -> None:
        """Check the health of all connections and log status."""
        unhealthy = self.get_unhealthy_connections()
        if unhealthy:
            logger.warning(f"Found {len(unhealthy)} unhealthy connections")
            for conn in unhealthy:
                logger.warning(
                    f"Unhealthy connection to {conn['peer_id']} (score: {conn['health_score']:.2f}): "
                    f"{conn['consecutive_errors']} errors, "
                    f"latency: {conn['average_latency'] or 'N/A'}s"
                )
        else:
            logger.debug("All connections are healthy")
    
    async def _attempt_reconnects(self) -> None:
        """Attempt to reconnect to failed connections."""
        # This would be implemented to work with your P2P node's connection manager
        # to re-establish connections to peers with failed connections
        pass
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
