"""
Bandwidth Monitoring for Adaptive Bandwidth Management.
Tracks network usage and performance metrics.
"""

import asyncio
import logging
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Deque, Set, Callable, Awaitable

from ...core.config import settings

logger = logging.getLogger(__name__)

@dataclass
class TrafficStats:
    """Traffic statistics for a connection or peer."""
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    timestamp: float = field(default_factory=time.time)
    
    def add_sent(self, size: int):
        """Add sent data to statistics."""
        self.bytes_sent += size
        self.packets_sent += 1
        self.timestamp = time.time()
        
    def add_received(self, size: int):
        """Add received data to statistics."""
        self.bytes_received += size
        self.packets_received += 1
        self.timestamp = time.time()
        
    def get_throughput(self, interval: float = 1.0) -> Tuple[float, float]:
        """Get throughput in bytes per second."""
        now = time.time()
        elapsed = now - self.timestamp
        if elapsed <= 0:
            return 0.0, 0.0
        return (
            self.bytes_sent / elapsed * interval,
            self.bytes_received / elapsed * interval
        )

@dataclass
class ConnectionMetrics:
    """Metrics for a single connection."""
    peer_id: str
    connection_id: str
    traffic: TrafficStats = field(default_factory=TrafficStats)
    rtt_history: Deque[float] = field(default_factory=deque)
    jitter: float = 0.0
    loss_rate: float = 0.0
    last_updated: float = field(default_factory=time.time)
    
    def update_rtt(self, rtt: float):
        """Update round-trip time metrics."""
        self.rtt_history.append(rtt)
        if len(self.rtt_history) > settings.BANDWIDTH_RTT_WINDOW:
            self.rtt_history.popleft()
        
        # Calculate jitter (average deviation from mean)
        if len(self.rtt_history) > 1:
            mean = sum(self.rtt_history) / len(self.rtt_history)
            deviations = [abs(rtt - mean) for rtt in self.rtt_history]
            self.jitter = sum(deviations) / len(deviations)
        
        self.last_updated = time.time()
    
    def get_avg_rtt(self) -> float:
        """Get average round-trip time."""
        if not self.rtt_history:
            return 0.0
        return sum(self.rtt_history) / len(self.rtt_history)

class BandwidthMonitor:
    """Monitors bandwidth usage and network conditions."""
    
    def __init__(
        self,
        update_interval: float = 1.0,
        history_size: int = 60,
        window_size: int = 10
    ):
        self.update_interval = update_interval
        self.history_size = history_size
        self.window_size = window_size
        
        # Connection tracking
        self.connections: Dict[str, ConnectionMetrics] = {}
        self.peer_connections: Dict[str, Set[str]] = defaultdict(set)
        
        # History for rate calculations
        self.history: Deque[Dict] = deque(maxlen=history_size)
        
        # Callbacks
        self.callbacks = {
            'on_congestion': [],
            'on_recovery': [],
            'on_threshold': []
        }
        
        # Background tasks
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
    def register_callback(self, event: str, callback: Callable[[Dict], Awaitable[None]]):
        """Register a callback for monitoring events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event}")
    
    async def start(self):
        """Start the bandwidth monitor."""
        if self._running:
            return
            
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Bandwidth monitor started")
    
    async def stop(self):
        """Stop the bandwidth monitor."""
        if not self._running:
            return
            
        self._running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Bandwidth monitor stopped")
    
    def register_connection(self, peer_id: str, connection_id: str) -> ConnectionMetrics:
        """Register a new connection for monitoring."""
        if connection_id in self.connections:
            return self.connections[connection_id]
            
        metrics = ConnectionMetrics(peer_id=peer_id, connection_id=connection_id)
        self.connections[connection_id] = metrics
        self.peer_connections[peer_id].add(connection_id)
        logger.debug(f"Registered connection {connection_id} for peer {peer_id}")
        return metrics
    
    def unregister_connection(self, connection_id: str):
        """Remove a connection from monitoring."""
        if connection_id in self.connections:
            peer_id = self.connections[connection_id].peer_id
            self.peer_connections[peer_id].discard(connection_id)
            if not self.peer_connections[peer_id]:
                del self.peer_connections[peer_id]
            del self.connections[connection_id]
            logger.debug(f"Unregistered connection {connection_id}")
    
    def record_sent(self, connection_id: str, size: int):
        """Record data sent on a connection."""
        if connection_id in self.connections:
            self.connections[connection_id].traffic.add_sent(size)
    
    def record_received(self, connection_id: str, size: int):
        """Record data received on a connection."""
        if connection_id in self.connections:
            self.connections[connection_id].traffic.add_received(size)
    
    def update_rtt(self, connection_id: str, rtt: float):
        """Update round-trip time for a connection."""
        if connection_id in self.connections:
            self.connections[connection_id].update_rtt(rtt)
    
    def get_peer_metrics(self, peer_id: str) -> Dict[str, Any]:
        """Get aggregated metrics for a peer."""
        if peer_id not in self.peer_connections:
            return {}
            
        metrics = {
            'connections': 0,
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'avg_rtt': 0.0,
            'jitter': 0.0,
            'loss_rate': 0.0,
            'throughput_up': 0.0,
            'throughput_down': 0.0
        }
        
        connections = self.peer_connections[peer_id]
        if not connections:
            return metrics
            
        metrics['connections'] = len(connections)
        
        # Aggregate metrics across all connections
        for conn_id in connections:
            conn = self.connections[conn_id]
            metrics['bytes_sent'] += conn.traffic.bytes_sent
            metrics['bytes_received'] += conn.traffic.bytes_received
            metrics['packets_sent'] += conn.traffic.packets_sent
            metrics['packets_received'] += conn.traffic.packets_received
            metrics['avg_rtt'] += conn.get_avg_rtt()
            metrics['jitter'] += conn.jitter
            metrics['loss_rate'] += conn.loss_rate
            
            up, down = conn.traffic.get_throughput()
            metrics['throughput_up'] += up
            metrics['throughput_down'] += down
        
        # Calculate averages
        metrics['avg_rtt'] /= len(connections)
        metrics['jitter'] /= len(connections)
        metrics['loss_rate'] /= len(connections)
        
        return metrics
    
    def get_network_metrics(self) -> Dict[str, Any]:
        """Get aggregated metrics for the entire network."""
        metrics = {
            'peers': len(self.peer_connections),
            'connections': len(self.connections),
            'bytes_sent': 0,
            'bytes_received': 0,
            'packets_sent': 0,
            'packets_received': 0,
            'throughput_up': 0.0,
            'throughput_down': 0.0
        }
        
        for peer_id in self.peer_connections:
            peer_metrics = self.get_peer_metrics(peer_id)
            if not peer_metrics:
                continue
                
            metrics['bytes_sent'] += peer_metrics['bytes_sent']
            metrics['bytes_received'] += peer_metrics['bytes_received']
            metrics['packets_sent'] += peer_metrics['packets_sent']
            metrics['packets_received'] += peer_metrics['packets_received']
            metrics['throughput_up'] += peer_metrics['throughput_up']
            metrics['throughput_down'] += peer_metrics['throughput_down']
        
        return metrics
    
    async def _monitor_loop(self):
        """Background task to monitor bandwidth usage."""
        last_update = time.time()
        
        while self._running:
            try:
                # Calculate time since last update
                now = time.time()
                elapsed = now - last_update
                last_update = now
                
                if elapsed <= 0:
                    await asyncio.sleep(self.update_interval)
                    continue
                
                # Collect metrics
                metrics = self.get_network_metrics()
                metrics['timestamp'] = now
                
                # Add to history
                self.history.append(metrics)
                
                # Check for congestion
                await self._check_congestion(metrics)
                
                # Sleep until next update
                sleep_time = max(0, self.update_interval - (time.time() - now))
                await asyncio.sleep(sleep_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitor loop: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    async def _check_congestion(self, metrics: Dict[str, Any]):
        """Check for network congestion based on metrics."""
        # Simple congestion detection based on packet loss and RTT
        # In a real implementation, this would be more sophisticated
        
        # Check for high packet loss
        if metrics.get('loss_rate', 0) > settings.BANDWIDTH_LOSS_THRESHOLD:
            await self._trigger_callbacks('on_congestion', {
                'reason': 'high_packet_loss',
                'loss_rate': metrics['loss_rate'],
                'threshold': settings.BANDWIDTH_LOSS_THRESHOLD
            })
        
        # Check for high latency
        avg_rtt = metrics.get('avg_rtt', 0)
        if avg_rtt > settings.BANDWIDTH_RTT_THRESHOLD:
            await self._trigger_callbacks('on_congestion', {
                'reason': 'high_latency',
                'rtt': avg_rtt,
                'threshold': settings.BANDWIDTH_RTT_THRESHOLD
            })
    
    async def _trigger_callbacks(self, event: str, data: Dict):
        """Trigger registered callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                await callback(data)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}")

# Example usage:
if __name__ == "__main__":
    import asyncio
    
    async def test_monitor():
        monitor = BandwidthMonitor(update_interval=1.0)
        await monitor.start()
        
        # Register a test connection
        conn = monitor.register_connection("peer1", "conn1")
        
        # Simulate some traffic
        for _ in range(5):
            monitor.record_sent("conn1", 1500)  # 1500 bytes per packet
            monitor.record_received("conn1", 1000)
            monitor.update_rtt("conn1", 0.05)  # 50ms RTT
            await asyncio.sleep(0.5)
        
        # Get metrics
        print("Peer metrics:", monitor.get_peer_metrics("peer1"))
        print("Network metrics:", monitor.get_network_metrics())
        
        await monitor.stop()
    
    asyncio.run(test_monitor())
