"""
Heartbeat Service for Scrambled Eggs P2P Network.
Monitors node health and detects network partitions.
"""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Deque, DefaultDict
from collections import deque, defaultdict

from .enhanced_p2p import P2PNetwork

logger = logging.getLogger(__name__)

@dataclass
class HeartbeatStats:
    """Statistics for node heartbeat monitoring."""
    last_seen: float = 0.0
    last_latency: float = 0.0
    response_times: Deque[float] = field(default_factory=deque)
    missed_beats: int = 0
    jitter: float = 0.0
    health_score: float = 1.0  # 1.0 = perfectly healthy, 0.0 = dead

class HeartbeatService:
    """Manages heartbeat monitoring between nodes."""
    
    def __init__(
        self,
        p2p_network: P2PNetwork,
        interval: float = 5.0,
        timeout: float = 10.0,
        window_size: int = 10,
        max_missed: int = 3
    ):
        self.p2p = p2p_network
        self.interval = interval
        self.timeout = timeout
        self.window_size = window_size
        self.max_missed = max_missed
        
        self.stats: Dict[str, HeartbeatStats] = {}
        self.callbacks = {
            'on_node_down': [],
            'on_node_up': [],
            'on_health_change': []
        }
        
        self._running = False
        self._tasks: List[asyncio.Task] = []
        
    def register_callback(self, event: str, callback):
        """Register a callback for heartbeat events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event}")
            
    async def start(self):
        """Start the heartbeat service."""
        if self._running:
            return
            
        self._running = True
        self._tasks = [
            asyncio.create_task(self._monitor_nodes()),
            asyncio.create_task(self._check_timeouts())
        ]
        logger.info("Heartbeat service started")
        
    async def stop(self):
        """Stop the heartbeat service."""
        if not self._running:
            return
            
        self._running = False
        for task in self._tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        logger.info("Heartbeat service stopped")
        
    async def _monitor_nodes(self):
        """Monitor all known nodes with heartbeats."""
        while self._running:
            try:
                # Get list of nodes to monitor
                nodes_to_check = list(self.p2p.connected_peers.keys())
                
                # Send heartbeats in parallel
                tasks = [self._send_heartbeat(node_id) for node_id in nodes_to_check]
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)
                    
                await asyncio.sleep(self.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in node monitoring: {e}")
                await asyncio.sleep(5)  # Back off on error
                
    async def _send_heartbeat(self, node_id: str):
        """Send a heartbeat to a node and record statistics."""
        if node_id not in self.stats:
            self.stats[node_id] = HeartbeatStats()
            
        stats = self.stats[node_id]
        start_time = time.time()
        
        try:
            # Send ping and measure response time
            response = await asyncio.wait_for(
                self.p2p.ping_peer(node_id),
                timeout=self.timeout
            )
            
            # Update statistics
            latency = (time.time() - start_time) * 1000  # Convert to ms
            stats.last_latency = latency
            stats.last_seen = time.time()
            stats.missed_beats = 0
            
            # Update response time window
            stats.response_times.append(latency)
            if len(stats.response_times) > self.window_size:
                stats.response_times.popleft()
                
            # Calculate jitter (standard deviation of last N pings)
            if len(stats.response_times) > 1:
                mean = sum(stats.response_times) / len(stats.response_times)
                variance = sum((x - mean) ** 2 for x in stats.response_times) / len(stats.response_times)
                stats.jitter = variance ** 0.5
                
            # Update health score (higher is better)
            old_score = stats.health_score
            stats.health_score = min(1.0, 1.0 - (stats.jitter / 100.0))  # Simple heuristic
            
            # Notify if node came back up
            if old_score < 0.5 <= stats.health_score:
                await self._trigger_callbacks('on_node_up', node_id, stats)
                
            # Notify of health changes
            if abs(old_score - stats.health_score) > 0.1:
                await self._trigger_callbacks('on_health_change', node_id, stats)
                
        except (asyncio.TimeoutError, Exception) as e:
            stats.missed_beats += 1
            logger.debug(f"Heartbeat to {node_id} failed: {e}")
            
            # If we've missed too many beats, mark as down
            if stats.missed_beats >= self.max_missed:
                stats.health_score = 0.0
                await self._trigger_callbacks('on_node_down', node_id, stats)
                
    async def _check_timeouts(self):
        """Check for nodes that have timed out."""
        while self._running:
            try:
                current_time = time.time()
                
                for node_id, stats in list(self.stats.items()):
                    # Skip if we have a recent response
                    if current_time - stats.last_seen < self.timeout * 2:
                        continue
                        
                    # Mark as down if we haven't heard from the node
                    if stats.health_score > 0:
                        stats.health_score = 0.0
                        await self._trigger_callbacks('on_node_down', node_id, stats)
                        
                await asyncio.sleep(self.interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in timeout check: {e}")
                await asyncio.sleep(5)
                
    async def _trigger_callbacks(self, event: str, node_id: str, stats: HeartbeatStats):
        """Trigger registered callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                await callback(node_id, stats)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}")
                
    def get_node_health(self, node_id: str) -> float:
        """Get the health score of a node (0.0 to 1.0)."""
        return self.stats.get(node_id, HeartbeatStats()).health_score
        
    def get_latency(self, node_id: str) -> float:
        """Get the last measured latency to a node in ms."""
        return self.stats.get(node_id, HeartbeatStats()).last_latency
        
    def get_jitter(self, node_id: str) -> float:
        """Get the current jitter to a node in ms."""
        return self.stats.get(node_id, HeartbeatStats()).jitter
        
    def get_missed_beats(self, node_id: str) -> int:
        """Get the number of consecutive missed heartbeats."""
        return self.stats.get(node_id, HeartbeatStats()).missed_beats
