"""
Traffic Shaping for Adaptive Bandwidth Management.
Implements traffic prioritization and rate limiting.
"""

import asyncio
import logging
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Deque, Tuple, Any, Callable, Awaitable

from ...core.config import settings

logger = logging.getLogger(__name__)

class TrafficClass(Enum):
    """Traffic priority classes."""
    CONTROL = 0        # Critical control messages (highest priority)
    REAL_TIME = 1      # Real-time voice/video
    INTERACTIVE = 2    # Interactive data (e.g., chat, commands)
    BULK = 3           # Bulk data transfer (lowest priority)
    BACKGROUND = 4     # Background tasks (lowest priority, may be throttled)

@dataclass
class TrafficRule:
    """Rule for traffic classification and shaping."""
    priority: int
    match: Dict[str, Any]
    rate_limit: Optional[float] = None  # bytes per second
    burst: Optional[float] = None      # burst size in bytes
    dscp: Optional[int] = None         # Differentiated Services Code Point
    
    def matches(self, packet: Dict[str, Any]) -> bool:
        """Check if this rule matches the given packet."""
        for key, value in self.match.items():
            if key not in packet or packet[key] != value:
                return False
        return True

@dataclass
class TokenBucket:
    """Token bucket for rate limiting."""
    rate: float           # Tokens per second
    capacity: float       # Maximum tokens in bucket
    tokens: float = 0     # Current tokens
    last_update: float = field(default_factory=time.time)
    
    def update(self):
        """Update token count based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now
        
        # Add tokens based on elapsed time
        self.tokens = min(
            self.capacity,
            self.tokens + elapsed * self.rate
        )
    
    def consume(self, tokens: float) -> bool:
        """Try to consume tokens. Returns True if successful."""
        self.update()
        if tokens <= self.tokens:
            self.tokens -= tokens
            return True
        return False

class TrafficShaper:
    """Manages traffic shaping and prioritization."""
    
    def __init__(
        self,
        monitor: 'BandwidthMonitor',
        update_interval: float = 0.1,
        default_rate_limit: Optional[float] = None,
        default_burst: Optional[float] = None
    ):
        self.monitor = monitor
        self.update_interval = update_interval
        self.default_rate_limit = default_rate_limit
        self.default_burst = default_burst or (default_rate_limit * 2 if default_rate_limit else None)
        
        # Traffic rules
        self.rules: List[TrafficRule] = []
        self.default_rule = TrafficRule(
            priority=TrafficClass.BACKGROUND,
            match={},
            rate_limit=default_rate_limit,
            burst=self.default_burst
        )
        
        # Rate limiting state
        self.buckets: Dict[Tuple[str, int], TokenBucket] = {}
        
        # Queues for different traffic classes
        self.queues: Dict[TrafficClass, asyncio.Queue] = {
            cls: asyncio.Queue() for cls in TrafficClass
        }
        
        # Background tasks
        self._running = False
        self._shaping_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            'packets_shaped': 0,
            'packets_dropped': 0,
            'bytes_shaped': 0,
            'bytes_dropped': 0,
            'queue_sizes': {cls: 0 for cls in TrafficClass}
        }
        
        # Initialize default rules
        self._init_default_rules()
    
    def _init_default_rules(self):
        """Initialize default traffic rules."""
        # Control traffic (highest priority, no rate limiting)
        self.add_rule(TrafficRule(
            priority=TrafficClass.CONTROL,
            match={'type': 'control'},
            dscp=46  # EF (Expedited Forwarding)
        ))
        
        # Real-time traffic (high priority, rate limited)
        self.add_rule(TrafficRule(
            priority=TrafficClass.REAL_TIME,
            match={'type': 'webrtc'},
            rate_limit=settings.BANDWIDTH_REALTIME_LIMIT,
            burst=settings.BANDWIDTH_REALTIME_BURST,
            dscp=34  # AF41 (Assured Forwarding)
        ))
        
        # Interactive traffic (medium priority)
        self.add_rule(TrafficRule(
            priority=TrafficClass.INTERACTIVE,
            match={'interactive': True},
            rate_limit=settings.BANDWIDTH_INTERACTIVE_LIMIT,
            burst=settings.BANDWIDTH_INTERACTIVE_BURST,
            dscp=18  # AF21
        ))
        
        # Bulk traffic (low priority)
        self.add_rule(TrafficRule(
            priority=TrafficClass.BULK,
            match={'type': 'bulk'},
            rate_limit=settings.BANDWIDTH_BULK_LIMIT,
            burst=settings.BANDWIDTH_BULK_BURST,
            dscp=10  # AF11
        ))
        
        # Background traffic (lowest priority)
        self.add_rule(TrafficRule(
            priority=TrafficClass.BACKGROUND,
            match={'background': True},
            rate_limit=settings.BANDWIDTH_BACKGROUND_LIMIT,
            burst=settings.BANDWIDTH_BACKGROUND_BURST,
            dscp=0   # Best Effort
        ))
    
    def add_rule(self, rule: TrafficRule):
        """Add a traffic rule."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority.value)
        logger.info(f"Added traffic rule: {rule}")
    
    def remove_rule(self, rule: TrafficRule):
        """Remove a traffic rule."""
        if rule in self.rules:
            self.rules.remove(rule)
            logger.info(f"Removed traffic rule: {rule}")
    
    def classify_packet(self, packet: Dict[str, Any]) -> TrafficRule:
        """Classify a packet and return the matching rule."""
        for rule in self.rules:
            if rule.matches(packet):
                return rule
        return self.default_rule
    
    def get_bucket(self, key: Tuple[str, int]) -> TokenBucket:
        """Get or create a token bucket for the given key."""
        if key not in self.buckets:
            self.buckets[key] = TokenBucket(
                rate=1.0,  # Will be updated by the rule
                capacity=1.0
            )
        return self.buckets[key]
    
    async def shape_packet(self, packet: Dict[str, Any]) -> bool:
        """
        Shape a packet according to traffic rules.
        Returns True if the packet should be sent, False if it was dropped.
        """
        # Classify the packet
        rule = self.classify_packet(packet)
        priority = rule.priority
        
        # Update statistics
        self.stats['packets_shaped'] += 1
        self.stats['bytes_shaped'] += packet.get('size', 0)
        
        # Apply rate limiting if configured
        if rule.rate_limit is not None:
            # Use peer_id if available, otherwise use 'global'
            peer_id = packet.get('peer_id', 'global')
            bucket_key = (peer_id, priority.value)
            
            # Get or create token bucket
            bucket = self.get_bucket(bucket_key)
            bucket.rate = rule.rate_limit or float('inf')
            bucket.capacity = rule.burst or (rule.rate_limit * 2) if rule.rate_limit else float('inf')
            
            # Check if we have enough tokens
            packet_size = packet.get('size', 1)
            if not bucket.consume(packet_size):
                # Rate limit exceeded, drop the packet
                self.stats['packets_dropped'] += 1
                self.stats['bytes_dropped'] += packet_size
                logger.debug(f"Rate limit exceeded for {peer_id}, packet dropped")
                return False
        
        # Enqueue the packet with its priority
        await self.queues[priority].put(packet)
        self.stats['queue_sizes'][priority] = self.queues[priority].qsize()
        
        return True
    
    async def get_next_packet(self) -> Optional[Dict]:
        """Get the next packet to send, according to priority."""
        # Check queues in priority order
        for priority in sorted(TrafficClass, key=lambda x: x.value):
            if not self.queues[priority].empty():
                packet = await self.queues[priority].get()
                self.stats['queue_sizes'][priority] = self.queues[priority].qsize()
                return packet
        return None
    
    async def start(self):
        """Start the traffic shaper."""
        if self._running:
            return
            
        self._running = True
        self._shaping_task = asyncio.create_task(self._shaping_loop())
        logger.info("Traffic shaper started")
    
    async def stop(self):
        """Stop the traffic shaper."""
        if not self._running:
            return
            
        self._running = False
        if self._shaping_task and not self._shaping_task.done():
            self._shaping_task.cancel()
            try:
                await self._shaping_task
            except asyncio.CancelledError:
                pass
        logger.info("Traffic shaper stopped")
    
    async def _shaping_loop(self):
        """Background task to handle traffic shaping."""
        while self._running:
            try:
                # Process packets from queues
                packet = await self.get_next_packet()
                if packet:
                    # In a real implementation, we would send the packet here
                    # For now, we just log it
                    logger.debug(f"Sending packet: {packet}")
                
                # Sleep to prevent busy-waiting
                await asyncio.sleep(self.update_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in shaping loop: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    def get_stats(self) -> Dict[str, Any]:
        """Get traffic shaping statistics."""
        return {
            **self.stats,
            'active_rules': len(self.rules),
            'active_buckets': len(self.buckets),
            'queue_sizes': {cls.name: size for cls, size in self.stats['queue_sizes'].items()}
        }

# Example usage:
if __name__ == "__main__":
    import asyncio
    from dataclasses import asdict
    from ...network.bandwidth.monitor import BandwidthMonitor
    
    async def test_shaper():
        monitor = BandwidthMonitor()
        shaper = TrafficShaper(monitor)
        
        await shaper.start()
        
        # Test packets
        packets = [
            {'type': 'control', 'size': 100, 'data': 'control message'},
            {'type': 'webrtc', 'size': 1500, 'data': 'video frame'},
            {'interactive': True, 'size': 500, 'data': 'chat message'},
            {'type': 'bulk', 'size': 5000, 'data': 'file chunk'},
            {'background': True, 'size': 1000, 'data': 'sync data'}
        ]
        
        # Shape some packets
        for packet in packets:
            await shaper.shape_packet(packet)
        
        # Get and print next packets in priority order
        print("Packets in priority order:")
        for _ in range(5):
            packet = await shaper.get_next_packet()
            if packet:
                print(f"  - {packet['data']} (size: {packet['size']})")
        
        # Print statistics
        print("\nTraffic shaping statistics:")
        for k, v in shaper.get_stats().items():
            print(f"  {k}: {v}")
        
        await shaper.stop()
    
    asyncio.run(test_shaper())
