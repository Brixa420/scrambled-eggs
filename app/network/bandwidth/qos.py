"""
Quality of Service (QoS) Management for Adaptive Bandwidth.
Implements traffic prioritization, scheduling, and policy enforcement.
"""

import asyncio
import logging
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Deque, Tuple, Any, Callable, Awaitable

from ...core.config import settings
from .monitor import BandwidthMonitor
from .shaper import TrafficShaper, TrafficClass, TrafficRule

logger = logging.getLogger(__name__)

class QoSClass(Enum):
    """QoS classes based on Differentiated Services (DiffServ) standards."""
    # Network Control (highest priority)
    NETWORK_CONTROL = (0, 0, 0, 0, "Network Control")
    
    # Expedited Forwarding (EF) - for low-loss, low-latency traffic
    EXPEDITED_FORWARDING = (1, 46, 0.1, 0.2, "Expedited Forwarding")
    
    # Assured Forwarding (AF) classes - for traffic with different drop precedences
    AF41 = (2, 34, 0.2, 0.3, "AF41 - High Priority")
    AF42 = (3, 36, 0.2, 0.3, "AF42 - High Priority")
    AF43 = (4, 38, 0.2, 0.3, "AF43 - High Priority")
    AF31 = (5, 26, 0.15, 0.25, "AF31 - Medium Priority")
    AF32 = (6, 28, 0.15, 0.25, "AF32 - Medium Priority")
    AF33 = (7, 30, 0.15, 0.25, "AF33 - Medium Priority")
    AF21 = (8, 18, 0.1, 0.2, "AF21 - Low Priority")
    AF22 = (9, 20, 0.1, 0.2, "AF22 - Low Priority")
    AF23 = (10, 22, 0.1, 0.2, "AF23 - Low Priority")
    AF11 = (11, 10, 0.05, 0.1, "AF11 - Background")
    AF12 = (12, 12, 0.05, 0.1, "AF12 - Background")
    AF13 = (13, 14, 0.05, 0.1, "AF13 - Background")
    
    # Best Effort (default)
    BEST_EFFORT = (14, 0, 0.0, 0.0, "Best Effort")
    
    def __init__(self, priority: int, dscp: int, min_share: float, max_share: float, description: str):
        self.priority = priority
        self.dscp = dscp
        self.min_share = min_share
        self.max_share = max_share
        self.description = description
    
    @classmethod
    def from_dscp(cls, dscp: int) -> 'QoSClass':
        """Get QoS class from DSCP value."""
        for qos_class in cls:
            if qos_class.dscp == dscp:
                return qos_class
        return cls.BEST_EFFORT

@dataclass
class QoSProfile:
    """QoS profile for a traffic flow or peer."""
    qos_class: QoSClass
    min_bandwidth: Optional[float] = None  # Minimum guaranteed bandwidth (bps)
    max_bandwidth: Optional[float] = None  # Maximum allowed bandwidth (bps)
    max_latency: Optional[float] = None    # Maximum allowed latency (seconds)
    max_loss: Optional[float] = None       # Maximum allowed packet loss (0-1)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'qos_class': self.qos_class.name,
            'min_bandwidth': self.min_bandwidth,
            'max_bandwidth': self.max_bandwidth,
            'max_latency': self.max_latency,
            'max_loss': self.max_loss
        }

class QoSManager:
    """Manages Quality of Service for the network."""
    
    def __init__(
        self,
        monitor: BandwidthMonitor,
        shaper: TrafficShaper,
        update_interval: float = 1.0
    ):
        self.monitor = monitor
        self.shaper = shaper
        self.update_interval = update_interval
        
        # QoS profiles by peer and traffic type
        self.profiles: Dict[Tuple[str, str], QoSProfile] = {}
        self.default_profile = QoSProfile(
            qos_class=QoSClass.BEST_EFFORT,
            min_bandwidth=None,
            max_bandwidth=None,
            max_latency=None,
            max_loss=None
        )
        
        # Bandwidth allocation
        self.total_bandwidth = settings.BANDWIDTH_TOTAL  # Total available bandwidth (bps)
        self.allocated_bandwidth: Dict[QoSClass, float] = defaultdict(float)
        
        # Callbacks
        self.callbacks = {
            'on_violation': [],
            'on_recovery': [],
            'on_allocation_change': []
        }
        
        # Background tasks
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'dropped_packets': 0,
            'violations': 0,
            'recoveries': 0,
            'bandwidth_utilization': 0.0,
            'allocation': {qos_class.name: 0.0 for qos_class in QoSClass}
        }
        
        # Initialize bandwidth allocation
        self._init_bandwidth_allocation()
    
    def _init_bandwidth_allocation(self):
        """Initialize bandwidth allocation based on QoS classes."""
        # Reset allocations
        self.allocated_bandwidth = defaultdict(float)
        
        # Allocate minimum guaranteed bandwidth first
        remaining_bandwidth = self.total_bandwidth
        
        # Allocate minimum guarantees
        for qos_class in sorted(QoSClass, key=lambda x: x.priority):
            min_bandwidth = qos_class.min_share * self.total_bandwidth
            if remaining_bandwidth >= min_bandwidth:
                self.allocated_bandwidth[qos_class] = min_bandwidth
                remaining_bandwidth -= min_bandwidth
            else:
                self.allocated_bandwidth[qos_class] = remaining_bandwidth
                remaining_bandwidth = 0
                break
        
        # Distribute remaining bandwidth according to max shares
        if remaining_bandwidth > 0:
            total_max_share = sum(
                qos_class.max_share for qos_class in QoSClass 
                if qos_class.max_share > 0
            )
            
            if total_max_share > 0:
                for qos_class in sorted(QoSClass, key=lambda x: x.priority):
                    if qos_class.max_share > 0:
                        additional = (qos_class.max_share / total_max_share) * remaining_bandwidth
                        self.allocated_bandwidth[qos_class] += additional
        
        # Update statistics
        self._update_statistics()
    
    def _update_statistics(self):
        """Update QoS statistics."""
        # Update bandwidth allocation statistics
        for qos_class in QoSClass:
            self.stats['allocation'][qos_class.name] = (
                self.allocated_bandwidth.get(qos_class, 0) / self.total_bandwidth
                if self.total_bandwidth > 0 else 0
            )
    
    def register_callback(self, event: str, callback: Callable[[Dict], Awaitable[None]]):
        """Register a callback for QoS events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event}")
    
    def set_profile(
        self,
        peer_id: str,
        traffic_type: str,
        profile: QoSProfile
    ) -> None:
        """Set QoS profile for a peer and traffic type."""
        self.profiles[(peer_id, traffic_type)] = profile
        logger.info(f"Set QoS profile for {peer_id}/{traffic_type}: {profile.qos_class.name}")
        
        # Update traffic shaping rules based on the new profile
        self._update_traffic_rules()
    
    def get_profile(self, peer_id: str, traffic_type: str) -> QoSProfile:
        """Get QoS profile for a peer and traffic type."""
        return self.profiles.get(
            (peer_id, traffic_type),
            self.default_profile
        )
    
    def _update_traffic_rules(self):
        """Update traffic shaping rules based on current QoS profiles."""
        # Clear existing rules (except defaults)
        self.shaper.rules = [
            rule for rule in self.shaper.rules 
            if rule.priority == TrafficClass.CONTROL
        ]
        
        # Add rules for each QoS class
        for (peer_id, traffic_type), profile in self.profiles.items():
            # Map QoS class to traffic class
            if profile.qos_class == QoSClass.EXPEDITED_FORWARDING:
                traffic_class = TrafficClass.REAL_TIME
            elif profile.qos_class in [QoSClass.AF41, QoSClass.AF42, QoSClass.AF43, 
                                     QoSClass.AF31, QoSClass.AF32, QoSClass.AF33]:
                traffic_class = TrafficClass.INTERACTIVE
            elif profile.qos_class in [QoSClass.AF21, QoSClass.AF22, QoSClass.AF23]:
                traffic_class = TrafficClass.BULK
            else:
                traffic_class = TrafficClass.BACKGROUND
            
            # Create traffic rule
            rule = TrafficRule(
                priority=traffic_class,
                match={
                    'peer_id': peer_id,
                    'type': traffic_type
                },
                rate_limit=profile.max_bandwidth,
                burst=profile.max_bandwidth * 2 if profile.max_bandwidth else None,
                dscp=profile.qos_class.dscp
            )
            
            self.shaper.add_rule(rule)
    
    async def check_qos_violations(self):
        """Check for QoS violations and take corrective actions."""
        # Get current network metrics
        metrics = self.monitor.get_network_metrics()
        
        # Check each peer's traffic against their QoS profiles
        for (peer_id, traffic_type), profile in self.profiles.items():
            peer_metrics = self.monitor.get_peer_metrics(peer_id)
            
            # Check latency violation
            if (profile.max_latency is not None and 
                    peer_metrics.get('avg_rtt', 0) > profile.max_latency):
                await self._handle_violation(
                    peer_id, 
                    traffic_type, 
                    'high_latency',
                    f"Latency {peer_metrics.get('avg_rtt', 0):.3f}s exceeds "
                    f"maximum {profile.max_latency}s"
                )
            
            # Check packet loss violation
            if (profile.max_loss is not None and 
                    peer_metrics.get('loss_rate', 0) > profile.max_loss):
                await self._handle_violation(
                    peer_id,
                    traffic_type,
                    'high_loss',
                    f"Packet loss {peer_metrics.get('loss_rate', 0):.1%} exceeds "
                    f"maximum {profile.max_loss:.1%}"
                )
            
            # Check bandwidth violation (if max_bandwidth is set)
            if profile.max_bandwidth is not None:
                throughput = peer_metrics.get('throughput_up', 0) + peer_metrics.get('throughput_down', 0)
                if throughput > profile.max_bandwidth * 1.1:  # 10% tolerance
                    await self._handle_violation(
                        peer_id,
                        traffic_type,
                        'bandwidth_exceeded',
                        f"Bandwidth {throughput/1e6:.2f}Mbps exceeds "
                        f"maximum {profile.max_bandwidth/1e6:.2f}Mbps"
                    )
    
    async def _handle_violation(
        self,
        peer_id: str,
        traffic_type: str,
        violation_type: str,
        message: str
    ):
        """Handle a QoS violation."""
        self.stats['violations'] += 1
        logger.warning(f"QoS violation for {peer_id}/{traffic_type}: {message}")
        
        # Trigger callbacks
        await self._trigger_callbacks('on_violation', {
            'peer_id': peer_id,
            'traffic_type': traffic_type,
            'violation_type': violation_type,
            'message': message,
            'timestamp': time.time()
        })
        
        # Take corrective actions based on violation type
        if violation_type == 'high_latency':
            await self._handle_high_latency(peer_id, traffic_type)
        elif violation_type == 'high_loss':
            await self._handle_high_loss(peer_id, traffic_type)
        elif violation_type == 'bandwidth_exceeded':
            await self._handle_bandwidth_exceeded(peer_id, traffic_type)
    
    async def _handle_high_latency(self, peer_id: str, traffic_type: str):
        """Handle high latency violation."""
        # Try to reduce latency by increasing priority temporarily
        profile = self.get_profile(peer_id, traffic_type)
        if profile.qos_class.priority > QoSClass.EXPEDITED_FORWARDING.priority:
            # Upgrade to a higher QoS class temporarily
            new_priority = max(1, profile.qos_class.priority - 2)  # Move up 2 priority levels
            new_qos_class = next(
                (q for q in QoSClass if q.priority == new_priority),
                profile.qos_class
            )
            
            # Create a temporary profile
            temp_profile = QoSProfile(
                qos_class=new_qos_class,
                min_bandwidth=profile.min_bandwidth,
                max_bandwidth=profile.max_bandwidth,
                max_latency=profile.max_latency,
                max_loss=profile.max_loss
            )
            
            # Apply temporary profile
            self.set_profile(peer_id, f"{traffic_type}_temp", temp_profile)
            
            # Schedule reversion after some time
            asyncio.create_task(self._revert_temporary_profile(peer_id, traffic_type, 30.0))
    
    async def _handle_high_loss(self, peer_id: str, traffic_type: str):
        """Handle high packet loss violation."""
        # Reduce sending rate to allow recovery
        profile = self.get_profile(peer_id, traffic_type)
        if profile.max_bandwidth is not None:
            # Reduce bandwidth by 20%
            new_bandwidth = profile.max_bandwidth * 0.8
            profile.max_bandwidth = max(new_bandwidth, 10000)  # Minimum 10Kbps
            self.set_profile(peer_id, traffic_type, profile)
    
    async def _handle_bandwidth_exceeded(self, peer_id: str, traffic_type: str):
        """Handle bandwidth exceeded violation."""
        # Enforce bandwidth limits more strictly
        profile = self.get_profile(peer_id, traffic_type)
        if profile.max_bandwidth is not None:
            # Reduce bandwidth allocation for this flow
            self.allocated_bandwidth[profile.qos_class] = max(
                profile.qos_class.min_share * self.total_bandwidth,
                self.allocated_bandwidth.get(profile.qos_class, 0) * 0.9  # Reduce by 10%
            )
            self._update_statistics()
    
    async def _revert_temporary_profile(self, peer_id: str, traffic_type: str, delay: float):
        """Revert a temporary QoS profile after a delay."""
        await asyncio.sleep(delay)
        temp_key = (peer_id, f"{traffic_type}_temp")
        if temp_key in self.profiles:
            del self.profiles[temp_key]
            logger.info(f"Reverted temporary QoS profile for {peer_id}/{traffic_type}")
    
    async def _monitor_loop(self):
        """Background task to monitor QoS metrics."""
        while self._running:
            try:
                # Check for QoS violations
                await self.check_qos_violations()
                
                # Update bandwidth allocation based on current conditions
                self._update_bandwidth_allocation()
                
                # Sleep until next update
                await asyncio.sleep(self.update_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in QoS monitor loop: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    def _update_bandwidth_allocation(self):
        """Dynamically adjust bandwidth allocation based on current conditions."""
        # This is a simplified implementation
        # In a real system, you would use more sophisticated algorithms
        
        # Get current network utilization
        metrics = self.monitor.get_network_metrics()
        total_used = metrics.get('throughput_up', 0) + metrics.get('throughput_down', 0)
        utilization = total_used / self.total_bandwidth if self.total_bandwidth > 0 else 0
        
        # Update statistics
        self.stats['bandwidth_utilization'] = utilization
        
        # If we're approaching capacity, reduce lower-priority allocations
        if utilization > 0.8:  # 80% utilization
            self._adjust_allocations_for_congestion()
        else:
            # Otherwise, try to restore allocations
            self._relax_allocations()
    
    def _adjust_allocations_for_congestion(self):
        """Adjust bandwidth allocations to handle network congestion."""
        # Reduce allocations for lower-priority traffic
        for qos_class in sorted(QoSClass, key=lambda x: -x.priority):  # Lowest priority first
            if qos_class.priority >= QoSClass.BEST_EFFORT.priority:
                # Reduce best effort traffic first
                reduction = self.allocated_bandwidth.get(qos_class, 0) * 0.1  # 10% reduction
                self.allocated_bandwidth[qos_class] -= reduction
                
                # Redistribute to higher-priority traffic
                for higher_prio in sorted(QoSClass, key=lambda x: x.priority):
                    if higher_prio.priority < qos_class.priority:
                        self.allocated_bandwidth[higher_prio] += reduction / qos_class.priority
                        reduction = 0
                        break
    
    def _relax_allocations(self):
        """Gradually relax bandwidth allocations when the network is not congested."""
        # Find underutilized classes and redistribute bandwidth
        for qos_class in sorted(QoSClass, key=lambda x: x.priority):  # Highest priority first
            current = self.allocated_bandwidth.get(qos_class, 0)
            max_allowed = qos_class.max_share * self.total_bandwidth
            
            if current < max_allowed:
                # This class could use more bandwidth
                increase = min(
                    max_allowed - current,
                    self.total_bandwidth * 0.01  # 1% increase per iteration
                )
                
                # Take from lower-priority classes
                remaining = increase
                for lower_prio in sorted(QoSClass, key=lambda x: -x.priority):
                    if lower_prio.priority <= qos_class.priority:
                        continue
                        
                    available = self.allocated_bandwidth.get(lower_prio, 0) - \
                               (lower_prio.min_share * self.total_bandwidth)
                    
                    if available > 0:
                        take = min(available, remaining)
                        self.allocated_bandwidth[lower_prio] -= take
                        self.allocated_bandwidth[qos_class] += take
                        remaining -= take
                        
                        if remaining <= 0:
                            break
    
    async def _trigger_callbacks(self, event: str, data: Dict):
        """Trigger registered callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                await callback(data)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}")
    
    async def start(self):
        """Start the QoS manager."""
        if self._running:
            return
            
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("QoS manager started")
    
    async def stop(self):
        """Stop the QoS manager."""
        if not self._running:
            return
            
        self._running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("QoS manager stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get QoS statistics and metrics."""
        return {
            **self.stats,
            'active_profiles': len(self.profiles),
            'total_bandwidth': self.total_bandwidth,
            'allocated_bandwidth': {
                qos_class.name: allocated 
                for qos_class, allocated in self.allocated_bandwidth.items()
            }
        }

# Example usage:
if __name__ == "__main__":
    import asyncio
    from ...network.bandwidth.monitor import BandwidthMonitor
    from .shaper import TrafficShaper
    
    async def test_qos_manager():
        monitor = BandwidthMonitor()
        shaper = TrafficShaper(monitor)
        qos_manager = QoSManager(monitor, shaper)
        
        await qos_manager.start()
        
        # Define a QoS profile for video streaming
        video_profile = QoSProfile(
            qos_class=QoSClass.EXPEDITED_FORWARDING,
            min_bandwidth=2_000_000,  # 2 Mbps
            max_bandwidth=5_000_000,  # 5 Mbps
            max_latency=0.1,          # 100ms
            max_loss=0.01             # 1%
        )
        
        # Set the profile for a peer
        qos_manager.set_profile("peer1", "video", video_profile)
        
        # Print initial stats
        print("Initial QoS stats:")
        for k, v in qos_manager.get_stats().items():
            print(f"  {k}: {v}")
        
        # Simulate some traffic
        for _ in range(5):
            await asyncio.sleep(1)
            print("\nCurrent QoS stats:")
            stats = qos_manager.get_stats()
            for k, v in stats.items():
                if k == 'allocation':
                    print(f"  {k}:")
                    for cls, alloc in v.items():
                        print(f"    {cls}: {alloc:.1%}")
                else:
                    print(f"  {k}: {v}")
        
        await qos_manager.stop()
    
    asyncio.run(test_qos_manager())
