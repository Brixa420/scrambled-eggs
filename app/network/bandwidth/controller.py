"""
Adaptive Bandwidth Controller for Scrambled Eggs P2P Network.
Implements adaptive algorithms to optimize network performance based on real-time conditions.
"""

import asyncio
import logging
import time
import math
from collections import deque, defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Deque, Tuple, Any, Callable, Awaitable

from ...core.config import settings
from .monitor import BandwidthMonitor
from .shaper import TrafficShaper, TrafficClass
from .qos import QoSManager, QoSClass, QoSProfile

logger = logging.getLogger(__name__)

class NetworkCondition(Enum):
    """Network condition states."""
    OPTIMAL = auto()      # Network is operating optimally
    CONGESTED = auto()    # Network is congested
    DEGRADED = auto()     # Network performance is degraded
    RECOVERING = auto()   # Network is recovering from issues
    CRITICAL = auto()     # Critical network issues detected

@dataclass
class AdaptationState:
    """State for adaptive algorithms."""
    current_condition: NetworkCondition = NetworkCondition.OPTIMAL
    last_condition_change: float = field(default_factory=time.time)
    condition_duration: float = 0.0
    metrics_history: Deque[Dict] = field(default_factory=deque)
    
    def update_condition(self, new_condition: NetworkCondition):
        """Update the current network condition."""
        now = time.time()
        self.condition_duration = now - self.last_condition_change
        
        if new_condition != self.current_condition:
            logger.info(
                f"Network condition changed from {self.current_condition.name} "
                f"to {new_condition.name} after {self.condition_duration:.1f}s"
            )
            self.current_condition = new_condition
            self.last_condition_change = now
            self.condition_duration = 0.0
            return True
        return False
    
    def add_metrics(self, metrics: Dict):
        """Add metrics to history."""
        self.metrics_history.append({
            'timestamp': time.time(),
            'metrics': metrics
        })
        # Keep only recent history
        while len(self.metrics_history) > settings.BANDWIDTH_HISTORY_SIZE:
            self.metrics_history.popleft()

class AdaptiveController:
    """
    Adaptive controller that manages bandwidth allocation and traffic shaping
    based on real-time network conditions.
    """
    
    def __init__(
        self,
        monitor: BandwidthMonitor,
        shaper: TrafficShaper,
        qos_manager: QoSManager,
        update_interval: float = 1.0,
        history_size: int = 60
    ):
        self.monitor = monitor
        self.shaper = shaper
        self.qos_manager = qos_manager
        self.update_interval = update_interval
        self.history_size = history_size
        
        # Adaptive state
        self.state = AdaptationState()
        
        # Configuration
        self.min_bitrate = settings.BANDWIDTH_MIN_BITRATE  # Minimum bitrate per stream (bps)
        self.max_bitrate = settings.BANDWIDTH_MAX_BITRATE  # Maximum bitrate per stream (bps)
        self.target_latency = settings.BANDWIDTH_TARGET_LATENCY  # Target latency (seconds)
        self.target_loss = settings.BANDWIDTH_TARGET_LOSS  # Target packet loss rate (0-1)
        
        # Callbacks
        self.callbacks = {
            'on_condition_change': [],
            'on_adaptation': [],
            'on_emergency': []
        }
        
        # Background tasks
        self._running = False
        self._control_task: Optional[asyncio.Task] = None
        
        # Statistics
        self.stats = {
            'total_adaptations': 0,
            'last_adaptation': 0.0,
            'adaptation_history': deque(maxlen=100)
        }
        
        # Register callbacks
        self._register_callbacks()
    
    def _register_callbacks(self):
        """Register callbacks with the monitor and QoS manager."""
        self.qos_manager.register_callback('on_violation', self._on_qos_violation)
        self.qos_manager.register_callback('on_recovery', self._on_qos_recovery)
    
    async def _on_qos_violation(self, data: Dict):
        """Handle QoS violation events."""
        logger.warning(
            f"QoS violation for {data['peer_id']}/{data['traffic_type']}: "
            f"{data['violation_type']} - {data['message']}"
        )
        
        # Trigger adaptation based on the violation type
        if data['violation_type'] in ['high_latency', 'high_loss']:
            await self.adapt_to_condition(NetworkCondition.CONGESTED)
    
    async def _on_qos_recovery(self, data: Dict):
        """Handle QoS recovery events."""
        logger.info(
            f"QoS recovered for {data['peer_id']}/{data['traffic_type']}: "
            f"{data['message']}"
        )
        
        # If conditions have improved, consider moving to a better state
        if self.state.current_condition != NetworkCondition.OPTIMAL:
            await self.assess_network_conditions()
    
    async def assess_network_conditions(self) -> NetworkCondition:
        """
        Assess current network conditions and determine the appropriate state.
        Returns the detected network condition.
        """
        # Get current metrics
        metrics = self.monitor.get_network_metrics()
        
        # Calculate key metrics
        total_throughput = metrics.get('throughput_up', 0) + metrics.get('throughput_down', 0)
        avg_rtt = metrics.get('avg_rtt', 0)
        loss_rate = metrics.get('loss_rate', 0)
        
        # Check for critical conditions
        if loss_rate > settings.BANDWIDTH_CRITICAL_LOSS:
            return NetworkCondition.CRITICAL
        
        # Check for congestion
        if (avg_rtt > settings.BANDWIDTH_CONGESTED_RTT or 
                loss_rate > settings.BANDWIDTH_CONGESTED_LOSS):
            return NetworkCondition.CONGESTED
        
        # Check for degraded performance
        if (avg_rtt > settings.BANDWIDTH_DEGRADED_RTT or 
                loss_rate > settings.BANDWIDTH_DEGRADED_LOSS):
            return NetworkCondition.DEGRADED
        
        # Check if we're recovering
        if self.state.current_condition in [NetworkCondition.CONGESTED, NetworkCondition.CRITICAL]:
            # Stay in recovery mode for a minimum time
            if self.state.condition_duration < settings.BANDWIDTH_RECOVERY_TIME:
                return NetworkCondition.RECOVERING
            
            # Check if metrics have stabilized
            if (avg_rtt < settings.BANDWIDTH_OPTIMAL_RTT and 
                    loss_rate < settings.BANDWIDTH_OPTIMAL_LOSS):
                return NetworkCondition.OPTIMAL
            else:
                return NetworkCondition.RECOVERING
        
        # Default to optimal conditions
        return NetworkCondition.OPTIMAL
    
    async def adapt_to_condition(self, condition: NetworkCondition):
        """
        Adapt network behavior based on the detected condition.
        
        Args:
            condition: The detected network condition
        """
        # Update the current condition
        condition_changed = self.state.update_condition(condition)
        
        # Take actions based on the condition
        if condition == NetworkCondition.OPTIMAL:
            await self._handle_optimal_condition()
        elif condition == NetworkCondition.DEGRADED:
            await self._handle_degraded_condition()
        elif condition == NetworkCondition.CONGESTED:
            await self._handle_congested_condition()
        elif condition == NetworkCondition.CRITICAL:
            await self._handle_critical_condition()
        elif condition == NetworkCondition.RECOVERING:
            await self._handle_recovering_condition()
        
        # Log and notify about the adaptation
        if condition_changed or condition in [NetworkCondition.CONGESTED, NetworkCondition.CRITICAL]:
            logger.info(f"Adapted to {condition.name} condition")
            self.stats['total_adaptations'] += 1
            self.stats['last_adaptation'] = time.time()
            self.stats['adaptation_history'].append({
                'timestamp': time.time(),
                'condition': condition.name,
                'metrics': self.monitor.get_network_metrics()
            })
            
            # Notify listeners
            await self._trigger_callbacks('on_condition_change', {
                'condition': condition.name,
                'timestamp': time.time(),
                'metrics': self.monitor.get_network_metrics()
            })
    
    async def _handle_optimal_condition(self):
        """Handle optimal network conditions."""
        # Gradually increase bandwidth for high-priority traffic
        for qos_class in [QoSClass.EXPEDITED_FORWARDING, QoSClass.AF41, QoSClass.AF31]:
            current = self.qos_manager.allocated_bandwidth.get(qos_class, 0)
            max_allowed = qos_class.max_share * self.qos_manager.total_bandwidth
            
            if current < max_allowed:
                # Increase by 5% or to max, whichever is smaller
                increase = min(max_allowed - current, max_allowed * 0.05)
                self.qos_manager.allocated_bandwidth[qos_class] += increase
                logger.debug(f"Increased {qos_class.name} allocation by {increase/1e6:.2f}Mbps")
        
        # Reset any aggressive rate limiting
        self.shaper.default_rule.rate_limit = None
        self.shaper.default_rule.burst = None
    
    async def _handle_degraded_condition(self):
        """Handle degraded network conditions."""
        # Slightly reduce best-effort traffic
        best_effort = QoSClass.BEST_EFFORT
        current = self.qos_manager.allocated_bandwidth.get(best_effort, 0)
        min_allowed = best_effort.min_share * self.qos_manager.total_bandwidth
        
        if current > min_allowed:
            # Reduce by 5% or to min, whichever is larger
            reduction = min(current - min_allowed, current * 0.05)
            self.qos_manager.allocated_bandwidth[best_effort] -= reduction
            logger.debug(f"Reduced {best_effort.name} allocation by {reduction/1e6:.2f}Mbps")
    
    async def _handle_congested_condition(self):
        """Handle congested network conditions."""
        # Get current metrics
        metrics = self.monitor.get_network_metrics()
        
        # Calculate how much we need to reduce traffic
        total_throughput = metrics.get('throughput_up', 0) + metrics.get('throughput_down', 0)
        available_bandwidth = self.qos_manager.total_bandwidth * 0.8  # Target 80% utilization
        
        if total_throughput > available_bandwidth:
            # Calculate reduction factor (how much to reduce by)
            reduction_factor = (total_throughput - available_bandwidth) / total_throughput
            
            # Apply reduction to lower priority traffic first
            for qos_class in sorted(QoSClass, key=lambda x: -x.priority):  # Lowest priority first
                if qos_class in [QoSClass.NETWORK_CONTROL, QoSClass.EXPEDITED_FORWARDING]:
                    continue  # Don't reduce critical traffic
                
                current = self.qos_manager.allocated_bandwidth.get(qos_class, 0)
                if current > 0:
                    reduction = current * reduction_factor
                    new_allocation = max(
                        qos_class.min_share * self.qos_manager.total_bandwidth,
                        current - reduction
                    )
                    self.qos_manager.allocated_bandwidth[qos_class] = new_allocation
                    logger.debug(
                        f"Reduced {qos_class.name} allocation by "
                        f"{(current - new_allocation)/1e6:.2f}Mbps due to congestion"
                    )
    
    async def _handle_critical_condition(self):
        """Handle critical network conditions."""
        # Drastic measures to recover the network
        
        # 1. Severely limit best-effort traffic
        best_effort = QoSClass.BEST_EFFORT
        self.qos_manager.allocated_bandwidth[best_effort] = (
            best_effort.min_share * self.qos_manager.total_bandwidth
        )
        
        # 2. Limit bulk traffic
        for qos_class in [QoSClass.AF11, QoSClass.AF12, QoSClass.AF13, QoSClass.AF21, QoSClass.AF22, QoSClass.AF23]:
            if qos_class in self.qos_manager.allocated_bandwidth:
                self.qos_manager.allocated_bandwidth[qos_class] *= 0.5  # Reduce by 50%
        
        # 3. Notify applications to reduce quality/bitrate
        await self._trigger_callbacks('on_emergency', {
            'message': 'Critical network condition detected',
            'timestamp': time.time(),
            'metrics': self.monitor.get_network_metrics()
        })
        
        logger.warning("Critical network condition - implemented emergency measures")
    
    async def _handle_recovering_condition(self):
        """Handle network recovery."""
        # Gradually restore allocations while monitoring conditions
        for qos_class in sorted(QoSClass, key=lambda x: x.priority):  # Highest priority first
            current = self.qos_manager.allocated_bandwidth.get(qos_class, 0)
            max_allowed = qos_class.max_share * self.qos_manager.total_bandwidth
            
            if current < max_allowed:
                # Small increase to test conditions
                increase = min(
                    max_allowed - current,
                    max_allowed * 0.01  # 1% increase per iteration
                )
                self.qos_manager.allocated_bandwidth[qos_class] += increase
    
    async def _control_loop(self):
        """Main control loop for adaptive bandwidth management."""
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
                
                # Assess current network conditions
                condition = await self.assess_network_conditions()
                
                # Adapt to the current condition
                await self.adapt_to_condition(condition)
                
                # Update statistics
                self._update_statistics()
                
                # Sleep until next update
                sleep_time = max(0, self.update_interval - (time.time() - now))
                await asyncio.sleep(sleep_time)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in control loop: {e}")
                await asyncio.sleep(1)  # Prevent tight loop on error
    
    def _update_statistics(self):
        """Update controller statistics."""
        # Add current metrics to history
        metrics = self.monitor.get_network_metrics()
        self.state.add_metrics(metrics)
    
    async def _trigger_callbacks(self, event: str, data: Dict):
        """Trigger registered callbacks for an event."""
        for callback in self.callbacks.get(event, []):
            try:
                await callback(data)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}")
    
    def register_callback(self, event: str, callback: Callable[[Dict], Awaitable[None]]):
        """Register a callback for controller events."""
        if event in self.callbacks:
            self.callbacks[event].append(callback)
        else:
            raise ValueError(f"Unknown event type: {event}")
    
    async def start(self):
        """Start the adaptive controller."""
        if self._running:
            return
            
        self._running = True
        self._control_task = asyncio.create_task(self._control_loop())
        logger.info("Adaptive bandwidth controller started")
    
    async def stop(self):
        """Stop the adaptive controller."""
        if not self._running:
            return
            
        self._running = False
        if self._control_task and not self._control_task.done():
            self._control_task.cancel()
            try:
                await self._control_task
            except asyncio.CancelledError:
                pass
        logger.info("Adaptive bandwidth controller stopped")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get controller statistics and metrics."""
        return {
            **self.stats,
            'current_condition': self.state.current_condition.name,
            'condition_duration': self.state.condition_duration,
            'metrics_history_size': len(self.state.metrics_history)
        }

# Example usage:
if __name__ == "__main__":
    import asyncio
    from ...network.bandwidth.monitor import BandwidthMonitor
    from .shaper import TrafficShaper
    from .qos import QoSManager
    
    async def test_controller():
        # Initialize components
        monitor = BandwidthMonitor()
        shaper = TrafficShaper(monitor)
        qos_manager = QoSManager(monitor, shaper)
        controller = AdaptiveController(monitor, shaper, qos_manager)
        
        # Start the controller
        await controller.start()
        
        # Simulate some traffic and network conditions
        try:
            for i in range(10):
                # Print current status
                stats = controller.get_stats()
                print(f"\n--- Iteration {i+1} ---")
                print(f"Condition: {stats['current_condition']} "
                      f"({stats['condition_duration']:.1f}s)")
                
                # Simulate changing conditions
                if i == 3:
                    print("\nSimulating network congestion...")
                    # This would normally come from actual network metrics
                    monitor.stats['avg_rtt'] = 0.5  # 500ms RTT
                    monitor.stats['loss_rate'] = 0.1  # 10% loss
                elif i == 6:
                    print("\nNetwork conditions improving...")
                    monitor.stats['avg_rtt'] = 0.1  # 100ms RTT
                    monitor.stats['loss_rate'] = 0.01  # 1% loss
                
                await asyncio.sleep(2)
                
        except KeyboardInterrupt:
            pass
        finally:
            # Clean up
            await controller.stop()
    
    asyncio.run(test_controller())
