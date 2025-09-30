""
Network scenarios for testing P2P network behavior under various conditions.
"""

import asyncio
import logging
import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)

class NetworkScenario(ABC):
    """Base class for network simulation scenarios."""
    
    def __init__(self, name: str, description: str = ""):
        """
        Initialize a network scenario.
        
        Args:
            name: Name of the scenario
            description: Description of the scenario
        """
        self.name = name
        self.description = description
        self._is_running = False
        self._background_tasks: Set[asyncio.Task] = set()
    
    async def start(self) -> None:
        """Start the scenario."""
        if self._is_running:
            return
            
        self._is_running = True
        logger.info(f"Started network scenario: {self.name}")
    
    async def stop(self) -> None:
        """Stop the scenario and clean up resources."""
        if not self._is_running:
            return
            
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        if self._background_tasks:
            await asyncio.wait(self._background_tasks, return_when=asyncio.ALL_COMPLETED)
        
        self._is_running = False
        logger.info(f"Stopped network scenario: {self.name}")
    
    @abstractmethod
    async def should_drop_message(
        self,
        peer_id: str,
        message_type: str,
        size: int,
        priority: int = 3
    ) -> bool:
        """
        Determine if a message should be dropped.
        
        Args:
            peer_id: ID of the target peer
            message_type: Type of the message
            size: Size of the message in bytes
            priority: Message priority (1-5, where 1 is highest)
            
        Returns:
            bool: True if the message should be dropped, False otherwise
        """
        pass
    
    @abstractmethod
    async def get_message_delay(
        self,
        peer_id: str,
        message_type: str,
        size: int,
        priority: int = 3
    ) -> float:
        """
        Get the delay to apply to a message in seconds.
        
        Args:
            peer_id: ID of the target peer
            message_type: Type of the message
            size: Size of the message in bytes
            priority: Message priority (1-5, where 1 is highest)
            
        Returns:
            float: Delay in seconds
        """
        pass
    
    async def should_allow_connection(self, peer_id: str) -> bool:
        """
        Determine if a connection should be allowed.
        
        Args:
            peer_id: ID of the peer attempting to connect
            
        Returns:
            bool: True if the connection should be allowed, False otherwise
        """
        return True
    
    async def get_connection_delay(self, peer_id: str) -> float:
        """
        Get the delay to apply when establishing a connection.
        
        Args:
            peer_id: ID of the peer being connected to
            
        Returns:
            float: Delay in seconds
        """
        return 0.0
    
    async def get_disconnection_delay(self, peer_id: str) -> float:
        """
        Get the delay to apply when disconnecting.
        
        Args:
            peer_id: ID of the peer being disconnected from
            
        Returns:
            float: Delay in seconds
        """
        return 0.0

@dataclass
class NetworkCondition:
    """Represents a network condition with configurable parameters."""
    base_delay: float = 0.0          # Base delay in seconds
    delay_variation: float = 0.0     # Random variation in delay
    drop_probability: float = 0.0    # Probability of dropping a message (0.0 to 1.0)
    bandwidth: Optional[int] = None  # Bandwidth in bytes per second (None for unlimited)

class StableNetwork(NetworkScenario):
    """Represents a stable, high-quality network connection."""
    
    def __init__(self):
        """Initialize the stable network scenario."""
        super().__init__(
            name="stable",
            description="Stable network with minimal latency and no packet loss"
        )
        self.condition = NetworkCondition(
            base_delay=0.05,     # 50ms base delay
            delay_variation=0.01,  # ±10ms jitter
            drop_probability=0.001,  # 0.1% packet loss
            bandwidth=10 * 1024 * 1024  # 10 Mbps
        )
    
    async def should_drop_message(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> bool:
        return random.random() < self.condition.drop_probability
    
    async def get_message_delay(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> float:
        base_delay = self.condition.base_delay
        jitter = (random.random() * 2 - 1) * self.condition.delay_variation
        
        # Add a small delay based on message size (simulate bandwidth constraints)
        if self.condition.bandwidth:
            transmission_delay = size / self.condition.bandwidth
            base_delay += transmission_delay
        
        return max(0.0, base_delay + jitter)

class HighLatencyNetwork(NetworkScenario):
    """Simulates a high-latency network (e.g., satellite connection)."""
    
    def __init__(self):
        """Initialize the high-latency network scenario."""
        super().__init__(
            name="high_latency",
            description="High-latency network with significant delay"
        )
        self.condition = NetworkCondition(
            base_delay=0.5,       # 500ms base delay
            delay_variation=0.2,   # ±200ms jitter
            drop_probability=0.01,  # 1% packet loss
            bandwidth=2 * 1024 * 1024  # 2 Mbps
        )
    
    async def should_drop_message(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> bool:
        return random.random() < self.condition.drop_probability
    
    async def get_message_delay(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> float:
        base_delay = self.condition.base_delay
        jitter = (random.random() * 2 - 1) * self.condition.delay_variation
        
        # Add transmission delay based on message size
        if self.condition.bandwidth:
            transmission_delay = size / self.condition.bandwidth
            base_delay += transmission_delay
        
        return max(0.1, base_delay + jitter)  # Minimum 100ms delay

class LossyNetwork(NetworkScenario):
    """Simulates a lossy network with high packet loss."""
    
    def __init__(self):
        """Initialize the lossy network scenario."""
        super().__init__(
            name="lossy",
            description="Network with high packet loss and moderate latency"
        )
        self.condition = NetworkCondition(
            base_delay=0.2,       # 200ms base delay
            delay_variation=0.1,   # ±100ms jitter
            drop_probability=0.2,   # 20% packet loss
            bandwidth=1 * 1024 * 1024  # 1 Mbps
        )
    
    async def should_drop_message(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> bool:
        # Higher priority messages have lower drop probability
        priority_factor = max(0.1, (6 - priority) / 5)  # 0.2 to 1.0
        effective_drop_prob = self.condition.drop_probability / priority_factor
        return random.random() < effective_drop_prob
    
    async def get_message_delay(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> float:
        base_delay = self.condition.base_delay
        jitter = (random.random() * 2 - 1) * self.condition.delay_variation
        
        # Add transmission delay based on message size
        if self.condition.bandwidth:
            transmission_delay = size / self.condition.bandwidth
            base_delay += transmission_delay
        
        # Higher priority messages have lower delay
        priority_factor = max(0.5, (6 - priority) / 5)  # 0.2 to 1.0
        
        return max(0.1, (base_delay + jitter) * priority_factor)

class CongestedNetwork(NetworkScenario):
    """Simulates a congested network with variable latency and packet loss."""
    
    def __init__(self):
        """Initialize the congested network scenario."""
        super().__init__(
            name="congested",
            description="Network with congestion and variable performance"
        )
        self.condition = NetworkCondition(
            base_delay=0.3,       # 300ms base delay
            delay_variation=0.3,   # ±300ms jitter
            drop_probability=0.1,   # 10% packet loss
            bandwidth=512 * 1024    # 512 Kbps
        )
        self._congestion_level = 0.0  # 0.0 to 1.0
        self._last_update = time.time()
    
    async def start(self) -> None:
        """Start the scenario with dynamic congestion."""
        await super().start()
        self._background_tasks.add(asyncio.create_task(self._update_congestion()))
    
    async def _update_congestion(self) -> None:
        """Update the congestion level over time."""
        while self._is_running:
            # Random walk the congestion level
            self._congestion_level += (random.random() * 0.2 - 0.1)
            self._congestion_level = max(0.0, min(1.0, self._congestion_level))
            
            # Update condition based on congestion
            self.condition.base_delay = 0.1 + self._congestion_level * 0.9  # 100ms to 1s
            self.condition.delay_variation = 0.05 + self._congestion_level * 0.25  # 50ms to 300ms
            self.condition.drop_probability = 0.01 + self._congestion_level * 0.2  # 1% to 21%
            
            await asyncio.sleep(5.0)  # Update every 5 seconds
    
    async def should_drop_message(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> bool:
        effective_drop_prob = self.condition.drop_probability * (1.0 + size / 1024)  # Larger messages more likely to drop
        priority_factor = max(0.1, (6 - priority) / 5)  # 0.2 to 1.0
        return random.random() < (effective_drop_prob / priority_factor)
    
    async def get_message_delay(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> float:
        # Base delay increases with congestion and message size
        size_factor = 1.0 + (size / (10 * 1024))  # 10KB = 2x delay
        congestion_factor = 1.0 + (self._congestion_level * 4.0)  # 1x to 5x based on congestion
        
        base_delay = self.condition.base_delay * size_factor * congestion_factor
        jitter = (random.random() * 2 - 1) * self.condition.delay_variation * congestion_factor
        
        # Add transmission delay based on message size and available bandwidth
        if self.condition.bandwidth:
            effective_bandwidth = self.condition.bandwidth * (1.0 - self._congestion_level * 0.8)  # 20-100% of nominal
            transmission_delay = size / max(1, effective_bandwidth)  # Avoid division by zero
            base_delay += transmission_delay
        
        # Higher priority messages have lower delay
        priority_factor = max(0.2, (6 - priority) / 5)  # 0.2 to 1.0
        
        return max(0.1, (base_delay + jitter) * priority_factor)

class FlakyConnection(NetworkScenario):
    """Simulates an unreliable connection that frequently drops."""
    
    def __init__(self):
        """Initialize the flaky connection scenario."""
        super().__init__(
            name="flaky",
            description="Unreliable connection with frequent drops and high variability"
        )
        self.condition = NetworkCondition(
            base_delay=0.4,       # 400ms base delay
            delay_variation=0.5,   # ±500ms jitter
            drop_probability=0.3,   # 30% packet loss
            bandwidth=256 * 1024    # 256 Kbps
        )
        self._connection_states: Dict[str, bool] = {}  # peer_id -> is_connected
        self._last_state_change: Dict[str, float] = {}
    
    async def start(self) -> None:
        """Start the scenario with connection flapping."""
        await super().start()
        self._background_tasks.add(asyncio.create_task(self._simulate_flapping()))
    
    async def _simulate_flapping(self) -> None:
        """Randomly change connection states."""
        while self._is_running:
            # Randomly change state for each peer
            for peer_id in list(self._connection_states.keys()):
                if random.random() < 0.1:  # 10% chance to change state
                    current_time = time.time()
                    last_change = self._last_state_change.get(peer_id, 0)
                    
                    # Don't flap too quickly (at least 2 seconds between changes)
                    if current_time - last_change >= 2.0:
                        self._connection_states[peer_id] = not self._connection_states[peer_id]
                        self._last_state_change[peer_id] = current_time
                        
                        state = "up" if self._connection_states[peer_id] else "down"
                        logger.debug(f"Connection to {peer_id} is now {state}")
            
            await asyncio.sleep(1.0)  # Check every second
    
    async def should_drop_message(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> bool:
        # If we don't have a state for this peer yet, initialize it
        if peer_id not in self._connection_states:
            self._connection_states[peer_id] = random.random() > 0.3  # 70% chance to start connected
            self._last_state_change[peer_id] = time.time()
        
        # If connection is down, drop all messages
        if not self._connection_states[peer_id]:
            return True
        
        # Otherwise, use the base drop probability
        return random.random() < self.condition.drop_probability
    
    async def get_message_delay(self, peer_id: str, message_type: str, size: int, priority: int = 3) -> float:
        base_delay = self.condition.base_delay
        jitter = (random.random() * 2 - 1) * self.condition.delay_variation
        
        # Add transmission delay based on message size
        if self.condition.bandwidth:
            transmission_delay = size / self.condition.bandwidth
            base_delay += transmission_delay
        
        # Randomly add extra delay to simulate connection issues
        if random.random() < 0.2:  # 20% chance of extra delay
            base_delay += random.random() * 2.0  # Up to 2 seconds extra delay
        
        return max(0.1, base_delay + jitter)
    
    async def should_allow_connection(self, peer_id: str) -> bool:
        # If we don't have a state for this peer yet, initialize it
        if peer_id not in self._connection_states:
            self._connection_states[peer_id] = random.random() > 0.3  # 70% chance to start connected
            self._last_state_change[peer_id] = time.time()
        
        return self._connection_states[peer_id]

# Predefined scenarios for easy access
PREDEFINED_SCENARIOS = {
    "stable": StableNetwork,
    "high_latency": HighLatencyNetwork,
    "lossy": LossyNetwork,
    "congested": CongestedNetwork,
    "flaky": FlakyConnection
}

def get_predefined_scenario(name: str) -> Optional[NetworkScenario]:
    """
    Get a predefined network scenario by name.
    
    Args:
        name: Name of the predefined scenario
        
    Returns:
        NetworkScenario instance or None if not found
    """
    scenario_class = PREDEFINED_SCENARIOS.get(name.lower())
    if scenario_class:
        return scenario_class()
    return None
