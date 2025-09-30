""
Network Simulator for testing P2P network behavior under various conditions.
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Callable, Awaitable, Any

from ..p2p import P2PNetwork
from .scenarios import NetworkScenario

logger = logging.getLogger(__name__)

@dataclass
class NetworkStats:
    """Tracks network simulation statistics."""
    total_messages_sent: int = 0
    total_messages_received: int = 0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    message_loss_count: int = 0
    message_delays: List[float] = field(default_factory=list)
    
    def add_message_sent(self, size: int) -> None:
        """Record a sent message."""
        self.total_messages_sent += 1
        self.total_bytes_sent += size
    
    def add_message_received(self, size: int, delay: Optional[float] = None) -> None:
        """Record a received message and its delay."""
        self.total_messages_received += 1
        self.total_bytes_received += size
        if delay is not None:
            self.message_delays.append(delay)
    
    def record_message_loss(self) -> None:
        """Record a lost message."""
        self.message_loss_count += 1
    
    @property
    def message_loss_rate(self) -> float:
        """Calculate the message loss rate."""
        if self.total_messages_sent == 0:
            return 0.0
        return self.message_loss_count / self.total_messages_sent
    
    @property
    def average_delay(self) -> float:
        """Calculate the average message delay in seconds."""
        if not self.message_delays:
            return 0.0
        return sum(self.message_delays) / len(self.message_delays)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of network statistics."""
        return {
            'messages_sent': self.total_messages_sent,
            'messages_received': self.total_messages_received,
            'bytes_sent': self.total_bytes_sent,
            'bytes_received': self.total_bytes_received,
            'message_loss_count': self.message_loss_count,
            'message_loss_rate': self.message_loss_rate,
            'average_delay': self.average_delay,
            'total_delays_recorded': len(self.message_delays)
        }

class NetworkSimulator:
    """
    Simulates network conditions for testing P2P network behavior.
    
    This class wraps a P2P network and applies various network conditions
    to test its behavior under different scenarios.
    """
    
    def __init__(self, p2p_network: P2PNetwork):
        """
        Initialize the network simulator.
        
        Args:
            p2p_network: The P2P network to simulate conditions for
        """
        self.p2p_network = p2p_network
        self.scenarios: Dict[str, NetworkScenario] = {}
        self.active_scenario: Optional[NetworkScenario] = None
        self.stats = NetworkStats()
        self._original_send_message = self.p2p_network.send_message
        self._original_handle_message = self.p2p_network._handle_message
        self._original_connect_to_peer = self.p2p_network.connect_to_peer
        self._original_disconnect_peer = self.p2p_network.disconnect_peer
        self._is_running = False
        self._lock = asyncio.Lock()
        self._message_handlers: Dict[str, Callable] = {}
        self._background_tasks: Set[asyncio.Task] = set()
    
    async def start(self) -> None:
        """Start the network simulator."""
        if self._is_running:
            return
            
        # Replace network methods with our simulated versions
        self.p2p_network.send_message = self._simulated_send_message
        self.p2p_network._handle_message = self._simulated_handle_message
        self.p2p_network.connect_to_peer = self._simulated_connect_to_peer
        self.p2p_network.disconnect_peer = self._simulated_disconnect_peer
        
        self._is_running = True
        logger.info("Network simulator started")
    
    async def stop(self) -> None:
        """Stop the network simulator and restore original methods."""
        if not self._is_running:
            return
            
        # Stop all scenarios
        if self.active_scenario:
            await self.active_scenario.stop()
            self.active_scenario = None
        
        # Restore original methods
        self.p2p_network.send_message = self._original_send_message
        self.p2p_network._handle_message = self._original_handle_message
        self.p2p_network.connect_to_peer = self._original_connect_to_peer
        self.p2p_network.disconnect_peer = self._original_disconnect_peer
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        if self._background_tasks:
            await asyncio.wait(self._background_tasks, return_when=asyncio.ALL_COMPLETED)
        
        self._is_running = False
        logger.info("Network simulator stopped")
    
    def add_scenario(self, name: str, scenario: 'NetworkScenario') -> None:
        """
        Add a network scenario to the simulator.
        
        Args:
            name: Name of the scenario
            scenario: NetworkScenario instance
        """
        self.scenarios[name] = scenario
        logger.info(f"Added network scenario: {name}")
    
    async def set_scenario(self, name: str) -> bool:
        """
        Set the active network scenario.
        
        Args:
            name: Name of the scenario to activate
            
        Returns:
            bool: True if the scenario was activated, False otherwise
        """
        if name not in self.scenarios:
            logger.error(f"Unknown network scenario: {name}")
            return False
            
        async with self._lock:
            # Stop current scenario if any
            if self.active_scenario:
                await self.active_scenario.stop()
            
            # Start new scenario
            self.active_scenario = self.scenarios[name]
            await self.active_scenario.start()
            
            logger.info(f"Activated network scenario: {name}")
            return True
    
    def get_available_scenarios(self) -> List[str]:
        """Get a list of available scenario names."""
        return list(self.scenarios.keys())
    
    def get_current_scenario(self) -> Optional[str]:
        """Get the name of the currently active scenario."""
        if not self.active_scenario:
            return None
        return next(
            (name for name, scenario in self.scenarios.items() 
             if scenario == self.active_scenario),
            None
        )
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """
        Register a message handler for a specific message type.
        
        Args:
            message_type: Type of message to handle
            handler: Callback function to handle the message
        """
        self._message_handlers[message_type] = handler
    
    async def _simulated_send_message(
        self,
        peer_id: str,
        message_type: str,
        payload: Dict[str, Any],
        priority: int = 3
    ) -> bool:
        """Simulated version of send_message with network conditions applied."""
        if not self._is_running:
            return await self._original_send_message(peer_id, message_type, payload, priority)
        
        # Get message size for statistics
        message_size = len(str(payload).encode('utf-8'))
        self.stats.add_message_sent(message_size)
        
        # Apply active scenario if any
        if self.active_scenario:
            should_drop = await self.active_scenario.should_drop_message(
                peer_id=peer_id,
                message_type=message_type,
                size=message_size,
                priority=priority
            )
            
            if should_drop:
                self.stats.record_message_loss()
                logger.debug(f"Dropped message to {peer_id} (type: {message_type})")
                return False
            
            # Get delay from scenario
            delay = await self.active_scenario.get_message_delay(
                peer_id=peer_id,
                message_type=message_type,
                size=message_size,
                priority=priority
            )
            
            # Schedule the message with delay
            asyncio.create_task(self._delayed_send(
                peer_id=peer_id,
                message_type=message_type,
                payload=payload,
                priority=priority,
                delay=delay
            ))
            
            return True
        
        # No active scenario, send immediately
        return await self._original_send_message(peer_id, message_type, payload, priority)
    
    async def _simulated_handle_message(self, peer_id: str, message: bytes) -> None:
        """Simulated version of _handle_message with network conditions."""
        if not self._is_running:
            return await self._original_handle_message(peer_id, message)
        
        # Record message received
        message_size = len(message)
        self.stats.add_message_received(message_size)
        
        # Call original handler
        await self._original_handle_message(peer_id, message)
    
    async def _simulated_connect_to_peer(self, peer_id: str, address: str) -> bool:
        """Simulated version of connect_to_peer with network conditions."""
        if not self._is_running or not self.active_scenario:
            return await self._original_connect_to_peer(peer_id, address)
        
        # Apply connection success rate from scenario
        if not await self.active_scenario.should_allow_connection(peer_id):
            logger.debug(f"Blocked connection to {peer_id} (simulated)")
            return False
        
        # Get connection delay from scenario
        delay = await self.active_scenario.get_connection_delay(peer_id)
        if delay > 0:
            await asyncio.sleep(delay)
        
        return await self._original_connect_to_peer(peer_id, address)
    
    async def _simulated_disconnect_peer(self, peer_id: str) -> None:
        """Simulated version of disconnect_peer with network conditions."""
        if not self._is_running or not self.active_scenario:
            return await self._original_disconnect_peer(peer_id)
        
        # Get disconnection delay from scenario
        delay = await self.active_scenario.get_disconnection_delay(peer_id)
        if delay > 0:
            await asyncio.sleep(delay)
        
        await self._original_disconnect_peer(peer_id)
    
    async def _delayed_send(
        self,
        peer_id: str,
        message_type: str,
        payload: Dict[str, Any],
        priority: int,
        delay: float
    ) -> None:
        """Send a message after a delay."""
        if delay > 0:
            await asyncio.sleep(delay)
        
        # Record the actual delay
        actual_delay = time.time() - payload.get('_send_time', time.time())
        self.stats.add_message_received(len(str(payload).encode('utf-8')), actual_delay)
        
        # Send the message
        try:
            await self._original_send_message(peer_id, message_type, payload, priority)
        except Exception as e:
            logger.error(f"Failed to send delayed message to {peer_id}: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current simulation statistics."""
        stats = self.stats.get_summary()
        stats['active_scenario'] = self.get_current_scenario()
        return stats
    
    def reset_stats(self) -> None:
        """Reset all statistics."""
        self.stats = NetworkStats()
        logger.info("Network simulation statistics reset")
