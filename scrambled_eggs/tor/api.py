""
Tor Integration API

This module provides a high-level API for Tor integration in the Scrambled Eggs application.
It combines the Tor manager, circuit manager, and proxy functionality into a single interface.
"""

import asyncio
import logging
from typing import Dict, Any, Optional, Tuple, List, Callable, Awaitable

from .tor_manager import TorManager, TorState
from ..p2p.circuit_manager import CircuitManager
from ..p2p.tor_proxy import TorProxyManager
from ..p2p.tor_integration import TorP2PIntegration
from .exceptions import TorError, TorStartupError
from ..config import get_config

logger = logging.getLogger(__name__)

class TorAPI:
    """High-level API for Tor integration."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Tor API.
        
        Args:
            config: Optional configuration dictionary. If None, uses default config.
        """
        self.config = config or get_config().get('tor', {})
        self.tor_manager: Optional[TorManager] = None
        self.circuit_manager: Optional[CircuitManager] = None
        self.proxy_manager: Optional[TorProxyManager] = None
        self.p2p_integration: Optional[TorP2PIntegration] = None
        self.is_initialized = False
        self.is_running = False
        
        # Event callbacks
        self.on_started: Optional[Callable[[], Awaitable[None]]] = None
        self.on_stopped: Optional[Callable[[], Awaitable[None]]] = None
        self.on_circuit_created: Optional[Callable[[Dict], Awaitable[None]]] = None
        self.on_circuit_closed: Optional[Callable[[str], Awaitable[None]]] = None
        self.on_circuit_failed: Optional[Callable[[str, str], Awaitable[None]]] = None
        self.on_hidden_service_ready: Optional[Callable[[str], Awaitable[None]]] = None
    
    async def initialize(self) -> None:
        """Initialize the Tor API and all components."""
        if self.is_initialized:
            logger.warning("Tor API already initialized")
            return
        
        logger.info("Initializing Tor API...")
        
        try:
            # Initialize Tor manager
            self.tor_manager = TorManager(
                tor_path=self.config.get('tor_path'),
                data_dir=self.config.get('data_dir'),
                control_port=self.config.get('control_port', 9051),
                socks_port=self.config.get('socks_port', 9050),
                use_system_tor=self.config.get('use_system_tor', True)
            )
            
            # Initialize circuit manager
            self.circuit_manager = CircuitManager(self.tor_manager)
            
            # Initialize proxy manager
            self.proxy_manager = TorProxyManager(self.tor_manager, self.circuit_manager)
            
            # Initialize P2P integration
            self.p2p_integration = TorP2PIntegration(self.config)
            
            # Set up event forwarding
            self._setup_event_forwarding()
            
            self.is_initialized = True
            logger.info("Tor API initialized successfully")
            
        except Exception as e:
            self.is_initialized = False
            logger.error(f"Failed to initialize Tor API: {e}")
            raise TorError(f"Failed to initialize Tor API: {e}") from e
    
    async def start(self) -> None:
        """Start the Tor API and all components."""
        if not self.is_initialized:
            await self.initialize()
        
        if self.is_running:
            logger.warning("Tor API is already running")
            return
        
        logger.info("Starting Tor API...")
        
        try:
            # Start Tor manager
            if not self.tor_manager:
                raise TorError("Tor manager not initialized")
                
            await self.tor_manager.start()
            
            # Start circuit manager
            if not self.circuit_manager:
                raise TorError("Circuit manager not initialized")
                
            await self.circuit_manager.start()
            
            # Start proxy manager if enabled
            if self.config.get('enable_socks_proxy', True):
                if not self.proxy_manager:
                    raise TorError("Proxy manager not initialized")
                    
                await self.proxy_manager.start()
            
            # Start P2P integration if enabled
            if self.config.get('onion_services', {}).get('enabled', False):
                if not self.p2p_integration:
                    raise TorError("P2P integration not initialized")
                    
                await self.p2p_integration.start()
            
            self.is_running = True
            logger.info("Tor API started successfully")
            
            # Notify listeners
            if self.on_started:
                await self.on_started()
            
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start Tor API: {e}")
            
            # Clean up partially started components
            try:
                await self.stop()
            except:
                pass
                
            raise TorStartupError(f"Failed to start Tor API: {e}") from e
    
    async def stop(self) -> None:
        """Stop the Tor API and all components."""
        if not self.is_running:
            return
        
        logger.info("Stopping Tor API...")
        
        # Stop components in reverse order of initialization
        try:
            if self.p2p_integration:
                await self.p2p_integration.stop()
            
            if self.proxy_manager:
                await self.proxy_manager.stop()
            
            if self.circuit_manager:
                await self.circuit_manager.stop()
            
            if self.tor_manager:
                await self.tor_manager.stop()
            
            self.is_running = False
            logger.info("Tor API stopped successfully")
            
            # Notify listeners
            if self.on_stopped:
                await self.on_stopped()
            
        except Exception as e:
            logger.error(f"Error stopping Tor API: {e}")
            raise TorError(f"Error stopping Tor API: {e}") from e
    
    def _setup_event_forwarding(self) -> None:
        """Set up event forwarding between components."""
        if not all([self.tor_manager, self.circuit_manager, self.proxy_manager, self.p2p_integration]):
            return
        
        # Forward circuit events
        self.circuit_manager.on_new_circuit = self._forward_circuit_created
        self.circuit_manager.on_circuit_closed = self._forward_circuit_closed
        self.circuit_manager.on_circuit_failed = self._forward_circuit_failed
        
        # Forward hidden service events from P2P integration
        self.p2p_integration.on_hidden_service_ready = self._forward_hidden_service_ready
    
    async def _forward_circuit_created(self, circuit: Dict) -> None:
        """Forward circuit created event to registered callbacks."""
        if self.on_circuit_created:
            await self.on_circuit_created(circuit)
    
    async def _forward_circuit_closed(self, circuit_id: str) -> None:
        """Forward circuit closed event to registered callbacks."""
        if self.on_circuit_closed:
            await self.on_circuit_closed(circuit_id)
    
    async def _forward_circuit_failed(self, circuit_id: str, reason: str) -> None:
        """Forward circuit failed event to registered callbacks."""
        if self.on_circuit_failed:
            await self.on_circuit_failed(circuit_id, reason)
    
    async def _forward_hidden_service_ready(self, onion_address: str) -> None:
        """Forward hidden service ready event to registered callbacks."""
        if self.on_hidden_service_ready:
            await self.on_hidden_service_ready(onion_address)
    
    # High-level API methods
    
    async def get_tor_proxy(self) -> Optional[Tuple[str, int]]:
        """Get the Tor SOCKS5 proxy address and port.
        
        Returns:
            Tuple of (host, port) for the SOCKS5 proxy, or None if not available.
        """
        if not self.proxy_manager or not self.is_running:
            return None
        
        return await self.proxy_manager.get_proxy_url()
    
    async def new_identity(self) -> bool:
        """Create a new Tor identity (new circuit).
        
        Returns:
            bool: True if a new identity was created, False otherwise.
        """
        if not self.tor_manager or not self.is_running:
            return False
        
        return await self.tor_manager.new_identity()
    
    async def get_circuits(self) -> List[Dict]:
        """Get information about active Tor circuits.
        
        Returns:
            List of dictionaries containing circuit information.
        """
        if not self.tor_manager or not self.is_running:
            return []
        
        return await self.tor_manager.get_circuit_info()
    
    async def is_connected(self) -> bool:
        """Check if Tor is connected to the network.
        
        Returns:
            bool: True if connected, False otherwise.
        """
        if not self.tor_manager or not self.is_running:
            return False
        
        return await self.tor_manager.is_connected()
    
    async def get_hidden_service_address(self) -> Optional[str]:
        """Get the .onion address of the hidden service if running.
        
        Returns:
            str: The .onion address, or None if not available.
        """
        if not self.p2p_integration or not self.is_running:
            return None
        
        return await self.p2p_integration.get_hidden_service_address()
    
    # Context manager support
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()

# Global instance for easy access
tor_api = TorAPI()

# Helper functions for the global instance

async def initialize() -> None:
    """Initialize the global Tor API instance."""
    await tor_api.initialize()

async def start() -> None:
    """Start the global Tor API instance."""
    await tor_api.start()

async def stop() -> None:
    """Stop the global Tor API instance."""
    await tor_api.stop()

def get_tor_api() -> TorAPI:
    """Get the global Tor API instance.
    
    Returns:
        The global TorAPI instance.
    """
    return tor_api
