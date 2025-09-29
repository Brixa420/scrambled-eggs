"""
Tor Integration for P2P Communication

This module provides functionality to integrate Tor with the P2P messaging system
for enhanced privacy and anonymity.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union

from ..config import get_config
from ..tor import OnionService, OnionServiceConfig, TorManager
from ..tor.exceptions import TorError, TorServiceError, TorStartupError

logger = logging.getLogger(__name__)


class TorP2PIntegration:
    """Manages Tor integration for P2P communications."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Tor P2P integration.

        Args:
            config: Optional configuration dictionary. If None, uses default config.
        """
        self.config = config or get_config().get("tor", {})
        self.tor_manager: Optional[TorManager] = None
        self.onion_service: Optional[OnionService] = None
        self.is_initialized = False
        self.is_running = False

        # Event callbacks
        self.on_tor_started: Optional[Callable[[], Awaitable[None]]] = None
        self.on_tor_stopped: Optional[Callable[[], Awaitable[None]]] = None
        self.on_circuit_created: Optional[Callable[[Dict], Awaitable[None]]] = None
        self.on_hidden_service_ready: Optional[Callable[[str], Awaitable[None]]] = None

    async def initialize(self) -> None:
        """Initialize the Tor integration."""
        if self.is_initialized:
            logger.warning("Tor integration already initialized")
            return

        logger.info("Initializing Tor integration...")

        try:
            # Create Tor manager with configuration
            self.tor_manager = TorManager(
                tor_path=self.config.get("tor_path"),
                data_dir=self.config.get("data_dir"),
                control_port=self.config.get("control_port", 9051),
                socks_port=self.config.get("socks_port", 9050),
                use_system_tor=self.config.get("use_system_tor", True),
            )

            self.is_initialized = True
            logger.info("Tor integration initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize Tor integration: {e}")
            self.is_initialized = False
            raise TorError(f"Failed to initialize Tor integration: {e}") from e

    async def start(self) -> None:
        """Start the Tor service and hidden services if configured."""
        if not self.is_initialized:
            await self.initialize()

        if self.is_running:
            logger.warning("Tor integration is already running")
            return

        logger.info("Starting Tor integration...")

        try:
            # Start Tor
            if not self.tor_manager:
                raise TorError("Tor manager not initialized")

            await self.tor_manager.start()
            self.is_running = True

            # Notify that Tor has started
            if self.on_tor_started:
                await self.on_tor_started()

            # Start hidden services if configured
            onion_config = self.config.get("onion_services", {})
            if onion_config.get("enabled", False):
                await self._start_hidden_services(onion_config)

            logger.info("Tor integration started successfully")

        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start Tor integration: {e}")
            raise TorStartupError(f"Failed to start Tor integration: {e}") from e

    async def stop(self) -> None:
        """Stop the Tor service and clean up resources."""
        if not self.is_running or not self.tor_manager:
            return

        logger.info("Stopping Tor integration...")

        try:
            # Stop hidden services first
            if self.onion_service:
                await self.onion_service.stop()
                self.onion_service = None

            # Stop Tor manager
            await self.tor_manager.stop()
            self.is_running = False

            # Notify that Tor has stopped
            if self.on_tor_stopped:
                await self.on_tor_stopped()

            logger.info("Tor integration stopped successfully")

        except Exception as e:
            logger.error(f"Error stopping Tor integration: {e}")
            raise TorError(f"Error stopping Tor integration: {e}") from e
        finally:
            self.is_running = False

    async def _start_hidden_services(self, config: Dict[str, Any]) -> None:
        """Start hidden services based on configuration."""
        if not self.tor_manager or not self.tor_manager.controller:
            raise TorError("Tor manager or controller not available")

        try:
            # Create hidden service configuration
            service_config = OnionServiceConfig(
                name="scrambled-eggs-p2p",
                version=config.get("version", 3),
                virtual_port=config.get("ports", [{}])[0].get("virtual_port", 80),
                target_address=config.get("ports", [{}])[0].get("target_address", "127.0.0.1"),
                target_port=config.get("ports", [{}])[0].get("target_port", 8080),
                client_auth=config.get("client_auth", False),
                max_streams=config.get("max_streams", 10),
                single_hop=config.get("single_hop", False),
                non_anonymous=config.get("non_anonymous", False),
                data_dir=config.get("data_dir"),
            )

            # Create and start the hidden service
            self.onion_service = OnionService(self.tor_manager.controller, service_config)
            onion_address = await self.onion_service.start()

            logger.info(f"Hidden service started at {onion_address}")

            # Notify that hidden service is ready
            if self.on_hidden_service_ready:
                await self.on_hidden_service_ready(onion_address)

            return onion_address

        except Exception as e:
            logger.error(f"Failed to start hidden service: {e}")
            raise TorServiceError(f"Failed to start hidden service: {e}") from e

    async def get_tor_proxy(self) -> Optional[Tuple[str, int]]:
        """Get the Tor SOCKS proxy address and port.

        Returns:
            Tuple of (host, port) for the SOCKS proxy, or None if not available.
        """
        if not self.tor_manager or not self.is_running:
            return None

        return self.tor_manager.get_socks_proxy()

    async def new_circuit(self) -> bool:
        """Create a new Tor circuit.

        Returns:
            bool: True if a new circuit was created, False otherwise.
        """
        if not self.tor_manager or not self.is_running:
            return False

        try:
            return await self.tor_manager.new_identity()
        except Exception as e:
            logger.error(f"Failed to create new Tor circuit: {e}")
            return False

    async def get_circuit_info(self) -> List[Dict]:
        """Get information about active Tor circuits.

        Returns:
            List of dictionaries containing circuit information.
        """
        if not self.tor_manager or not self.is_running:
            return []

        try:
            return await self.tor_manager.get_circuit_info()
        except Exception as e:
            logger.error(f"Failed to get circuit info: {e}")
            return []

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
        if not self.onion_service or not self.onion_service.is_running:
            return None

        return self.onion_service.hostname

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
