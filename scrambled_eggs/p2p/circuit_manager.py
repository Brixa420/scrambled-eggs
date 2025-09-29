"""
Tor Circuit Manager

This module provides advanced circuit management for Tor connections,
including circuit creation, maintenance, and monitoring.
"""

import asyncio
import logging
import random
import time
from typing import Awaitable, Callable, Dict, List, Optional, Set, Tuple

from ..config import get_config
from ..tor import TorManager
from ..tor.exceptions import TorError

logger = logging.getLogger(__name__)


class CircuitManager:
    """Manages Tor circuits for improved anonymity and reliability."""

    def __init__(self, tor_manager: TorManager):
        """Initialize the CircuitManager.

        Args:
            tor_manager: An instance of TorManager to use for circuit operations.
        """
        self.tor_manager = tor_manager
        self.config = get_config().get("tor", {})
        self.circuits: Dict[str, Dict] = {}
        self.active_circuit_id: Optional[str] = None
        self.is_running = False
        self._maintenance_task: Optional[asyncio.Task] = None
        self._circuit_cleanup_interval = 300  # 5 minutes
        self._circuit_max_age = 3600  # 1 hour
        self._min_circuits = 3
        self._max_circuits = 10
        self._excluded_nodes: Set[str] = set()
        self._excluded_exit_nodes: Set[str] = set()
        self._preferred_exit_nodes: Set[str] = set()

        # Event callbacks
        self.on_new_circuit: Optional[Callable[[Dict], Awaitable[None]]] = None
        self.on_circuit_closed: Optional[Callable[[str], Awaitable[None]]] = None
        self.on_circuit_failed: Optional[Callable[[str, str], Awaitable[None]]] = None

    async def start(self) -> None:
        """Start the circuit manager."""
        if self.is_running:
            return

        logger.info("Starting Tor circuit manager...")
        self.is_running = True

        # Load configuration
        self._load_config()

        # Start maintenance task
        self._maintenance_task = asyncio.create_task(self._maintenance_loop())

        # Create initial circuits
        await self._create_initial_circuits()

        logger.info("Tor circuit manager started")

    async def stop(self) -> None:
        """Stop the circuit manager and clean up resources."""
        if not self.is_running:
            return

        logger.info("Stopping Tor circuit manager...")
        self.is_running = False

        # Cancel maintenance task
        if self._maintenance_task and not self._maintenance_task.done():
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass

        # Clear circuits
        self.circuits.clear()
        self.active_circuit_id = None

        logger.info("Tor circuit manager stopped")

    def _load_config(self) -> None:
        """Load configuration from the app config."""
        # Load excluded nodes
        if "exclude_nodes" in self.config:
            self._excluded_nodes.update(self.config["exclude_nodes"])

        if "exclude_exit_nodes" in self.config:
            self._excluded_exit_nodes.update(self.config["exclude_exit_nodes"])

        if "exit_nodes" in self.config:
            self._preferred_exit_nodes.update(self.config["exit_nodes"])

        # Load circuit settings
        self._min_circuits = self.config.get("min_circuits", self._min_circuits)
        self._max_circuits = self.config.get("max_circuits", self._max_circuits)
        self._circuit_max_age = self.config.get("circuit_max_age", self._circuit_max_age)
        self._circuit_cleanup_interval = self.config.get(
            "circuit_cleanup_interval", self._circuit_cleanup_interval
        )

    async def _create_initial_circuits(self) -> None:
        """Create the initial set of circuits."""
        # Create minimum number of circuits
        for _ in range(self._min_circuits):
            try:
                await self.create_circuit()
            except Exception as e:
                logger.error(f"Failed to create initial circuit: {e}")

    async def create_circuit(self, purpose: str = "general") -> Optional[Dict]:
        """Create a new Tor circuit.

        Args:
            purpose: Purpose of the circuit (e.g., 'general', 'streaming', 'download').

        Returns:
            Dictionary with circuit information, or None if creation failed.
        """
        if not self.tor_manager.controller:
            logger.error("Tor controller not available")
            return None

        try:
            # Build circuit parameters based on purpose
            params = self._get_circuit_params(purpose)

            # Create a new circuit
            circuit_id = await asyncio.to_thread(
                self.tor_manager.controller.new_circuit, await self._build_path_spec(params)
            )

            # Get circuit info
            circuit = {
                "id": circuit_id,
                "created_at": time.time(),
                "last_used": time.time(),
                "purpose": purpose,
                "params": params,
                "is_usable": True,
                "error_count": 0,
                "bytes_sent": 0,
                "bytes_received": 0,
                "streams": [],
            }

            # Add to circuit dictionary
            self.circuits[circuit_id] = circuit

            # Set as active if none is set
            if self.active_circuit_id is None:
                self.active_circuit_id = circuit_id

            logger.info(f"Created new circuit {circuit_id} for {purpose}")

            # Notify listeners
            if self.on_new_circuit:
                await self.on_new_circuit(circuit)

            return circuit

        except Exception as e:
            logger.error(f"Failed to create circuit: {e}")
            return None

    async def close_circuit(self, circuit_id: str, reason: str = "normal") -> bool:
        """Close a Tor circuit.

        Args:
            circuit_id: ID of the circuit to close.
            reason: Reason for closing the circuit.

        Returns:
            bool: True if the circuit was closed, False otherwise.
        """
        if circuit_id not in self.circuits:
            return False

        try:
            # Close the circuit
            await asyncio.to_thread(self.tor_manager.controller.close_circuit, circuit_id)

            # Remove from active circuits
            circuit = self.circuits.pop(circuit_id, None)

            # Update active circuit if needed
            if self.active_circuit_id == circuit_id:
                self.active_circuit_id = (
                    next(iter(self.circuits.keys()), None) if self.circuits else None
                )

            logger.info(f"Closed circuit {circuit_id} ({reason})")

            # Notify listeners
            if circuit and self.on_circuit_closed:
                await self.on_circuit_closed(circuit_id)

            return True

        except Exception as e:
            logger.error(f"Failed to close circuit {circuit_id}: {e}")
            return False

    async def mark_circuit_failed(self, circuit_id: str, reason: str) -> None:
        """Mark a circuit as failed and take appropriate action.

        Args:
            circuit_id: ID of the failed circuit.
            reason: Reason for the failure.
        """
        if circuit_id not in self.circuits:
            return

        circuit = self.circuits[circuit_id]
        circuit["error_count"] += 1
        circuit["last_error"] = reason
        circuit["last_error_time"] = time.time()

        logger.warning(f"Circuit {circuit_id} failed: {reason}")

        # Notify listeners
        if self.on_circuit_failed:
            await self.on_circuit_failed(circuit_id, reason)

        # Close the circuit if it has too many errors
        if circuit["error_count"] >= 3:
            await self.close_circuit(circuit_id, "too many errors")

    async def get_circuit_for_stream(self, stream_purpose: str = "general") -> Optional[Dict]:
        """Get the best circuit for a new stream.

        Args:
            stream_purpose: Purpose of the stream.

        Returns:
            Dictionary with circuit information, or None if no suitable circuit is available.
        """
        if not self.circuits:
            # Try to create a new circuit if none exist
            circuit = await self.create_circuit(stream_purpose)
            if circuit:
                return circuit
            return None

        # Try to find a suitable circuit
        suitable_circuits = [
            c for c in self.circuits.values() if c["is_usable"] and c["purpose"] == stream_purpose
        ]

        if not suitable_circuits and stream_purpose != "general":
            # Fall back to general-purpose circuits
            suitable_circuits = [
                c for c in self.circuits.values() if c["is_usable"] and c["purpose"] == "general"
            ]

        if not suitable_circuits:
            # Try to create a new circuit if no suitable ones exist
            circuit = await self.create_circuit(stream_purpose)
            if circuit:
                return circuit

            # If still no circuits, return None
            return None

        # Select the least recently used circuit
        selected = min(suitable_circuits, key=lambda c: c["last_used"])
        selected["last_used"] = time.time()

        # Set as active circuit
        self.active_circuit_id = selected["id"]

        return selected

    async def _maintenance_loop(self) -> None:
        """Background task for circuit maintenance."""
        while self.is_running:
            try:
                await self._do_maintenance()
            except Exception as e:
                logger.error(f"Error in circuit maintenance: {e}")

            # Wait before next maintenance cycle
            await asyncio.sleep(self._circuit_cleanup_interval)

    async def _do_maintenance(self) -> None:
        """Perform maintenance tasks on circuits."""
        if not self.is_running:
            return

        current_time = time.time()

        # Close old circuits
        for circuit_id in list(self.circuits.keys()):
            circuit = self.circuits[circuit_id]
            circuit_age = current_time - circuit["created_at"]

            if circuit_age > self._circuit_max_age:
                await self.close_circuit(circuit_id, "circuit too old")

        # Ensure we have enough circuits
        active_circuits = len(self.circuits)
        if active_circuits < self._min_circuits:
            for _ in range(self._min_circuits - active_circuits):
                await self.create_circuit()

        # If we have too many circuits, close some
        elif active_circuits > self._max_circuits:
            # Close the least recently used circuits
            circuits_by_age = sorted(self.circuits.values(), key=lambda c: c["last_used"])

            for circuit in circuits_by_age[self._max_circuits :]:
                await self.close_circuit(circuit["id"], "too many circuits")

    def _get_circuit_params(self, purpose: str) -> Dict:
        """Get parameters for a new circuit based on its purpose.

        Args:
            purpose: Purpose of the circuit.

        Returns:
            Dictionary of circuit parameters.
        """
        params = {
            "purpose": purpose,
            "exclude_nodes": list(self._excluded_nodes),
            "exclude_exit_nodes": list(self._excluded_exit_nodes),
            "prefer_exit_nodes": list(self._preferred_exit_nodes),
            "enforce_distinct_subnets": self.config.get("enforce_distinct_subnets", True),
            "use_vanguards": self.config.get("use_vanguards", True),
            "use_ntor_v3": self.config.get("use_ntor_v3", True),
        }

        # Adjust parameters based on purpose
        if purpose == "streaming":
            # Prefer faster nodes for streaming
            params["prefer_fast"] = True
            params["prefer_stable"] = True
            params["need_uptime"] = True
        elif purpose == "download":
            # Prefer high-bandwidth nodes for downloads
            params["prefer_fast"] = True
            params["prefer_stable"] = True
        elif purpose == "general":
            # Balanced approach for general use
            params["prefer_stable"] = True

        return params

    async def _build_path_spec(self, params: Dict) -> List[Dict]:
        """Build a path specification for a new circuit.

        Args:
            params: Circuit parameters.

        Returns:
            List of path specifications for the circuit.
        """
        # This is a simplified version - in a real implementation, you would
        # use the Tor control protocol to build a more sophisticated path spec

        # Get the number of hops (default to 3 for normal circuits)
        num_hops = 3
        if params.get("single_hop", False):
            num_hops = 1

        path_spec = []

        # Add entry guard if configured
        if params.get("use_vanguards", True) and num_hops > 1:
            # In a real implementation, you would select from configured guards
            pass

        # Add middle nodes
        for i in range(1, num_hops):
            # In a real implementation, you would select nodes based on params
            node_spec = {}

            if i == num_hops - 1 and params.get("prefer_exit_nodes"):
                # Prefer exit nodes for the last hop
                node_spec["exit"] = True

            path_spec.append(node_spec)

        return path_spec

    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
