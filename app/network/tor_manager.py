"""
Tor connection manager with circuit isolation and automatic renewal.
"""

import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from threading import Lock, Timer
from typing import Dict, List, Optional

import stem
import stem.connection
import stem.control
import stem.process

# Configure logging
logger = logging.getLogger(__name__)


class TorCircuitState(Enum):
    """State of a Tor circuit."""

    NEW = auto()
    BUILDING = auto()
    READY = auto()
    FAILED = auto()
    CLOSED = auto()


@dataclass
class TorCircuit:
    """Represents a Tor circuit with its state and metadata."""

    circuit_id: str
    purpose: str
    state: TorCircuitState = TorCircuitState.NEW
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_isolated: bool = True
    stream_count: int = 0
    nodes: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "circuit_id": self.circuit_id,
            "purpose": self.purpose,
            "state": self.state.name,
            "age_seconds": int(time.time() - self.created_at),
            "idle_seconds": int(time.time() - self.last_used),
            "is_isolated": self.is_isolated,
            "stream_count": self.stream_count,
            "node_count": len(self.nodes),
            "nodes": self.nodes,
        }


class TorManager:
    """Manages Tor connections and circuit isolation."""

    def __init__(
        self,
        control_port: int = 9051,  # Control port (default for Tor Browser)
        socks_port: int = 9050,  # SOCKS port (default for Tor Browser)
        tor_data_dir: str = None,
        tor_binary: str = None,
        password: str = None,
        circuit_timeout: int = 600,  # 10 minutes
        max_circuit_dirtiness: int = 3600,  # 1 hour
        max_circuits_per_purpose: int = 3,
    ):
        """Initialize the Tor manager.

        Args:
            control_port: Tor control port
            socks_port: Tor SOCKS port
            tor_data_dir: Directory for Tor data files
            tor_binary: Path to Tor binary (if None, will use system Tor)
            password: Tor control port password (if None, will try to authenticate without password)
            circuit_timeout: Seconds before an idle circuit is closed
            max_circuit_dirtiness: Maximum lifetime of a circuit in seconds
            max_circuits_per_purpose: Maximum number of circuits to maintain per purpose
        """
        self.control_port = control_port
        self.socks_port = socks_port
        self.tor_data_dir = Path(tor_data_dir) if tor_data_dir else Path("tor_data")
        self.tor_binary = tor_binary
        self.password = password
        self.circuit_timeout = circuit_timeout
        self.max_circuit_dirtiness = max_circuit_dirtiness
        self.max_circuits_per_purpose = max_circuits_per_purpose

        self.controller: Optional[stem.control.Controller] = None
        self.tor_process: Optional[stem.process.LaunchedTor] = None
        self.circuits: Dict[str, TorCircuit] = {}
        self.circuit_lock = Lock()
        self.is_running = False
        self.monitor_thread = None
        self.cleanup_timer = None

        # Circuit isolation flags for different purposes
        self.purpose_isolation = {
            "default": True,
            "browsing": True,
            "api": True,
            "download": True,
            "onion": True,
        }

    def start(self) -> bool:
        """Start the Tor manager and establish control connection."""
        if self.is_running:
            return True

        try:
            # Try to connect to existing Tor instance
            self.controller = self._connect_to_tor()
            if not self.controller:
                logger.info("No existing Tor instance found. Starting new Tor process...")
                if not self._start_tor():
                    logger.error("Failed to start Tor process")
                    return False
                # Give Tor some time to start
                time.sleep(2)
                self.controller = self._connect_to_tor()

            if not self.controller:
                logger.error("Failed to connect to or start Tor")
                return False

            # Enable events for circuit monitoring
            self.controller.add_event_listener(
                self._handle_tor_event,
                stem.control.EventType.CIRC,
                stem.control.EventType.STREAM,
                stem.control.EventType.NOTICE,
                stem.control.EventType.WARN,
                stem.control.EventType.ERR,
            )

            # Start background tasks
            self.is_running = True
            self._start_cleanup_timer()

            logger.info(
                f"Tor manager started successfully (control_port={self.control_port}, socks_port={self.socks_port})"
            )
            return True

        except Exception as e:
            logger.exception("Failed to start Tor manager")
            self.stop()
            return False

    def stop(self) -> None:
        """Stop the Tor manager and clean up resources."""
        self.is_running = False

        if self.cleanup_timer:
            self.cleanup_timer.cancel()
            self.cleanup_timer = None

        if self.controller:
            try:
                self.controller.remove_event_listener(self._handle_tor_event)
                self.controller.close()
            except Exception:
                pass
            self.controller = None

        if self.tor_process:
            try:
                self.tor_process.terminate()
            except Exception:
                pass
            self.tor_process = None

        logger.info("Tor manager stopped")

    def _connect_to_tor(self) -> Optional[stem.control.Controller]:
        """Connect to an existing Tor instance."""
        try:
            controller = stem.control.Controller.from_port(port=self.control_port)

            # Authenticate
            try:
                if self.password:
                    controller.authenticate(password=self.password)
                else:
                    # Try authentication without password (cookie auth)
                    try:
                        controller.authenticate()
                    except stem.connection.AuthenticationFailure as e:
                        logger.warning(
                            f"Cookie authentication failed: {e}. Trying without authentication..."
                        )
                        # Try one more time without authentication
                        controller.authenticate(None)

                logger.info("Connected to existing Tor instance")
                return controller

            except stem.connection.MissingPassword:
                logger.warning("Tor requires a password for authentication")
                return None

        except Exception as e:
            logger.debug(f"Could not connect to Tor control port: {e}")
            return None

    def _find_available_port(self, start_port: int, max_attempts: int = 10) -> int:
        """Find an available port starting from start_port."""
        import socket

        for port in range(start_port, start_port + max_attempts):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.bind(("127.0.0.1", port))
                    return port
            except (OSError, socket.error):
                continue
        raise RuntimeError(
            f"Could not find available port in range {start_port}-{start_port + max_attempts}"
        )

    def _start_tor(self) -> bool:
        """Start a new Tor process with better error handling and logging.

        Returns:
            bool: True if Tor started successfully, False otherwise
        """
        try:
            # Create data directory if it doesn't exist
            self.tor_data_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Using Tor data directory: {self.tor_data_dir}")

            # Try to find available ports if default ports are in use
            try:
                # First try the default Tor Browser ports
                if self.control_port == 9051 and self.socks_port == 9050:
                    try:
                        # Check if ports are available
                        self._find_available_port(9051, 1)
                        self._find_available_port(9050, 1)
                    except RuntimeError:
                        # If default ports are in use, find alternatives
                        self.control_port = self._find_available_port(9052)
                        self.socks_port = self._find_available_port(9053)
                else:
                    # If custom ports are specified, just check if they're available
                    self.control_port = self._find_available_port(self.control_port, 1)
                    self.socks_port = self._find_available_port(self.socks_port, 1)

                logger.info(
                    f"Using control port: {self.control_port}, SOCKS port: {self.socks_port}"
                )
            except Exception as e:
                logger.error(f"Could not find available ports: {e}")
                return False

            # Use cookie authentication instead of password
            password_config = None
            logger.info("Using cookie authentication")

            # Configure Tor with essential settings
            torrc = {
                "ControlPort": str(self.control_port),
                "SOCKSPort": str(self.socks_port),
                "DataDirectory": str(self.tor_data_dir),
                "Log": "notice stdout",
                "ClientOnly": "1",
                "AvoidDiskWrites": "1",
                "LogMessageDomains": "1",
            }

            # Add password authentication if available, otherwise use cookie auth
            if password_config:
                torrc["HashedControlPassword"] = password_config
            else:
                torrc["CookieAuthentication"] = "1"

            # Try to find Tor binary if not specified
            if not self.tor_binary:
                possible_paths = [
                    r"C:\Users\Admin\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
                    r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
                    r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe",
                    "/usr/bin/tor",
                    "/usr/local/bin/tor",
                    "/opt/homebrew/bin/tor",
                ]

                for path in possible_paths:
                    if os.path.exists(path):
                        self.tor_binary = path
                        logger.info(f"Found Tor binary at: {path}")
                        break

                if not self.tor_binary:
                    logger.error(
                        "Could not find Tor binary. Please install Tor Browser or specify the path."
                    )
                    return False

            # Start Tor process
            logger.info("Starting Tor process...")
            try:
                launch_kwargs = {
                    "config": torrc,
                    "init_msg_handler": self._tor_status_update,
                    "tor_cmd": self.tor_binary,
                    "take_ownership": True,
                    "completion_percent": 100,  # Wait for full bootstrap
                }

                # Only add timeout on non-Windows systems
                if os.name != "nt":
                    launch_kwargs["timeout"] = 120

                self.tor_process = stem.process.launch_tor_with_config(**launch_kwargs)
                logger.info("Tor process started successfully")
            except OSError as e:
                if "The system cannot find the file specified" in str(e):
                    error_msg = """
                    Could not find Tor executable. Please install Tor Browser from:
                    https://www.torproject.org/download/
                    
                    Or specify the path to the Tor binary when initializing TorManager:
                    tor_manager = TorManager(tor_binary=r'C:\\path\\to\\tor.exe')
                    """
                    logger.error(error_msg)
                    return False
                logger.error(f"Failed to start Tor process: {e}")
                return False
            except Exception as e:
                logger.error(f"Unexpected error starting Tor: {e}")
                return False

            return True

            # Connect to the new Tor instance with retries
            max_retries = 3
            for attempt in range(max_retries):
                self.controller = self._connect_to_tor()
                if self.controller:
                    break
                logger.warning(
                    f"Connection attempt {attempt + 1}/{max_retries} failed, retrying..."
                )
                time.sleep(1)

            if not self.controller:
                raise RuntimeError(
                    f"Failed to connect to Tor control port after {max_retries} attempts. "
                    f"Make sure Tor is running and the control port ({self.control_port}) is accessible."
                )

            logger.info("Successfully started and connected to Tor")

            # Verify Tor is working
            try:
                version = self.controller.get_version()
                logger.info(f"Connected to Tor version: {version}")
            except Exception as e:
                logger.warning(f"Could not get Tor version: {e}")

        except Exception as e:
            logger.exception("Failed to start Tor")
            if hasattr(self, "tor_process") and self.tor_process:
                try:
                    self.tor_process.terminate()
                except Exception as term_e:
                    logger.warning(f"Error terminating Tor process: {term_e}")
                self.tor_process = None
            raise

    def _tor_status_update(self, line: str) -> None:
        """Handle Tor bootstrap status updates."""
        if "Bootstrapped" in line:
            logger.info(f"Tor: {line}")

    def _handle_tor_event(self, event: stem.response.events.Event) -> None:
        """Handle Tor control port events."""
        try:
            if isinstance(event, stem.response.events.CircuitEvent):
                self._handle_circuit_event(event)
            elif isinstance(event, stem.response.events.StreamEvent):
                self._handle_stream_event(event)
            elif isinstance(
                event,
                (
                    stem.response.events.NoticeEvent,
                    stem.response.events.WarnEvent,
                    stem.response.events.ErrorEvent,
                ),
            ):
                logger.log(
                    (
                        logging.WARNING
                        if isinstance(event, stem.response.events.WarnEvent)
                        else (
                            logging.ERROR
                            if isinstance(event, stem.response.events.ErrorEvent)
                            else logging.INFO
                        )
                    ),
                    f"Tor: {event}",
                )
        except Exception as e:
            logger.exception(f"Error handling Tor event: {e}")

    def _handle_circuit_event(self, event: stem.response.events.CircuitEvent) -> None:
        """Handle circuit-related events."""
        with self.circuit_lock:
            circuit_id = event.id

            if event.status == "BUILT":
                # New circuit built
                if circuit_id not in self.circuits:
                    # This is a circuit we didn't explicitly create, possibly from another controller
                    return

                circuit = self.circuits[circuit_id]
                circuit.state = TorCircuitState.READY
                circuit.nodes = self._get_circuit_nodes(circuit_id)
                logger.debug(f"Circuit {circuit_id} is ready with {len(circuit.nodes)} nodes")

            elif event.status == "CLOSED":
                # Circuit closed
                if circuit_id in self.circuits:
                    del self.circuits[circuit_id]
                    logger.debug(f"Circuit {circuit_id} closed")

            elif event.status in ("FAILED", "CLOSED"):
                # Circuit failed or was closed
                if circuit_id in self.circuits:
                    circuit = self.circuits[circuit_id]
                    circuit.state = (
                        TorCircuitState.FAILED
                        if event.status == "FAILED"
                        else TorCircuitState.CLOSED
                    )
                    logger.warning(
                        f"Circuit {circuit_id} {event.status.lower()}: purpose={circuit.purpose}"
                    )

    def _handle_stream_event(self, event: stem.response.events.StreamEvent) -> None:
        """Handle stream-related events."""
        if event.status == "SUCCEEDED" and event.circ_id in self.circuits:
            with self.circuit_lock:
                circuit = self.circuits[event.circ_id]
                circuit.stream_count += 1
                circuit.last_used = time.time()

    def _get_circuit_nodes(self, circuit_id: str) -> List[str]:
        """Get the list of nodes in a circuit."""
        if not self.controller:
            return []

        try:
            circuit = self.controller.get_circuit(circuit_id)
            return [path[0] for path in circuit.path]
        except Exception as e:
            logger.warning(f"Failed to get nodes for circuit {circuit_id}: {e}")
            return []

    def _start_cleanup_timer(self) -> None:
        """Start the periodic circuit cleanup timer."""
        if not self.is_running:
            return

        self.cleanup_timer = Timer(60.0, self._cleanup_circuits)
        self.cleanup_timer.daemon = True
        self.cleanup_timer.start()

    def _cleanup_circuits(self) -> None:
        """Clean up old and unused circuits."""
        try:
            if not self.controller:
                return

            now = time.time()
            circuits_to_close = []

            with self.circuit_lock:
                # Group circuits by purpose
                circuits_by_purpose = {}
                for circuit_id, circuit in list(self.circuits.items()):
                    if circuit.purpose not in circuits_by_purpose:
                        circuits_by_purpose[circuit.purpose] = []
                    circuits_by_purpose[circuit.purpose].append(circuit)

                # Close circuits that are too old or idle
                for purpose, circuits in circuits_by_purpose.items():
                    # Sort by last_used (oldest first)
                    circuits.sort(key=lambda c: c.last_used)

                    # Close circuits that are too old
                    for circuit in circuits:
                        circuit_age = now - circuit.created_at
                        idle_time = now - circuit.last_used

                        if circuit_age > self.max_circuit_dirtiness or (
                            idle_time > self.circuit_timeout and circuit.stream_count > 0
                        ):
                            circuits_to_close.append(circuit.circuit_id)

                    # If we have too many circuits for this purpose, close the oldest ones
                    if len(circuits) > self.max_circuits_per_purpose:
                        for circuit in circuits[: len(circuits) - self.max_circuits_per_purpose]:
                            if circuit.circuit_id not in circuits_to_close:
                                circuits_to_close.append(circuit.circuit_id)

                # Close the circuits
                for circuit_id in circuits_to_close:
                    if circuit_id in self.circuits:
                        circuit = self.circuits[circuit_id]
                        logger.debug(
                            f"Closing circuit {circuit_id} (purpose={circuit.purpose}, "
                            f"age={int(now - circuit.created_at)}s, "
                            f"idle={int(now - circuit.last_used)}s)"
                        )

                        try:
                            self.controller.close_circuit(circuit_id)
                        except Exception as e:
                            logger.warning(f"Failed to close circuit {circuit_id}: {e}")

                        if circuit_id in self.circuits:
                            del self.circuits[circuit_id]

        except Exception as e:
            logger.exception("Error in circuit cleanup")

        finally:
            # Schedule the next cleanup
            self._start_cleanup_timer()

    def get_circuit_for_purpose(self, purpose: str) -> Optional[str]:
        """Get or create a circuit for the given purpose."""
        if not self.controller or not self.is_running:
            return None

        with self.circuit_lock:
            # Check for existing circuits for this purpose
            now = time.time()
            existing_circuits = []

            for circuit_id, circuit in self.circuits.items():
                if (
                    circuit.purpose == purpose
                    and circuit.state == TorCircuitState.READY
                    and now - circuit.last_used < self.circuit_timeout
                ):
                    existing_circuits.append(circuit)

            # Sort by stream count (least used first)
            existing_circuits.sort(key=lambda c: c.stream_count)

            # Return the least used circuit if we have one
            if existing_circuits:
                circuit = existing_circuits[0]
                circuit.last_used = now
                logger.debug(f"Reusing circuit {circuit.circuit_id} for purpose '{purpose}'")
                return circuit.circuit_id

            # No suitable circuit found, create a new one
            try:
                # Generate a unique circuit ID
                circuit_id = str(len(self.circuits) + 1)

                # Create a new circuit
                self.controller.new_circuit(
                    await_build=True,
                    purpose=purpose,
                    isolation_flags=(
                        ["IsolateDestPort", "IsolateDestAddr"]
                        if self.purpose_isolation.get(purpose, True)
                        else []
                    ),
                )

                # Create circuit object
                circuit = TorCircuit(
                    circuit_id=circuit_id,
                    purpose=purpose,
                    state=TorCircuitState.BUILDING,
                    is_isolated=self.purpose_isolation.get(purpose, True),
                )

                self.circuits[circuit_id] = circuit
                logger.debug(f"Created new circuit {circuit_id} for purpose '{purpose}'")

                # Wait for circuit to be built (with timeout)
                start_time = time.time()
                while (
                    circuit.state != TorCircuitState.READY and time.time() - start_time < 30
                ):  # 30 second timeout
                    time.sleep(0.1)
                    circuit = self.circuits.get(circuit_id)
                    if not circuit:
                        break

                if circuit and circuit.state == TorCircuitState.READY:
                    return circuit_id
                else:
                    logger.warning(f"Timed out waiting for circuit {circuit_id} to build")
                    if circuit_id in self.circuits:
                        del self.circuits[circuit_id]
                    return None

            except Exception as e:
                logger.exception(f"Failed to create circuit for purpose '{purpose}': {e}")
                if circuit_id in self.circuits:
                    del self.circuits[circuit_id]
                return None

    def get_circuit_info(self, circuit_id: str) -> Optional[dict]:
        """Get information about a circuit."""
        with self.circuit_lock:
            circuit = self.circuits.get(circuit_id)
            if circuit:
                return circuit.to_dict()
            return None

    def get_all_circuits(self) -> List[dict]:
        """Get information about all circuits."""
        with self.circuit_lock:
            return [circuit.to_dict() for circuit in self.circuits.values()]

    def close_circuit(self, circuit_id: str) -> bool:
        """Close a circuit."""
        if not self.controller:
            return False

        try:
            self.controller.close_circuit(circuit_id)
            with self.circuit_lock:
                if circuit_id in self.circuits:
                    del self.circuits[circuit_id]
            return True
        except Exception as e:
            logger.warning(f"Failed to close circuit {circuit_id}: {e}")
            return False

    def new_identity(self) -> bool:
        """Request a new identity (new Tor circuit)."""
        if not self.controller:
            return False

        try:
            self.controller.signal(stem.Signal.NEWNYM)
            logger.info("Requested new Tor identity")
            return True
        except Exception as e:
            logger.error(f"Failed to request new Tor identity: {e}")
            return False

    def get_connection_status(self) -> dict:
        """Get the current Tor connection status."""
        if not self.controller:
            return {
                "connected": False,
                "status": "disconnected",
                "circuit_count": 0,
                "active_streams": 0,
                "tor_version": None,
                "is_newnym_available": False,
                "isolation_enabled": True,
            }

        try:
            # Get basic Tor info
            tor_info = self.controller.get_info(
                [
                    "version",
                    "status/circuit-established",
                    "circuit-status",
                    "stream-status",
                    "net/listeners/socks",
                    "net/listeners/control",
                    "entry-guards",
                    "ns/all",
                    "address-mappings/all",
                    "accounting/bytes",
                    "accounting/bytes-left",
                    "accounting/enabled",
                    "accounting/hibernating",
                    "accounting/limit",
                    "accounting/start",
                    "accounting/used",
                ]
            )

            # Count active circuits and streams
            circuits = self.controller.get_circuits()
            active_circuits = [c for c in circuits if c.status == "BUILT"]

            streams = self.controller.get_streams()
            active_streams = [s for s in streams if s.status == "SUCCEEDED"]

            # Check if we can request a new identity
            can_new_identity = False
            try:
                self.controller.signal("HEARTBEAT")
                can_new_identity = True
            except:
                pass

            return {
                "connected": True,
                "status": "connected",
                "circuit_count": len(active_circuits),
                "active_streams": len(active_streams),
                "tor_version": tor_info.get("version", "unknown"),
                "is_newnym_available": can_new_identity,
                "isolation_enabled": True,
                "socks_port": self.socks_port,
                "control_port": self.control_port,
                "circuits": [
                    {
                        "id": c.id,
                        "status": c.status,
                        "purpose": c.purpose if hasattr(c, "purpose") else "unknown",
                        "built": c.status == "BUILT",
                        "path": [hop[0] for hop in c.path] if c.path else [],
                        "time_created": c.time_created if hasattr(c, "time_created") else 0,
                    }
                    for c in active_circuits
                ],
                "bandwidth": {
                    "bytes_read": int(tor_info.get("traffic/read", 0)),
                    "bytes_written": int(tor_info.get("traffic/written", 0)),
                },
                "entry_guards": (
                    tor_info.get("entry-guards", "").split("\n")
                    if "entry-guards" in tor_info
                    else []
                ),
            }

        except Exception as e:
            logger.exception("Error getting Tor connection status")
            return {
                "connected": False,
                "status": "error",
                "error": str(e),
                "circuit_count": 0,
                "active_streams": 0,
                "tor_version": None,
                "is_newnym_available": False,
                "isolation_enabled": False,
            }

    def get_network_info(self) -> dict:
        """Get information about the Tor network."""
        if not self.controller:
            return {}

        try:
            # Get network status documents
            consensus = self.controller.get_network_statuses()

            # Count relays by type
            relays = {}
            for desc in consensus:
                relay_type = []
                if "Exit" in desc.flags:
                    relay_type.append("exit")
                if "Guard" in desc.flags:
                    relay_type.append("guard")
                if "Authority" in desc.flags:
                    relay_type.append("authority")
                if not relay_type:
                    relay_type.append("middle")

                for t in relay_type:
                    relays[t] = relays.get(t, 0) + 1

            # Get Tor version
            tor_version = self.controller.get_version()

            return {
                "relay_counts": relays,
                "total_relays": len(consensus),
                "tor_version": str(tor_version),
                "is_live": True,
            }

        except Exception as e:
            logger.exception("Error getting Tor network info")
            return {"error": str(e), "is_live": False}


# Singleton instance
tor_manager = TorManager()
