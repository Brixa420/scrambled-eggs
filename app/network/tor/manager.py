""
Tor connection manager with circuit isolation, metrics, and monitoring.
"""
import os
import time
import logging
import threading
import random
from enum import Enum, auto
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

import stem
import stem.control
import stem.process
import stem.connection
from stem.control import Controller, EventType
from stem.process import launch_tor_with_config
from stem.util import term

from .metrics import MetricsStorage
from .dashboard import MetricsDashboard

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
    """Represents a Tor circuit with its state and metrics."""
    circuit_id: str
    purpose: str
    isolation_group: str
    state: TorCircuitState = TorCircuitState.NEW
    created_at: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    is_isolated: bool = True
    stream_count: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    request_count: int = 0
    error_count: int = 0
    latency_samples: List[float] = field(default_factory=list)
    state_changes: Dict[str, float] = field(default_factory=dict)
    
    def __post_init__(self):
        self.record_state_change('created')
    
    def record_state_change(self, state: str) -> None:
        """Record a state change with timestamp."""
        self.state_changes[state] = time.time()
    
    def record_request(self, bytes_sent: int, bytes_received: int, latency: float) -> None:
        """Record a successful request through this circuit."""
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        self.request_count += 1
        self.latency_samples.append(latency)
        self.last_used = time.time()
    
    def record_error(self) -> None:
        """Record a failed request."""
        self.error_count += 1
        self.request_count += 1
        self.last_used = time.time()
    
    @property
    def avg_latency(self) -> Optional[float]:
        """Get the average request latency in seconds."""
        if not self.latency_samples:
            return None
        return sum(self.latency_samples) / len(self.latency_samples)
    
    @property
    def error_rate(self) -> float:
        """Get the error rate as a percentage."""
        if self.request_count == 0:
            return 0.0
        return (self.error_count / self.request_count) * 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'circuit_id': self.circuit_id,
            'purpose': self.purpose,
            'isolation_group': self.isolation_group,
            'state': self.state.name,
            'created_at': self.created_at,
            'last_used': self.last_used,
            'is_isolated': self.is_isolated,
            'stream_count': self.stream_count,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'request_count': self.request_count,
            'error_count': self.error_count,
            'avg_latency': self.avg_latency,
            'error_rate': self.error_rate,
            'state_changes': self.state_changes,
            'latency_samples_count': len(self.latency_samples)
        }

class TorManager:
    """Manages Tor connections, circuits, and metrics."""
    
    def __init__(
        self,
        control_port: int = 9051,  # Default Tor control port
        socks_port: int = 9050,    # Default Tor SOCKS port
        tor_data_dir: Optional[str] = None,
        tor_binary: Optional[str] = None,
        password: Optional[str] = None,
        enable_metrics: bool = True,
        metrics_db_url: Optional[str] = None,
        enable_dashboard: bool = False,
        dashboard_host: str = '127.0.0.1',
        dashboard_port: int = 8050
    ):
        """Initialize the Tor manager.
        
        Args:
            control_port: Port for Tor control connection
            socks_port: Port for Tor SOCKS proxy
            tor_data_dir: Directory for Tor data files
            tor_binary: Path to Tor binary (auto-detected if None)
            password: Password for Tor control port
            enable_metrics: Whether to collect and store metrics
            metrics_db_url: Database URL for metrics storage
            enable_dashboard: Whether to enable the web dashboard
            dashboard_host: Dashboard bind address
            dashboard_port: Dashboard port
        """
        self.control_port = control_port
        self.socks_port = socks_port
        self.tor_data_dir = Path(tor_data_dir) if tor_data_dir else Path('tor_data')
        self.tor_binary = tor_binary or self._find_tor_binary()
        self.password = password
        
        # Circuit management
        self.circuits: Dict[str, TorCircuit] = {}
        self.circuit_lock = threading.RLock()
        self.is_running = False
        self.controller: Optional[Controller] = None
        self.tor_process = None
        
        # Metrics and monitoring
        self.enable_metrics = enable_metrics
        self.metrics_storage = None
        self.metrics_thread = None
        self.metrics_interval = 60  # seconds
        
        if enable_metrics:
            try:
                self.metrics_storage = MetricsStorage(metrics_db_url)
                logger.info("Metrics collection enabled")
            except Exception as e:
                logger.error(f"Failed to initialize metrics storage: {e}")
                self.enable_metrics = False
        
        # Web dashboard
        self.dashboard = None
        self.enable_dashboard = enable_dashboard and self.enable_metrics
        
        if self.enable_dashboard:
            try:
                self.dashboard = MetricsDashboard(
                    storage=self.metrics_storage,
                    host=dashboard_host,
                    port=dashboard_port
                )
                logger.info(f"Dashboard enabled at http://{dashboard_host}:{dashboard_port}")
            except Exception as e:
                logger.error(f"Failed to initialize dashboard: {e}")
                self.enable_dashboard = False
        
        # Circuit isolation settings
        self.purpose_isolation = {
            'default': True,
            'browsing': True,
            'api': True,
            'download': True,
            'onion': True
        }
        
        # Default circuit settings
        self.circuit_timeout = 600  # 10 minutes
        self.max_circuit_dirtiness = 3600  # 1 hour
        self.max_circuits_per_purpose = 3
        
        logger.info("TorManager initialized")
    
    # Core Tor Management Methods
    
    def start(self) -> bool:
        """Start the Tor process and initialize the controller."""
        if self.is_running:
            logger.warning("Tor manager is already running")
            return True
        
        try:
            # Create data directory if it doesn't exist
            self.tor_data_dir.mkdir(parents=True, exist_ok=True)
            
            # Start Tor process
            self._start_tor_process()
            
            # Connect to control port
            self._connect_to_controller()
            
            # Start metrics collection
            if self.enable_metrics:
                self._start_metrics_collection()
            
            # Start dashboard if enabled
            if self.enable_dashboard and self.dashboard:
                self.dashboard.start()
            
            self.is_running = True
            logger.info("Tor manager started successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start Tor manager: {e}")
            self.stop()
            return False
    
    def stop(self) -> None:
        """Stop the Tor process and clean up resources."""
        if not self.is_running:
            return
        
        logger.info("Stopping Tor manager...")
        
        # Stop metrics collection
        if self.metrics_thread:
            self.metrics_thread.cancel()
            self.metrics_thread = None
        
        # Close all circuits
        with self.circuit_lock:
            for circuit_id in list(self.circuits.keys()):
                self._close_circuit(circuit_id)
        
        # Stop Tor process
        if self.controller:
            try:
                self.controller.close()
            except Exception as e:
                logger.error(f"Error closing controller: {e}")
            self.controller = None
        
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait()
            except Exception as e:
                logger.error(f"Error stopping Tor process: {e}")
            self.tor_process = None
        
        self.is_running = False
        logger.info("Tor manager stopped")
    
    def _start_tor_process(self) -> None:
        """Start the Tor process if not already running."""
        if self.tor_process is not None:
            return
        
        # Check if Tor is already running
        if self._is_tor_running():
            logger.info("Using existing Tor process")
            return
        
        # Configure Tor
        torrc = {
            'ControlPort': str(self.control_port),
            'SOCKSPort': str(self.socks_port),
            'DataDirectory': str(self.tor_data_dir),
            'Log': 'notice stdout',
            'ClientOnly': '1',
            'AvoidDiskWrites': '1',
            'LogMessageDomains': '1',
        }
        
        if self.password:
            hashed_password = self._hash_control_password()
            torrc['HashedControlPassword'] = hashed_password
        else:
            torrc['CookieAuthentication'] = '1'
        
        # Start Tor
        logger.info("Starting Tor process...")
        self.tor_process = launch_tor_with_config(
            config=torrc,
            init_msg_handler=self._tor_status_update,
            tor_cmd=self.tor_binary,
            take_ownership=True,
            completion_percent=100  # Wait for full bootstrap
        )
        logger.info("Tor process started")
    
    def _connect_to_controller(self) -> None:
        """Connect to the Tor control port."""
        if self.controller is not None:
            return
        
        logger.info(f"Connecting to Tor control port {self.control_port}...")
        
        try:
            self.controller = Controller.from_port(port=self.control_port)
            
            # Authenticate
            if self.password:
                self.controller.authenticate(password=self.password)
            else:
                try:
                    self.controller.authenticate()
                except stem.connection.MissingPassword:
                    # Try without authentication
                    self.controller.authenticate(None)
            
            logger.info("Successfully connected to Tor control port")
            
            # Set up event listeners
            self.controller.add_event_listener(
                self._handle_tor_event,
                EventType.STREAM,
                EventType.CIRC,
                EventType.NOTICE,
                EventType.WARN,
                EventType.ERR
            )
            
        except Exception as e:
            self.controller = None
            logger.error(f"Failed to connect to Tor control port: {e}")
            raise
    
    # Circuit Management Methods
    
    def get_circuit(
        self,
        purpose: str = "default",
        isolation_group: Optional[str] = None,
        force_new: bool = False
    ) -> Optional[TorCircuit]:
        """Get or create a circuit for the given purpose and isolation group.
        
        Args:
            purpose: Purpose of the circuit (e.g., 'browsing', 'api')
            isolation_group: Isolation group for the circuit
            force_new: If True, always create a new circuit
            
        Returns:
            TorCircuit instance or None if creation failed
        """
        if not self.is_running:
            logger.warning("Tor manager is not running")
            return None
        
        isolation_group = isolation_group or purpose
        
        with self.circuit_lock:
            # Clean up old circuits first
            self._cleanup_old_circuits()
            
            # Find an existing circuit if not forcing a new one
            if not force_new:
                circuit = self._find_available_circuit(purpose, isolation_group)
                if circuit:
                    return circuit
            
            # Create a new circuit
            return self._create_new_circuit(purpose, isolation_group)
    
    def close_circuit(self, circuit_id: str) -> bool:
        """Close a circuit by ID.
        
        Args:
            circuit_id: ID of the circuit to close
            
        Returns:
            bool: True if the circuit was closed, False otherwise
        """
        with self.circuit_lock:
            return self._close_circuit(circuit_id)
    
    def get_circuit_status(self, circuit_id: str) -> Optional[Dict[str, Any]]:
        """Get the status of a circuit.
        
        Args:
            circuit_id: ID of the circuit
            
        Returns:
            Dictionary with circuit status or None if not found
        """
        with self.circuit_lock:
            circuit = self.circuits.get(circuit_id)
            if not circuit:
                return None
            
            status = circuit.to_dict()
            
            # Add Tor controller status if available
            if self.controller:
                try:
                    tor_circuit = self.controller.get_circuit(circuit_id)
                    if tor_circuit:
                        status.update({
                            'tor_status': tor_circuit.status,
                            'tor_purpose': tor_circuit.purpose,
                            'tor_flags': tor_circuit.flags,
                            'tor_build_flags': tor_circuit.build_flags,
                            'tor_time_created': tor_circuit.time_created,
                        })
                except Exception as e:
                    logger.warning(f"Failed to get Tor circuit status: {e}")
            
            return status
    
    # Helper Methods
    
    def _find_tor_binary(self) -> Optional[str]:
        """Find the Tor binary path."""
        # Common Tor binary locations
        possible_paths = [
            '/usr/bin/tor',
            '/usr/local/bin/tor',
            '/opt/homebrew/bin/tor',
            'C:\\Program Files\\Tor\\tor.exe',
            'C:\\Program Files (x86)\\Tor\\tor.exe',
            'C:\\Users\\' + os.getlogin() + '\\Desktop\\Tor Browser\\Browser\\TorBrowser\\Tor\\tor.exe',
        ]
        
        for path in possible_paths:
            if os.path.isfile(path):
                return path
        
        # Try to find Tor in PATH
        import shutil
        tor_path = shutil.which('tor')
        if tor_path:
            return tor_path
        
        logger.warning("Could not find Tor binary. Please install Tor or specify the path.")
        return None
    
    def _tor_status_update(self, line: str) -> None:
        """Handle Tor bootstrap status updates."""
        if "Bootstrapped" in line:
            logger.info(f"Tor: {line.strip()}")
        elif "WARN" in line or "ERR" in line:
            logger.warning(f"Tor: {line.strip()}")
        elif "NOTICE" in line:
            logger.debug(f"Tor: {line.strip()}")
    
    def _handle_tor_event(self, event: stem.response.events.Event) -> None:
        """Handle Tor control port events."""
        if not self.is_running:
            return
        
        try:
            if isinstance(event, stem.response.events.StreamEvent):
                self._handle_stream_event(event)
            elif isinstance(event, stem.response.events.CircuitEvent):
                self._handle_circuit_event(event)
            elif isinstance(event, (stem.response.events.LogEvent, stem.response.events.StatusEvent)):
                # Log Tor status messages
                if event.severity in ('WARN', 'ERR'):
                    logger.warning(f"Tor: {event.message}")
                else:
                    logger.debug(f"Tor: {event.message}")
        except Exception as e:
            logger.error(f"Error handling Tor event: {e}", exc_info=True)
    
    def _handle_stream_event(self, event: stem.response.events.StreamEvent) -> None:
        """Handle Tor stream events."""
        circuit = self.circuits.get(event.circuit_id)
        if not circuit:
            return
        
        # Update circuit state based on stream event
        if event.status == 'SUCCEEDED':
            circuit.stream_count += 1
            circuit.last_used = time.time()
        elif event.status in ('FAILED', 'CLOSED'):
            circuit.stream_count = max(0, circuit.stream_count - 1)
    
    def _handle_circuit_event(self, event: stem.response.events.CircuitEvent) -> None:
        """Handle Tor circuit events."""
        circuit = self.circuits.get(event.id)
        if not circuit:
            return
        
        # Update circuit state based on circuit event
        if event.status == 'BUILT':
            circuit.state = TorCircuitState.READY
            circuit.record_state_change('built')
        elif event.status == 'CLOSED':
            circuit.state = TorCircuitState.CLOSED
            circuit.record_state_change('closed')
            with self.circuit_lock:
                self.circuits.pop(event.id, None)
        elif event.status == 'FAILED':
            circuit.state = TorCircuitState.FAILED
            circuit.record_state_change('failed')
    
    def _is_tor_running(self) -> bool:
        """Check if Tor is already running."""
        try:
            controller = Controller.from_port(port=self.control_port)
            controller.close()
            return True
        except:
            return False
    
    def _hash_control_password(self) -> str:
        """Hash the control password for Tor configuration."""
        from hashlib import sha1
        import base64
        # Tor's hashing algorithm: SHA1 of the password
        digest = sha1(self.password.encode('utf-8')).digest()
        hashed = base64.b64encode(digest).decode('utf-8')
        return f"16:{hashed}"
    
    def _find_available_circuit(self, purpose: str, isolation_group: str) -> Optional[TorCircuit]:
        """Find an available circuit for the given purpose and isolation group."""
        now = time.time()
        
        # Count circuits for this purpose
        purpose_count = sum(
            1 for c in self.circuits.values()
            if c.purpose == purpose and c.state == TorCircuitState.READY
        )
        
        # If we're at the limit, try to find an idle circuit to reuse
        if purpose_count >= self.max_circuits_per_purpose:
            for circuit in self.circuits.values():
                if (circuit.purpose == purpose and 
                    circuit.state == TorCircuitState.READY and 
                    (now - circuit.last_used) > self.circuit_timeout):
                    return circuit
            return None
        
        # Find an existing circuit that's ready and not too old
        for circuit in self.circuits.values():
            if (circuit.purpose == purpose and 
                circuit.isolation_group == isolation_group and
                circuit.state == TorCircuitState.READY and
                (now - circuit.last_used) < self.max_circuit_dirtiness):
                return circuit
        
        return None
    
    def _create_new_circuit(self, purpose: str, isolation_group: str) -> Optional[TorCircuit]:
        """Create a new Tor circuit."""
        if not self.controller:
            logger.error("Cannot create circuit: Not connected to Tor control port")
            return None
        
        try:
            # Create a new circuit
            circuit_id = self.controller.new_circuit(await_build=True)
            if not circuit_id:
                logger.error("Failed to create new circuit")
                return None
            
            # Create circuit object
            circuit = TorCircuit(
                circuit_id=circuit_id,
                purpose=purpose,
                isolation_group=isolation_group,
                is_isolated=self.purpose_isolation.get(purpose, True)
            )
            
            # Store circuit
            with self.circuit_lock:
                self.circuits[circuit_id] = circuit
            
            logger.info(f"Created new circuit {circuit_id} for {purpose} (isolation: {isolation_group})")
            return circuit
            
        except Exception as e:
            logger.error(f"Failed to create new circuit: {e}")
            return None
    
    def _close_circuit(self, circuit_id: str) -> bool:
        """Close a circuit by ID."""
        if not self.controller:
            return False
        
        circuit = self.circuits.get(circuit_id)
        if not circuit:
            return False
        
        try:
            self.controller.close_circuit(circuit_id)
            circuit.state = TorCircuitState.CLOSED
            circuit.record_state_change('closed')
            self.circuits.pop(circuit_id, None)
            logger.debug(f"Closed circuit {circuit_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to close circuit {circuit_id}: {e}")
            return False
    
    def _cleanup_old_circuits(self) -> None:
        """Clean up old and unused circuits."""
        if not self.circuits:
            return
        
        now = time.time()
        to_remove = []
        
        with self.circuit_lock:
            for circuit_id, circuit in list(self.circuits.items()):
                # Skip if circuit is already closed
                if circuit.state == TorCircuitState.CLOSED:
                    to_remove.append(circuit_id)
                    continue
                
                # Close circuits that are too old
                circuit_age = now - circuit.created_at
                if circuit_age > self.max_circuit_dirtiness:
                    logger.debug(f"Closing old circuit {circuit_id} (age: {circuit_age:.1f}s)")
                    self._close_circuit(circuit_id)
                    to_remove.append(circuit_id)
                    continue
                
                # Close idle circuits
                idle_time = now - circuit.last_used
                if (circuit.state == TorCircuitState.READY and 
                    idle_time > self.circuit_timeout):
                    logger.debug(f"Closing idle circuit {circuit_id} (idle: {idle_time:.1f}s)")
                    self._close_circuit(circuit_id)
                    to_remove.append(circuit_id)
            
            # Remove closed circuits
            for circuit_id in to_remove:
                self.circuits.pop(circuit_id, None)
    
    # Metrics Collection
    
    def _start_metrics_collection(self) -> None:
        """Start periodic metrics collection."""
        if not self.enable_metrics or not self.metrics_storage:
            return
        
        def collect_metrics():
            try:
                self._collect_and_store_metrics()
            except Exception as e:
                logger.error(f"Error collecting metrics: {e}")
            finally:
                # Reschedule
                self.metrics_thread = threading.Timer(
                    self.metrics_interval,
                    collect_metrics
                )
                self.metrics_thread.daemon = True
                self.metrics_thread.start()
        
        # Start the first collection
        self.metrics_thread = threading.Timer(10.0, collect_metrics)  # Initial delay
        self.metrics_thread.daemon = True
        self.metrics_thread.start()
        logger.info("Started metrics collection")
    
    def _collect_and_store_metrics(self) -> None:
        """Collect and store metrics for all circuits."""
        if not self.enable_metrics or not self.metrics_storage:
            return
        
        try:
            # Get current time for this collection
            now = time.time()
            
            # Collect metrics for each circuit
            with self.circuit_lock:
                for circuit in list(self.circuits.values()):
                    try:
                        # Convert circuit to dict and add timestamp
                        metrics = circuit.to_dict()
                        metrics['timestamp'] = now
                        
                        # Save to storage
                        self.metrics_storage.save_circuit_metrics(metrics)
                    except Exception as e:
                        logger.error(f"Error saving metrics for circuit {circuit.circuit_id}: {e}")
            
            # Save aggregate metrics
            self._save_aggregate_metrics(now)
            
            # Clean up old metrics (once per day, with 5% probability on each collection)
            if random.random() < 0.05:
                self.metrics_storage.cleanup_old_metrics(max_age_days=30)
            
            logger.debug(f"Collected metrics for {len(self.circuits)} circuits")
            
        except Exception as e:
            logger.error(f"Error in metrics collection: {e}")
    
    def _save_aggregate_metrics(self, timestamp: float) -> None:
        """Save aggregated metrics for the current time window."""
        if not self.enable_metrics or not self.metrics_storage:
            return
        
        try:
            # Get metrics for all purposes
            purposes = set(c.purpose for c in self.circuits.values())
            
            # Save overall metrics
            overall_metrics = self._calculate_aggregate_metrics()
            if overall_metrics:
                overall_metrics['timestamp'] = timestamp
                overall_metrics['purpose'] = None
                overall_metrics['isolation_group'] = None
                self.metrics_storage.save_metrics_aggregate(overall_metrics)
            
            # Save per-purpose metrics
            for purpose in purposes:
                purpose_metrics = self._calculate_aggregate_metrics(purpose=purpose)
                if purpose_metrics:
                    purpose_metrics['timestamp'] = timestamp
                    purpose_metrics['purpose'] = purpose
                    purpose_metrics['isolation_group'] = None
                    self.metrics_storage.save_metrics_aggregate(purpose_metrics)
            
            # Save per-isolation-group metrics
            isolation_groups = set(c.isolation_group for c in self.circuits.values())
            for group in isolation_groups:
                group_metrics = self._calculate_aggregate_metrics(isolation_group=group)
                if group_metrics:
                    group_metrics['timestamp'] = timestamp
                    group_metrics['purpose'] = None
                    group_metrics['isolation_group'] = group
                    self.metrics_storage.save_metrics_aggregate(group_metrics)
            
        except Exception as e:
            logger.error(f"Error saving aggregate metrics: {e}")
    
    def _calculate_aggregate_metrics(
        self, 
        purpose: Optional[str] = None,
        isolation_group: Optional[str] = None
    ) -> Dict[str, Any]:
        """Calculate aggregate metrics for the given filters."""
        now = time.time()
        
        # Filter circuits
        circuits = []
        for circuit in self.circuits.values():
            if purpose is not None and circuit.purpose != purpose:
                continue
            if isolation_group is not None and circuit.isolation_group != isolation_group:
                continue
            circuits.append(circuit)
        
        if not circuits:
            return {}
        
        # Calculate aggregates
        total_requests = sum(c.request_count for c in circuits)
        total_errors = sum(c.error_count for c in circuits)
        total_bytes_sent = sum(c.bytes_sent for c in circuits)
        total_bytes_received = sum(c.bytes_received for c in circuits)
        
        # Calculate average latency
        latency_samples = []
        for c in circuits:
            latency_samples.extend(c.latency_samples)
        avg_latency = sum(latency_samples) / len(latency_samples) if latency_samples else None
        
        return {
            'time_window': self.metrics_interval,
            'circuit_count': len(circuits),
            'total_requests': total_requests,
            'total_errors': total_errors,
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_received': total_bytes_received,
            'avg_latency': avg_latency,
            'request_rate': total_requests / self.metrics_interval if self.metrics_interval > 0 else 0,
            'error_rate': (total_errors / total_requests * 100) if total_requests > 0 else 0,
            'throughput_up': total_bytes_sent / self.metrics_interval if self.metrics_interval > 0 else 0,
            'throughput_down': total_bytes_received / self.metrics_interval if self.metrics_interval > 0 else 0,
            'timestamp': now
        }

# Singleton instance
tor_manager = TorManager()
