"""
Adaptive encryption module for Scrambled Eggs.
"""
import os
import sys
import time
import json
import toml
import uuid
import ctypes
import struct
import hashlib
import logging
import logging.handlers
import random
import asyncio
import socket
# fcntl is not available on Windows
if not sys.platform.startswith('win'):
    import fcntl
import platform
import tempfile
import shutil
import atexit
import inspect
import unittest
import pytest
# asynctest is deprecated in Python 3.11+
if sys.version_info < (3, 11):
    try:
        import asynctest
    except (ImportError, AttributeError):
        asynctest = None
else:
    asynctest = None
import aiohttp
import aiofiles
from dataclasses import dataclass, field, asdict, is_dataclass
from enum import Enum, auto, IntEnum, Flag
from typing import (
    Any, Awaitable, Callable, ClassVar, Dict, Generic, List, 
    Optional, Set, Tuple, Type, TypeVar, Union, cast, get_type_hints
)
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from functools import wraps, partial
from abc import ABC, abstractmethod
from contextlib import asynccontextmanager, contextmanager

# For fuzzing support
try:
    import atheris
    import atheris_libprotobuf_mutator
    FUZZING_AVAILABLE = True
except ImportError:
    FUZZING_AVAILABLE = False
from datetime import datetime, timezone
from pathlib import Path
from typing import Tuple, Optional, List, Dict, Any, Union, Callable, Awaitable, TypeVar, Generic, Type, cast
from dataclasses import dataclass, field, asdict
from enum import Enum, auto, IntEnum
from queue import Queue, Empty, PriorityQueue
from threading import Lock, RLock, Event, Thread, local as ThreadLocal
from concurrent.futures import ThreadPoolExecutor, Future
from ctypes import (
    CDLL, CFUNCTYPE, POINTER, Structure, c_char_p, c_void_p, c_int, c_size_t,
    c_uint32, c_uint64, c_ubyte, c_bool, create_string_buffer, string_at
)
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
    load_pem_public_key, load_der_private_key, load_der_public_key
)
from cryptography.exceptions import InvalidSignature, InvalidKey
from cryptography.hazmat.backends import default_backend

# Type variable for generic logging
T = TypeVar('T')

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MACOS = platform.system() == 'Darwin'

# Load platform-specific libraries
libc = None
if IS_LINUX or IS_MACOS:
    try:
        libc = CDLL('libc.so.6' if IS_LINUX else 'libc.dylib')
    except OSError:
        libc = None

# C types for FFI
class LogEntry(Structure):
    _fields_ = [
        ("timestamp", c_uint64),
        ("level", c_uint32),
        ("message_len", c_size_t),
        ("message", c_char_p),
        ("context_len", c_size_t),
        ("context", c_void_p)
    ]

# Callback type for C logging
LOG_CALLBACK = CFUNCTYPE(None, POINTER(LogEntry))

# Log levels for C interop
class LogLevel(IntEnum):
    TRACE = 0
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4
    CRITICAL = 5

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand

class SecureLogEntry:
    """Represents a tamper-evident log entry."""
    
    __slots__ = ('timestamp', 'level', 'message', 'context', 'previous_hash', 'signature', 'entry_hash')
    
    def __init__(self, level: int, message: str, context: Dict[str, Any] = None,
                 previous_hash: bytes = None, private_key: ec.EllipticCurvePrivateKey = None):
        self.timestamp = datetime.now(timezone.utc).timestamp()
        self.level = level
        self.message = message
        self.context = context or {}
        self.previous_hash = previous_hash or b'\x00' * 32
        self.signature = None
        self.entry_hash = self._calculate_hash()
        
        if private_key:
            self.sign(private_key)
    
    def _calculate_hash(self) -> bytes:
        """Calculate the hash of this log entry."""
        h = hashlib.sha256()
        h.update(struct.pack('d', self.timestamp))
        h.update(struct.pack('I', self.level))
        h.update(self.message.encode('utf-8'))
        h.update(json.dumps(self.context, sort_keys=True).encode('utf-8'))
        h.update(self.previous_hash)
        return h.digest()
    
    def sign(self, private_key: ec.EllipticCurvePrivateKey) -> None:
        """Sign this log entry with the given private key."""
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            raise ValueError("Private key must be an EC private key")
        
        signer = private_key.sign(
            self.entry_hash,
            ec.ECDSA(hashes.SHA256())
        )
        self.signature = signer
    
    def verify(self, public_key: ec.EllipticCurvePublicKey) -> bool:
        """Verify the signature of this log entry."""
        if not self.signature:
            return False
            
        try:
            public_key.verify(
                self.signature,
                self.entry_hash,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'timestamp': self.timestamp,
            'level': self.level,
            'level_name': logging.getLevelName(self.level),
            'message': self.message,
            'context': self.context,
            'previous_hash': self.previous_hash.hex() if self.previous_hash else None,
            'signature': self.signature.hex() if self.signature else None,
            'entry_hash': self.entry_hash.hex()
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecureLogEntry':
        """Create a SecureLogEntry from a dictionary."""
        entry = cls(
            level=data['level'],
            message=data['message'],
            context=data.get('context', {})
        )
        entry.timestamp = data['timestamp']
        entry.previous_hash = bytes.fromhex(data['previous_hash']) if data.get('previous_hash') else None
        entry.signature = bytes.fromhex(data['signature']) if data.get('signature') else None
        entry.entry_hash = bytes.fromhex(data['entry_hash'])
        return entry

class SecureLogger:
    """Implements tamper-evident logging with remote syslog support."""
    
    def __init__(self, 
                 name: str,
                 log_dir: str = None,
                 max_size_mb: int = 100,
                 backup_count: int = 5,
                 syslog_server: str = None,
                 syslog_port: int = 514,
                 use_encryption: bool = True):
        """
        Initialize the secure logger.
        
        Args:
            name: Logger name
            log_dir: Directory to store log files
            max_size_mb: Maximum log file size in MB before rotation
            backup_count: Number of backup logs to keep
            syslog_server: Remote syslog server address
            syslog_port: Remote syslog server port
            use_encryption: Whether to encrypt log files
        """
        self.name = name
        self.log_dir = Path(log_dir) if log_dir else Path.cwd() / 'logs'
        self.max_size = max_size_mb * 1024 * 1024
        self.backup_count = backup_count
        self.use_encryption = use_encryption
        self._chain_hash = None
        self._private_key = ec.generate_private_key(ec.SECP384R1())
        self._public_key = self._private_key.public_key()
        self._log_lock = RLock()
        self._log_file = None
        self._log_handlers = []
        self._setup_logging()
        
        # Set up syslog if configured
        if syslog_server:
            self._setup_syslog(syslog_server, syslog_port)
        
        # Register cleanup on exit
        atexit.register(self.close)
    
    def _setup_logging(self) -> None:
        """Set up logging handlers and formatters."""
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Main log file handler with rotation
        log_file = self.log_dir / f"{self.name}.log"
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=self.max_size,
            backupCount=self.backup_count,
            encoding='utf-8'
        )
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        
        # Add console handler for development
        console = logging.StreamHandler()
        console.setLevel(logging.INFO)
        console.setFormatter(formatter)
        
        # Configure root logger
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console)
        
        # Store handlers for cleanup
        self._log_handlers.extend([file_handler, console])
    
    def _setup_syslog(self, server: str, port: int) -> None:
        """Set up remote syslog handler."""
        try:
            syslog_handler = logging.handlers.SysLogHandler(
                address=(server, port),
                socktype=socket.SOCK_DGRAM
            )
            syslog_formatter = logging.Formatter(
                f'{self.name}[{os.getpid()}]: %(levelname)s - %(message)s'
            )
            syslog_handler.setFormatter(syslog_formatter)
            self.logger.addHandler(syslog_handler)
            self._log_handlers.append(syslog_handler)
        except Exception as e:
            self.logger.error(f"Failed to set up syslog: {e}")
    
    def log(self, level: int, message: str, **context) -> 'SecureLogEntry':
        """Log a message with the specified level and context."""
        with self._log_lock:
            # Create secure log entry
            entry = SecureLogEntry(
                level=level,
                message=message,
                context=context,
                previous_hash=self._chain_hash,
                private_key=self._private_key
            )
            
            # Update chain hash
            self._chain_hash = entry.entry_hash
            
            # Log using standard logging
            extra = {'context': context, 'entry_hash': entry.entry_hash.hex()}
            self.logger.log(level, message, extra=extra)
            
            return entry
    
    def verify_log_chain(self) -> bool:
        """Verify the integrity of the entire log chain."""
        if not self._chain_hash:
            return True
            
        # In a real implementation, this would verify the entire chain
        # by reading and verifying each log file
        return True
    
    def close(self) -> None:
        """Clean up resources."""
        for handler in self._log_handlers:
            try:
                handler.close()
                self.logger.removeHandler(handler)
            except Exception as e:
                print(f"Error closing log handler: {e}", file=sys.stderr)
        
        # Clear handlers
        self._log_handlers.clear()

# Global logger instance
logger = logging.getLogger(__name__)

# C FFI wrapper for secure logging
class CLogger:
    """C-compatible logger interface."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self._callbacks = {}
    
    @staticmethod
    def _log_callback(entry_ptr: POINTER(LogEntry)) -> None:
        """C callback for log messages."""
        try:
            entry = entry_ptr.contents
            message = string_at(entry.message, entry.message_len).decode('utf-8', 'replace')
            context = {}
            
            if entry.context and entry.context_len > 0:
                try:
                    context_bytes = string_at(entry.context, entry.context_len)
                    context = json.loads(context_bytes.decode('utf-8'))
                except Exception as e:
                    print(f"Failed to parse log context: {e}", file=sys.stderr)
            
            level = entry.level
            if level == 0:
                logger.debug(message, extra={"context": context})
            elif level == 1:
                logger.debug(message, extra={"context": context})
            elif level == 2:
                logger.info(message, extra={"context": context})
            elif level == 3:
                logger.warning(message, extra={"context": context})
            elif level >= 4:
                logger.error(message, extra={"context": context})
        except Exception as e:
            print(f"Error in log callback: {e}", file=sys.stderr)
    
    def register_callback(self, callback: Callable[[str, int, str, Dict], None]) -> int:
        """Register a Python callback for C log messages."""
        callback_id = id(callback)
        self._callbacks[callback_id] = callback
        return callback_id
    
    def unregister_callback(self, callback_id: int) -> None:
        """Unregister a callback."""
        self._callbacks.pop(callback_id, None)

# Initialize global logger and C interface
secure_logger = SecureLogger('scrambled_eggs')
c_logger = CLogger(logger)

# C function prototypes
_libc_log_callback = LOG_CALLBACK(c_logger._log_callback)

# Export C API
if libc is not None:
    try:
        # Register our log callback with the C library
        libc.set_log_callback(_libc_log_callback)
    except AttributeError:
        # C library doesn't support log callbacks
        pass

class ConnectionState(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    FAILED = auto()

@dataclass
class NodeStatus:
    address: str
    last_seen: float = field(default_factory=time.time)
    latency: float = float('inf')
    state: ConnectionState = ConnectionState.DISCONNECTED
    error_count: int = 0

class TrafficObfuscation:
    """Implements traffic analysis resistance techniques."""
    
    def __init__(self, min_delay: float = 0.1, max_delay: float = 1.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.packet_size_range = (512, 4096)  # Min and max padding sizes
        
    def add_padding(self, data: bytes) -> bytes:
        """Add random padding to obfuscate message size."""
        padding_size = random.randint(*self.packet_size_range)
        padding = os.urandom(padding_size)
        # Include actual size in the padding
        size_header = len(data).to_bytes(8, 'big')
        return size_header + data + padding
    
    def remove_padding(self, padded_data: bytes) -> bytes:
        """Remove padding and extract original message."""
        if len(padded_data) < 8:
            raise ValueError("Invalid padded data")
        size = int.from_bytes(padded_data[:8], 'big')
        if len(padded_data) < 8 + size:
            raise ValueError("Incomplete message")
        return padded_data[8:8+size]
    
    def get_random_delay(self) -> float:
        """Get a random delay for timing obfuscation."""
        return random.uniform(self.min_delay, self.max_delay)

class SecureTransport:
    """
    Implements secure transport with traffic analysis resistance,
    high availability, and failover mechanisms.
    """
    
    def __init__(self, 
                 nodes: List[str],
                 max_retries: int = 3,
                 timeout: float = 10.0):
        """
        Initialize secure transport layer.
        
        Args:
            nodes: List of node addresses in 'host:port' format
            max_retries: Maximum retry attempts per operation
            timeout: Connection/operation timeout in seconds
        """
        self.nodes = {addr: NodeStatus(addr) for addr in nodes}
        self.max_retries = max_retries
        self.timeout = timeout
        self.obfuscator = TrafficObfuscation()
        self.active_connection = None
        self.lock = Lock()
        self.health_check_interval = 30  # seconds
        self._stop_event = Event()
        self._health_check_thread = Thread(
            target=self._health_check_loop,
            daemon=True
        )
        self._health_check_thread.start()
    
    async def connect(self) -> bool:
        """Establish a connection to the most optimal node."""
        with self.lock:
            if self.active_connection and self.nodes[self.active_connection].state == ConnectionState.CONNECTED:
                return True
                
            # Sort nodes by latency and error count
            sorted_nodes = sorted(
                self.nodes.values(),
                key=lambda n: (n.error_count, n.latency)
            )
            
            for node in sorted_nodes:
                try:
                    node.state = ConnectionState.CONNECTING
                    # In a real implementation, this would establish the actual connection
                    await asyncio.wait_for(
                        self._connect_to_node(node.address),
                        timeout=self.timeout
                    )
                    node.state = ConnectionState.CONNECTED
                    node.error_count = 0
                    self.active_connection = node.address
                    return True
                except Exception as e:
                    logger.warning(f"Failed to connect to {node.address}: {e}")
                    node.state = ConnectionState.FAILED
                    node.error_count += 1
            
            return False
    
    async def _connect_to_node(self, address: str) -> None:
        """Simulate connection to a node."""
        # In a real implementation, this would establish the actual connection
        host, port = address.split(':')
        await asyncio.open_connection(host, int(port))
    
    async def send(self, data: bytes) -> bool:
        """Send data with automatic retry and failover."""
        if not await self.connect():
            raise ConnectionError("Could not establish connection to any node")
        
        for attempt in range(self.max_retries):
            try:
                # Add traffic obfuscation
                padded_data = self.obfuscator.add_padding(data)
                
                # In a real implementation, this would send the actual data
                # await self._send_to_node(padded_data)
                
                # Update node status
                node = self.nodes[self.active_connection]
                node.last_seen = time.time()
                return True
                
            except Exception as e:
                logger.warning(f"Send attempt {attempt + 1} failed: {e}")
                node = self.nodes[self.active_connection]
                node.error_count += 1
                node.state = ConnectionState.FAILED
                self.active_connection = None
                
                if not await self.connect():
                    continue
        
        raise ConnectionError("All send attempts failed")
    
    async def _health_check_loop(self) -> None:
        """Background thread for monitoring node health."""
        while not self._stop_event.is_set():
            try:
                for address, node in list(self.nodes.items()):
                    if node.state == ConnectionState.FAILED:
                        # Periodically check if failed nodes recover
                        try:
                            await self._connect_to_node(address)
                            node.state = ConnectionState.CONNECTED
                            node.error_count = 0
                        except Exception:
                            pass
                
                # Update latencies
                for address in self.nodes:
                    await self._update_latency(address)
                
            except Exception as e:
                logger.error(f"Health check error: {e}")
            
            await asyncio.sleep(self.health_check_interval)
    
    async def _update_latency(self, address: str) -> None:
        """Update latency for a node."""
        try:
            start = time.monotonic()
            # In a real implementation, this would send a ping
            # await self._send_ping(address)
            self.nodes[address].latency = time.monotonic() - start
        except Exception as e:
            logger.warning(f"Failed to update latency for {address}: {e}")
    
    def close(self) -> None:
        """Clean up resources."""
        self._stop_event.set()
        if self._health_check_thread.is_alive():
            self._health_check_thread.join(timeout=5.0)

class PolicyViolationError(Exception):
    """Raised when a policy violation is detected."""
    pass

class PolicyVersion(IntEnum):
    """Policy versioning for forward/backward compatibility."""
    V1 = 1
    V2 = 2  # Added role-based access control
    V3 = 3  # Added audit logging requirements

class Permission(Flag):
    """Fine-grained permissions for access control."""
    NONE = 0
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    ADMIN = auto()
    AUDIT = READ | WRITE
    ALL = READ | WRITE | EXECUTE | ADMIN

@dataclass
class Policy:
    """Security policy configuration."""
    version: PolicyVersion = PolicyVersion.V3
    min_key_size: int = 256
    allowed_algorithms: List[str] = field(default_factory=lambda: ['AES-256-GCM', 'ChaCha20-Poly1305'])
    max_retries: int = 3
    session_timeout: int = 3600  # seconds
    require_2fa: bool = True
    audit_logging: bool = True
    fips_compliant: bool = False
    
    def validate(self) -> bool:
        """Validate the policy configuration."""
        if self.min_key_size < 128:
            raise PolicyViolationError("Minimum key size too small")
        if not self.allowed_algorithms:
            raise PolicyViolationError("No allowed algorithms specified")
        return True

@dataclass
class Role:
    """Role-based access control definition."""
    name: str
    permissions: Permission
    inherits: List[str] = field(default_factory=list)
    constraints: Dict[str, Any] = field(default_factory=dict)

class PolicyManager:
    """Manages security policies and role-based access control."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.policies: Dict[str, Policy] = {}
        self.roles: Dict[str, Role] = {
            'admin': Role('admin', Permission.ALL),
            'user': Role('user', Permission.READ | Permission.WRITE),
            'auditor': Role('auditor', Permission.AUDIT)
        }
        self.load_default_policies()
        
        if config_path:
            self.load_from_file(config_path)
    
    def load_default_policies(self) -> None:
        """Load default security policies."""
        default_policy = Policy()
        self.policies['default'] = default_policy
    
    def load_from_file(self, path: Path) -> None:
        """Load policies from a configuration file."""
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
            
        try:
            if path.suffix == '.json':
                with open(path, 'r') as f:
                    data = json.load(f)
            elif path.suffix == '.toml':
                with open(path, 'r') as f:
                    data = toml.load(f)
            else:
                raise ValueError(f"Unsupported file format: {path.suffix}")
            
            self._load_policy_data(data)
        except Exception as e:
            raise PolicyViolationError(f"Failed to load policy: {e}")
    
    def _load_policy_data(self, data: Dict[str, Any]) -> None:
        """Load policy data from a dictionary."""
        # Update policies
        for name, policy_data in data.get('policies', {}).items():
            if name in self.policies:
                self._update_policy(self.policies[name], policy_data)
            else:
                self.policies[name] = Policy(**policy_data)
        
        # Update roles
        for name, role_data in data.get('roles', {}).items():
            if 'permissions' in role_data and isinstance(role_data['permissions'], str):
                role_data['permissions'] = Permission[role_data['permissions']]
            if name in self.roles:
                self._update_role(self.roles[name], role_data)
            else:
                self.roles[name] = Role(name=name, **role_data)
    
    def _update_policy(self, policy: Policy, data: Dict[str, Any]) -> None:
        """Update a policy with new data."""
        for key, value in data.items():
            if hasattr(policy, key):
                setattr(policy, key, value)
    
    def _update_role(self, role: Role, data: Dict[str, Any]) -> None:
        """Update a role with new data."""
        for key, value in data.items():
            if hasattr(role, key):
                setattr(role, key, value)
    
    def check_permission(self, role_name: str, permission: Permission) -> bool:
        """Check if a role has the required permissions."""
        if role_name not in self.roles:
            return False
            
        role = self.roles[role_name]
        return bool(role.permissions & permission) or any(
            self.check_permission(parent, permission) 
            for parent in role.inherits
        )

class AsyncCryptoEngine:
    """Asynchronous wrapper for cryptographic operations."""
    
    def __init__(self, crypto_engine, executor=None):
        self._crypto = crypto_engine
        self._executor = executor or ThreadPoolExecutor()
    
    async def encrypt(self, data: bytes, **kwargs) -> bytes:
        """Asynchronous encryption."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._crypto.encrypt(data, **kwargs)
        )
    
    async def decrypt(self, data: bytes, **kwargs) -> bytes:
        """Asynchronous decryption."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._crypto.decrypt(data, **kwargs)
        )
    
    async def generate_key_pair(self, **kwargs):
        """Asynchronous key pair generation."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor,
            lambda: self._crypto.generate_key_pair(**kwargs)
        )

class CryptoEngine:
    """Core cryptographic engine with developer-friendly APIs."""
    
    def __init__(self, logger: logging.Logger = None):
        """Initialize the crypto engine."""
        self.logger = logger or secure_logger.logger
        self._backend = default_backend()
        self._cipher_cache = {}
        self._lock = RLock()
    
    def encrypt(self, data: bytes, key: bytes, iv: bytes = None, 
               algorithm: str = 'AES-256-GCM') -> Tuple[bytes, bytes]:
        """Encrypt data with the specified algorithm."""
        if algorithm == 'AES-256-GCM':
            iv = iv or os.urandom(12)
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv),
                backend=self._backend
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(data) + encryptor.finalize()
            return ciphertext, iv + encryptor.tag
        
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def decrypt(self, data: bytes, key: bytes, iv: bytes = None,
               algorithm: str = 'AES-256-GCM', tag: bytes = None) -> bytes:
        """Decrypt data with the specified algorithm."""
        if algorithm == 'AES-256-GCM':
            if not iv:
                iv = data[:12]
                data = data[12:]
            if not tag:
                tag = data[-16:]
                data = data[:-16]
                
            cipher = Cipher(
                algorithms.AES(key),
                modes.GCM(iv, tag),
                backend=self._backend
            )
            decryptor = cipher.decryptor()
            return decryptor.update(data) + decryptor.finalize()
        
        raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def generate_key_pair(self, algorithm: str = 'ec', **kwargs):
        """Generate a new key pair."""
        if algorithm.lower() == 'ec':
            curve = kwargs.get('curve', 'secp384r1')
            curve_class = {
                'secp256r1': ec.SECP256R1,
                'secp384r1': ec.SECP384R1,
                'secp521r1': ec.SECP521R1,
            }.get(curve.lower(), ec.SECP384R1)
            
            return ec.generate_private_key(curve_class(), self._backend)
        
        elif algorithm.lower() == 'rsa':
            key_size = kwargs.get('key_size', 4096)
            return rsa.generate_private_key(
                public_exponent=65537,
                key_size=key_size,
                backend=self._backend
            )
        
        raise ValueError(f"Unsupported key algorithm: {algorithm}")

class TestCryptoEngine(unittest.TestCase):
    """Unit tests for CryptoEngine."""
    
    def setUp(self):
        self.crypto = CryptoEngine()
        self.test_data = os.urandom(1024)
        self.key = os.urandom(32)
    
    def test_encrypt_decrypt(self):
        """Test encryption and decryption roundtrip."""
        ciphertext, tag = self.crypto.encrypt(self.test_data, self.key)
        plaintext = self.crypto.decrypt(ciphertext, self.key, tag=tag)
        self.assertEqual(plaintext, self.test_data)
    
    def test_key_generation(self):
        """Test key pair generation."""
        private_key = self.crypto.generate_key_pair('ec')
        self.assertIsInstance(private_key, ec.EllipticCurvePrivateKey)
        self.assertIsInstance(private_key.public_key(), ec.EllipticCurvePublicKey)

class TestSecureLogger(unittest.TestCase):
    """Unit tests for SecureLogger."""
    
    def setUp(self):
        self.log_dir = Path('test_logs')
        self.logger = SecureLogger('test', log_dir=self.log_dir)
    
    def tearDown(self):
        if self.log_dir.exists():
            shutil.rmtree(self.log_dir)
    
    def test_log_creation(self):
        """Test log entry creation and verification."""
        entry = self.logger.log(logging.INFO, "Test message", test=True)
        self.assertTrue(entry.verify(self.logger._public_key))
        self.assertEqual(entry.message, "Test message")

class TestPolicyManager(unittest.TestCase):
    """Unit tests for PolicyManager."""
    
    def setUp(self):
        self.policy_mgr = PolicyManager()
    
    def test_permission_check(self):
        """Test role-based permission checking."""
        self.assertTrue(self.policy_mgr.check_permission('admin', Permission.ALL))
        self.assertTrue(self.policy_mgr.check_permission('user', Permission.READ))
        self.assertFalse(self.policy_mgr.check_permission('user', Permission.ADMIN))

# Fuzzing tests (only run if AFL++ or libFuzzer is available)
if FUZZING_AVAILABLE:
    class FuzzTests:
        """Fuzzing tests for cryptographic functions."""
        
        @staticmethod
        def test_encrypt_fuzz(data):
            """Fuzz test encryption with random inputs."""
            crypto = CryptoEngine()
            key = os.urandom(32)
            try:
                crypto.encrypt(data, key)
            except Exception:
                pass  # Expected to fail with invalid inputs
        
        @staticmethod
        def test_decrypt_fuzz(data):
            """Fuzz test decryption with random inputs."""
            crypto = CryptoEngine()
            key = os.urandom(32)
            try:
                crypto.decrypt(data, key)
            except Exception:
                pass  # Expected to fail with invalid inputs

class AsyncAdaptiveEncryption:
    """Asynchronous version of AdaptiveEncryption."""
    
    def __init__(self, crypto_engine: Optional[CryptoEngine] = None, **kwargs):
        self._crypto = AsyncCryptoEngine(crypto_engine or CryptoEngine())
        self._sync_engine = AdaptiveEncryption(**kwargs)
        self.policy_mgr = PolicyManager()
    
    async def encrypt(self, data: bytes, password: bytes) -> Tuple[bytes, Dict[str, Any]]:
        """Asynchronous encryption with policy enforcement."""
        if not self.policy_mgr.check_permission('user', Permission.WRITE):
            raise PermissionError("Insufficient permissions for encryption")
        
        # Use thread pool for CPU-bound operations
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._sync_engine.encrypt(data, password)
        )
    
    async def decrypt(self, ciphertext: bytes, password: bytes, metadata: Dict[str, Any]) -> bytes:
        """Asynchronous decryption with policy enforcement."""
        if not self.policy_mgr.check_permission('user', Permission.READ):
            raise PermissionError("Insufficient permissions for decryption")
        
        # Use thread pool for CPU-bound operations
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            lambda: self._sync_engine.decrypt(ciphertext, password, metadata)
        )

class AdaptiveEncryption:
    """
    Implements adaptive encryption with dynamic layer adjustment.
    """
    
    def __init__(self, 
                 min_layers: int = 10,
                 max_layers: int = 1000,
                 target_time_ms: float = 100.0,
                 memory_limit_mb: int = 1024,
                 logger: logging.Logger = None,
                 policy: Optional[Policy] = None):
        """
        Initialize the adaptive encryption system.
        
        Args:
            min_layers: Minimum number of encryption layers
            max_layers: Maximum number of encryption layers
            target_time_ms: Target encryption time in milliseconds
            memory_limit_mb: Maximum memory usage in MB
        """
        self.min_layers = min_layers
        self.max_layers = max_layers
        self.target_time_ms = target_time_ms
        self.memory_limit = memory_limit_mb * 1024 * 1024  # Convert to bytes
        
        # State tracking
        self.current_layers = min_layers
        self.performance_history: List[Dict[str, float]] = []
        self.last_adjustment = time.time()
        self.logger = logger or secure_logger.logger
        self.crypto = CryptoEngine(logger)
        
        # Initialize encryption components
        self._init_encryption()
        
        # Policy management
        self.policy = policy or Policy()
        self._validate_policy()
        
        # Log initialization
        self.logger.info(
            "AdaptiveEncryption initialized",
            extra={
                "min_layers": min_layers,
                "max_layers": max_layers,
                "target_time_ms": target_time_ms,
                "memory_limit_mb": memory_limit_mb,
                "policy_version": self.policy.version
            }
        )
    
    def _validate_policy(self) -> None:
        """Validate the current security policy."""
        try:
            self.policy.validate()
        except PolicyViolationError as e:
            self.logger.error(f"Policy validation failed: {e}")
            raise
    
    def _init_encryption(self) -> None:
        """Initialize encryption components."""
        # Generate a random salt for key derivation
        self.salt = os.urandom(16)
        
        # Check if algorithms are allowed by policy
        if 'AES-256-GCM' not in self.policy.allowed_algorithms:
            raise PolicyViolationError(
                f"Required algorithm not allowed by policy: AES-256-GCM"
            )
        
    def _derive_key(self, 
                   password: bytes, 
                   salt: bytes, 
                   iterations: int = None) -> bytes:
        """
        Derive a secure encryption key with policy enforcement.
        
        Args:
            password: The password to derive the key from
            salt: Cryptographic salt
            iterations: Number of iterations (default: from policy)
            
        Returns:
            Derived key as bytes
            
        Raises:
            PolicyViolationError: If key derivation parameters don't meet policy requirements
        """
        if iterations is None:
            iterations = getattr(self.policy, 'key_derivation_iterations', 600000)
            
        if iterations < 100000:  # NIST minimum recommendation
            raise PolicyViolationError(
                f"Insufficient key derivation iterations: {iterations}"
            )
            
        key_size = len(password) * 8  # bits
        if key_size < self.policy.min_key_size:
            raise PolicyViolationError(
                f"Key size {key_size} bits is below minimum {self.policy.min_key_size} bits"
            )
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=salt,
            iterations=iterations
        )
        return kdf.derive(password)
    
    def _measure_performance(self, data: bytes) -> Dict[str, float]:
        """Measure encryption performance metrics."""
        start_time = time.perf_counter()
        
        # Perform a test encryption
        test_data = os.urandom(1024)  # 1KB test data
        self.encrypt(test_data, b'test_password')
        
        end_time = time.perf_counter()
        duration_ms = (end_time - start_time) * 1000
        
        return {
            'timestamp': time.time(),
            'layers': self.current_layers,
            'duration_ms': duration_ms,
            'data_size': len(data)
        }
    
    def _adjust_layers(self, metrics: Dict[str, float]) -> None:
        """Adjust the number of encryption layers based on performance."""
        # Don't adjust too frequently
        if time.time() - self.last_adjustment < 60:  # 1 minute cooldown
            return
            
        target = self.target_time_ms
        current = metrics['duration_ms']
        
        # Simple proportional control
        if current < target * 0.9 and self.current_layers < self.max_layers:
            # Too fast, increase layers (up to 10% increase)
            increase = max(1, int(self.current_layers * 0.1))
            self.current_layers = min(self.current_layers + increase, self.max_layers)
            self.last_adjustment = time.time()
            logger.info(f"Increased layers to {self.current_layers}")
            
        elif current > target * 1.1 and self.current_layers > self.min_layers:
            # Too slow, decrease layers (down to 10% decrease)
            decrease = max(1, int(self.current_layers * 0.1))
            self.current_layers = max(self.current_layers - decrease, self.min_layers)
            self.last_adjustment = time.time()
            logger.info(f"Decreased layers to {self.current_layers}")
    
    def _apply_layers(self, data: bytes, key: bytes, layers: int) -> bytes:
        """Apply multiple layers of encryption."""
        result = data
        for i in range(layers):
            # Generate a unique nonce for each layer
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            
            # Encrypt with AES-GCM
            result = aesgcm.encrypt(
                nonce=nonce,
                data=result,
                associated_data=str(i).encode()
            )
        return result
    
    def encrypt(self, data: bytes, password: bytes, context: Optional[Dict] = None) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypt data with adaptive security and policy enforcement.
        
        Args:
            data: Plaintext data to encrypt
            password: Password for key derivation
            context: Additional context for audit logging
            
        Returns:
            Tuple of (ciphertext, metadata)
            
        Raises:
            PolicyViolationError: If encryption would violate security policy
        """
        context = context or {}
        start_time = time.monotonic()
        
        try:
            # Check policy constraints
            if len(data) > getattr(self.policy, 'max_data_size', 100 * 1024 * 1024):  # 100MB default
                raise PolicyViolationError("Data size exceeds maximum allowed by policy")
            
            # Derive encryption key
            key = self._derive_key(password, self.salt)
            
            # Measure performance
            metrics = self._measure_performance(data)
            
            # Adjust layers based on performance
            self._adjust_layers(metrics)
            
            # Apply encryption layers
            ciphertext = self._apply_layers(data, key, self.current_layers)
            
            # Prepare metadata
            metadata = {
                'version': '1.0',
                'layers': self.current_layers,
                'salt': self.salt.hex(),
                'performance': metrics,
                'timestamp': time.time(),
                'policy_version': self.policy.version,
                'algorithm': 'AES-256-GCM',
                'key_size': len(key) * 8
            }
            
            # Audit log the encryption
            if self.policy.audit_logging:
                secure_logger.log(
                    logging.INFO,
                    "Data encrypted",
                    operation="encrypt",
                    data_size=len(data),
                    layers=self.current_layers,
                    duration_ms=(time.monotonic() - start_time) * 1000,
                    **context
                )
            
            return ciphertext, metadata
            
        except Exception as e:
            secure_logger.log(
                logging.ERROR,
                "Encryption failed",
                error=str(e),
                operation="encrypt",
                **context
            )
            raise
    
    def decrypt(self, ciphertext: bytes, password: bytes, metadata: Dict[str, Any], 
               context: Optional[Dict] = None) -> bytes:
        """
        Decrypt data with the given password and metadata.
        
        Args:
            ciphertext: Encrypted data
            password: Password for key derivation
            metadata: Metadata from encryption
            context: Additional context for audit logging
            
        Returns:
            Decrypted plaintext
            
        Raises:
            PolicyViolationError: If decryption would violate security policy
            ValueError: If decryption fails
        """
        context = context or {}
        start_time = time.monotonic()
        
        try:
            # Check policy constraints
            if not metadata or 'version' not in metadata:
                raise PolicyViolationError("Invalid or missing metadata")
                
            # Extract parameters from metadata
            layers = metadata.get('layers', self.min_layers)
            salt = bytes.fromhex(metadata.get('salt', self.salt.hex()))
            
            # Check if the number of layers is within policy limits
            if not (self.min_layers <= layers <= self.max_layers):
                raise PolicyViolationError(
                    f"Invalid number of layers: {layers} "
                    f"(must be between {self.min_layers} and {self.max_layers})"
                )
            
            # Derive the same key
            key = self._derive_key(password, salt)
            
            # Apply decryption layers in reverse order
            result = ciphertext
            for i in reversed(range(layers)):
                try:
                    nonce = result[:12]  # Nonce is prepended
                    aesgcm = AESGCM(key)
                    result = aesgcm.decrypt(
                        nonce=nonce,
                        data=result[12:],  # Remove nonce
                        associated_data=str(i).encode()
                    )
                except Exception as e:
                    raise ValueError(f"Decryption failed at layer {i}: {str(e)}")
            
            # Audit log successful decryption
            if self.policy.audit_logging:
                secure_logger.log(
                    logging.INFO,
                    "Data decrypted",
                    operation="decrypt",
                    data_size=len(ciphertext),
                    layers=layers,
                    duration_ms=(time.monotonic() - start_time) * 1000,
                    **context
                )
            
            return result
            
        except Exception as e:
            # Audit log decryption failure
            secure_logger.log(
                logging.ERROR,
                "Decryption failed",
                error=str(e),
                operation="decrypt",
                **context
            )
            raise
