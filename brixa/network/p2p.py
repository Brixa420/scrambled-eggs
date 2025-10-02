"""
P2P Network Implementation for Brixa Blockchain
"""
import asyncio
import json
import logging
import os
import time
from typing import Dict, List, Optional, Set, Tuple, Any, Callable, Awaitable, Union
from dataclasses import dataclass, field, asdict
import aiohttp
from aiohttp import web, ClientSession
import random
import socket
import hashlib
import hmac
import base64
import pathlib
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# Import file transfer module
from .file_transfer import FileTransferManager

# Import NAT traversal and monitoring
from .nat_advanced import NATDetector, NATType, HolePuncher
from .turn_client import TURNServer, TURNClient, TURNProtocol
from .connection_monitor import ConnectionMonitor, ConnectionStats
from .metrics import get_metrics, MetricType

class MessageSigner:
    """Handles message signing and verification for P2P messages."""
    
    def __init__(self, private_key: Optional[ec.EllipticCurvePrivateKey] = None):
        """Initialize with an optional private key.
        
        Args:
            private_key: Optional private key. If not provided, a new one will be generated.
        """
        self.private_key = private_key or ec.generate_private_key(
            ec.SECP256K1(), default_backend()
        )
        self.public_key = self.private_key.public_key()
        
    def get_public_key_bytes(self) -> bytes:
        """Get the public key in compressed format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
    def sign_message(self, message: Union[Dict, bytes]) -> bytes:
        """Sign a message.
        
        Args:
            message: Message to sign (dict or bytes)
            
        Returns:
            bytes: The signature
        """
        if isinstance(message, dict):
            message_str = json.dumps(message, sort_keys=True)
            message_bytes = message_str.encode('utf-8')
        else:
            message_bytes = message
            
        signature = self.private_key.sign(
            message_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return signature
        
    def verify_message(self, message: Union[Dict, bytes], signature: bytes, 
                      public_key_bytes: bytes) -> bool:
        """Verify a message signature.
        
        Args:
            message: The message that was signed
            signature: The signature to verify
            public_key_bytes: The sender's public key in compressed format
            
        Returns:
            bool: True if the signature is valid, False otherwise
        """
        try:
            if isinstance(message, dict):
                message_str = json.dumps(message, sort_keys=True)
                message_bytes = message_str.encode('utf-8')
            else:
                message_bytes = message
                
            public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(),
                public_key_bytes
            )
            
            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            return True
            
        except (InvalidSignature, ValueError):
            return False
    
    def derive_shared_secret(self, peer_public_key_bytes: bytes) -> bytes:
        """Derive a shared secret using ECDH.
        
        Args:
            peer_public_key_bytes: The peer's public key in compressed format
            
        Returns:
            bytes: The derived shared secret
        """
        peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256K1(),
            peer_public_key_bytes
        )
        
        shared_key = self.private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'brixa_shared_secret',
            backend=default_backend()
        ).derive(shared_key)
        
        return derived_key
    
    def encrypt_message(self, message: Union[Dict, str, bytes], 
                       recipient_public_key_bytes: bytes) -> Dict:
        """Encrypt a message for a specific recipient.
        
        Args:
            message: The message to encrypt (dict, str, or bytes)
            recipient_public_key_bytes: The recipient's public key in compressed format
            
        Returns:
            Dict: Dictionary containing the encrypted message and metadata
        """
        # Convert message to bytes if it's a dict or str
        if isinstance(message, dict):
            message_bytes = json.dumps(message).encode('utf-8')
        elif isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message
            
        # Generate an ephemeral key pair for ECDH
        ephemeral_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
        ephemeral_public_key = ephemeral_key.public_key().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        
        # Derive the shared secret
        shared_secret = ephemeral_key.exchange(
            ec.ECDH(),
            ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(),
                recipient_public_key_bytes
            )
        )
        
        # Derive encryption and MAC keys
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes for encryption, 32 bytes for MAC
            salt=None,
            info=b'brixa_message_encryption',
            backend=default_backend()
        )
        key_material = hkdf.derive(shared_secret)
        enc_key = key_material[:32]  # First 32 bytes for encryption
        mac_key = key_material[32:]  # Next 32 bytes for MAC
        
        # Generate a random IV
        iv = os.urandom(16)
        
        # Encrypt the message
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
        
        # Get the authentication tag
        tag = encryptor.tag
        
        # Create the MAC over the ciphertext and IV
        mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha256).digest()
        
        # Return the encrypted message package
        return {
            'version': '1.0',
            'ephemeral_public_key': base64.b64encode(ephemeral_public_key).decode('ascii'),
            'iv': base64.b64encode(iv).decode('ascii'),
            'ciphertext': base64.b64encode(ciphertext).decode('ascii'),
            'tag': base64.b64encode(tag).decode('ascii'),
            'mac': base64.b64encode(mac).decode('ascii')
        }
    
    def decrypt_message(self, encrypted_message: Dict) -> bytes:
        """Decrypt a message using our private key.
        
        Args:
            encrypted_message: The encrypted message dictionary
            
        Returns:
            bytes: The decrypted message
            
        Raises:
            ValueError: If decryption or verification fails
        """
        try:
            # Extract and decode components
            ephemeral_public_key_bytes = base64.b64decode(encrypted_message['ephemeral_public_key'])
            iv = base64.b64decode(encrypted_message['iv'])
            ciphertext = base64.b64decode(encrypted_message['ciphertext'])
            tag = base64.b64decode(encrypted_message['tag'])
            received_mac = base64.b64decode(encrypted_message['mac'])
            
            # Derive the shared secret
            ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256K1(),
                ephemeral_public_key_bytes
            )
            
            shared_secret = self.private_key.exchange(
                ec.ECDH(),
                ephemeral_public_key
            )
            
            # Derive the same keys as the sender
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,  # 32 bytes for encryption, 32 bytes for MAC
                salt=None,
                info=b'brixa_message_encryption',
                backend=default_backend()
            )
            key_material = hkdf.derive(shared_secret)
            enc_key = key_material[:32]  # First 32 bytes for encryption
            mac_key = key_material[32:]  # Next 32 bytes for MAC
            
            # Verify the MAC
            mac = hmac.new(mac_key, ciphertext + iv, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, received_mac):
                raise ValueError("Invalid MAC")
            
            # Decrypt the message
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            return plaintext
            
        except (KeyError, ValueError, InvalidSignature) as e:
            raise ValueError(f"Decryption failed: {str(e)}")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class Peer:
    """Represents a peer in the P2P network."""
    peer_id: str
    host: str
    port: int
    last_seen: float = field(default_factory=time.time)
    connection_type: str = "direct"  # direct, relay, or hole_punch
    relay_server: Optional[Tuple[str, int]] = None
    is_connected: bool = False
    
    @property
    def address(self) -> str:
        """Get the connection address for this peer."""
        if self.relay_server and self.connection_type == "relay":
            return f"turn://{self.host}:{self.port}?relay={self.relay_server[0]}:{self.relay_server[1]}"
        return f"{self.host}:{self.port}"
    
    @property
    def is_behind_nat(self) -> bool:
        """Check if this peer is behind a NAT."""
        return self.connection_type != "direct"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert peer to dictionary."""
        return {
            "peer_id": self.peer_id,
            "host": self.host,
            "port": self.port,
            "last_seen": self.last_seen,
            "connection_type": self.connection_type,
            "is_connected": self.is_connected,
            "relay_server": f"{self.relay_server[0]}:{self.relay_server[1]}" if self.relay_server else None
        }

class P2PNode:
    """P2P Network Node for Brixa Blockchain with NAT traversal and relay support."""
    
    def __init__(
        self, 
        host: str = '0.0.0.0', 
        port: int = 5000, 
        peer_id: Optional[str] = None,
        enable_nat: bool = True,
        turn_servers: Optional[List[Dict[str, Any]]] = None,
        connection_timeout: float = 30.0,
        max_peers: int = 50,
        ssl_context = None,
        reconnect_interval: float = 30.0,
        private_key: Optional[bytes] = None
    ):
        # Network configuration
        self.host = host
        self.port = port
        self.peer_id = peer_id or self._generate_peer_id()
        self.max_peers = max_peers
        self.connection_timeout = connection_timeout
        self.ssl_context = ssl_context
        self.reconnect_interval = reconnect_interval
        
        # Track connection state
        self.failed_direct_connections = set()
        self.reconnecting_peers = set()
        self.relay_address: Optional[str] = None
        self.is_running = False
        
        # Initialize metrics
        self._init_metrics()
        
        # Initialize message signing
        self.signer = MessageSigner(private_key)
        self.peer_public_keys: Dict[str, bytes] = {}  # peer_id -> public_key
        
        # Initialize file transfer
        self.file_transfer: Optional[FileTransferManager] = None
        
        # Peer management
        self.peers: Dict[str, 'Peer'] = {}
        self.pending_peers: Dict[str, asyncio.Future] = {}
        self.connection_handlers: Dict[str, Callable[[str, bytes], Awaitable[None]]] = {}
        
        # Web server
        self.app = web.Application()
        self.runner = None
        self.site = None
        self.session: Optional[ClientSession] = None
        
        # NAT and TURN
        self.nat_detector = NATDetector()
        self.nat_type: Optional[NATType] = None
        self.hole_puncher = HolePuncher()
        self.turn_clients: Dict[str, TURNClient] = {}
        self.turn_servers = [
            TURNServer(**server) for server in (turn_servers or [])
        ]
        
        # Connection monitoring
        self.connection_monitor = ConnectionMonitor(
            reconnect_interval=reconnect_interval,
            health_check_interval=60.0  # Check peer health every minute
        )
        
        # Message queue for broadcasting
        self.message_queue: asyncio.Queue[Tuple[bytes, List[str]]] = asyncio.Queue()
        self.message_processor_task: Optional[asyncio.Task] = None
        
        # Set up routes
        self.setup_routes()
        
        # Initialize NAT traversal if enabled
        if enable_nat and host not in ['0.0.0.0', '127.0.0.1']:
            asyncio.create_task(self._init_nat_traversal())
    
    def _generate_peer_id(self) -> str:
        """Generate a unique peer ID."""
        import hashlib
        host_part = self.host.replace('.', '-')
        return f"{host_part}-{self.port}-{hashlib.sha256(f'{time.time()}:{os.urandom(16).hex()}'.encode()).hexdigest()[:8]}"
        
    def _init_metrics(self) -> None:
        """Initialize metrics collection for the P2P node."""
        metrics = get_metrics()
        
        # Connection metrics
        metrics.register_metric('p2p_connections_total', 'counter', 
                              'Total number of peer connections',
                              labels=['peer_id', 'type'])
                              
        metrics.register_metric('p2p_connection_errors_total', 'counter',
                              'Total number of connection errors',
                              labels=['error_type'])
                              
        metrics.register_metric('p2p_connection_latency_ms', 'histogram',
                              'Connection establishment latency in milliseconds',
                              buckets=[10, 50, 100, 250, 500, 1000, 2500])
                              
        # Message metrics
        metrics.register_metric('p2p_messages_sent_total', 'counter',
                              'Total number of messages sent',
                              labels=['message_type', 'status'])
                              
        metrics.register_metric('p2p_messages_received_total', 'counter',
                              'Total number of messages received',
                              labels=['message_type'])
                              
        metrics.register_metric('p2p_message_size_bytes', 'histogram',
                              'Size of messages in bytes',
                              buckets=[100, 1024, 10*1024, 100*1024, 1024*1024])
                              
        # Network metrics
        metrics.register_metric('p2p_bandwidth_bytes', 'counter',
                              'Network bandwidth usage in bytes',
                              labels=['direction'])  # in/out
                              
        metrics.register_metric('p2p_peers_connected', 'gauge',
                              'Number of currently connected peers')
                              
        metrics.register_metric('p2p_peers_known', 'gauge',
                              'Number of known peers in the network')
                              
        # TURN relay metrics
        metrics.register_metric('p2p_turn_relay_connections_total', 'counter',
                              'Total number of TURN relay connections',
                              labels=['turn_server'])
                              
        metrics.register_metric('p2p_turn_relay_errors_total', 'counter',
                              'Total number of TURN relay errors',
                              labels=['error_type'])
                              
        # NAT traversal metrics
        metrics.register_metric('p2p_nat_traversal_attempts_total', 'counter',
                              'Total number of NAT traversal attempts',
                              labels=['method', 'success'])
                              
        metrics.register_metric('p2p_nat_type', 'gauge',
                              'Detected NAT type',
                              labelnames=['nat_type'])
                              
        # Queue metrics
        metrics.register_metric('p2p_message_queue_size', 'gauge',
                              'Current size of the message queue')
                              
        metrics.register_metric('p2p_message_queue_delay_seconds', 'histogram',
                              'Time messages spend in the queue',
                              buckets=[0.001, 0.01, 0.1, 0.5, 1, 5, 10])
                              
        logger.info("Initialized P2P metrics collection")
        
    def _init_metrics(self) -> None:
        """Initialize metrics collection for the P2P node."""
        metrics = get_metrics()
        
        # Connection metrics
        metrics.register_metric('p2p_connections_total', 'counter', 
                              'Total number of peer connections',
                              labels=['peer_id', 'type'])
                              
        metrics.register_metric('p2p_connection_errors_total', 'counter',
                              'Total number of connection errors',
                              labels=['error_type'])
                              
        metrics.register_metric('p2p_connection_latency_ms', 'histogram',
                              'Connection establishment latency in milliseconds',
                              buckets=[10, 50, 100, 250, 500, 1000, 2500])
                              
        # Message metrics
        metrics.register_metric('p2p_messages_sent_total', 'counter',
                              'Total number of messages sent',
                              labels=['message_type', 'status'])
                              
        metrics.register_metric('p2p_messages_received_total', 'counter',
                              'Total number of messages received',
                              labels=['message_type'])
                              
        metrics.register_metric('p2p_message_size_bytes', 'histogram',
                              'Size of messages in bytes',
                              buckets=[100, 1024, 10*1024, 100*1024, 1024*1024])
                              
        # Network metrics
        metrics.register_metric('p2p_bandwidth_bytes', 'counter',
                              'Network bandwidth usage in bytes',
                              labels=['direction'])  # in/out
                              
        metrics.register_metric('p2p_peers_connected', 'gauge',
                              'Number of currently connected peers')
                              
        metrics.register_metric('p2p_peers_known', 'gauge',
                              'Number of known peers in the network')
                              
        # TURN relay metrics
        metrics.register_metric('p2p_turn_relay_connections_total', 'counter',
                              'Total number of TURN relay connections',
                              labels=['turn_server'])
                              
        metrics.register_metric('p2p_turn_relay_errors_total', 'counter',
                              'Total number of TURN relay errors',
                              labels=['error_type'])
                              
        # NAT traversal metrics
        metrics.register_metric('p2p_nat_traversal_attempts_total', 'counter',
                              'Total number of NAT traversal attempts',
                              labels=['method', 'success'])
                              
        metrics.register_metric('p2p_nat_type', 'gauge',
                              'Detected NAT type',
                              labelnames=['nat_type'])
                              
        # Queue metrics
        metrics.register_metric('p2p_message_queue_size', 'gauge',
                              'Current size of the message queue')
                              
        metrics.register_metric('p2p_message_queue_delay_seconds', 'histogram',
                              'Time messages spend in the queue',
                              buckets=[0.001, 0.01, 0.1, 0.5, 1, 5, 10])
                              
        logger.info("Initialized P2P metrics collection")
    
    def _init_nat_traversal(self) -> None:
        """Initialize NAT traversal components."""
        self.nat_detector = NATDetector()
        self.hole_puncher = HolePuncher()
        
        # Start NAT type detection
        asyncio.create_task(self._detect_nat_type())
        
        # Initialize TURN clients
        for server in self.turn_servers:
            turn_client = TURNClient(server)
            self.turn_clients[server.host] = turn_client
            asyncio.create_task(self._init_turn_client(turn_client))
        
    def setup_routes(self) -> None:
        """Set up HTTP routes for P2P communication."""
        self.app.add_routes([
            web.get('/peers', self.get_peers),
            web.post('/peers/register', self.register_peer),
            web.get('/blocks', self.get_blocks),
            web.post('/blocks', self.receive_block),
            web.get('/transactions', self.get_transactions),
            web.post('/transactions', self.receive_transaction),
            web.post('/message', self.handle_message),
            web.post('/file/upload', self.handle_file_upload),
            web.get('/file/download/{file_id}', self.handle_file_download),
        ])
    
    async def _detect_nat_type(self) -> None:
        """Detect the type of NAT we're behind."""
        if not self.nat_detector:
            return
            
        try:
            self.nat_type = await self.nat_detector.detect_nat_type(self.port)
            logger.info(f"Detected NAT type: {self.nat_type.value}")
            
            # Update connection strategy based on NAT type
            await self._update_connection_strategy()
            
        except Exception as e:
            logger.error(f"Failed to detect NAT type: {e}")
            self.nat_type = NATType.UNKNOWN
    
    async def _init_turn_client(self, client: TURNClient) -> None:
        """Initialize a TURN client and connect to the server."""
        try:
            if await client.connect():
                logger.info(f"Connected to TURN server at {client.server.host}:{client.server.port}")
                # Register our relay address with the peer discovery service
                await self._register_relay_address(client)
        except Exception as e:
            logger.error(f"Failed to connect to TURN server {client.server.host}: {e}")
    
    async def _register_relay_address(self, client: TURNClient) -> None:
        """Register our relay address with the peer discovery service."""
        # This would be implemented to register with a peer discovery service
        # or DHT to make our relay address discoverable by other peers
        pass
    
    async def _update_connection_strategy(self) -> None:
        """Update our connection strategy based on NAT type and available relays."""
        if self.nat_type == NATType.OPEN_INTERNET:
            # Direct connections should work
            logger.info("Using direct connection strategy")
        elif self.nat_type in [NATType.FULL_CONE, NATType.RESTRICTED_CONE, NATType.PORT_RESTRICTED_CONE]:
            # Try hole punching first, fall back to TURN
            logger.info("Using hole punching with TURN fallback strategy")
        else:  # SYMMETRIC or UNKNOWN
            # Prefer TURN relays
            logger.info("Using TURN relay strategy")
    
    async def start(self) -> None:
        """Start the P2P node and all required services."""
        if self.is_running:
            logger.warning("P2P node is already running")
            return
            
        self.is_running = True
        
        try:
            # Initialize the HTTP session
            self.session = ClientSession()
            
            # Start the connection monitor
            await self.connection_monitor.start()
            
            # Set up the web server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            # Try to bind to the specified port, or find an available one
            for port_offset in range(10):  # Try up to 10 ports
                try:
                    current_port = self.port + port_offset
                    self.site = web.TCPSite(self.runner, self.host, current_port)
                    await self.site.start()
                    
                    # Update port in case we had to use a different one
                    self.port = current_port
                    logger.info(f"P2P Node {self.peer_id[:8]} running at {'https' if self.ssl_context else 'http'}://{self.host}:{self.port}")
                    
                    # Start the message processor
                    # Initialize file transfer manager
                    self.file_transfer = FileTransferManager(self)
                    
                    # Start background tasks
                    self.message_processor_task = asyncio.create_task(self._process_message_queue())
                    self.connection_monitor_task = asyncio.create_task(self._monitor_connections())
                    self.nat_traversal_task = asyncio.create_task(self._handle_nat_traversal())
                    
                    logger.info("P2P node started successfully")
                    return
                    
                except OSError as e:
                    if "Address already in use" in str(e) and port_offset < 9:
                        logger.warning(f"Port {current_port} in use, trying {current_port + 1}...")
                        continue
                    
                    logger.error(f"Failed to start server: {e}")
                    raise
            
            raise RuntimeError(f"Could not bind to any port in range {self.port}-{self.port + 9}")
            
        except Exception as e:
            self.is_running = False
            logger.error(f"Failed to start P2P node: {e}", exc_info=True)
            await self.stop()
            raise
    
    async def _monitor_connections(self) -> None:
        """Background task to monitor and maintain peer connections."""
        while self.is_running:
            try:
                # Check for disconnected peers and attempt to reconnect
                disconnected_peers = [
                    peer_id for peer_id, peer in self.peers.items()
                    if not peer.is_connected and peer_id not in self.reconnecting_peers
                ]
                
                for peer_id in disconnected_peers:
                    asyncio.create_task(self._reconnect_peer(peer_id))
                
                # Clean up old failed direct connections
                self.failed_direct_connections = {
                    (host, port) for host, port in self.failed_direct_connections
                    if time.time() - self.peers.get(f"{host}:{port}", Peer(host, port, "")).last_seen < 3600  # 1 hour
                }
                
                # Update metrics
                get_metrics().get_metric('p2p_peers_connected').set(len([p for p in self.peers.values() if p.is_connected]))
                get_metrics().get_metric('p2p_peers_known').set(len(self.peers))
                
                # Wait before next check
                await asyncio.sleep(30)
                
            except asyncio.CancelledError:
                logger.info("Connection monitor task cancelled")
                break
                
            except Exception as e:
                logger.error(f"Error in connection monitor: {e}", exc_info=True)
                await asyncio.sleep(10)  # Avoid tight loop on errors
    
    async def _reconnect_peer(self, peer_id: str) -> None:
        """Attempt to reconnect to a disconnected peer.
        
        Args:
            peer_id: The ID of the peer to reconnect to
        """
        if peer_id not in self.peers or peer_id in self.reconnecting_peers:
            return
            
        self.reconnecting_peers.add(peer_id)
        peer = self.peers[peer_id]
        
        try:
            logger.info(f"Attempting to reconnect to peer {peer_id}...")
            
            # Use exponential backoff for reconnection attempts
            max_attempts = 5
            base_delay = 2  # seconds
            
            for attempt in range(max_attempts):
                try:
                    # Try direct connection first
                    if (peer.host, peer.port) not in self.failed_direct_connections:
                        try:
                            await self.register_with_peer(peer)
                            logger.info(f"Successfully reconnected to {peer_id} (attempt {attempt + 1})")
                            return
                        except Exception as e:
                            logger.debug(f"Direct reconnection to {peer_id} failed: {e}")
                            self.failed_direct_connections.add((peer.host, peer.port))
                    
                    # Try TURN relay if direct connection failed
                    if self.turn_clients:
                        await self._try_turn_connection(peer.host, peer.port)
                        if peer.peer_id in self.peers and self.peers[peer.peer_id].is_connected:
                            logger.info(f"Successfully reconnected to {peer_id} via TURN (attempt {attempt + 1})")
                            return
                    
                    # Calculate backoff delay (exponential with jitter)
                    delay = min(base_delay * (2 ** attempt), 300)  # Cap at 5 minutes
                    jitter = random.uniform(0.8, 1.2)  # Add some jitter
                    await asyncio.sleep(delay * jitter)
                    
                except asyncio.CancelledError:
                    logger.info(f"Reconnection to {peer_id} was cancelled")
                    return
                except Exception as e:
                    logger.warning(f"Error during reconnection attempt {attempt + 1} to {peer_id}: {e}")
        
        except Exception as e:
            logger.error(f"Unexpected error during reconnection to {peer_id}: {e}", exc_info=True)
        
        finally:
            self.reconnecting_peers.discard(peer_id)
            
            # If we've exhausted all attempts and still not connected, mark as failed
            if peer_id in self.peers and not self.peers[peer_id].is_connected:
                logger.warning(f"Failed to reconnect to {peer_id} after {max_attempts} attempts")
                del self.peers[peer_id]
                
                # Update metrics
                get_metrics().get_metric('p2p_connection_errors_total').inc(
                    labels={'error_type': 'reconnect_failed'}
                )
    
    async def stop(self) -> None:
        """Stop the P2P node and clean up resources."""
        if not self.is_running:
            return
            
        logger.info("Stopping P2P node...")
        self.is_running = False
        
        # Stop the message processor
        if self.message_processor_task:
            self.message_processor_task.cancel()
            try:
                await self.message_processor_task
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"Error stopping message processor: {e}")
            self.message_processor_task = None
        
        # Cancel all pending peer connections
        for future in self.pending_peers.values():
            if not future.done():
                future.cancel()
        self.pending_peers.clear()
        
        # Clear reconnecting peers set
        self.reconnecting_peers.clear()
        
        # Disconnect from all peers
        await self.cleanup_peers()
        
        # Stop the connection monitor
        try:
            await self.connection_monitor.stop()
        except Exception as e:
            logger.error(f"Error stopping connection monitor: {e}")
        
        # Close TURN clients
        for client in list(self.turn_clients.values()):
            try:
                await client.close()
            except Exception as e:
                logger.error(f"Error closing TURN client {client.server.host}: {e}")
        self.turn_clients.clear()
        
        # Stop the web server
        if self.site:
            try:
                await self.site.stop()
            except Exception as e:
                logger.error(f"Error stopping web server: {e}")
        
        if self.runner:
            try:
                await self.runner.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up web runner: {e}")
        
        if self.session:
            try:
                await self.session.close()
            except Exception as e:
                logger.error(f"Error closing HTTP session: {e}")
        
        # Clear all peers
        self.peers.clear()
        
        logger.info("P2P node stopped")
    
    async def cleanup_peers(self) -> None:
        """Clean up all peer connections."""
        if not self.session:
            return
            
        tasks = []
        for peer_id, peer in list(self.peers.items()):
            if peer.is_connected:
                tasks.append(self.disconnect_peer(peer_id))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        # Clear peer dictionaries
        self.peers.clear()
        self.pending_peers.clear()
        
        logger.info("Cleaned up all peer connections")
    
    # P2P API Endpoints
    async def get_peers(self, request: web.Request) -> web.Response:
        """Return list of known peers."""
        peers_data = [{"host": p.host, "port": p.port} for p in self.peers.values()]
        return web.json_response({"peers": peers_data})
    
    async def register_peer(self, request: web.Request) -> web.Response:
        """Register a new peer."""
        try:
            data = await request.json()
            peer_id = data.get('peer_id')
            host = data['host']
            port = data['port']
            
            # Don't register self
            if host == self.host and port == self.port:
                return web.json_response({"status": "success", "message": "Cannot register self as peer"})
            
            # Create or update peer
            peer = Peer(
                peer_id=peer_id or f"{host}:{port}",
                host=host,
                port=port,
                connection_type=data.get('connection_type', 'direct'),
                relay_server=tuple(data['relay_server'].split(':')) if 'relay_server' in data else None
            )
            
            # Add to peers if not already present
            if peer.peer_id not in self.peers:
                self.peers[peer.peer_id] = peer
                logger.info(f"Registered new peer: {peer.peer_id} ({peer.host}:{peer.port})")
                
                # Optionally connect to the peer
                if data.get('auto_connect', True):
                    asyncio.create_task(self._connect_to_peer(peer))
            
            # Return success with our peer info
            return web.json_response({
                "status": "success",
                "peer_id": self.peer_id,
                "host": self.host,
                "port": self.port,
                "peers": [
                    {"host": p.host, "port": p.port, "peer_id": p.peer_id}
                    for p in self.peers.values()
                    if p.peer_id != peer_id  # Don't include the requesting peer
                ]
            })
            
        except KeyError as e:
            error_msg = f"Missing required field: {e}"
            logger.error(f"Error registering peer: {error_msg}")
            return web.json_response({"error": error_msg}, status=400)
            
        except Exception as e:
            error_msg = f"Error registering peer: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return web.json_response({"error": error_msg}, status=500)
    
    async def get_blocks(self, request: web.Request) -> web.Response:
        """Return the blockchain."""
        try:
            # Get the latest block hash if provided
            since_hash = request.query.get('since')
            limit = min(100, int(request.query.get('limit', '10')))
            
            # TODO: Implement actual blockchain retrieval with pagination
            blocks = []  # This would be replaced with actual blockchain query
            
            # Update metrics
            get_metrics().get_metric('p2p_block_requests_total').inc()
            
            return web.json_response({
                "status": "success",
                "blocks": blocks,
                "count": len(blocks),
                "peer_id": self.peer_id
            })
            
        except Exception as e:
            logger.error(f"Error retrieving blocks: {e}", exc_info=True)
            return web.json_response({"error": str(e)}, status=500)
    
    async def receive_block(self, request: web.Request) -> web.Response:
        """Receive a new block from a peer."""
        try:
            data = await request.json()
            block = data.get('block')
            
            if not block:
                return web.json_response({"error": "No block data provided"}, status=400)
            
            # Validate block structure (basic validation)
            required_fields = ['index', 'hash', 'previous_hash', 'timestamp', 'transactions']
            if not all(field in block for field in required_fields):
                return web.json_response({"error": "Invalid block format"}, status=400)
            
            # TODO: Add more validation and add to blockchain
            logger.info(f"Received new block #{block['index']} with hash {block['hash']}")
            
            # Update metrics
            get_metrics().get_metric('p2p_blocks_received_total').inc()
            
            # Broadcast to other peers
            await self.broadcast_block(block)
            
            return web.json_response({
                "status": "received",
                "block_hash": block['hash'],
                "block_index": block['index']
            })
            
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
            
        except Exception as e:
            logger.error(f"Error processing block: {e}", exc_info=True)
            return web.json_response({"error": str(e)}, status=500)
    
    async def get_transactions(self, request: web.Request) -> web.Response:
        """Return pending transactions."""
        try:
            # Get query parameters
            limit = min(100, int(request.query.get('limit', '50')))
            since = int(request.query.get('since', '0'))
            
            # TODO: Implement actual transaction pool query with pagination
            transactions = []  # This would be replaced with actual transaction pool query
            
            # Update metrics
            get_metrics().get_metric('p2p_transaction_requests_total').inc()
            
            return web.json_response({
                "status": "success",
                "transactions": transactions,
                "count": len(transactions),
                "peer_id": self.peer_id
            })
            
        except Exception as e:
            logger.error(f"Error retrieving transactions: {e}", exc_info=True)
            return web.json_response({"error": str(e)}, status=500)
    
    async def receive_transaction(self, request: web.Request) -> web.Response:
        """Receive a new transaction from a peer."""
        try:
            data = await request.json()
            tx = data.get('transaction')
            
            if not tx:
                return web.json_response({"error": "No transaction data provided"}, status=400)
            
            # Validate transaction structure (basic validation)
            required_fields = ['txid', 'inputs', 'outputs', 'timestamp']
            if not all(field in tx for field in required_fields):
                return web.json_response({"error": "Invalid transaction format"}, status=400)
            
            # TODO: Add transaction validation and add to mempool
            logger.info(f"Received new transaction: {tx['txid']}")
            
            # Update metrics
            get_metrics().get_metric('p2p_transactions_received_total').inc()
            
            # Broadcast to other peers
            await self.broadcast_transaction(tx)
            
            return web.json_response({
                "status": "received",
                "txid": tx['txid']
            })
            
        except json.JSONDecodeError:
            return web.json_response({"error": "Invalid JSON"}, status=400)
            
        except Exception as e:
            logger.error(f"Error processing transaction: {e}", exc_info=True)
            return web.json_response({"error": str(e)}, status=500)
    
    # P2P Network Operations
    async def connect_to_peers(self, initial_peers: List[Tuple[str, int]]) -> None:
        """Connect to initial set of peers with retry logic."""
        tasks = []
        for host, port in initial_peers:
            if host == self.host and port == self.port:
                continue  # Skip self
            
            peer_id = f"{host}:{port}"
            if peer_id in self.peers or peer_id in self.pending_peers:
                continue  # Already connected or connecting
            
            # Create a future to track this connection attempt
            future = asyncio.Future()
            self.pending_peers[peer_id] = future
            
            # Start connection attempt in the background
            task = asyncio.create_task(self._connect_to_peer_with_retry(host, port, future))
            tasks.append(task)
        
        # Wait for all connection attempts to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _connect_to_peer_with_retry(self, host: str, port: int, future: asyncio.Future) -> None:
        """Attempt to connect to a peer with retry logic."""
        max_retries = 3
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                peer = Peer(host=host, port=port, peer_id=f"{host}:{port}")
                await self.register_with_peer(peer)
                
                if not future.done():
                    future.set_result(True)
                    
                logger.info(f"Successfully connected to peer: {host}:{port}")
                return
                
            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    error_msg = f"Failed to connect to {host}:{port} after {max_retries} attempts: {e}"
                    logger.warning(error_msg)
                    
                    if not future.done():
                        future.set_exception(ConnectionError(error_msg))
                    
                    # Add to failed connections to try TURN later
                    self.failed_direct_connections.add((host, port))
                    
                    # Try TURN if available
                    if self.turn_clients:
                        await self._try_turn_connection(host, port)
                else:
                    logger.debug(f"Connection attempt {attempt + 1}/{max_retries} to {host}:{port} failed: {e}")
                    await asyncio.sleep(retry_delay * (attempt + 1))  # Exponential backoff
    
    async def _try_turn_connection(self, host: str, port: int) -> None:
        """Attempt to connect to a peer using TURN relay."""
        if not self.turn_clients:
            return
            
        for turn_client in self.turn_clients.values():
            try:
                # Create a relayed connection through TURN
                peer_id = f"turn:{host}:{port}"
                relay_peer = Peer(
                    peer_id=peer_id,
                    host=host,
                    port=port,
                    connection_type="relay",
                    relay_server=(turn_client.server.host, turn_client.server.port)
                )
                
                await self.register_with_peer(relay_peer)
                logger.info(f"Connected to {host}:{port} via TURN relay {turn_client.server.host}")
                return
                
            except Exception as e:
                logger.warning(f"TURN relay connection to {host}:{port} failed: {e}")
    
    async def _send_to_peer(self, peer: 'Peer', message: Dict[str, Any], 
                         encrypt: bool = False) -> None:
        """Send a message to a specific peer.
        
        Args:
            peer: The peer to send the message to
            message: The message to send (will be JSON-serialized)
            encrypt: Whether to encrypt the message for the recipient
            
        Raises:
            ConnectionError: If the message could not be delivered
            ValueError: If the message is invalid or encryption fails
        """
        if not self.is_running:
            raise ConnectionError("P2P node is not running")
            
        if not peer.is_connected:
            raise ConnectionError(f"Peer {peer.peer_id} is not connected")
            
        message_type = message.get('type', 'unknown')
        
        try:
            # Add standard fields if missing
            if 'timestamp' not in message:
                message['timestamp'] = time.time()
                
            if 'sender' not in message:
                message['sender'] = self.peer_id
                
            if 'message_id' not in message:
                import uuid
                message['message_id'] = str(uuid.uuid4())
            
            # Sign the message
            message_copy = message.copy()
            signature = self.signer.sign_message(message_copy)
            message['signature'] = base64.b64encode(signature).decode('ascii')
            
            # Add our public key if the peer might not have it
            if peer.peer_id not in self.peer_public_keys:
                message['public_key'] = base64.b64encode(
                    self.signer.get_public_key_bytes()
                ).decode('ascii')
            
            # Encrypt the message if requested and we have the peer's public key
            if encrypt and peer.peer_id in self.peer_public_keys:
                try:
                    peer_public_key = self.peer_public_keys[peer.peer_id]
                    encrypted_message = self.signer.encrypt_message(
                        message,
                        peer_public_key
                    )
                    # Replace the message with the encrypted version
                    message = {
                        'type': 'encrypted',
                        'data': encrypted_message,
                        'sender': self.peer_id,
                        'timestamp': time.time(),
                        'message_id': message['message_id']
                    }
                    # Re-sign the encrypted message
                    signature = self.signer.sign_message(message)
                    message['signature'] = base64.b64encode(signature).decode('ascii')
                except Exception as e:
                    logger.error(f"Failed to encrypt message: {e}")
                    if encrypt:  # If encryption was required, fail
                        raise
            
            # Prepare the message for sending
            message_str = json.dumps(message)
            message_bytes = message_str.encode('utf-8')
            
            # Update metrics
            get_metrics().get_metric('p2p_messages_sent_total').inc(
                labels={'message_type': message_type, 'status': 'attempt'}
            )
            
            # Record start time for latency measurement
            start_time = time.time()
            
            # Determine the protocol and URL
            protocol = "https" if self.ssl_context else "http"
            url = f"{protocol}://{peer.host}:{peer.port}/message"
            
            # Configure timeout
            timeout = aiohttp.ClientTimeout(total=self.connection_timeout)
            
            # Send the message
            try:
                async with self.session.post(
                    url,
                    data=message_bytes,
                    headers={'Content-Type': 'application/json'},
                    timeout=timeout,
                    ssl=self.ssl_context
                ) as response:
                    if response.status != 200:
                        error_text = await response.text()
                        raise ConnectionError(
                            f"Failed to send message to {peer.peer_id}: "
                            f"HTTP {response.status}: {error_text}"
                        )
                    
                    # Update metrics on success
                    latency = time.time() - start_time
                    get_metrics().get_metric('p2p_message_latency_seconds').observe(latency)
                    get_metrics().get_metric('p2p_messages_sent_total').inc(
                        labels={'message_type': message_type, 'status': 'success'}
                    )
                    get_metrics().get_metric('p2p_bandwidth_bytes').inc(
                        value=len(message_bytes),
                        labels={'direction': 'out'}
                    )
                    
                    logger.debug(
                        f"Sent {message_type} message to {peer.peer_id} "
                        f"({len(message_bytes)} bytes, {latency*1000:.2f}ms)"
                    )
                    
            except asyncio.TimeoutError:
                raise ConnectionError(f"Timeout while sending message to {peer.peer_id}")
                
        except json.JSONEncodeError as e:
            raise ValueError(f"Failed to serialize message: {e}")
            
        except Exception as e:
            # Update error metrics
            get_metrics().get_metric('p2p_messages_sent_total').inc(
                labels={'message_type': message_type, 'status': 'error'}
            )
            logger.error(f"Error sending message to {peer.peer_id}: {e}", exc_info=True)
            raise ConnectionError(f"Failed to send message to {peer.peer_id}: {str(e)}")
    
    async def handle_message(self, request: web.Request) -> web.Response:
        """Handle incoming messages from other peers.
        
        This endpoint receives messages from other peers in the network and processes them
        based on their type. It supports both direct messages and broadcasts.
        
        Expected JSON format:
        {
            "type": "message_type",  # e.g., 'chat', 'block', 'transaction', etc.
            "data": {...},           # Message payload
            "sender": "peer_id",     # Sender's peer ID
            "timestamp": 1234567890, # Unix timestamp
            "message_id": "uuid",    # Optional unique message ID
            "signature": "base64",   # Message signature
            "public_key": "base64"   # Sender's public key (if not already known)
        }
        """
        try:
            # Get the sender's IP and port
            peer_host = request.remote
            peer_port = request.transport.get_extra_info('peername')[1]
            
            # Parse the message
            try:
                message = await request.json()
            except json.JSONDecodeError:
                return web.json_response(
                    {"error": "Invalid JSON"}, 
                    status=400
                )
            
            # Validate required fields
            required_fields = ['type', 'data', 'sender', 'signature']
            if not all(field in message for field in required_fields):
                return web.json_response(
                    {"error": f"Missing required fields. Required: {required_fields}"},
                    status=400
                )
                
            # Get the sender's public key
            sender_id = message['sender']
            public_key_b64 = message.get('public_key')
            
            if not public_key_b64 and sender_id not in self.peer_public_keys:
                return web.json_response(
                    {"error": "Public key required for new senders"},
                    status=400
                )
                
            if public_key_b64:
                try:
                    public_key = base64.b64decode(public_key_b64)
                    self.peer_public_keys[sender_id] = public_key
                except Exception as e:
                    return web.json_response(
                        {"error": f"Invalid public key: {str(e)}"},
                        status=400
                    )
            else:
                public_key = self.peer_public_keys.get(sender_id)
                
            # Verify the message signature
            try:
                signature = base64.b64decode(message['signature'])
                message_copy = message.copy()
                message_copy.pop('signature', None)
                message_copy.pop('public_key', None)
                
                if not self.signer.verify_message(message_copy, signature, public_key):
                    return web.json_response(
                        {"error": "Invalid message signature"},
                        status=401
                    )
            except Exception as e:
                logger.error(f"Error verifying message signature: {e}", exc_info=True)
                return web.json_response(
                    {"error": f"Signature verification failed: {str(e)}"},
                    status=400
                )
            
            # Add timestamp if not provided
            if 'timestamp' not in message:
                message['timestamp'] = time.time()
            
            # Add message ID if not provided
            if 'message_id' not in message:
                import uuid
                message['message_id'] = str(uuid.uuid4())
            
            # Update metrics
            message_type = message['type']
            get_metrics().get_metric('p2p_messages_received_total').inc(
                labels={'message_type': message_type}
            )
            
            # Update bandwidth metrics
            message_size = len(await request.read())
            get_metrics().get_metric('p2p_bandwidth_bytes').inc(
                value=message_size,
                labels={'direction': 'in'}
            )
            
            # Log the message
            logger.debug(
                f"Received {message_type} message from {message['sender']} "
                f"({message_size} bytes, id: {message['message_id']})"
            )
            
            # Process the message based on its type
            try:
                # Look for a specific handler for this message type
                handler_name = f"_handle_{message_type}_message"
                handler = getattr(self, handler_name, None)
                
                if handler and callable(handler):
                    # Call the specific handler if it exists
                    await handler(message, peer_host, peer_port)
                else:
                    # Default message handling
                    await self._handle_default_message(message, peer_host, peer_port)
                
                return web.json_response({
                    "status": "received",
                    "message_id": message['message_id'],
                    "type": message_type
                })
                
            except Exception as e:
                logger.error(
                    f"Error processing {message_type} message from {message['sender']}: {e}",
                    exc_info=True
                )
                return web.json_response(
                    {"error": f"Failed to process message: {str(e)}"},
                    status=500
                )
                
        except Exception as e:
            logger.error(f"Unexpected error in handle_message: {e}", exc_info=True)
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def handle_file_upload(self, request: web.Request) -> web.Response:
        """Handle file uploads from peers."""
        try:
            reader = await request.multipart()
            field = await reader.next()
            
            if field.name != 'file':
                return web.json_response(
                    {"error": "Expected 'file' field"},
                    status=400
                )
            
            # Get file info
            file_name = field.filename
            file_size = 0
            file_id = request.query.get('file_id', str(uuid.uuid4()))
            
            # Create upload directory if it doesn't exist
            upload_dir = Path("uploads") / file_id
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            # Save the file
            file_path = upload_dir / file_name
            with open(file_path, 'wb') as f:
                while True:
                    chunk = await field.read_chunk()  # 8192 bytes by default
                    if not chunk:
                        break
                    file_size += len(chunk)
                    f.write(chunk)
            
            return web.json_response({
                "status": "success",
                "file_id": file_id,
                "file_name": file_name,
                "file_size": file_size,
                "path": str(file_path)
            })
            
        except Exception as e:
            logger.error(f"File upload failed: {e}", exc_info=True)
            return web.json_response(
                {"error": f"File upload failed: {str(e)}"},
                status=500
            )
    
    async def handle_file_download(self, request: web.Request) -> web.StreamResponse:
        """Handle file downloads for peers."""
        file_id = request.match_info.get('file_id')
        if not file_id:
            return web.json_response(
                {"error": "File ID is required"},
                status=400
            )
        
        try:
            # In a real implementation, you would look up the file path from the file_id
            # For this example, we'll just use the file_id as the path
            file_path = Path("uploads") / file_id / "file"  # This is just an example
            
            if not file_path.exists():
                return web.json_response(
                    {"error": "File not found"},
                    status=404
                )
            
            # Stream the file
            response = web.StreamResponse(
                status=200,
                reason='OK',
                headers={
                    'Content-Type': 'application/octet-stream',
                    'Content-Disposition': f'attachment; filename="{file_path.name}"'
                }
            )
            
            await response.prepare(request)
            
            # Stream the file in chunks
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    await response.write(chunk)
            
            return response
            
        except Exception as e:
            logger.error(f"File download failed: {e}", exc_info=True)
            return web.json_response(
                {"error": f"File download failed: {str(e)}"},
                status=500
            )
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """Register a handler for a specific message type.
        
        Args:
            message_type: The message type to handle
            handler: The handler function (async function that takes sender_id and message)
        """
        self.connection_handlers[message_type] = handler
    
    async def _handle_default_message(self, message: Dict, peer_host: str, peer_port: int) -> None:
        """Default handler for messages without a specific handler.
        
        Args:
            message: The message dictionary
            peer_host: IP address of the sender
            peer_port: Port of the sender
        """
        # Default behavior: just log the message
        logger.info(
            f"Received {message['type']} message from {message.get('sender', 'unknown')} "
            f"at {peer_host}:{peer_port}: {message.get('data', 'No data')}"
        )
        
        # Update last seen time for this peer
        sender_id = message.get('sender')
        if sender_id and sender_id in self.peers:
            self.peers[sender_id].last_seen = time.time()
    
    async def _process_message_queue(self) -> None:
        """Process messages from the outbound message queue.
        
        This method runs in a background task and continuously processes messages
        from the queue, sending them to the appropriate peers.
        """
        while self.is_running:
            try:
                # Wait for a message with a small timeout to allow for clean shutdown
                try:
                    message, exclude_peer_ids = await asyncio.wait_for(
                        self.message_queue.get(),
                        timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                if not message:
                    continue
                    
                # Update queue metrics
                queue_size = self.message_queue.qsize()
                get_metrics().get_metric('p2p_message_queue_size').set(queue_size)
                
                # Record queue delay
                if 'timestamp' in message:
                    delay = time.time() - message['timestamp']
                    get_metrics().get_metric('p2p_message_queue_delay_seconds').observe(delay)
                
                # Prepare message for sending
                message_id = message.get('id', str(uuid.uuid4()))
                message_type = message.get('type', 'unknown')
                
                # Get list of target peers (all connected peers except excluded ones)
                target_peers = [
                    peer for peer in self.peers.values()
                    if peer.is_connected and peer.peer_id not in (exclude_peer_ids or [])
                ]
                
                if not target_peers:
                    logger.debug(f"No peers available to send message {message_id} to")
                    continue
                
                # Send message to all target peers in parallel
                send_tasks = []
                for peer in target_peers:
                    send_tasks.append(self._send_to_peer(peer, message))
                
                # Wait for all sends to complete or timeout
                results = await asyncio.gather(
                    *send_tasks,
                    return_exceptions=True
                )
                
                # Process results
                success_count = 0
                for peer, result in zip(target_peers, results):
                    if isinstance(result, Exception):
                        logger.warning(
                            f"Failed to send {message_type} to {peer.peer_id}: {result}"
                        )
                        # Update error metrics
                        get_metrics().get_metric('p2p_messages_sent_total').inc(
                            labels={'message_type': message_type, 'status': 'error'}
                        )
                        # Mark peer as disconnected and schedule reconnection
                        if peer.peer_id in self.peers:
                            self.peers[peer.peer_id].is_connected = False
                            asyncio.create_task(self._reconnect_peer(peer.peer_id))
                    else:
                        success_count += 1
                        # Update success metrics
                        get_metrics().get_metric('p2p_messages_sent_total').inc(
                            labels={'message_type': message_type, 'status': 'success'}
                        )
                
                logger.debug(
                    f"Sent {message_type} to {success_count}/{len(target_peers)} peers "
                    f"(message_id: {message_id})"
                )
                
                # Update bandwidth metrics (approximate, doesn't count protocol overhead)
                message_size = len(json.dumps(message).encode('utf-8'))
                get_metrics().get_metric('p2p_bandwidth_bytes').inc(
                    value=message_size * success_count,
                    labels={'direction': 'out'}
                )
                
            except asyncio.CancelledError:
                logger.info("Message queue processor received cancellation signal")
                break
                
            except Exception as e:
                logger.error(f"Error in message queue processor: {e}", exc_info=True)
                # Avoid tight loop on errors
                await asyncio.sleep(1)
                
        logger.info("Message queue processor stopped")
    
    async def register_with_peer(self, peer: Peer) -> None:
        """Register with a peer and exchange peer lists."""
        if peer.peer_id in self.peers:
            return  # Already connected to this peer
            
        try:
            protocol = "https" if self.ssl_context else "http"
            url = f"{protocol}://{peer.host}:{peer.port}/register"
            
            # Prepare registration data
            data = {
                'peer_id': self.peer_id,
                'host': self.host,
                'port': self.port,
                'connection_type': 'direct',
                'auto_connect': False
            }
            
            # Add TURN relay info if available
            if self.relay_address:
                data['relay_server'] = self.relay_address
            
            # Configure timeout
            timeout = aiohttp.ClientTimeout(total=self.connection_timeout)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(url, json=data, ssl=self.ssl_context) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Update peer with ID from server
                        peer.peer_id = result.get('peer_id', peer.peer_id)
                        peer.is_connected = True
                        
                        # Add to connected peers
                        self.peers[peer.peer_id] = peer
                        
                        # Update connection monitor
                        self.connection_monitor.register_connection(
                            peer.peer_id, 
                            (peer.host, peer.port)
                        )
                        
                        # Connect to new peers if we're below max_peers
                        if len(self.peers) < self.max_peers:
                            for p in result.get('peers', []):
                                if p['peer_id'] != self.peer_id and p['peer_id'] not in self.peers:
                                    new_peer = Peer(
                                        peer_id=p['peer_id'],
                                        host=p['host'],
                                        port=p['port'],
                                        connection_type=p.get('connection_type', 'direct'),
                                        relay_server=tuple(p['relay_server'].split(':')) if 'relay_server' in p else None
                                    )
                                    asyncio.create_task(self.register_with_peer(new_peer))
                        
                        logger.info(f"Successfully registered with peer {peer.peer_id} at {peer.host}:{peer.port}")
                        return
                    
                    # Handle error response
                    error_text = await response.text()
                    raise Exception(f"Registration failed with status {response.status}: {error_text}")
                    
        except asyncio.TimeoutError:
            raise Exception(f"Connection to {peer.host}:{peer.port} timed out")
            
        except Exception as e:
            logger.error(f"Error registering with peer {peer.host}:{peer.port}: {e}")
            if peer.peer_id in self.peers:
                del self.peers[peer.peer_id]
            raise

        try:
            # Process peer list from registration response
            for p in peer_list:
                if p['host'] != self.host or p['port'] != self.port:
                    self.peers.add(Peer(host=p['host'], port=p['port']))
        except Exception as e:
            logger.warning(f"Failed to process peer list from {peer.host}:{peer.port}: {e}")
    
    async def broadcast_block(self, block_data: Dict) -> None:
        """Broadcast a new block to all peers."""
        for peer in list(self.peers):
            try:
                async with self.session.post(
                    f"{peer.address}/blocks",
                    json=block_data,
                    timeout=10
                ) as response:
                    if response.status == 200:
                        logger.info(f"Successfully broadcast block to {peer.host}:{peer.port}")
            except Exception as e:
                logger.warning(f"Failed to broadcast to {peer.host}:{peer.port}: {e}")
    
    async def broadcast_transaction(self, tx_data: Dict) -> None:
        """Broadcast a new transaction to all peers."""
        for peer in list(self.peers):
            try:
                async with self.session.post(
                    f"{peer.address}/transactions",
                    json=tx_data,
                    timeout=5
                ) as response:
                    if response.status == 200:
                        logger.debug(f"Broadcasted transaction to {peer.host}:{peer.port}")
            except Exception as e:
                logger.warning(f"Failed to broadcast transaction to {peer.host}:{peer.port}: {e}")

# Singleton instance
node: Optional[P2PNode] = None

async def get_p2p_node(host: str = '0.0.0.0', port: int = 5000) -> P2PNode:
    """Get or create the P2P node instance."""
    global node
    if node is None:
        node = P2PNode(host=host, port=port)
        await node.start()
    return node
