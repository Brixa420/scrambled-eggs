"""
Enhanced P2P Manager with DHT, mDNS, and NAT traversal support.
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import socket
import struct
import time
import uuid
from typing import Dict, List, Optional, Any, Callable, Set, Tuple, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature, InvalidKey

# Third-party imports
try:
    import stem
    import stem.control
    from stem.control import Controller
    from stem import process
    from stem.util import term
    TOR_AVAILABLE = True
except ImportError:
    TOR_AVAILABLE = False
    logger.warning("Tor controller not available. Install with: pip install stem")

try:
    import stun
    STUN_AVAILABLE = True
except ImportError:
    STUN_AVAILABLE = False
    logger.warning("STUN not available. Install with: pip install pystun3")

# Import our custom modules
from .dht_manager import DHTManager, PeerInfo as DHT_PeerInfo
from .mdns_manager import MDNSManager, PeerInfo as MDNS_PeerInfo

logger = logging.getLogger(__name__)

# Constants
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051
TOR_HIDDEN_SERVICE_PORT = 80
TOR_HIDDEN_SERVICE_DIR = os.path.join(os.path.expanduser('~'), '.tor', 'hidden_service')

class TorManager:
    """Manages Tor connections and hidden services."""
    
    def __init__(self, control_port: int = TOR_CONTROL_PORT, 
                 socks_port: int = TOR_SOCKS_PORT,
                 hidden_service_dir: str = TOR_HIDDEN_SERVICE_DIR,
                 hidden_service_port: int = TOR_HIDDEN_SERVICE_PORT):
        """Initialize the Tor manager.
        
        Args:
            control_port: Port for Tor control connection
            socks_port: Port for Tor SOCKS proxy
            hidden_service_dir: Directory to store hidden service keys
            hidden_service_port: Port to expose as hidden service
        """
        self.control_port = control_port
        self.socks_port = socks_port
        self.hidden_service_dir = os.path.abspath(hidden_service_dir)
        self.hidden_service_port = hidden_service_port
        
        self.controller = None
        self.hidden_service = None
        self.onion_address = None
        
        # Create hidden service directory if it doesn't exist
        os.makedirs(self.hidden_service_dir, exist_ok=True, mode=0o700)
    
    def start(self) -> bool:
        """Start the Tor service and configure it."""
        if not TOR_AVAILABLE:
            logger.error("Tor is not available. Install with: pip install stem")
            return False
        
        try:
            # Try to connect to existing Tor process
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate()
            logger.info("Connected to existing Tor process")
        except Exception as e:
            logger.warning(f"Could not connect to existing Tor: {e}. Attempting to start Tor...")
            try:
                # Start a new Tor process
                tor_process = process.launch_tor_with_config(
                    tor_cmd='tor',
                    init_msg_handler=print,
                    take_ownership=True,
                    config={
                        'SocksPort': str(self.socks_port),
                        'ControlPort': str(self.control_port),
                        'DataDirectory': os.path.join(os.path.expanduser('~'), '.tor'),
                    }
                )
                self.controller = tor_process.controller
                logger.info("Started new Tor process")
            except Exception as e:
                logger.error(f"Failed to start Tor: {e}")
                return False
        
        # Set up hidden service if not already running
        if not self._setup_hidden_service():
            logger.error("Failed to set up hidden service")
            return False
        
        return True
    
    def _setup_hidden_service(self) -> bool:
        """Set up a hidden service for peer discovery."""
        try:
            # Check if we already have a hidden service
            services = self.controller.list_ephemeral_hidden_services()
            
            if services:
                self.onion_address = list(services.keys())[0]
                logger.info(f"Using existing hidden service: {self.onion_address}")
                return True
            
            # Create a new hidden service
            service = self.controller.create_ephemeral_hidden_service(
                {self.hidden_service_port: 5000},  # Map hidden service port to local port 5000
                key_type='NEW',
                key_content='ED25519-V3',
                detached=True,
                await_publication=True
            )
            
            self.onion_address = service.service_id + ".onion"
            logger.info(f"Created new hidden service: {self.onion_address}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up hidden service: {e}")
            return False
    
    def stop(self) -> None:
        """Stop the Tor service."""
        if self.controller:
            try:
                if self.hidden_service:
                    self.controller.remove_ephemeral_hidden_service(self.hidden_service.service_id)
                self.controller.close()
                logger.info("Tor controller stopped")
            except Exception as e:
                logger.error(f"Error stopping Tor controller: {e}")
            finally:
                self.controller = None
                self.hidden_service = None
                self.onion_address = None

class EncryptionManager:
    """Handles encryption and decryption of messages."""
    
    def __init__(self, private_key: bytes = None, public_key: bytes = None):
        """Initialize the encryption manager.
        
        Args:
            private_key: Optional private key in PEM format
            public_key: Optional public key in PEM format
        """
        self.private_key = None
        self.public_key = None
        self.peer_public_keys = {}
        
        if private_key:
            self.load_private_key(private_key)
        if public_key:
            self.load_public_key(public_key)
        
        # Generate new key pair if none provided
        if not self.private_key:
            self._generate_key_pair()
    
    def _generate_key_pair(self) -> None:
        """Generate a new RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def load_private_key(self, key_data: bytes) -> bool:
        """Load a private key from PEM or DER format."""
        try:
            self.private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            return True
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            return False
    
    def load_public_key(self, key_data: bytes) -> bool:
        """Load a public key from PEM or DER format."""
        try:
            self.public_key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            return True
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            return False
    
    def add_peer_public_key(self, peer_id: str, key_data: bytes) -> bool:
        """Add a peer's public key for secure communication."""
        try:
            public_key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            self.peer_public_keys[peer_id] = public_key
            return True
        except Exception as e:
            logger.error(f"Failed to add peer public key: {e}")
            return False
    
    def encrypt_message(self, peer_id: str, message: bytes) -> Optional[bytes]:
        """Encrypt a message for a specific peer."""
        if peer_id not in self.peer_public_keys:
            logger.error(f"No public key found for peer {peer_id}")
            return None
        
        try:
            # Generate a random symmetric key for this message
            sym_key = os.urandom(32)
            iv = os.urandom(16)
            
            # Encrypt the message with AES-256-CBC
            padder = sym_padding.PKCS7(128).padder()
            padded_data = padder.update(message) + padder.finalize()
            
            cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            # Encrypt the symmetric key with the peer's public key
            encrypted_key = self.peer_public_keys[peer_id].encrypt(
                sym_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Combine the encrypted key, IV, and ciphertext
            return (
                len(encrypted_key).to_bytes(4, 'big') +  # Key length (4 bytes)
                len(iv).to_bytes(4, 'big') +            # IV length (4 bytes)
                encrypted_key +                         # Encrypted symmetric key
                iv +                                    # Initialization vector
                ciphertext                              # Encrypted message
            )
            
        except Exception as e:
            logger.error(f"Failed to encrypt message: {e}")
            return None
    
    def decrypt_message(self, encrypted_data: bytes) -> Optional[bytes]:
        """Decrypt a message using our private key."""
        if not self.private_key:
            logger.error("No private key available for decryption")
            return None
        
        try:
            # Parse the encrypted data
            key_len = int.from_bytes(encrypted_data[:4], 'big')
            iv_len = int.from_bytes(encrypted_data[4:8], 'big')
            
            encrypted_key = encrypted_data[8:8+key_len]
            iv = encrypted_data[8+key_len:8+key_len+iv_len]
            ciphertext = encrypted_data[8+key_len+iv_len:]
            
            # Decrypt the symmetric key with our private key
            sym_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt the message with the symmetric key
            cipher = Cipher(algorithms.AES(sym_key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad the decrypted data
            unpadder = sym_padding.PKCS7(128).unpadder()
            return unpadder.update(padded_data) + unpadder.finalize()
            
        except Exception as e:
            logger.error(f"Failed to decrypt message: {e}")
            return None
    
    def sign_message(self, message: bytes) -> Optional[bytes]:
        """Sign a message with our private key."""
        if not self.private_key:
            logger.error("No private key available for signing")
            return None
        
        try:
            signature = self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature
        except Exception as e:
            logger.error(f"Failed to sign message: {e}")
            return None
    
    def verify_signature(self, peer_id: str, message: bytes, signature: bytes) -> bool:
        """Verify a message signature with a peer's public key."""
        if peer_id not in self.peer_public_keys:
            logger.error(f"No public key found for peer {peer_id}")
            return False
        
        try:
            self.peer_public_keys[peer_id].verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            logger.error(f"Error verifying signature: {e}")
            return False

class NATTraversal:
    """Handles NAT traversal using STUN and hole punching."""
    
    def __init__(self, stun_servers: List[Tuple[str, int]] = None):
        """Initialize the NAT traversal helper.
        
        Args:
            stun_servers: List of (host, port) tuples for STUN servers
        """
        self.stun_servers = stun_servers or [
            ('stun.l.google.com', 19302),
            ('stun1.l.google.com', 19302),
            ('stun2.l.google.com', 19302)
        ]
        self.public_ip = None
        self.public_port = None
        self.nat_type = None
    
    def get_public_address(self) -> Optional[Tuple[str, int]]:
        """Get the public IP address and port using STUN."""
        if not STUN_AVAILABLE:
            logger.warning("STUN is not available. Install with: pip install pystun3")
            return None
        
        for stun_host, stun_port in self.stun_servers:
            try:
                nat_type, nat = stun.get_ip_info(stun_host=stun_host, stun_port=stun_port)
                if nat and 'external' in nat and ':' in nat['external']:
                    ip, port = nat['external'].split(':')
                    self.public_ip = ip
                    self.public_port = int(port)
                    self.nat_type = nat_type
                    return (ip, int(port))
            except Exception as e:
                logger.warning(f"STUN request to {stun_host}:{stun_port} failed: {e}")
        
        logger.error("All STUN servers failed")
        return None
    
    async def punch_hole(self, peer_addr: Tuple[str, int], local_port: int) -> bool:
        """Attempt to establish a direct connection through NAT using hole punching.
        
        Args:
            peer_addr: The peer's public address (ip, port)
            local_port: Local port to use for the connection
            
        Returns:
            bool: True if hole punching was successful
        """
        if not self.public_ip or not self.public_port:
            logger.error("Public address not known. Call get_public_address() first.")
            return False
        
        try:
            # Create a UDP socket for hole punching
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5.0)
            sock.bind(('0.0.0.0', local_port))
            
            # Send a packet to the peer to open the NAT port
            sock.sendto(b'PUNCH', peer_addr)
            
            # Wait for a response
            try:
                data, addr = sock.recvfrom(1024)
                if data == b'PUNCH_ACK':
                    logger.info(f"Hole punching successful with {addr}")
                    return True
            except socket.timeout:
                logger.warning("Hole punching timed out")
            
            return False
            
        except Exception as e:
            logger.error(f"Hole punching failed: {e}")
            return False
        finally:
            if 'sock' in locals():
                sock.close()

@dataclass
class PeerInfo:
    """Enhanced peer information with connectivity status and security context."""
    peer_id: str
    address: str
    port: int
    public_key: str = ""
    last_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    is_connected: bool = False
    connection_attempts: int = 0
    last_attempt: float = 0.0
    is_tor: bool = False
    is_authenticated: bool = False
    session_key: Optional[bytes] = None  # For symmetric encryption
    handshake_complete: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary for serialization."""
        return {
            'peer_id': self.peer_id,
            'address': self.address,
            'port': self.port,
            'public_key': self.public_key,
            'last_seen': self.last_seen,
            'metadata': self.metadata,
            'is_connected': self.is_connected,
            'connection_attempts': self.connection_attempts,
            'last_attempt': self.last_attempt
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PeerInfo':
        """Create a PeerInfo from a dictionary."""
        return cls(
            peer_id=data['peer_id'],
            address=data['address'],
            port=data['port'],
            public_key=data.get('public_key', ''),
            last_seen=data.get('last_seen', time.time()),
            metadata=data.get('metadata', {}),
            is_connected=data.get('is_connected', False),
            connection_attempts=data.get('connection_attempts', 0),
            last_attempt=data.get('last_attempt', 0.0)
        )

class EnhancedP2PManager:
    """
    Enhanced P2P manager with DHT, mDNS, Tor, NAT traversal, and encryption support.
    
    This class provides a comprehensive P2P networking solution with the following features:
    - Peer discovery via DHT and mDNS
    - Secure communication using end-to-end encryption
    - NAT traversal using STUN and hole punching
    - Tor support for anonymous communication
    - Web interface for monitoring and control
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the enhanced P2P manager.
        
        Args:
            config: Configuration dictionary with the following optional keys:
                - peer_id: Unique identifier for this peer (default: auto-generated)
                - port: Port to listen on (default: 0 = random port)
                - max_peers: Maximum number of peers to connect to (default: 50)
                - enable_dht: Whether to enable DHT for peer discovery (default: True)
                - enable_mdns: Whether to enable mDNS for local discovery (default: True)
                - enable_tor: Whether to enable Tor for anonymous communication (default: False)
                - enable_nat_traversal: Whether to enable NAT traversal (default: True)
                - bootstrap_nodes: List of (host, port) tuples for initial DHT bootstrap
                - stun_servers: List of (host, port) tuples for STUN servers
                - public_key: Public key for this peer (PEM format)
                - private_key: Private key for this peer (PEM format, keep secure!)
                - key_file: Path to load/save key pair (default: 'p2p_keys.pem')
        """
        self.config = config or {}
        
        # Basic configuration
        self.peer_id = self.config.get('peer_id', f"peer_{str(uuid.uuid4())[:8]}")
        self.port = self.config.get('port', 0)
        self.max_peers = self.config.get('max_peers', 50)
        
        # Initialize encryption
        self.encryption = EncryptionManager()
        self._load_or_generate_keys()
        
        # State
        self.peers: Dict[str, PeerInfo] = {}
        self.connections: Dict[str, Any] = {}  # Active connections
        self.message_handlers: Dict[str, Callable] = {}
        self.running = False
        self.server = None
        
        # Event loop and executors
        self.loop = asyncio.get_event_loop()
        self.executor = ThreadPoolExecutor(max_workers=8)
        
        # Initialize Tor
        self.tor_manager = None
        self.tor_enabled = self.config.get('enable_tor', False)
        if self.tor_enabled and TOR_AVAILABLE:
            self.tor_manager = TorManager()
        
        # Initialize NAT traversal
        self.nat_traversal = None
        if self.config.get('enable_nat_traversal', True) and STUN_AVAILABLE:
            self.nat_traversal = NATTraversal(
                stun_servers=self.config.get('stun_servers')
            )
        
        # Initialize discovery services
        self._init_discovery_services()
        
        # Web interface
        self.web_interface = None
        if self.config.get('enable_web_interface', True):
            self._init_web_interface()
    
    def _load_or_generate_keys(self) -> None:
        """Load or generate encryption keys."""
        key_file = self.config.get('key_file', 'p2p_keys.pem')
        
        # Try to load keys from file
        if os.path.exists(key_file):
            try:
                with open(key_file, 'rb') as f:
                    private_key = f.read()
                    self.encryption.load_private_key(private_key)
                    logger.info(f"Loaded encryption keys from {key_file}")
                    return
            except Exception as e:
                logger.warning(f"Failed to load encryption keys: {e}")
        
        # Generate new keys
        self.encryption._generate_key_pair()
        
        # Save the private key
        try:
            private_key = self.encryption.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(key_file, 'wb') as f:
                f.write(private_key)
            logger.info(f"Generated and saved new encryption keys to {key_file}")
        except Exception as e:
            logger.error(f"Failed to save encryption keys: {e}")
    
    def _init_web_interface(self) -> None:
        """Initialize the web interface for monitoring and control."""
        from flask import Flask, jsonify, render_template, request
        from flask_socketio import SocketIO
        
        self.web_app = Flask(__name__)
        self.web_app.config['SECRET_KEY'] = os.urandom(24)
        self.socketio = SocketIO(self.web_app, async_mode='threading')
        
        @self.web_app.route('/')
        def index():
            return render_template('p2p_network.html')
        
        @self.web_app.route('/api/peers')
        def get_peers():
            return jsonify({
                'peers': [
                    {
                        'id': peer_id,
                        'address': f"{peer.address}:{peer.port}",
                        'connected': peer.is_connected,
                        'last_seen': peer.last_seen,
                        'is_tor': peer.is_tor,
                        'is_authenticated': peer.is_authenticated
                    }
                    for peer_id, peer in self.peers.items()
                ]
            })
        
        @self.socketio.on('connect')
        def handle_connect():
            self.socketio.emit('status', {'peers': len(self.peers)})
        
        # Start the web interface in a separate thread
        def run_web_interface():
            self.socketio.run(
                self.web_app,
                host='127.0.0.1',
                port=self.config.get('web_port', 5000),
                debug=False,
                use_reloader=False
            )
        
        import threading
        web_thread = threading.Thread(target=run_web_interface, daemon=True)
        web_thread.start()
        logger.info(f"Web interface started at http://127.0.0.1:{self.config.get('web_port', 5000)}")
    
    def get_public_key_pem(self) -> bytes:
        """Get the public key in PEM format."""
        if not self.encryption.public_key:
            return b''
        return self.encryption.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        logger.info(f"Enhanced P2P Manager initialized with ID: {self.peer_id}")
    
    def _init_discovery_services(self) -> None:
        """Initialize peer discovery services."""
        # DHT configuration
        dht_config = self.config.get('dht', {})
        self.enable_dht = dht_config.get('enabled', True)
        self.dht_bootstrap_nodes = dht_config.get('bootstrap_nodes', [])
        
        # Initialize DHT if enabled
        if self.enable_dht:
            try:
                self.dht = DHTManager(
                    node_id=self.peer_id,
                    port=dht_config.get('port', 0),
                    bootstrap_nodes=self.dht_bootstrap_nodes
                )
                logger.info("DHT service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize DHT: {e}")
                self.enable_dht = False
        
        # mDNS configuration
        mdns_config = self.config.get('mdns', {})
        self.enable_mdns = mdns_config.get('enabled', True)
        self.mdns_service_name = mdns_config.get('service_name', '_scrambledeggs._tcp.local.')
        
        # Initialize mDNS if enabled
        if self.enable_mdns:
            try:
                self.mdns = MDNSManager(
                    service_name=self.mdns_service_name,
                    service_port=self.port,
                    properties={
                        'peer_id': self.peer_id,
                        'public_key': self.get_public_key_pem().decode('utf-8'),
                        'version': '1.0.0'
                    }
                )
                logger.info("mDNS service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize mDNS: {e}")
                self.enable_mdns = False
        
        # NAT traversal configuration
        self.nat_type = self.config.get('nat_type', 'unknown')
        self.stun_servers = self.config.get('stun_servers', [
            ('stun.l.google.com', 19302),
            ('stun1.l.google.com', 19302),
            ('stun2.l.google.com', 19302)
        ])
        
        # Initialize discovery services
        self.dht = None
        self.mdns = None
        
        if self.enable_dht:
            try:
                self.dht = DHTManager(
                    node_id=self.peer_id,
                    port=dht_config.get('port', 0),
                    bootstrap_nodes=self.dht_bootstrap_nodes
                )
                logger.info("DHT service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize DHT: {e}")
                self.enable_dht = False
        
        if self.enable_mdns:
            try:
                self.mdns = MDNSManager(
                    service_name=self.mdns_service_name,
                    service_port=self.port,
                    properties={
                        'peer_id': self.peer_id,
                        'public_key': self.public_key,
                        'version': '1.0.0'
                    }
                )
                logger.info("mDNS service initialized")
            except Exception as e:
                logger.error(f"Failed to initialize mDNS: {e}")
                self.enable_mdns = False
    
    async def start(self) -> bool:
        """Start the P2P manager and all discovery services."""
        if self.running:
            return True
        
        try:
            # Start Tor if enabled
            if self.tor_enabled and self.tor_manager:
                if not self.tor_manager.start():
                    logger.error("Failed to start Tor service")
                    return False
                logger.info(f"Tor service started. Onion address: {self.tor_manager.onion_address}")
            
            # Start the TCP server
            self.server = await asyncio.start_server(
                self._handle_connection,
                '0.0.0.0',
                self.port
            )
            
            # Update port if it was auto-assigned
            self.port = self.server.sockets[0].getsockname()[1]
            logger.info(f"P2P server started on port {self.port}")
            
            # Start discovery services
            await self._start_discovery_services()
            
            # Start NAT traversal if enabled
            if self.nat_traversal:
                public_addr = self.nat_traversal.get_public_address()
                if public_addr:
                    logger.info(f"Public address: {public_addr[0]}:{public_addr[1]}")
                else:
                    logger.warning("Could not determine public address")
            
            # Start background tasks
            asyncio.create_task(self._maintain_connections())
            
            # Publish our peer info
            await self._publish_peer_info()
            
            self.running = True
            logger.info(f"P2P manager started successfully (ID: {self.peer_id})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start P2P manager: {e}")
            await self.stop()
            return False
    
    async def _start_discovery_services(self) -> None:
        """Start all enabled discovery services."""
        # Start DHT
        if self.enable_dht and self.dht:
            try:
                await self.dht.start()
                # Publish our peer info to the DHT
                await self._publish_peer_info()
                logger.info("DHT service started")
            except Exception as e:
                logger.error(f"Failed to start DHT service: {e}")
                self.enable_dht = False
        
        # Start mDNS
        if self.enable_mdns and self.mdns:
            try:
                self.mdns.start(
                    on_peer_added=self._on_mdns_peer_added,
                    on_peer_removed=self._on_mdns_peer_removed
                )
                logger.info("mDNS service started")
            except Exception as e:
                logger.error(f"Failed to start mDNS service: {e}")
                self.enable_mdns = False
    
    async def stop(self) -> None:
        """Stop the P2P manager and all services."""
        if not self.running:
            return
        
        logger.info("Stopping P2P manager...")
        self.running = False
        
        # Stop discovery services
        if self.dht:
            try:
                await self.dht.stop()
            except Exception as e:
                logger.error(f"Error stopping DHT service: {e}")
        
        if self.mdns:
            try:
                self.mdns.stop()
            except Exception as e:
                logger.error(f"Error stopping mDNS service: {e}")
        
        # Close all connections
        for peer_id, conn in list(self.connections.items()):
            try:
                conn.close()
                await conn.wait_closed()
            except Exception as e:
                logger.error(f"Error closing connection to {peer_id}: {e}")
        
        # Close the server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("P2P manager stopped")
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connections."""
        try:
            # Get peer address
            peer_addr = writer.get_extra_info('peername')
            logger.info(f"New connection from {peer_addr}")
            
            # Read the handshake message
            data = await reader.read(4096)
            if not data:
                logger.warning("Empty handshake received, closing connection")
                writer.close()
                return
            
            try:
                handshake = json.loads(data.decode('utf-8'))
                peer_id = handshake.get('peer_id')
                
                if not peer_id:
                    logger.warning("No peer ID in handshake")
                    writer.close()
                    return
                
                # Update peer info
                peer = self.peers.get(peer_id)
                if not peer:
                    peer = PeerInfo(
                        peer_id=peer_id,
                        address=peer_addr[0],
                        port=peer_addr[1],
                        public_key=handshake.get('public_key', ''),
                        metadata=handshake.get('metadata', {})
                    )
                    self.peers[peer_id] = peer
                
                # Update connection status
                peer.is_connected = True
                peer.last_seen = time.time()
                
                # Store the connection
                self.connections[peer_id] = {
                    'reader': reader,
                    'writer': writer,
                    'last_active': time.time()
                }
                
                # Send our handshake
                await self._send_handshake(writer)
                
                # Start listening for messages
                await self._handle_messages(reader, writer, peer_id)
                
            except json.JSONDecodeError as e:
                logger.error(f"Invalid handshake: {e}")
                writer.close()
            
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
    
    async def _handle_messages(self, reader: asyncio.StreamReader, 
                             writer: asyncio.StreamWriter, peer_id: str) -> None:
        """Handle incoming messages from a peer."""
        try:
            while self.running:
                # Read message length (first 4 bytes)
                length_bytes = await reader.readexactly(4)
                if not length_bytes:
                    break
                
                # Convert length to int
                length = int.from_bytes(length_bytes, byteorder='big')
                
                # Read the message
                data = await reader.readexactly(length)
                
                # Parse the message
                try:
                    message = json.loads(data.decode('utf-8'))
                    message_type = message.get('type')
                    
                    # Update last active time
                    if peer_id in self.connections:
                        self.connections[peer_id]['last_active'] = time.time()
                    
                    # Handle the message
                    await self._handle_message(peer_id, message_type, message)
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid message format: {e}")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
        
        except (ConnectionResetError, asyncio.IncompleteReadError):
            logger.info(f"Connection closed by peer: {peer_id}")
        except Exception as e:
            logger.error(f"Error in message handler for {peer_id}: {e}")
        finally:
            # Clean up
            if peer_id in self.connections:
                del self.connections[peer_id]
            
            if peer_id in self.peers:
                self.peers[peer_id].is_connected = False
            
            writer.close()
            try:
                await writer.wait_closed()
            except:
                pass
    
    async def _handle_message(self, peer_id: str, message_type: str, message: Dict[str, Any]) -> None:
        """Handle an incoming message."""
        # Update last seen time
        if peer_id in self.peers:
            self.peers[peer_id].last_seen = time.time()
        
        # Call the appropriate handler if one is registered
        handler = self.message_handlers.get(message_type)
        if handler:
            try:
                await handler(peer_id, message)
            except Exception as e:
                logger.error(f"Error in message handler for type '{message_type}': {e}")
    
    async def _send_handshake(self, writer: asyncio.StreamWriter) -> None:
        """Send a handshake message to a peer."""
        handshake = {
            'type': 'handshake',
            'peer_id': self.peer_id,
            'public_key': self.public_key,
            'version': '1.0.0',
            'timestamp': time.time(),
            'metadata': {
                'capabilities': ['dht', 'mdns', 'nat_traversal']
            }
        }
        await self._send_message(writer, handshake)
    
    async def _send_message(self, writer: asyncio.StreamWriter, message: Dict[str, Any]) -> None:
        """Send a message to a peer."""
        try:
            # Convert message to JSON
            data = json.dumps(message).encode('utf-8')
            
            # Send message length (4 bytes)
            writer.write(len(data).to_bytes(4, byteorder='big'))
            
            # Send the message
            writer.write(data)
            await writer.drain()
            
        except Exception as e:
            logger.error(f"Error sending message: {e}")
            raise
    
    async def _publish_peer_info(self) -> None:
        """Publish our peer information to the DHT and other discovery services."""
        # Publish to DHT if enabled
        if self.enable_dht and self.dht:
            try:
                # Get our public address
                public_ip = '127.0.0.1'  # Default to localhost
                if self.nat_traversal and self.nat_traversal.public_ip:
                    public_ip = self.nat_traversal.public_ip
                
                # Create peer info for DHT
                peer_info = DHT_PeerInfo(
                    peer_id=self.peer_id,
                    address=public_ip,
                    port=self.port,
                    public_key=self.get_public_key_pem().decode('utf-8'),
                    metadata={
                        'version': '1.0.0',
                        'capabilities': [
                            'dht',
                            'mdns',
                            'nat_traversal' if self.nat_traversal else '',
                            'tor' if self.tor_enabled else ''
                        ],
                        'tor_address': self.tor_manager.onion_address if self.tor_enabled and self.tor_manager else None,
                        'timestamp': time.time()
                    }
                )
                
                # Publish to DHT
                await self.dht.publish_peer_info(peer_info)
                logger.debug("Published peer info to DHT")
                
            except Exception as e:
                logger.error(f"Failed to publish peer info to DHT: {e}")
        
        # Publish to mDNS if enabled
        if self.enable_mdns and self.mdns:
            try:
                # mDNS updates are handled automatically by the MDNSManager
                pass
            except Exception as e:
                logger.error(f"Failed to publish peer info to mDNS: {e}")
        
        # If we have a web interface, update it
        if hasattr(self, 'socketio'):
            try:
                self.socketio.emit('peer_update', {
                    'peer_id': self.peer_id,
                    'address': f"{self._get_public_address()}:{self.port}",
                    'is_self': True,
                    'is_connected': True,
                    'is_tor': self.tor_enabled,
                    'public_key': self.get_public_key_pem().decode('utf-8')
                })
            except Exception as e:
                logger.error(f"Failed to update web interface: {e}"
            
        except Exception as e:
            logger.error(f"Failed to publish peer info to DHT: {e}")
    
    def _on_mdns_peer_added(self, name: str, peer_info: MDNS_PeerInfo) -> None:
        """Handle a new peer discovered via mDNS."""
        try:
            peer_id = peer_info.properties.get('peer_id')
            if not peer_id or peer_id == self.peer_id:
                return
            
            # Check if we already know this peer
            if peer_id in self.peers:
                peer = self.peers[peer_id]
                peer.last_seen = time.time()
            else:
                # Create a new peer
                peer = PeerInfo(
                    peer_id=peer_id,
                    address=peer_info.address,
                    port=peer_info.port,
                    public_key=peer_info.properties.get('public_key', ''),
                    metadata={
                        'discovery_method': 'mdns',
                        'hostname': name.split('.')[0],
                        **peer_info.properties
                    }
                )
                self.peers[peer_id] = peer
                logger.info(f"Discovered new peer via mDNS: {peer_id} at {peer_info.address}:{peer_info.port}")
            
            # Try to connect if we're not already connected
            if not peer.is_connected and len(self.connections) < self.max_peers:
                asyncio.create_task(self.connect_to_peer(peer_id))
                
        except Exception as e:
            logger.error(f"Error handling mDNS peer added event: {e}")
    
    def _on_mdns_peer_removed(self, name: str) -> None:
        """Handle a peer that is no longer available via mDNS."""
        # We don't remove the peer immediately as it might still be available via DHT
        # Just log the event for now
        logger.info(f"Peer no longer available via mDNS: {name}")
    
    async def _maintain_connections(self) -> None:
        """Maintain connections to peers."""
        while self.running:
            try:
                # Try to maintain a minimum number of connections
                if len(self.connections) < min(5, self.max_peers):
                    await self._find_and_connect_to_peers()
                
                # Clean up dead connections
                await self._cleanup_dead_connections()
                
                # Re-publish our peer info periodically
                if self.enable_dht and self.dht and time.time() % 300 < 1:  # Every 5 minutes
                    await self._publish_peer_info()
                
                # Sleep for a while
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.error(f"Error in connection maintenance: {e}")
                await asyncio.sleep(5)
    
    async def _find_and_connect_to_peers(self) -> None:
        """Find and connect to new peers."""
        # Get a list of peers we can try to connect to
        potential_peers = []
        
        # Add peers from DHT
        if self.enable_dht and self.dht:
            try:
                dht_peers = await self.dht.find_peers(limit=10)
                for peer in dht_peers:
                    if peer.peer_id != self.peer_id and peer.peer_id not in self.connections:
                        potential_peers.append((peer, 'dht'))
            except Exception as e:
                logger.error(f"Error getting peers from DHT: {e}")
        
        # Add peers from mDNS
        if self.enable_mdns and self.mdns:
            try:
                for peer in self.mdns.get_peers():
                    peer_id = peer.properties.get('peer_id')
                    if peer_id and peer_id != self.peer_id and peer_id not in self.connections:
                        potential_peers.append((peer, 'mdns'))
            except Exception as e:
                logger.error(f"Error getting peers from mDNS: {e}")
        
        # Try to connect to potential peers
        for peer, source in potential_peers:
            if len(self.connections) >= self.max_peers:
                break
                
            peer_id = getattr(peer, 'peer_id', peer.properties.get('peer_id'))
            if not peer_id or peer_id in self.connections:
                continue
                
            # Rate limiting
            if peer_id in self.peers:
                peer_info = self.peers[peer_id]
                if time.time() - peer_info.last_attempt < 60:  # 1 minute cooldown
                    continue
                
                if peer_info.connection_attempts > 5:  # Max attempts
                    continue
            
            # Try to connect
            await self.connect_to_peer(peer_id)
    
    async def connect_to_peer(self, peer_id: str) -> bool:
        """Connect to a specific peer."""
        if peer_id == self.peer_id:
            return False
            
        if peer_id in self.connections:
            return True
            
        # Get or create peer info
        if peer_id not in self.peers:
            self.peers[peer_id] = PeerInfo(
                peer_id=peer_id,
                address='',  # We don't know the address yet
                port=0
            )
            
        peer = self.peers[peer_id]
        
        # Check if we have enough information to connect
        if not peer.address or not peer.port:
            logger.warning(f"Insufficient information to connect to peer {peer_id}")
            return False
            
        # Rate limiting
        current_time = time.time()
        if current_time - peer.last_attempt < 60:  # 1 minute cooldown
            return False
            
        if peer.connection_attempts > 5:  # Max attempts
            return False
            
        # Update attempt info
        peer.last_attempt = current_time
        peer.connection_attempts += 1
        
        try:
            logger.info(f"Connecting to peer {peer_id} at {peer.address}:{peer.port}...")
            
            # Try to establish a connection
            reader, writer = await asyncio.open_connection(peer.address, peer.port)
            
            # Send handshake
            await self._send_handshake(writer)
            
            # Read handshake response
            data = await reader.read(4096)
            if not data:
                raise Exception("Empty handshake response")
                
            handshake = json.loads(data.decode('utf-8'))
            if handshake.get('type') != 'handshake':
                raise Exception("Invalid handshake response")
                
            # Verify peer ID
            if handshake.get('peer_id') != peer_id:
                raise Exception(f"Unexpected peer ID: {handshake.get('peer_id')}")
                
            # Update peer info
            peer.public_key = handshake.get('public_key', peer.public_key)
            peer.metadata.update(handshake.get('metadata', {}))
            peer.is_connected = True
            peer.last_seen = time.time()
            
            # Store the connection
            self.connections[peer_id] = {
                'reader': reader,
                'writer': writer,
                'last_active': time.time()
            }
            
            # Start message handler
            asyncio.create_task(self._handle_messages(reader, writer, peer_id))
            
            logger.info(f"Successfully connected to peer {peer_id}")
            return True
            
        except Exception as e:
            logger.warning(f"Failed to connect to peer {peer_id}: {e}")
            if peer_id in self.connections:
                del self.connections[peer_id]
            return False
    
    async def _cleanup_dead_connections(self) -> None:
        """Clean up dead connections."""
        current_time = time.time()
        dead_peers = []
        
        for peer_id, conn in list(self.connections.items()):
            # Check if connection is dead
            if current_time - conn['last_active'] > 300:  # 5 minutes of inactivity
                dead_peers.append(peer_id)
            
            # Check if the connection is still alive
            elif current_time - conn['last_active'] > 60:  # 1 minute since last message
                try:
                    # Send a ping
                    await self._send_message(conn['writer'], {'type': 'ping', 'timestamp': time.time()})
                except:
                    dead_peers.append(peer_id)
        
        # Remove dead connections
        for peer_id in dead_peers:
            if peer_id in self.connections:
                try:
                    self.connections[peer_id]['writer'].close()
                    await self.connections[peer_id]['writer'].wait_closed()
                except:
                    pass
                
                del self.connections[peer_id]
                
                if peer_id in self.peers:
                    self.peers[peer_id].is_connected = False
                
                logger.info(f"Removed dead connection to peer {peer_id}")
    
    def _get_public_address(self) -> str:
        """Get the public IP address of this node."""
        # This is a simplified implementation
        # In a real application, you would use STUN or a similar protocol
        try:
            # Try to get the local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))  # Google DNS
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return '127.0.0.1'
    
    # Public API methods
    
    async def send_message(self, peer_id: str, message: Dict[str, Any]) -> bool:
        """Send a message to a peer."""
        if peer_id not in self.connections:
            logger.warning(f"No active connection to peer {peer_id}")
            return False
            
        try:
            conn = self.connections[peer_id]
            await self._send_message(conn['writer'], message)
            return True
        except Exception as e:
            logger.error(f"Failed to send message to {peer_id}: {e}")
            
            # Remove the connection
            if peer_id in self.connections:
                del self.connections[peer_id]
                
            if peer_id in self.peers:
                self.peers[peer_id].is_connected = False
                
            return False
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """Register a handler for a specific message type."""
        self.message_handlers[message_type] = handler
    
    def get_connected_peers(self) -> List[Dict[str, Any]]:
        """Get a list of connected peers."""
        return [
            {
                'peer_id': peer_id,
                'address': conn['writer'].get_extra_info('peername')[0],
                'port': conn['writer'].get_extra_info('peername')[1],
                'last_active': conn['last_active']
            }
            for peer_id, conn in self.connections.items()
        ]
    
    def get_known_peers(self) -> List[Dict[str, Any]]:
        """Get a list of all known peers."""
        return [peer.to_dict() for peer in self.peers.values()]

# Example usage
if __name__ == "__main__":
    import logging
    import asyncio
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Configuration
    config = {
        'peer_id': 'test-peer-1',
        'port': 0,  # Random port
        'max_peers': 10,
        'public_key': 'test-public-key-123',
        'dht': {
            'enabled': True,
            'bootstrap_nodes': [('127.0.0.1', 8468)]  # Local DHT bootstrap node
        },
        'mdns': {
            'enabled': True
        }
    }
    
    # Create and start the P2P manager
    async def run():
        p2p = EnhancedP2PManager(config)
        
        # Register a message handler
        def handle_chat_message(peer_id, message):
            print(f"\n[Chat from {peer_id}]: {message.get('text', '')}")
            
        p2p.register_message_handler('chat', handle_chat_message)
        
        # Start the P2P manager
        if not await p2p.start():
            print("Failed to start P2P manager")
            return
        
        print(f"P2P manager started with ID: {p2p.peer_id}")
        print("Type 'peers' to list connected peers")
        print("Type 'connect <peer_id>' to connect to a peer")
        print("Type 'send <peer_id> <message>' to send a message")
        print("Type 'exit' to quit\n")
        
        # Simple command-line interface
        while True:
            try:
                cmd = input("> ").strip().split()
                if not cmd:
                    continue
                    
                if cmd[0] == 'exit':
                    break
                    
                elif cmd[0] == 'peers':
                    print("\nConnected peers:")
                    for peer in p2p.get_connected_peers():
                        print(f"- {peer['peer_id']} ({peer['address']}:{peer['port']})")
                    
                    print("\nKnown peers:")
                    for peer in p2p.get_known_peers():
                        status = "(connected)" if peer['is_connected'] else "(disconnected)"
                        print(f"- {peer['peer_id']} {status}")
                    print()
                    
                elif cmd[0] == 'connect' and len(cmd) > 1:
                    peer_id = cmd[1]
                    print(f"Connecting to {peer_id}...")
                    await p2p.connect_to_peer(peer_id)
                    
                elif cmd[0] == 'send' and len(cmd) > 2:
                    peer_id = cmd[1]
                    message = ' '.join(cmd[2:])
                    
                    if await p2p.send_message(peer_id, {
                        'type': 'chat',
                        'text': message,
                        'timestamp': time.time()
                    }):
                        print(f"Message sent to {peer_id}")
                    else:
                        print(f"Failed to send message to {peer_id}")
                        
                else:
                    print("Unknown command")
                    
            except (KeyboardInterrupt, EOFError):
                break
            except Exception as e:
                print(f"Error: {e}")
        
        # Stop the P2P manager
        await p2p.stop()
    
    # Run the example
    asyncio.run(run())
