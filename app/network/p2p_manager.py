"""
P2P Manager

Handles secure peer-to-peer networking functionality with integrated encryption gates.
"""
import asyncio
import base64
import json
import logging
import time
from typing import Dict, List, Optional, Any, Callable, Set, Tuple
from dataclasses import dataclass, field
from uuid import uuid4
from datetime import datetime, timedelta

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from ..security.security_manager import SecurityManager, SecurityEvent, SecurityEventType, SecurityLevel
from ..security.gate_system import GateSystem, GateType
from ..core.crypto import CryptoEngine

logger = logging.getLogger(__name__)

@dataclass
class PeerInfo:
    """Information about a connected peer with security context and monitoring."""
    peer_id: str
    address: str
    port: int
    public_key: Optional[bytes] = None
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    session_key: Optional[bytes] = None
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    gate_sequence: List[int] = field(default_factory=list)
    handshake_complete: bool = False
    connection: Any = None  # Will hold the StreamWriter
    
    # Connection quality metrics
    message_count: int = 0
    error_count: int = 0
    avg_latency: float = 0.0
    last_latency: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    # Rate limiting
    last_message_time: float = field(default_factory=time.time)
    message_rate: float = 0.0  # messages per second
    
    # Connection state
    is_trusted: bool = False
    is_blacklisted: bool = False
    blacklist_reason: Optional[str] = None
    blacklist_until: float = 0.0
    
    def update_latency(self, latency: float) -> None:
        """Update connection latency metrics with exponential moving average."""
        self.last_latency = latency
        alpha = 0.2  # Smoothing factor
        self.avg_latency = (alpha * latency) + ((1 - alpha) * self.avg_latency)
    
    def update_message_rate(self) -> None:
        """Update message rate calculation."""
        now = time.time()
        time_diff = now - self.last_message_time
        self.last_message_time = now
        
        if time_diff > 0:
            # Simple exponential moving average for message rate
            current_rate = 1.0 / time_diff
            alpha = 0.3  # Smoothing factor
            self.message_rate = (alpha * current_rate) + ((1 - alpha) * self.message_rate)
    
    def record_error(self) -> None:
        """Record an error for this peer."""
        self.error_count += 1
        # Consider blacklisting if too many errors
        if self.error_count > 10 and not self.is_blacklisted:
            self.is_blacklisted = True
            self.blacklist_reason = "Excessive errors"
            self.blacklist_until = time.time() + 3600  # Blacklist for 1 hour

class P2PManager:
    """
    Manages secure peer-to-peer networking with integrated encryption gates.
    
    Features:
    - Secure peer discovery and authentication
    - Connection quality monitoring
    - Rate limiting and DoS protection
    - Automatic reconnection and failover
    - Message encryption and signing
    - Peer reputation management
    """
    
    def __init__(self, 
                 security_manager: SecurityManager,
                 gate_system: GateSystem,
                 config: Optional[Dict[str, Any]] = None):
        """
        Initialize the P2P manager with security components.
        
        Args:
            security_manager: Instance of SecurityManager for security operations
            gate_system: Instance of GateSystem for encryption gates
            config: Configuration dictionary with optional settings:
                - peer_id: Unique identifier for this node
                - port: Port to listen on (0 for random)
                - max_peers: Maximum number of concurrent peers
                - max_message_size: Maximum message size in bytes (default: 10MB)
                - handshake_timeout: Handshake timeout in seconds (default: 10s)
                - ping_interval: Interval between pings in seconds (default: 30s)
                - peer_discovery_interval: Interval between peer discovery attempts (default: 60s)
        """
        self.config = {
            'peer_id': f"node_{uuid4().hex[:8]}",
            'port': 8765,
            'max_peers': 50,
            'max_message_size': 10 * 1024 * 1024,  # 10MB
            'handshake_timeout': 10.0,  # seconds
            'ping_interval': 30.0,  # seconds
            'peer_discovery_interval': 60.0,  # seconds
            'max_message_rate': 100,  # messages per second
            'blacklist_duration': 3600,  # seconds
            **(config or {})
        }
        
        self.security_manager = security_manager
        self.gate_system = gate_system
        
        # Node identity and state
        self.peer_id = self.config['peer_id']
        self.port = self.config['port']
        self.max_peers = self.config['max_peers']
        self.peers: Dict[str, PeerInfo] = {}
        self.peer_lock = asyncio.Lock()  # For thread-safe peer operations
        self.message_handlers: Dict[str, Callable] = {}
        self.running = False
        self.server = None
        
        # Generate ECDSA key pair for this node
        self.private_key = ec.generate_private_key(
            ec.SECP384R1(), default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Connection management
        self.connection_attempts: Dict[str, float] = {}
        self.blacklist: Dict[str, Tuple[float, str]] = {}  # peer_id -> (unblock_time, reason)
        
        # Initialize asyncio event loop
        self.loop = asyncio.get_event_loop()
        
        # Task tracking
        self.tasks: Set[asyncio.Task] = set()
        
        # Register default message handlers
        self._register_default_handlers()
        
        # Initialize metrics
        self.metrics = {
            'messages_sent': 0,
            'messages_received': 0,
            'connection_errors': 0,
            'security_events': 0,
            'start_time': time.time()
        }
        
        logger.info(f"Secure P2P Manager initialized with ID: {self.peer_id}")
        
    def _create_task(self, coro, name: Optional[str] = None) -> asyncio.Task:
        """Create a task and add it to the tasks set."""
        task = asyncio.create_task(coro, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task
        
    def _get_timestamp(self) -> float:
        """Get the current timestamp in seconds since epoch.
        
        Returns:
            float: Current timestamp in seconds since epoch
        """
        return time.time()
    
    def log_security_event(self, event_type: str, peer_id: str, details: Dict[str, Any]) -> None:
        """Log a security event.
        
        Args:
            event_type: Type of security event
            peer_id: ID of the peer involved
            details: Additional details about the event
        """
        event = {
            'timestamp': time.time(),
            'event_type': event_type,
            'peer_id': peer_id,
            'details': details
        }
        
        self.security_events.append(event)
        
        # Keep only the most recent events
        if len(self.security_events) > self.max_security_events:
            self.security_events = self.security_events[-self.max_security_events:]
        
        # Log the event
        self.logger.warning(f"Security event: {event_type} from {peer_id}: {details}")
    
    async def _cleanup_expired_entries(self) -> None:
        """Clean up expired blacklist entries and session keys."""
        current_time = time.time()
        
        # Clean up expired blacklist entries
        expired_peers = [
            peer_id for peer_id, (expiry, _) in self.blacklist.items()
            if expiry < current_time
        ]
        
        for peer_id in expired_peers:
            del self.blacklist[peer_id]
            self.logger.info(f"Removed {peer_id} from blacklist (expired)")
        
        # Clean up old session keys (older than 24 hours)
        expired_sessions = [
            peer_id for peer_id, key_info in self.session_keys.items()
            if key_info.get('created_at', 0) < current_time - 86400  # 24 hours
        ]
        
        for peer_id in expired_sessions:
            del self.session_keys[peer_id]
            self.logger.debug(f"Removed expired session key for {peer_id}")
        
        # Clean up old security events (older than 7 days)
        cutoff_time = current_time - (7 * 86400)
        self.security_events = [
            event for event in self.security_events
            if event['timestamp'] > cutoff_time
        ]
    
    async def _check_security_status(self) -> None:
        """Check the security status and take action if needed."""
        # Check for peers with too many errors
        current_time = time.time()
        for peer_id, peer_info in list(self.peers.items()):
            if peer_info.error_count > 10 and peer_info.last_error and (current_time - peer_info.last_error) < 3600:
                # Too many recent errors, blacklist the peer
                await self._blacklist_peer(
                    peer_id,
                    reason=f"Too many errors: {peer_info.error_count} in the last hour"
                )
        
        # Check for suspicious activity
        # (This is a placeholder for more sophisticated anomaly detection)
        
        # Log the security status
        self.logger.info(
            f"Security status: {len(self.blacklist)} peers blacklisted, "
            f"{len(self.session_keys)} active sessions"
        )
        
    def _get_signing_payload(self, message: Dict[str, Any]) -> bytes:
        """Create a consistent payload for message signing.
        
        Args:
            message: Message dictionary to create payload from
            
        Returns:
            bytes: Payload for signing
        """
        # Create a copy to avoid modifying the original
        payload = message.copy()
        # Remove signature if present
        payload.pop('signature', None)
        # Convert to JSON string and encode to bytes
        return json.dumps(payload, sort_keys=True).encode('utf-8')
        
    def _sign_message(self, message: Dict[str, Any]) -> str:
        """Sign a message using the node's private key.
        
        Args:
            message: Message to sign
            
        Returns:
            str: Base64-encoded signature
            
        Raises:
            ValueError: If signing fails
        """
        try:
            # Get the payload to sign
            payload = self._get_signing_payload(message)
            
            # Sign the payload
            signature = self.private_key.sign(
                payload,
                ec.ECDSA(hashes.SHA256())
            )
            
            # Return base64 encoded signature
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error signing message: {e}", exc_info=True)
            raise ValueError(f"Failed to sign message: {e}")
            
    def _verify_signature(self, public_key_pem: str, payload: bytes, signature_b64: str) -> bool:
        """Verify a message signature.
        
        Args:
            public_key_pem: Sender's public key in PEM format
            payload: Original message payload that was signed
            signature_b64: Base64-encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Decode the public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Decode the signature
            signature = base64.b64decode(signature_b64)
            
            # Verify the signature
            public_key.verify(
                signature,
                payload,
                ec.ECDSA(hashes.SHA256())
            )
            return True
            
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False
    
    def _register_default_handlers(self) -> None:
        """Register default message handlers."""
        handlers = {
            "handshake": self._handle_handshake,
            "handshake_ack": self._handle_handshake_response,
            "ping": self._handle_ping,
            "pong": self._handle_pong,
            "gate_sequence": self._handle_gate_sequence,
            "get_peers": self._handle_get_peers,
            "peers_list": self._handle_peers_list,
            "error": self._handle_error
        }
        
        for msg_type, handler in handlers.items():
            self.register_message_handler(msg_type, handler)
    
    async def _check_peer_blacklist(self, peer_id: str, address: str) -> bool:
        """Check if a peer is blacklisted and update blacklist if expired.
        
        Args:
            peer_id: The peer ID to check
            address: The peer's IP address
            
        Returns:
            bool: True if peer is blacklisted, False otherwise
        """
        now = time.time()
        
        # Check peer ID blacklist
        if peer_id in self.blacklist:
            unblock_time, reason = self.blacklist[peer_id]
            if now < unblock_time:
                logger.warning(f"Rejecting blacklisted peer {peer_id}: {reason}")
                return True
            # Clean up expired blacklist entry
            del self.blacklist[peer_id]
        
        # Check IP-based blacklist (prevent DoS)
        if address in self.blacklist:
            unblock_time, reason = self.blacklist[address]
            if now < unblock_time:
                logger.warning(f"Rejecting blacklisted IP {address}: {reason}")
                return True
            # Clean up expired blacklist entry
            del self.blacklist[address]
            
        return False
    
    async def _enforce_rate_limit(self, peer_info: PeerInfo) -> bool:
        """Enforce rate limiting for a peer.
        
        Args:
            peer_info: Information about the peer
            
        Returns:
            bool: True if rate limit is exceeded, False otherwise
        """
        now = time.time()
        
        # Update message rate
        peer_info.update_message_rate()
        
        # Check message rate limit
        if peer_info.message_rate > self.config['max_message_rate']:
            logger.warning(f"Rate limit exceeded for {peer_info.peer_id}: {peer_info.message_rate:.1f} msgs/sec")
            # Blacklist the peer temporarily
            self.blacklist[peer_info.peer_id] = (
                now + self.config['blacklist_duration'],
                f"Rate limit exceeded ({peer_info.message_rate:.1f} msgs/sec)"
            )
            return True
            
        return False
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection from a peer.
        
        Args:
            reader: Stream reader for incoming data
            writer: Stream writer for outgoing data
        """
        peer_addr = writer.get_extra_info('peername')
        peer_id = f"{peer_addr[0]}:{peer_addr[1]}"
        peer_info = None
        
        try:
            # Check if peer is blacklisted
            if await self._check_peer_blacklist(peer_id, peer_addr[0]):
                writer.close()
                await writer.wait_closed()
                return
                
            # Read handshake with timeout
            try:
                data = await asyncio.wait_for(
                    reader.readuntil(b'\n'),
                    timeout=self.config['handshake_timeout']
                )
                handshake = json.loads(data.decode().strip())
            except (asyncio.TimeoutError, json.JSONDecodeError) as e:
                logger.warning(f"Invalid handshake from {peer_addr}: {e}")
                writer.close()
                await writer.wait_closed()
                return
                
            # Verify handshake
            if handshake.get('type') != 'handshake':
                logger.warning(f"Invalid handshake type from {peer_addr}")
                writer.close()
                await writer.wait_closed()
                return
                
            # Create peer info
            peer_id = handshake.get('peer_id', peer_id)
            peer_info = PeerInfo(
                peer_id=peer_id,
                address=peer_addr[0],
                port=handshake.get('port', peer_addr[1]),
                last_seen=time.time()
            )
            
            # Check if we're already connected to this peer
            async with self.peer_lock:
                if peer_id in self.peers or len(self.peers) >= self.max_peers:
                    logger.warning(f"Rejecting connection from {peer_id}: {'Peer already connected' if peer_id in self.peers else 'Max peers reached'}")
                    writer.close()
                    await writer.wait_closed()
                    return
                
                # Add peer to our list
                self.peers[peer_id] = peer_info
            
            # Send handshake ack
            ack = {
                'type': 'handshake_ack',
                'peer_id': self.peer_id,
                'public_key': self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                'timestamp': time.time()
            }
            
            # Sign the ack
            ack['signature'] = self._sign_message(ack)
            
            # Send ack
            writer.write(json.dumps(ack).encode() + b'\n')
            await writer.drain()
            
            logger.info(f"Established connection with peer {peer_id} at {peer_addr[0]}:{peer_addr[1]}")
            
            # Start handling messages from this peer
            await self._handle_peer_messages(reader, writer, peer_info)
            
        except Exception as e:
            logger.error(f"Error handling connection from {peer_addr}: {e}", exc_info=True)
            
            # Update error count if we have peer_info
            if peer_info:
                peer_info.record_error()
                
            # Blacklist peer if too many errors
            if peer_info and peer_info.error_count > 5:
                self.blacklist[peer_id] = (
                    time.time() + self.config['blacklist_duration'],
                    f"Too many errors: {peer_info.error_count}"
                )
                
        finally:
            # Clean up
            if peer_id and peer_id in self.peers:
                async with self.peer_lock:
                    if peer_id in self.peers:
                        del self.peers[peer_id]
                        
            if not writer.is_closing():
                writer.close()
                await writer.wait_closed()
    
    async def _handle_peer_messages(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, peer_info: PeerInfo) -> None:
        """Handle messages from a connected peer with comprehensive error handling.
        
        Args:
            reader: Stream reader for incoming data
            writer: Stream writer for outgoing data
            peer_info: Information about the peer
            
        This method handles the main message loop for a connected peer, including:
        - Reading and parsing incoming messages
        - Rate limiting
        - Message validation
        - Error handling and recovery
        """
        peer_id = peer_info.peer_id
        peer_addr = f"{peer_info.address}:{peer_info.port}"
        logger.info(f"Starting message handler for peer {peer_id} ({peer_addr})")
        
        try:
            while self.running and not reader.at_eof():
                try:
                    # Read message with timeout
                    try:
                        data = await asyncio.wait_for(
                            reader.readuntil(b'\n'),
                            timeout=300.0  # 5 minute timeout for messages
                        )
                        logger.debug(f"Received {len(data)} bytes from {peer_id}")
                    except asyncio.TimeoutError:
                        logger.warning(f"Connection timeout for peer {peer_id}")
                        break
                    except asyncio.IncompleteReadError as e:
                        if not e.partial:  # Connection closed cleanly
                            logger.info(f"Peer {peer_id} closed the connection")
                        else:
                            logger.warning(f"Incomplete read from peer {peer_id}: {e}")
                        break
                    except ConnectionResetError:
                        logger.warning(f"Connection reset by peer {peer_id}")
                        break
                        
                    # Update peer metrics
                    peer_info.bytes_received += len(data)
                    peer_info.last_seen = time.time()
                    
                    # Check rate limiting
                    if await self._enforce_rate_limit(peer_info):
                        logger.warning(f"Rate limit exceeded for {peer_id}, disconnecting")
                        await self._send_error(peer_info, "rate_limit_exceeded", "Rate limit exceeded")
                        break
                    
                    # Process the message
                    await self._process_message(data, peer_info)
                    
                except Exception as e:
                    logger.error(f"Unexpected error processing message from {peer_id}: {e}", 
                               exc_info=True)
                    peer_info.record_error()
                    
                    # If we've had too many errors, disconnect
                    if peer_info.error_count > 10:
                        logger.warning(f"Too many errors from {peer_id}, disconnecting")
                        break
                    
        except Exception as e:
            logger.error(f"Fatal error in message handler for {peer_id}: {e}", 
                        exc_info=True)
        finally:
            # Clean up resources
            logger.info(f"Cleaning up connection to {peer_id}")
            await self._cleanup_peer_connection(peer_info, writer)
    
    async def _process_message(self, data: bytes, peer_info: PeerInfo) -> None:
        """Process a single message from a peer with decryption and validation.
        
        Args:
            data: Raw message data
            peer_info: Information about the peer
        """
        try:
            # Parse JSON message
            try:
                message = json.loads(data.decode().strip())
                self.logger.debug(f"Received message from {peer_info.peer_id}: {message.get('type')}")
            except json.JSONDecodeError as e:
                self.logger.warning(f"Invalid JSON from {peer_info.peer_id}: {e}")
                await self._send_error(peer_info, "invalid_json", "Invalid JSON format")
                return
                
            # Validate message structure
            if not isinstance(message, dict):
                self.logger.warning(f"Invalid message format from {peer_info.peer_id}")
                await self._send_error(peer_info, "invalid_format", "Message must be a JSON object")
                return
                
            # Handle encrypted messages
            if message.get('type') == 'encrypted_message':
                decrypted = await self._decrypt_message(peer_info.peer_id, message)
                if not decrypted:
                    self.logger.warning(f"Failed to decrypt message from {peer_info.peer_id}")
                    await self._send_error(peer_info, "decryption_error", "Failed to decrypt message")
                    return
                message = decrypted
                
            # Validate decrypted message structure
            if 'type' not in message:
                self.logger.warning(f"Missing message type from {peer_info.peer_id}")
                await self._send_error(peer_info, "invalid_format", "Missing message type")
                return
                
            # Check for duplicate message (optional, requires message_id)
            message_id = message.get('message_id')
            if message_id and message_id in peer_info.received_message_ids:
                self.logger.debug(f"Ignoring duplicate message {message_id} from {peer_info.peer_id}")
                return
                
            # Add to received messages (for deduplication)
            if message_id:
                peer_info.received_message_ids.add(message_id)
                # Keep only the most recent message IDs to prevent memory leaks
                if len(peer_info.received_message_ids) > 1000:
                    peer_info.received_message_ids = set(list(peer_info.received_message_ids)[-1000:])
            
            # Get message handler
            message_type = message['type']
            handler = self.message_handlers.get(message_type)
            
            if not handler:
                self.logger.debug(f"No handler for message type '{message_type}' from {peer_info.peer_id}")
                await self._send_error(
                    peer_info, 
                    "unknown_message_type", 
                    f"Unknown message type: {message_type}"
                )
                return
                
            # Process the message
            try:
                # Check if peer is allowed to send this message type
                if not await self.gate_system.check_message_allowed(peer_info, message_type):
                    self.logger.warning(f"Message type '{message_type}' not allowed from {peer_info.peer_id}")
                    await self._send_error(
                        peer_info,
                        "message_not_allowed",
                        f"Message type '{message_type}' is not allowed"
                    )
                    return
                
                # Update peer metrics
                peer_info.last_message_time = time.time()
                peer_info.message_count += 1
                
                # Call the handler
                await handler(message, peer_info)
                self.logger.debug(f"Successfully processed {message_type} from {peer_info.peer_id}")
                
                # Acknowledge successful processing if message has an ID
                if message_id and message_type != 'ack':
                    await self._send_ack(peer_info, message_id)
                    
            except Exception as e:
                self.logger.error(
                    f"Error processing {message_type} from {peer_info.peer_id}: {e}", 
                    exc_info=True
                )
                await self._send_error(
                    peer_info, 
                    "processing_error", 
                    f"Error processing {message_type}: {str(e)}"
                )
                
        except Exception as e:
            self.logger.error(f"Unexpected error in _process_message for {peer_info.peer_id}: {e}", 
                            exc_info=True)
            # Don't re-raise to prevent crashing the message handler
    
    async def _send_error(self, peer_info: PeerInfo, error_code: str, message: str) -> None:
        """Send an error message to a peer.
        
        Args:
            peer_info: Information about the peer
            error_code: Error code
            message: Error message
        """
        error_msg = {
            'type': 'error',
            'code': error_code,
            'message': message,
            'timestamp': time.time()
        }
        
        try:
            await self._send_message(peer_info, error_msg)
        except Exception as e:
            logger.error(f"Failed to send error message to {peer_info.peer_id}: {e}")
    
    async def _cleanup_peer_connection(self, peer_info: PeerInfo, writer: asyncio.StreamWriter) -> None:
        """Clean up resources for a peer connection.
        
        Args:
            peer_info: Information about the peer
            writer: Stream writer for the connection
        """
        peer_id = peer_info.peer_id
        
        try:
            # Close the writer if it's not already closed
            if writer and not writer.is_closing():
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), timeout=5.0)
                except (asyncio.TimeoutError, Exception) as e:
                    logger.warning(f"Timeout closing connection to {peer_id}: {e}")
            
            # Remove from connected peers
            async with self.peer_lock:
                if peer_id in self.peers:
                    del self.peers[peer_id]
                    logger.info(f"Removed peer {peer_id} from active connections")
                    
        except Exception as e:
            logger.error(f"Error cleaning up connection to {peer_id}: {e}", exc_info=True)
        finally:
            logger.info(f"Connection to {peer_id} closed")
    
    async def _broadcast_peers(self, exclude_peer_id: Optional[str] = None) -> None:
        """Broadcast peer list to all connected peers.
        
        Args:
{{ ... }}
            exclude_peer_id: Peer ID to exclude from broadcast
        """
        if not self.peers:
            return
            
        # Get list of connected peers
        peers_list = []
        for peer_id, peer in self.peers.items():
            if peer_id == exclude_peer_id or not peer.handshake_complete:
                continue
                
            peers_list.append({
                'peer_id': peer_id,
                'address': peer.address,
                'port': peer.port,
                'public_key': peer.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8') if peer.public_key else None
            })
        
        if not peers_list:
            return
            
        # Create and broadcast message
        message = {
            'type': 'peers_list',
            'peers': peers_list,
            'timestamp': time.time()
        }
        
        await self.broadcast_message(message, exclude={exclude_peer_id} if exclude_peer_id else None)
        
    async def _handle_handshake(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle incoming handshake message from a peer.
        
        Args:
            message: Handshake message from peer
            peer_info: Information about the peer
        """
        try:
            # Verify handshake contains required fields
            if not all(field in message for field in ['peer_id', 'public_key', 'timestamp']):
                logger.warning(f"Invalid handshake from {peer_info.peer_id}")
                return
                
            # Verify signature if present
            if 'signature' in message and peer_info.public_key:
                if not self._verify_signature(
                    message['public_key'],
                    self._get_signing_payload(message),
                    message['signature']
                ):
                    logger.warning(f"Invalid signature in handshake from {peer_info.peer_id}")
                    return
            
            # Update peer info
            peer_info.public_key = serialization.load_pem_public_key(
                message['public_key'].encode('utf-8'),
                backend=default_backend()
            )
            peer_info.handshake_complete = True
            
            logger.info(f"Completed handshake with peer {peer_info.peer_id}")
            
            # Log security event
            self.security_manager.log_event(
                SecurityEvent(
                    event_type=SecurityEventType.HANDSHAKE_COMPLETE,
                    peer_id=peer_info.peer_id,
                    details={"security_level": peer_info.security_level.value}
                )
            )
            
            # Send our gate sequence
            await self._send_gate_sequence(peer_info)
            
        except Exception as e:
            logger.error(f"Error processing handshake from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _send_gate_sequence(self, peer_info: PeerInfo) -> None:
        """Send our gate sequence to a peer.
        
        Args:
            peer_info: Information about the peer
        """
        try:
            message = {
                'type': 'gate_sequence',
                'sequence': self.gate_system.get_active_gate_ids(),
                'timestamp': time.time()
            }
            
            if peer_info.connection and not peer_info.connection.is_closing():
                await self._send_message(peer_info, message)
                
        except Exception as e:
            logger.error(f"Error sending gate sequence to {peer_info.peer_id}: {e}")
    
    async def _handle_handshake_response(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle handshake response from a peer.
        
        Args:
            message: Handshake response message
            peer_info: Information about the peer
        """
        try:
            # Verify the response contains required fields
            if not all(field in message for field in ['peer_id', 'public_key', 'timestamp']):
                logger.warning(f"Invalid handshake response from {peer_info.peer_id}")
                return
                
            # Verify signature if present
            if 'signature' in message:
                if not self._verify_signature(
                    message['public_key'],
                    self._get_signing_payload(message),
                    message['signature']
                ):
                    logger.warning(f"Invalid signature in handshake response from {peer_info.peer_id}")
                    return
            
            # Update peer info
            peer_info.public_key = serialization.load_pem_public_key(
                message['public_key'].encode('utf-8'),
                backend=default_backend()
            )
            peer_info.handshake_complete = True
            
            logger.info(f"Handshake completed with peer {peer_info.peer_id}")
            
            # Log security event
            self.security_manager.log_event(
                SecurityEvent(
                    event_type=SecurityEventType.HANDSHAKE_COMPLETE,
                    peer_id=peer_info.peer_id,
                    details={"security_level": peer_info.security_level.value}
                )
            )
            
            # Request peer list
            await self._request_peers(peer_info)
            
        except Exception as e:
            logger.error(f"Error processing handshake response from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _request_peers(self, peer_info: PeerInfo) -> None:
        """Request peer list from a peer.
        
        Args:
            peer_info: Information about the peer
        """
        try:
            message = {
                'type': 'get_peers',
                'timestamp': time.time()
            }
            
            if peer_info.connection and not peer_info.connection.is_closing():
                await self._send_message(peer_info, message)
                
        except Exception as e:
            logger.error(f"Error requesting peers from {peer_info.peer_id}: {e}")
    
    async def _handle_get_peers(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle peer list request from a peer.
        
        Args:
            message: Get peers message
            peer_info: Information about the peer
        """
        try:
            # Only respond to peers we've completed handshake with
            if not peer_info.handshake_complete:
                return
                
            # Get list of connected peers (excluding the requesting peer)
            peers_list = []
            for pid, peer in self.peers.items():
                if pid != peer_info.peer_id and peer.handshake_complete:
                    peers_list.append({
                        'peer_id': peer.peer_id,
                        'address': peer.address,
                        'port': peer.port,
                        'public_key': peer.public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo
                        ).decode('utf-8') if peer.public_key else None
                    })
            
            if peers_list:
                response = {
                    'type': 'peers_list',
                    'peers': peers_list,
                    'timestamp': time.time()
                }
                
                if peer_info.connection and not peer_info.connection.is_closing():
                    await self._send_message(peer_info, response)
                    
        except Exception as e:
            logger.error(f"Error handling get_peers from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _handle_peers_list(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle peer list from a peer.
        
        Args:
            message: Peers list message
            peer_info: Information about the peer
        """
        try:
            if 'peers' not in message or not isinstance(message['peers'], list):
                logger.warning(f"Invalid peers list from {peer_info.peer_id}")
                return
                
            # Process each peer in the list
            for peer_data in message['peers']:
                try:
                    if not all(field in peer_data for field in ['peer_id', 'address', 'port']):
                        continue
                        
                    # Skip ourselves
                    if peer_data['peer_id'] == self.peer_id:
                        continue
                        
                    # Skip if we're already connected
                    if peer_data['peer_id'] in self.peers:
                        continue
                        
                    # Check if we should connect to this peer
                    if len(self.peers) < self.max_peers:
                        # Connect in the background
                        self._create_task(
                            self.connect_to_peer(peer_data['address'], peer_data['port']),
                            name=f"connect_to_{peer_data['peer_id']}"
                        )
                        
                except Exception as e:
                    logger.debug(f"Error processing peer {peer_data.get('peer_id')}: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing peers list from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _handle_error(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle error message from a peer.
        
        Args:
            message: Error message
            peer_info: Information about the peer
        """
        try:
            error_msg = message.get('message', 'Unknown error')
            error_code = message.get('code', 0)
            
            logger.warning(f"Error from {peer_info.peer_id} (code {error_code}): {error_msg}")
            
            # Log security event for certain error types
            if error_code >= 400:  # Client errors
                self.security_manager.log_event(
                    SecurityEvent(
                        event_type=SecurityEventType.PEER_ERROR,
                        peer_id=peer_info.peer_id,
                        details={
                            'code': error_code,
                            'message': error_msg
                        }
                    )
                )
                
        except Exception as e:
            logger.error(f"Error processing error message from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _handle_ping(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle ping message from a peer.
        
        Args:
            message: Ping message
            peer_info: Information about the peer
        """
        try:
            # Update last seen timestamp
            peer_info.last_seen = time.time()
            
            # Send pong response
            pong = {
                'type': 'pong',
                'timestamp': message.get('timestamp'),
                'node_time': time.time()
            }
            
            if peer_info.connection and not peer_info.connection.is_closing():
                await self._send_message(peer_info, pong)
                
        except Exception as e:
            logger.error(f"Error handling ping from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _handle_pong(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle pong message from a peer.
        
        Args:
            message: Pong message
            peer_info: Information about the peer
        """
        try:
            # Calculate latency if timestamp is provided
            if 'timestamp' in message:
                latency = time.time() - float(message['timestamp'])
                peer_info.update_latency(latency)
                logger.debug(f"Ping latency to {peer_info.peer_id}: {latency*1000:.2f}ms")
                
        except Exception as e:
            logger.error(f"Error handling pong from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _handle_gate_sequence(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle gate sequence update from a peer.
        
        Args:
            message: Gate sequence message
            peer_info: Information about the peer
        """
        try:
            if 'sequence' not in message or not isinstance(message['sequence'], list):
                logger.warning(f"Invalid gate sequence from {peer_info.peer_id}")
                return
                
            # Update peer's gate sequence
            peer_info.gate_sequence = message['sequence']
            
            logger.debug(f"Updated gate sequence for peer {peer_info.peer_id}: {peer_info.gate_sequence}")
            
            # Log security event
            self.security_manager.log_event(
                SecurityEvent(
                    event_type=SecurityEventType.GATE_SEQUENCE_UPDATED,
                    peer_id=peer_info.peer_id,
                    details={"gate_sequence": peer_info.gate_sequence}
                )
            )
            
        except Exception as e:
            logger.error(f"Error handling gate sequence from {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
    
    async def _send_message(self, peer_info: PeerInfo, message: Dict[str, Any]) -> bool:
        """Send a message to a peer.
        
        Args:
            peer_info: Information about the peer
            message: Message to send (will be JSON-serialized)
            
        Returns:
            bool: True if message was sent successfully, False otherwise
        """
        try:
            if not peer_info.connection or peer_info.connection.is_closing():
                return False
                
            # Add timestamp if not present
            if 'timestamp' not in message:
                message['timestamp'] = time.time()
                
            # Serialize message
            message_str = json.dumps(message)
            message_bytes = message_str.encode('utf-8')
            
            # Check message size
            if len(message_bytes) > self.config['max_message_size']:
                logger.warning(f"Message too large ({len(message_bytes)} bytes) for {peer_info.peer_id}")
                return False
                
            # Update peer metrics
            peer_info.bytes_sent += len(message_bytes)
            peer_info.message_count += 1
            peer_info.last_seen = time.time()
            
            # Send message with newline terminator
            peer_info.connection.write(message_bytes + b'\n')
            await peer_info.connection.drain()
            
            return True
            
        except Exception as e:
            logger.error(f"Error sending message to {peer_info.peer_id}: {e}", exc_info=True)
            peer_info.record_error()
            return False
    
    async def _handle_ping(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle ping message from a peer.
        
        Args:
            message: Ping message
            peer_info: Information about the peer
        """
        try:
            # Update last seen timestamp
            peer_info.last_seen = self._get_timestamp()
            
            # Send pong response
            pong = {
                'type': 'pong',
                'timestamp': message.get('timestamp'),
                'node_time': self._get_timestamp()
            }
            
            writer = peer_info.connection
            if writer and not writer.is_closing():
                writer.write(json.dumps(pong).encode() + b'\n')
                await writer.drain()
                
        except Exception as e:
            logger.error(f"Error handling ping from {peer_info.peer_id}: {e}")
    
    async def _handle_pong(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle pong message from a peer.
        
        Args:
            message: Pong message
            peer_info: Information about the peer
        """
        try:
            # Update last seen timestamp
            peer_info.last_seen = self._get_timestamp()
            
            # Calculate latency if timestamp is provided
            if 'timestamp' in message:
                latency = self._get_timestamp() - float(message['timestamp'])
                logger.debug(f"Ping latency to {peer_info.peer_id}: {latency*1000:.2f}ms")
                
        except Exception as e:
            logger.error(f"Error handling pong from {peer_info.peer_id}: {e}")
    
    async def _handle_gate_sequence(self, message: Dict[str, Any], peer_info: PeerInfo) -> None:
        """Handle gate sequence update from a peer.
        
        Args:
            message: Gate sequence message
            peer_info: Information about the peer
        """
        try:
            # Verify the message contains a sequence
            if 'sequence' not in message or not isinstance(message['sequence'], list):
                logger.warning(f"Invalid gate sequence message from {peer_info.peer_id}")
                return
                
            # Update peer's gate sequence
            peer_info.gate_sequence = message['sequence']
            peer_info.last_seen = self._get_timestamp()
            
            logger.debug(f"Updated gate sequence for peer {peer_info.peer_id}: {peer_info.gate_sequence}")
            
            # Log security event
            self.security_manager.log_event(
                SecurityEvent(
                    event_type=SecurityEventType.GATE_SEQUENCE_UPDATED,
                    peer_id=peer_info.peer_id,
                    details={"gate_sequence": peer_info.gate_sequence}
                )
            )
            
        except Exception as e:
            logger.error(f"Error handling gate sequence from {peer_info.peer_id}: {e}")
    
    def _sign_message(self, message: Dict[str, Any]) -> str:
        """Sign a message with the node's private key.
        
        Args:
            message: Message to sign
            
        Returns:
            str: Base64-encoded signature
        """
        try:
            # Create a copy and remove any existing signature
            msg_copy = message.copy()
            msg_copy.pop('signature', None)
            
            # Convert to canonical JSON string
            msg_str = json.dumps(msg_copy, sort_keys=True, separators=(',', ':'))
            
            # Sign the message
            signature = self.private_key.sign(
                msg_str.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            
            # Return base64-encoded signature
            import base64
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Error signing message: {e}")
            return ""
    
    def _verify_signature(self, public_key_pem: str, data: bytes, signature_b64: str) -> bool:
        """Verify a message signature.
        
        Args:
            public_key_pem: PEM-encoded public key
            data: Data that was signed
            signature_b64: Base64-encoded signature
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Decode signature
            import base64
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            public_key.verify(
                signature,
                data,
                ec.ECDSA(hashes.SHA256())
            )
            
            return True
            
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False
    
    def _get_signing_payload(self, message: Dict[str, Any]) -> bytes:
        """Get the payload to sign/verify from a message.
        
        Args:
            message: Message to get payload from
            
        Returns:
            bytes: Canonical JSON representation of the message (without signature)
        """
        # Create a copy and remove the signature
        msg_copy = message.copy()
        msg_copy.pop('signature', None)
        
        # Convert to canonical JSON string
        return json.dumps(msg_copy, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    async def start(self) -> bool:
        """
        Start the P2P server and connect to the network.
        
        Returns:
            bool: True if started successfully, False otherwise
        """
        if self.running:
            logger.warning("P2P Manager is already running")
            return True
            
        try:
            # Start the TCP server
            self.server = await asyncio.start_server(
                self._handle_connection,
                host='0.0.0.0',
                port=self.port,
                reuse_address=True,
                reuse_port=True
            )
            
            # Update port if it was set to 0 (random port)
            if self.port == 0:
                self.port = self.server.sockets[0].getsockname()[1]
                
            self.running = True
            
            # Start the peer discovery task
            asyncio.create_task(self._peer_discovery())
            
            logger.info(f"P2P server started on port {self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start P2P server: {e}")
            return False
    
    async def stop(self) -> None:
        """Stop the P2P server and disconnect from all peers."""
        if not self.running:
            return
            
        self.running = False
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            
        logger.info("P2P server stopped")
    
    async def connect_to_peer(self, address: str, port: int) -> bool:
        """
        Connect to a peer.
        
        Args:
            address: IP address or hostname of the peer
            port: Port of the peer
            
        Returns:
            bool: True if connection was successful, False otherwise
        """
        if len(self.peers) >= self.max_peers:
            logger.warning("Maximum number of peers reached")
            return False
            
        peer_id = f"{address}:{port}"
        
        if peer_id in self.peers:
            logger.debug(f"Already connected to peer {peer_id}")
            return True
            
        try:
            reader, writer = await asyncio.open_connection(address, port)
            
            # Send handshake message
            handshake = {
                'type': 'handshake',
                'peer_id': self.peer_id,
                'port': self.port,
                'timestamp': self._get_timestamp()
            }
            
            writer.write(json.dumps(handshake).encode() + b'\n')
            await writer.drain()
            
            # Wait for response
            data = await asyncio.wait_for(reader.readline(), timeout=10.0)
            response = json.loads(data.decode().strip())
            
            if response.get('type') != 'handshake_ack':
                logger.warning(f"Invalid handshake response from {address}:{port}")
                writer.close()
                await writer.wait_closed()
                return False
            
            # Add peer to our list
            peer_info = PeerInfo(
                peer_id=response.get('peer_id', peer_id),
                address=address,
                port=port,
                public_key=response.get('public_key'),
                last_seen=self._get_timestamp()
            )
            
            self.peers[peer_id] = peer_info
            logger.info(f"Connected to peer {peer_id} at {address}:{port}")
            
            # Start listening for messages from this peer
            asyncio.create_task(self._handle_peer_connection(reader, writer, peer_info))
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to connect to peer {address}:{port}: {e}")
            return False
    
    async def broadcast_message(self, message: Dict[str, Any], exclude_peers: Optional[Set[str]] = None) -> int:
        """
        Broadcast a message to all connected peers.
        
        Args:
            message: Message to broadcast (must be JSON-serializable)
            exclude_peers: Set of peer IDs to exclude from the broadcast
            
        Returns:
            int: Number of peers the message was sent to
        """
        if not self.running:
            return 0
            
        exclude_peers = exclude_peers or set()
        message['sender_id'] = self.peer_id
        message['message_id'] = str(uuid4())
        message['timestamp'] = self._get_timestamp()
        
        message_str = json.dumps(message) + '\n'
        message_bytes = message_str.encode()
        
        sent_count = 0
        
        for peer_id, peer_info in list(self.peers.items()):
            if peer_id in exclude_peers:
                continue
                
            try:
                _, writer = await asyncio.open_connection(peer_info.address, peer_info.port)
                writer.write(message_bytes)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                sent_count += 1
                
            except Exception as e:
                logger.warning(f"Failed to send message to {peer_id}: {e}")
                # Remove disconnected peer
                self.peers.pop(peer_id, None)
        
        return sent_count
    
    def register_message_handler(self, message_type: str, handler: Callable) -> None:
        """
        Register a handler for a specific message type.
        
        Args:
            message_type: Type of message to handle
            handler: Function to handle the message
        """
        self.message_handlers[message_type] = handler
        logger.debug(f"Registered handler for message type: {message_type}")
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """
        Handle incoming connection from a peer.
        
        Args:
            reader: Stream reader for incoming data
            writer: Stream writer for outgoing data
        """
        try:
            peer_addr = writer.get_extra_info('peername')
            peer_id = f"{peer_addr[0]}:{peer_addr[1]}"
            
            # Read handshake
            data = await asyncio.wait_for(reader.readline(), timeout=10.0)
            handshake = json.loads(data.decode().strip())
            
            if handshake.get('type') != 'handshake':
                logger.warning(f"Invalid handshake from {peer_addr}")
                writer.close()
                return
            
            # Send handshake acknowledgment
            ack = {
                'type': 'handshake_ack',
                'peer_id': self.peer_id,
                'public_key': self.config.get('public_key'),
                'timestamp': self._get_timestamp()
            }
            
            writer.write(json.dumps(ack).encode() + b'\n')
            await writer.drain()
            
            # Add peer to our list
            peer_info = PeerInfo(
                peer_id=handshake.get('peer_id', peer_id),
                address=peer_addr[0],
                port=handshake.get('port', peer_addr[1]),
                public_key=handshake.get('public_key'),
                last_seen=self._get_timestamp()
            )
            
            self.peers[peer_id] = peer_info
            logger.info(f"Accepted connection from peer {peer_id} at {peer_addr[0]}:{peer_addr[1]}")
            
            # Start handling messages from this peer
            await self._handle_peer_connection(reader, writer, peer_info)
            
        except asyncio.TimeoutError:
            logger.warning(f"Connection timeout from {peer_addr}")
        except Exception as e:
            logger.error(f"Error handling connection from {peer_addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()
    
    async def _handle_peer_connection(
        self, 
        reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter,
        peer_info: PeerInfo
    ) -> None:
        """
        Handle messages from a connected peer.
        
        Args:
            reader: Stream reader for incoming data
            writer: Stream writer for outgoing data
            peer_info: Information about the connected peer
        """
        peer_id = f"{peer_info.address}:{peer_info.port}"
        
        try:
            while self.running:
                data = await asyncio.wait_for(reader.readline(), timeout=300.0)
                
                if not data:
                    break
                    
                try:
                    message = json.loads(data.decode().strip())
                    message_type = message.get('type')
                    
                    # Update last seen timestamp
                    peer_info.last_seen = self._get_timestamp()
                    
                    # Handle the message
                    if message_type in self.message_handlers:
                        try:
                            await self.message_handlers[message_type](message, peer_info)
                        except Exception as e:
                            logger.error(f"Error in message handler for {message_type}: {e}")
                    else:
                        logger.debug(f"No handler for message type: {message_type}")
                        
                except json.JSONDecodeError:
                    logger.warning(f"Invalid JSON received from {peer_id}")
                except Exception as e:
                    logger.error(f"Error processing message from {peer_id}: {e}")
                    
        except asyncio.TimeoutError:
            logger.info(f"Connection timeout with {peer_id}")
        except ConnectionResetError:
            logger.info(f"Connection reset by peer {peer_id}")
        except Exception as e:
            logger.error(f"Error in peer connection {peer_id}: {e}")
        finally:
            # Clean up
            writer.close()
            await writer.wait_closed()
            self.peers.pop(peer_id, None)
            logger.info(f"Disconnected from peer {peer_id}")
    
    async def _peer_discovery(self) -> None:
        """Periodically discover and connect to new peers."""
        while self.running:
            try:
                # Get list of known peer addresses from config
                known_peers = self.config.get('known_peers', [])
                
                # Try to connect to new peers if we're below the max
                if len(self.peers) < self.max_peers and known_peers:
                    for peer_addr in known_peers:
                        if len(self.peers) >= self.max_peers:
                            break
                            
                        if ':' not in peer_addr:
                            continue
                            
                        address, port_str = peer_addr.rsplit(':', 1)
                        
                        try:
                            port = int(port_str)
                            peer_id = f"{address}:{port}"
                            
                            if peer_id not in self.peers and peer_id != f"0.0.0.0:{self.port}":
                                logger.debug(f"Attempting to connect to peer at {address}:{port}")
                                await self.connect_to_peer(address, port)
                                
                        except (ValueError, IndexError):
                            continue
                
                # Clean up disconnected peers
                current_time = self._get_timestamp()
                for peer_id, peer_info in list(self.peers.items()):
                    if current_time - peer_info.last_seen > 300:  # 5 minutes
                        logger.info(f"Removing inactive peer: {peer_id}")
                        self.peers.pop(peer_id, None)
                
                # Wait before next discovery cycle
                await asyncio.sleep(30.0)
                
            except Exception as e:
                logger.error(f"Error in peer discovery: {e}")
                await asyncio.sleep(10.0)  # Shorter delay on error
    
    def _get_timestamp(self) -> float:
        """Get current timestamp in seconds since epoch."""
        import time
        return time.time()
    
    def get_connected_peers(self) -> List[Dict[str, Any]]:
        """
        Get information about connected peers.
        
        Returns:
            List of dictionaries containing peer information
        """
        return [
            {
                'peer_id': info.peer_id,
                'address': info.address,
                'port': info.port,
                'last_seen': info.last_seen,
                'public_key': info.public_key
            }
            for info in self.peers.values()
        ]
    
    def is_connected(self, peer_id: str) -> bool:
        """
        Check if connected to a specific peer.
        
        Args:
            peer_id: ID of the peer to check
            
        Returns:
            bool: True if connected, False otherwise
        """
        return any(p.peer_id == peer_id for p in self.peers.values())
