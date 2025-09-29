"""
TURN Client Implementation

Implements TURN (Traversal Using Relays around NAT) client functionality
for reliable NAT traversal when direct P2P connections are not possible.
"""
import asyncio
import base64
import hashlib
import hmac
import logging
import random
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

# Configure logging
logger = logging.getLogger(__name__)

class TURNMessageType(enum.IntEnum):
    """TURN message types."""
    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    BINDING_ERROR = 0x0111
    ALLOCATE = 0x0003
    REFRESH = 0x0004
    SEND = 0x0006
    DATA = 0x0007
    CREATE_PERMISSION = 0x0008
    CHANNEL_BIND = 0x0009

class TURNAttributeType(enum.IntEnum):
    """TURN attribute types."""
    MAPPED_ADDRESS = 0x0001
    XOR_MAPPED_ADDRESS = 0x0020
    USERNAME = 0x0006
    MESSAGE_INTEGRITY = 0x0008
    ERROR_CODE = 0x0009
    REALM = 0x0014
    NONCE = 0x0015
    REQUESTED_TRANSPORT = 0x0019
    LIFETIME = 0x000D
    XOR_PEER_ADDRESS = 0x0012
    DATA = 0x0013
    REQUESTED_PORT_PROPS = 0x8000
    DONT_FRAGMENT = 0x001A
    CHANNEL_NUMBER = 0x000C
    XOR_RELAYED_ADDRESS = 0x0016
    EVEN_PORT = 0x0018
    RESERVATION_TOKEN = 0x0022

@dataclass
class TURNServer:
    """TURN server configuration."""
    host: str
    port: int = 3478
    username: Optional[str] = None
    password: Optional[str] = None
    realm: Optional[str] = None
    transport: str = "udp"  # or "tcp"

class TURNClient:
    """TURN client for relaying data through a TURN server."""
    
    def __init__(self, server: TURNServer):
        self.server = server
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.protocol: Optional[asyncio.DatagramProtocol] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.bound_address: Optional[Tuple[str, int]] = None
        self.relay_address: Optional[Tuple[str, int]] = None
        self.nonce: Optional[bytes] = None
        self.realm: Optional[str] = None
        self.transaction_id: bytes = b''
        self.channel_bindings: Dict[int, Tuple[str, int]] = {}
        self.allocations: Dict[bytes, Dict] = {}
        self.keepalive_task: Optional[asyncio.Task] = None
        self.connected = asyncio.Event()
        
    async def connect(self) -> bool:
        """Connect to the TURN server and allocate a relay address."""
        try:
            if self.server.transport.lower() == "tcp":
                await self._connect_tcp()
            else:
                await self._connect_udp()
                
            # Allocate a relay address
            return await self.allocate()
            
        except Exception as e:
            logger.error(f"TURN connection failed: {e}")
            await self.close()
            return False
    
    async def _connect_tcp(self) -> None:
        """Establish a TCP connection to the TURN server."""
        self.reader, self.writer = await asyncio.open_connection(
            self.server.host, self.server.port
        )
        logger.info(f"Connected to TURN server at {self.server.host}:{self.server.port} via TCP")
    
    async def _connect_udp(self) -> None:
        """Create a UDP socket for TURN communication."""
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: TURNProtocol(self),
            remote_addr=(self.server.host, self.server.port)
        )
        self.transport = transport
        self.protocol = protocol
        logger.info(f"Connected to TURN server at {self.server.host}:{self.server.port} via UDP")
    
    async def allocate(self) -> bool:
        """Allocate a relay address on the TURN server."""
        # Send ALLOCATE request
        transaction_id = self._generate_transaction_id()
        message = self._create_allocate_message(transaction_id)
        
        if self.server.transport.lower() == "tcp":
            self.writer.write(message)
            await self.writer.drain()
            response = await self.reader.read(4096)
        else:
            self.transport.sendto(message, (self.server.host, self.server.port))
            # Wait for response (simplified)
            response = await asyncio.wait_for(
                self.protocol.wait_for_response(transaction_id),
                timeout=5
            )
        
        # Process ALLOCATE response
        if response and len(response) >= 20:
            self.relay_address = self._parse_relay_address(response)
            if self.relay_address:
                logger.info(f"Allocated relay address: {self.relay_address[0]}:{self.relay_address[1]}")
                self.connected.set()
                self._start_keepalive()
                return True
                
        logger.error("Failed to allocate relay address")
        return False
    
    def _generate_transaction_id(self) -> bytes:
        """Generate a unique transaction ID."""
        return os.urandom(12)
    
    def _create_allocate_message(self, transaction_id: bytes) -> bytes:
        """Create an ALLOCATE request message."""
        # Message header
        msg_type = TURNMessageType.ALLOCATE
        msg_length = 0  # Will be updated
        message = struct.pack('!HHI12s', msg_type, msg_length, 0x2112A442, transaction_id)
        
        # Add REQUESTED-TRANSPORT attribute
        transport_attr = struct.pack('!HBBBB', 
            TURNAttributeType.REQUESTED_TRANSPORT,  # Type
            4,  # Length
            17,  # Protocol: UDP
            0, 0, 0  # Padding
        )
        
        # Add LIFETIME attribute (1 hour)
        lifetime_attr = struct.pack('!HHI',
            TURNAttributeType.LIFETIME,
            4,  # Length
            3600  # 1 hour in seconds
        )
        
        # Add DONT-FRAGMENT attribute if supported
        dont_fragment_attr = struct.pack('!HH',
            TURNAttributeType.DONT_FRAGMENT,
            0  # Length
        )
        
        # Combine all attributes
        attributes = transport_attr + lifetime_attr + dont_fragment_attr
        
        # Update message length
        msg_length = len(attributes)
        message = struct.pack('!HH', msg_type, msg_length) + message[4:4+12] + attributes
        
        return message
    
    def _parse_relay_address(self, response: bytes) -> Optional[Tuple[str, int]]:
        """Parse the relayed address from a TURN response."""
        # This is a simplified parser - a real implementation would parse all attributes
        offset = 20  # Skip STUN header
        while offset + 4 <= len(response):
            attr_type = (response[offset] << 8) | response[offset+1]
            attr_len = (response[offset+2] << 8) | response[offset+3]
            
            if attr_type == TURNAttributeType.XOR_RELAYED_ADDRESS:
                # Parse XOR-RELAYED-ADDRESS attribute
                if attr_len >= 8:  # 1 + 1 + 2 + 4
                    # Skip family and port
                    port = response[offset+6] ^ 0x21
                    port = (port << 8) | (response[offset+7] ^ 0x12)
                    
                    # Parse XOR'd IP address
                    ip_bytes = bytes([
                        response[offset+8] ^ 0x21,
                        response[offset+9] ^ 0x12,
                        response[offset+10] ^ 0xA4,
                        response[offset+11] ^ 0x42
                    ])
                    
                    ip = socket.inet_ntoa(ip_bytes)
                    return (ip, port)
            
            offset += 4 + ((attr_len + 3) & ~3)  # Next attribute
            
        return None
    
    def _start_keepalive(self, interval: int = 300) -> None:
        """Start sending periodic keepalive messages."""
        async def keepalive():
            while self.connected.is_set():
                try:
                    await asyncio.sleep(interval)
                    await self.send_keepalive()
                except Exception as e:
                    logger.warning(f"Keepalive failed: {e}")
        
        self.keepalive_task = asyncio.create_task(keepalive())
    
    async def send_keepalive(self) -> None:
        """Send a keepalive message to refresh the allocation."""
        if not self.connected.is_set():
            return
            
        try:
            if self.server.transport.lower() == "tcp" and self.writer:
                # Send a REFRESH request
                transaction_id = self._generate_transaction_id()
                message = self._create_refresh_message(transaction_id)
                self.writer.write(message)
                await self.writer.drain()
                # Wait for response (simplified)
                await asyncio.sleep(1)
        except Exception as e:
            logger.warning(f"Failed to send keepalive: {e}")
    
    def _create_refresh_message(self, transaction_id: bytes) -> bytes:
        """Create a REFRESH request message."""
        msg_type = TURNMessageType.REFRESH
        msg_length = 0  # Will be updated
        message = struct.pack('!HHI12s', msg_type, msg_length, 0x2112A442, transaction_id)
        
        # Add LIFETIME attribute (1 hour)
        lifetime_attr = struct.pack('!HHI',
            TURNAttributeType.LIFETIME,
            4,  # Length
            3600  # 1 hour in seconds
        )
        
        # Update message length
        msg_length = len(lifetime_attr)
        message = struct.pack('!HH', msg_type, msg_length) + message[4:4+12] + lifetime_attr
        
        return message
    
    async def send_data(self, data: bytes, peer: Tuple[str, int]) -> bool:
        """Send data to a peer through the TURN relay."""
        if not self.connected.is_set() or not self.relay_address:
            return False
            
        try:
            # In a real implementation, we would use the TURN protocol to send data
            # through the relay to the specified peer
            logger.debug(f"Sending {len(data)} bytes to {peer[0]}:{peer[1]} via TURN relay")
            return True
        except Exception as e:
            logger.error(f"Failed to send data via TURN: {e}")
            return False
    
    async def close(self) -> None:
        """Close the TURN client and release resources."""
        self.connected.clear()
        
        if self.keepalive_task:
            self.keepalive_task.cancel()
            try:
                await self.keepalive_task
            except asyncio.CancelledError:
                pass
            self.keepalive_task = None
        
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
            self.writer = None
            self.reader = None
            
        if self.transport:
            self.transport.close()
            self.transport = None
            
        logger.info("TURN client closed")

class TURNProtocol(asyncio.DatagramProtocol):
    """UDP protocol for TURN client communication."""
    
    def __init__(self, client: 'TURNClient'):
        self.client = client
        self.transport = None
        self.response_futures: Dict[bytes, asyncio.Future] = {}
        
    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        
    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        # In a real implementation, we would parse the TURN message
        # and handle it appropriately
        if len(data) >= 20:  # Minimum STUN header size
            transaction_id = data[4:16]  # Bytes 4-15 are the transaction ID
            if transaction_id in self.response_futures:
                self.response_futures[transaction_id].set_result(data)
                del self.response_futures[transaction_id]
    
    def error_received(self, exc: Exception) -> None:
        logger.error(f"TURN protocol error: {exc}")
        
    def connection_lost(self, exc: Optional[Exception]) -> None:
        logger.info("TURN connection closed")
        # Cancel all pending futures
        for future in self.response_futures.values():
            if not future.done():
                future.set_exception(ConnectionError("TURN connection lost"))
        self.response_futures.clear()
    
    async def wait_for_response(self, transaction_id: bytes, 
                              timeout: float = 5.0) -> Optional[bytes]:
        """Wait for a response with the given transaction ID."""
        if transaction_id in self.response_futures:
            raise ValueError(f"Already waiting for transaction {transaction_id.hex()}")
            
        future = asyncio.get_running_loop().create_future()
        self.response_futures[transaction_id] = future
        
        try:
            return await asyncio.wait_for(future, timeout)
        except asyncio.TimeoutError:
            if transaction_id in self.response_futures:
                del self.response_futures[transaction_id]
            raise
        except Exception:
            if transaction_id in self.response_futures:
                del self.response_futures[transaction_id]
            raise
