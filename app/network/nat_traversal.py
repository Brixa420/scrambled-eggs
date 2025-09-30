"""
NAT Traversal Manager for Scrambled Eggs P2P Network.
Implements various NAT traversal techniques including STUN, TURN, and hole punching.
"""

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set

import aiohttp
import netifaces

from ..core.config import settings

logger = logging.getLogger(__name__)

class NATType(Enum):
    """Types of NAT based on behavior."""
    UNKNOWN = "unknown"
    OPEN_INTERNET = "open_internet"
    FULL_CONE = "full_cone"
    RESTRICTED_CONE = "restricted_cone"
    PORT_RESTRICTED_CONE = "port_restricted_cone"
    SYMMETRIC = "symmetric"

@dataclass
class NATInfo:
    """Information about the NAT configuration."""
    type: NATType = NATType.UNKNOWN
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    local_ip: str = "0.0.0.0"
    local_port: int = 0
    stun_servers: List[Tuple[str, int]] = None
    turn_servers: List[Tuple[str, int, str, str]] = None  # (host, port, username, password)

class NATTraversal:
    """Manages NAT traversal for P2P connections."""
    
    def __init__(self, local_port: int = 0):
        self.local_port = local_port
        self.nat_info = NATInfo(
            stun_servers=[
                ('stun.l.google.com', 19302),
                ('stun1.l.google.com', 19302),
                ('stun2.l.google.com', 19302)
            ],
            turn_servers=[]  # Should be populated from config
        )
        self.session: Optional[aiohttp.ClientSession] = None
        
    async def initialize(self):
        """Initialize the NAT traversal manager."""
        self.session = aiohttp.ClientSession()
        await self.detect_nat_type()
        
    async def close(self):
        """Clean up resources."""
        if self.session:
            await self.session.close()
            
    async def detect_nat_type(self) -> NATType:
        """Detect the type of NAT using STUN servers."""
        if not self.session:
            raise RuntimeError("NATTraversal not initialized")
            
        # Get local IP address
        self.nat_info.local_ip = self._get_local_ip()
        self.nat_info.local_port = self.local_port or self._find_free_port()
        
        # Test with STUN servers
        for stun_host, stun_port in self.nat_info.stun_servers:
            try:
                # Test 1: Basic binding request
                mapped_addr1 = await self._stun_binding_request(stun_host, stun_port)
                if not mapped_addr1:
                    continue
                    
                # Test 2: Same server, different port
                mapped_addr2 = await self._stun_binding_request(stun_host, stun_port + 1)
                
                # Test 3: Different server
                mapped_addr3 = await self._stun_binding_request(
                    f"stun{hash(stun_host) % 10}.example.com", stun_port
                )
                
                # Analyze results to determine NAT type
                if mapped_addr1 == (self.nat_info.local_ip, self.nat_info.local_port):
                    self.nat_info.type = NATType.OPEN_INTERNET
                elif mapped_addr1 == mapped_addr2 == mapped_addr3:
                    self.nat_info.type = NATType.FULL_CONE
                elif mapped_addr1 == mapped_addr2 != mapped_addr3:
                    self.nat_info.type = NATType.RESTRICTED_CONE
                else:
                    self.nat_info.type = NATType.SYMMETRIC
                    
                self.nat_info.public_ip, self.nat_info.public_port = mapped_addr1
                break
                
            except Exception as e:
                logger.warning(f"STUN test failed with {stun_host}:{stun_port}: {e}")
                continue
                
        logger.info(f"Detected NAT type: {self.nat_info.type}")
        return self.nat_info.type
        
    async def _stun_binding_request(self, host: str, port: int) -> Optional[Tuple[str, int]]:
        """Send a STUN binding request and parse the response."""
        if not self.session:
            return None
            
        # Simple STUN binding request
        transaction_id = os.urandom(12)
        request = (
            b'\x00\x01' +  # Message Type: Binding Request
            b'\x00\x00' +  # Message Length
            b'\x21\x12\xA4\x42' +  # Magic Cookie
            transaction_id  # Transaction ID
        )
        
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            sock.bind(('0.0.0.0', self.local_port))
            
            # Send request
            sock.sendto(request, (host, port))
            
            # Wait for response
            response, _ = sock.recvfrom(2048)
            
            # Parse response (simplified)
            if len(response) >= 20 and response[0:2] == b'\x01\x01':
                # Find MAPPED-ADDRESS attribute (0x0001)
                offset = 20  # Skip STUN header
                while offset + 4 <= len(response):
                    attr_type = int.from_bytes(response[offset:offset+2], 'big')
                    attr_len = int.from_bytes(response[offset+2:offset+4], 'big')
                    
                    if attr_type == 0x0001 and attr_len >= 8:  # MAPPED-ADDRESS
                        port = int.from_bytes(response[offset+6:offset+8], 'big')
                        ip = socket.inet_ntoa(response[offset+8:offset+12])
                        return (ip, port)
                        
                    offset += 4 + ((attr_len + 3) & ~3)  # Align to 4 bytes
                    
        except (socket.timeout, ConnectionError) as e:
            logger.warning(f"STUN request to {host}:{port} failed: {e}")
            return None
            
        finally:
            sock.close()
            
        return None
        
    async def punch_hole(self, remote_ip: str, remote_port: int):
        """Attempt to punch a hole through NAT for direct connection."""
        if not self.session:
            raise RuntimeError("NATTraversal not initialized")
            
        # Implementation depends on NAT type
        if self.nat_info.type in [NATType.OPEN_INTERNET, NATType.FULL_CONE]:
            # Direct connection should work
            return True
            
        elif self.nat_info.type == NATType.SYMMETRIC:
            # Most challenging case - may need TURN relay
            return await self._use_turn_relay(remote_ip, remote_port)
            
        else:
            # For other NAT types, try hole punching
            return await self._try_hole_punch(remote_ip, remote_port)
            
    async def _try_hole_punch(self, remote_ip: str, remote_port: int) -> bool:
        """Attempt hole punching by coordinating through a rendezvous server."""
        # This would coordinate with the remote peer through a signaling server
        # to simultaneously attempt connections to each other
        pass
        
    async def _use_turn_relay(self, remote_ip: str, remote_port: int) -> bool:
        """Use a TURN relay for NAT traversal."""
        if not self.nat_info.turn_servers:
            logger.warning("No TURN servers configured")
            return False
            
        # Implementation would use TURN protocol to establish relay
        return False
        
    def _get_local_ip(self) -> str:
        """Get the local IP address."""
        try:
            # Try to get the default gateway's interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET][1]
            
            # Get the address for that interface
            addrs = netifaces.ifaddresses(default_gateway)
            return addrs[netifaces.AF_INET][0]['addr']
            
        except Exception:
            # Fallback to socket method
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Doesn't need to be reachable
                s.connect(('10.255.255.255', 1))
                return s.getsockname()[0]
            except Exception:
                return '127.0.0.1'
            finally:
                s.close()
                
    def _find_free_port(self) -> int:
        """Find a free port on the local machine."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', 0))
            return s.getsockname()[1]
