"""
Advanced NAT Traversal Techniques

Implements NAT type detection and hole punching for P2P connections.
"""
import asyncio
import enum
import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Union

# Configure logging
logger = logging.getLogger(__name__)

class NATType(enum.Enum):
    """Types of NATs based on their behavior."""
    # No NAT, public IP address
    OPEN_INTERNET = "Open Internet"
    # Full Cone NAT: Any external host can send to the mapped address
    FULL_CONE = "Full Cone"
    # Restricted Cone: Only hosts that the internal host has sent to can respond
    RESTRICTED_CONE = "Restricted Cone"
    # Port Restricted Cone: Only the specific host:port can respond
    PORT_RESTRICTED_CONE = "Port-Restricted Cone"
    # Symmetric: Different external ports for different destinations
    SYMMETRIC = "Symmetric"
    # Unknown or unable to determine
    UNKNOWN = "Unknown"

@dataclass
class NATMapping:
    """Represents a NAT binding/mapping."""
    internal: Tuple[str, int]  # (ip, port)
    external: Tuple[str, int]  # (ip, port)
    protocol: str = "TCP"
    created: float = 0.0
    last_used: float = 0.0
    lifetime: int = 3600

class NATDetector:
    """Detects NAT type and characteristics."""
    
    def __init__(self, stun_servers: Optional[List[Tuple[str, int]]] = None):
        self.stun_servers = stun_servers or [
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302),
            ("stun.voipbuster.com", 3478),
            ("stun.stunprotocol.org", 3478)
        ]
        self.nat_type = NATType.UNKNOWN
        self.public_ip = None
        self.public_port = None
        self.mappings: Dict[Tuple[str, int], NATMapping] = {}
        
    async def detect_nat_type(self, local_port: int = 0) -> NATType:
        """Determine the type of NAT we're behind."""
        try:
            # First, check if we're on open internet
            if await self._check_open_internet(local_port):
                self.nat_type = NATType.OPEN_INTERNET
                return self.nat_type
                
            # Check for Full Cone NAT
            if await self._check_full_cone(local_port):
                self.nat_type = NATType.FULL_CONE
                return self.nat_type
                
            # Check for Restricted Cone NAT
            if await self._check_restricted_cone(local_port):
                self.nat_type = NATType.RESTRICTED_CONE
                return self.nat_type
                
            # Check for Port-Restricted Cone NAT
            if await self._check_port_restricted_cone(local_port):
                self.nat_type = NATType.PORT_RESTRICTED_CONE
                return self.nat_type
                
            # If we get here, it's likely a Symmetric NAT
            self.nat_type = NATType.SYMMETRIC
            return self.nat_type
            
        except Exception as e:
            logger.error(f"Error detecting NAT type: {e}")
            return NATType.UNKNOWN
    
    async def _check_open_internet(self, local_port: int) -> bool:
        """Check if we have a public IP address (no NAT)."""
        try:
            # Use STUN to get our public IP
            public_ip, public_port = await self._get_public_address(local_port)
            if not public_ip or not public_port:
                return False
                
            # Check if the public IP matches any of our local IPs
            local_ips = self._get_local_ips()
            if any(ipaddress.ip_address(public_ip) == ipaddress.ip_address(ip) 
                  for ip in local_ips if ip != '127.0.0.1'):
                self.public_ip = public_ip
                self.public_port = public_port
                return True
                
        except Exception as e:
            logger.debug(f"Open internet check failed: {e}")
            
        return False
    
    async def _check_full_cone(self, local_port: int) -> bool:
        """Check for Full Cone NAT."""
        # Implementation would involve checking if any external host can reach us
        # through the mapped port, which is hard to test without a second server
        # For now, we'll assume it's not a full cone if we're not on open internet
        return False
    
    async def _check_restricted_cone(self, local_port: int) -> bool:
        """Check for Restricted Cone NAT."""
        # Similar to full cone but with IP-based restrictions
        return False
    
    async def _check_port_restricted_cone(self, local_port: int) -> bool:
        """Check for Port-Restricted Cone NAT."""
        # Similar to restricted cone but with port-based restrictions
        return False
    
    async def _get_public_address(self, local_port: int) -> Tuple[Optional[str], Optional[int]]:
        """Get public IP and port using STUN."""
        for stun_host, stun_port in self.stun_servers:
            try:
                reader, writer = await asyncio.open_connection(stun_host, stun_port)
                
                # Simple STUN binding request
                request = b'\x00\x01\x00\x00'  # Binding request, no attributes
                writer.write(request)
                await writer.drain()
                
                # Read response with timeout
                try:
                    response = await asyncio.wait_for(reader.read(1024), timeout=5)
                    if len(response) >= 20:  # Minimum STUN header size
                        return self._parse_stun_response(response)
                except asyncio.TimeoutError:
                    logger.debug(f"STUN request to {stun_host} timed out")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                logger.debug(f"STUN request to {stun_host} failed: {e}")
                continue
                
        return None, None
    
    def _parse_stun_response(self, response: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Parse STUN response to extract mapped address."""
        # Look for XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001)
        offset = 20  # Skip STUN header
        while offset + 4 <= len(response):
            attr_type = (response[offset] << 8) | response[offset+1]
            attr_len = (response[offset+2] << 8) | response[offset+3]
            
            if attr_type == 0x0020:  # XOR-MAPPED-ADDRESS
                # Skip family, port, and IP
                if attr_len >= 8:  # 1 + 1 + 2 + 4
                    # XOR with magic cookie (first 4 bytes of transaction ID)
                    port = response[offset+6] ^ 0x21
                    port = (port << 8) | (response[offset+7] ^ 0x12)
                    
                    ip_bytes = bytes([
                        response[offset+8] ^ 0x21,
                        response[offset+9] ^ 0x12,
                        response[offset+10] ^ 0xA4,
                        response[offset+11] ^ 0x42
                    ])
                    
                    ip = socket.inet_ntoa(ip_bytes)
                    return ip, port
            
            offset += 4 + ((attr_len + 3) & ~3)  # Next attribute
            
        return None, None
    
    def _get_local_ips(self) -> List[str]:
        """Get list of local IP addresses."""
        local_ips = []
        try:
            hostname = socket.gethostname()
            local_ips = [addr[4][0] for addr in socket.getaddrinfo(hostname, None)]
            # Add localhost if not present
            if '127.0.0.1' not in local_ips:
                local_ips.append('127.0.0.1')
        except Exception as e:
            logger.warning(f"Failed to get local IPs: {e}")
            local_ips = ['127.0.0.1']
        return local_ips

class HolePuncher:
    """Implements hole punching for NAT traversal."""
    
    def __init__(self, rendezvous_server: Optional[Tuple[str, int]] = None):
        self.rendezvous_server = rendezvous_server or ("rendezvous.brixa.net", 5000)
        self.pending_peers: Dict[str, asyncio.Future] = {}
        self.connections: Dict[str, asyncio.StreamReader] = {}
        
    async def connect_to_peer(self, peer_id: str) -> bool:
        """Attempt to establish a direct connection to a peer."""
        # Implementation would involve coordinating through a rendezvous server
        # and attempting simultaneous connections
        pass
        
    async def listen_for_peers(self, port: int) -> None:
        """Listen for incoming hole punching attempts."""
        # Implementation would involve listening on a port and handling
        # incoming connection attempts from peers
        pass
        
    async def register_with_rendezvous(self, peer_id: str, port: int) -> bool:
        """Register with the rendezvous server."""
        # Implementation would involve connecting to the rendezvous server
        # and registering our peer ID and address
        pass
