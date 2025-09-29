"""
NAT Traversal for Brixa P2P Network

Implements techniques for nodes behind NATs/firewalls to establish direct connections.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Tuple, Set
import aiohttp
import socket
import struct
import random
import time
from dataclasses import dataclass

# Configure logging
logger = logging.getLogger(__name__)

@dataclass
class NATMapping:
    """Represents a NAT port mapping."""
    internal_port: int
    external_port: int
    protocol: str = "TCP"
    lifetime: int = 3600  # seconds
    last_used: float = 0.0

class NATTraversal:
    """Handles NAT traversal for P2P connections."""

    def __init__(self, p2p_node, stun_servers: Optional[List[Tuple[str, int]]] = None):
        self.p2p_node = p2p_node
        self.stun_servers = stun_servers or [
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302),
            ("stun.voipbuster.com", 3478)
        ]
        self.port_mappings: Dict[Tuple[str, int], NATMapping] = {}
        self.upnp_enabled = False
        self.pcp_enabled = False
        
    async def initialize(self) -> None:
        """Initialize NAT traversal by detecting NAT type and setting up mappings."""
        # Try UPnP first
        if await self._try_upnp():
            self.upnp_enabled = True
            logger.info("NAT: UPnP port mapping enabled")
        # Then try PCP
        elif await self._try_pcp():
            self.pcp_enabled = True
            logger.info("NAT: PCP port mapping enabled")
        else:
            logger.warning("NAT: Could not set up automatic port mapping")
        
        # Get external IP and port using STUN
        ext_ip, ext_port = await self.get_public_address()
        if ext_ip and ext_port:
            logger.info(f"NAT: External address: {ext_ip}:{ext_port}")
    
    async def _try_upnp(self) -> bool:
        """Try to set up port mapping using UPnP IGD."""
        try:
            import miniupnpc
            upnp = miniupnpc.UPnP()
            upnp.discoverdelay = 200
            logger.debug("NAT: Searching for UPnP devices...")
            ndevices = upnp.discover()
            if ndevices > 0:
                upnp.selectigd()
                # Try to add port mapping
                external_port = self.p2p_node.port
                internal_ip = upnp.lanaddr
                internal_port = self.p2p_node.port
                upnp.addportmapping(
                    external_port, 'TCP', internal_ip, internal_port,
                    'Brixa P2P', ''
                )
                self.port_mappings[('TCP', external_port)] = NATMapping(
                    internal_port=internal_port,
                    external_port=external_port,
                    protocol='TCP'
                )
                return True
        except Exception as e:
            logger.warning(f"NAT: UPnP failed: {e}")
        return False
    
    async def _try_pcp(self) -> bool:
        """Try to set up port mapping using PCP (Port Control Protocol)."""
        # TODO: Implement PCP support
        return False
    
    async def get_public_address(self) -> Tuple[Optional[str], Optional[int]]:
        """Get the public IP and port using STUN."""
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
                        # Parse XOR-MAPPED-ADDRESS attribute
                        # This is a simplified parser - a real implementation would be more robust
                        if response[0] == 1 and response[1] == 1:  # Binding response
                            return self._parse_stun_response(response)
                except asyncio.TimeoutError:
                    logger.warning(f"NAT: STUN request to {stun_host} timed out")
                
                writer.close()
                await writer.wait_closed()
                
            except Exception as e:
                logger.warning(f"NAT: STUN request to {stun_host} failed: {e}")
                continue
                
        return None, None
    
    def _parse_stun_response(self, response: bytes) -> Tuple[Optional[str], Optional[int]]:
        """Parse STUN response to extract mapped address."""
        # This is a simplified STUN parser
        # A real implementation would properly parse all attributes
        
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
    
    async def close(self) -> None:
        """Clean up NAT mappings."""
        if self.upnp_enabled:
            try:
                import miniupnpc
                upnp = miniupnpc.UPnP()
                upnp.discoverdelay = 100
                if upnp.discover() > 0:
                    upnp.selectigd()
                    for mapping in self.port_mappings.values():
                        upnp.deleteportmapping(mapping.external_port, 'TCP')
            except Exception as e:
                logger.warning(f"NAT: Error cleaning up UPnP mappings: {e}")
