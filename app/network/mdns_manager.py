"""
mDNS (Multicast DNS) service for local network peer discovery.
"""
import socket
import time
import logging
import threading
import ipaddress
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from zeroconf import (
    ServiceInfo,
    Zeroconf,
    ServiceBrowser,
    ServiceListener,
    IPVersion
)

logger = logging.getLogger(__name__)

@dataclass
class PeerInfo:
    """Information about a discovered peer."""
    name: str
    address: str
    port: int
    properties: Dict[str, str] = field(default_factory=dict)
    last_seen: float = field(default_factory=time.time)

class MDNSListener(ServiceListener):
    """Listener for mDNS service discovery events."""
    
    def __init__(self, on_peer_added: Callable[[str, PeerInfo], None] = None,
                 on_peer_removed: Callable[[str], None] = None):
        """Initialize the listener with callback functions."""
        self.peers: Dict[str, PeerInfo] = {}
        self.on_peer_added = on_peer_added
        self.on_peer_removed = on_peer_removed
    
    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle service update events."""
        logger.debug(f"Service updated: {name}")
        self.add_service(zc, type_, name)
    
    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle service removal events."""
        logger.info(f"Service removed: {name}")
        if name in self.peers:
            if self.on_peer_removed:
                self.on_peer_removed(name)
            del self.peers[name]
    
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Handle new service events."""
        info = zc.get_service_info(type_, name)
        if not info:
            return
        
        # Get the first IPv4 address
        address = None
        for addr in info.addresses:
            try:
                # Convert from bytes to IPv4 address
                ip = socket.inet_ntoa(addr)
                if ipaddress.ip_address(ip).is_private:
                    address = ip
                    break
            except (socket.error, ValueError):
                continue
        
        if not address:
            logger.warning(f"No valid private IP address found for {name}")
            return
        
        # Create peer info
        peer = PeerInfo(
            name=name,
            address=address,
            port=info.port,
            properties=info.properties or {}
        )
        
        # Update or add peer
        is_new = name not in self.peers
        self.peers[name] = peer
        
        if is_new:
            logger.info(f"Discovered new peer: {name} at {address}:{info.port}")
            if self.on_peer_added:
                self.on_peer_added(name, peer)
        else:
            logger.debug(f"Updated peer: {name} at {address}:{info.port}")

class MDNSManager:
    """Manager for mDNS service discovery and advertisement."""
    
    def __init__(self, service_name: str = "_scrambledeggs._tcp.local.", 
                 service_port: int = 0, 
                 properties: Optional[Dict[str, str]] = None):
        """Initialize the mDNS manager.
        
        Args:
            service_name: The service type to advertise/discover
            service_port: The port to advertise (0 = don't advertise)
            properties: Additional properties to include in the service advertisement
        """
        self.service_name = service_name
        self.service_port = service_port
        self.properties = properties or {}
        
        self.zeroconf = None
        self.service_info = None
        self.listener = None
        self.browser = None
        self.running = False
        self.thread = None
    
    def start(self, on_peer_added: Callable[[str, PeerInfo], None] = None,
              on_peer_removed: Callable[[str], None] = None) -> None:
        """Start the mDNS service.
        
        Args:
            on_peer_added: Callback when a new peer is discovered
            on_peer_removed: Callback when a peer is removed
        """
        if self.running:
            return
        
        # Create a new thread for the mDNS service
        self.thread = threading.Thread(
            target=self._run,
            args=(on_peer_added, on_peer_removed),
            daemon=True
        )
        self.thread.start()
        self.running = True
    
    def _run(self, on_peer_added, on_peer_removed) -> None:
        """Internal method to run the mDNS service in a separate thread."""
        try:
            # Create Zeroconf instance
            self.zeroconf = Zeroconf(ip_version=IPVersion.V4Only)
            
            # Create and start the listener
            self.listener = MDNSListener(on_peer_added, on_peer_removed)
            self.browser = ServiceBrowser(
                self.zeroconf, 
                self.service_name, 
                listener=self.listener
            )
            
            # Advertise our own service if a port is specified
            if self.service_port > 0:
                self._advertise_service()
            
            # Keep the thread alive
            while self.running:
                time.sleep(1)
                
        except Exception as e:
            logger.error(f"mDNS service error: {e}")
            self.running = False
        finally:
            self._cleanup()
    
    def _advertise_service(self) -> None:
        """Advertise this service on the local network."""
        if not self.zeroconf or not self.service_port:
            return
        
        try:
            # Get local IP address
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # Create service info
            self.service_info = ServiceInfo(
                self.service_name,
                f"{hostname}.{self.service_name}",
                addresses=[socket.inet_aton(local_ip)],
                port=self.service_port,
                properties=self.properties,
                server=f"{hostname}.local."
            )
            
            # Register the service
            self.zeroconf.register_service(self.service_info)
            logger.info(f"mDNS service registered: {self.service_info.name} at {local_ip}:{self.service_port}")
            
        except Exception as e:
            logger.error(f"Failed to advertise mDNS service: {e}")
    
    def stop(self) -> None:
        """Stop the mDNS service."""
        if not self.running:
            return
        
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        self._cleanup()
    
    def _cleanup(self) -> None:
        """Clean up resources."""
        try:
            if self.service_info and self.zeroconf:
                self.zeroconf.unregister_service(self.service_info)
                self.service_info = None
            
            if self.zeroconf:
                self.zeroconf.close()
                self.zeroconf = None
                
        except Exception as e:
            logger.error(f"Error cleaning up mDNS service: {e}")
    
    def get_peers(self) -> List[PeerInfo]:
        """Get a list of discovered peers."""
        if not self.listener:
            return []
        return list(self.listener.peers.values())
    
    def get_peer(self, name: str) -> Optional[PeerInfo]:
        """Get a specific peer by name."""
        if not self.listener:
            return None
        return self.listener.peers.get(name)

# Example usage
if __name__ == "__main__":
    import json
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create and start the mDNS manager
    mdns = MDNSManager(
        service_name="_scrambledeggs._tcp.local.",
        service_port=5000,
        properties={"version": "1.0.0", "id": "test-peer-1"}
    )
    
    # Define callbacks
    def on_peer_added(name: str, peer: PeerInfo) -> None:
        print(f"Peer added: {name} at {peer.address}:{peer.port}")
        print(f"  Properties: {json.dumps(peer.properties, indent=2)}")
    
    def on_peer_removed(name: str) -> None:
        print(f"Peer removed: {name}")
    
    # Start the service
    print("Starting mDNS service...")
    mdns.start(on_peer_added=on_peer_added, on_peer_removed=on_peer_removed)
    
    try:
        # Keep the main thread alive
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping mDNS service...")
        mdns.stop()
