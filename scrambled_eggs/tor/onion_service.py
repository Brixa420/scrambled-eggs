"""
Onion Service Management for Scrambled Eggs

This module provides functionality to create and manage Tor hidden services
for the Scrambled Eggs P2P messaging application.
"""

import asyncio
import base64
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from stem.control import Controller
from stem.descriptor.hidden_service import HiddenServiceDescriptor

from .exceptions import TorServiceError

logger = logging.getLogger(__name__)

@dataclass
class OnionServiceConfig:
    """Configuration for a Tor hidden service."""
    # Service settings
    name: str = "scrambled-eggs"
    version: int = 3  # Default to v3 for better security
    virtual_port: int = 80
    target_address: str = "127.0.0.1"
    target_port: int = 8080
    
    # Authentication settings
    client_auth: bool = False
    max_streams: int = 10
    
    # Hidden service directory settings
    data_dir: Optional[Path] = None
    private_key: Optional[bytes] = None
    
    # Service options
    single_hop: bool = False
    non_anonymous: bool = False
    
    # Additional options
    options: Dict[str, Union[str, int, bool]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate configuration after initialization."""
        if self.version not in [2, 3]:
            raise ValueError("Onion service version must be 2 or 3")
        
        if self.virtual_port < 1 or self.virtual_port > 65535:
            raise ValueError("Virtual port must be between 1 and 65535")
        
        if self.target_port < 1 or self.target_port > 65535:
            raise ValueError("Target port must be between 1 and 65535")
        
        # Set default data directory if not provided
        if self.data_dir is None:
            self.data_dir = Path.home() / ".scrambled-eggs" / "onion-services" / self.name
        
        # Ensure data directory exists
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate private key if not provided
        if self.private_key is None:
            if self.version == 3:
                # Generate a new v3 private key
                private_key = x25519.X25519PrivateKey.generate()
                self.private_key = private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                )
                logger.info("Generated new v3 private key for onion service")
            else:
                # For v2, we'll let Tor generate the key
                pass

class OnionService:
    """Manages a Tor hidden service."""
    
    def __init__(self, controller: Controller, config: OnionServiceConfig) -> None:
        """
        Initialize the OnionService.
        
        Args:
            controller: An authenticated Tor controller.
            config: Configuration for the hidden service.
        """
        self.controller = controller
        self.config = config
        self.service_id: Optional[str] = None
        self.hostname: Optional[str] = None
        self.private_key: Optional[str] = None
        self.is_running: bool = False
        
        # Set up service directory
        self.service_dir = self.config.data_dir / f"{self.config.name}"
        self.service_dir.mkdir(parents=True, exist_ok=True)
        
        # Set up key file
        self.key_file = self.service_dir / "private_key"
        
        logger.info(f"Initialized OnionService '{self.config.name}'")
    
    async def start(self) -> str:
        """
        Start the hidden service.
        
        Returns:
            The .onion address of the service.
            
        Raises:
            TorServiceError: If the service fails to start.
        """
        if self.is_running:
            logger.warning("Onion service is already running")
            return self.hostname or ""
        
        try:
            # Prepare the service configuration
            service_config = {
                'key_type': 'ED25519-V3' if self.config.version == 3 else 'RSA1024',
                'key_content': self.config.private_key.hex() if self.config.private_key else None,
                'ports': [f"{self.config.virtual_port} {self.config.target_address}:{self.config.target_port}"],
                'max_streams': self.config.max_streams,
                'single_hop': self.config.single_hop,
                'non_anonymous': self.config.non_anonymous,
                **self.config.options
            }
            
            # Create the hidden service
            response = await asyncio.to_thread(
                self.controller.create_ephemeral_hidden_service,
                str(self.service_dir),
                **{k: v for k, v in service_config.items() if v is not None}
            )
            
            # Extract service details
            self.service_id = response.service_id
            self.hostname = f"{self.service_id}.onion"
            self.private_key = response.private_key
            self.is_running = True
            
            logger.info(f"Started onion service at {self.hostname}")
            
            # Save the private key if it was generated by Tor
            if not self.config.private_key and self.private_key:
                self._save_private_key()
            
            return self.hostname
            
        except Exception as e:
            error_msg = f"Failed to start onion service: {str(e)}"
            logger.error(error_msg)
            self.is_running = False
            raise TorServiceError(error_msg) from e
    
    async def stop(self) -> None:
        """Stop the hidden service."""
        if not self.is_running:
            return
        
        try:
            if self.service_id:
                await asyncio.to_thread(
                    self.controller.remove_ephemeral_hidden_service,
                    self.service_id
                )
                logger.info(f"Stopped onion service {self.hostname}")
        except Exception as e:
            logger.error(f"Error stopping onion service: {e}")
        finally:
            self.is_running = False
            self.service_id = None
            self.hostname = None
    
    async def get_service_descriptor(self) -> Optional[HiddenServiceDescriptor]:
        """
        Get the hidden service descriptor.
        
        Returns:
            The hidden service descriptor or None if not available.
        """
        if not self.service_id:
            return None
            
        try:
            return await asyncio.to_thread(
                self.controller.get_hidden_service_descriptor,
                self.service_id
            )
        except Exception as e:
            logger.warning(f"Failed to get service descriptor: {e}")
            return None
    
    async def add_port_mapping(
        self, 
        virtual_port: int, 
        target_address: str, 
        target_port: int
    ) -> bool:
        """
        Add a port mapping to the hidden service.
        
        Args:
            virtual_port: The virtual port on the hidden service.
            target_address: The target address to forward to.
            target_port: The target port to forward to.
            
        Returns:
            True if the mapping was added successfully, False otherwise.
        """
        if not self.is_running or not self.service_id:
            logger.warning("Cannot add port mapping: service not running")
            return False
            
        try:
            await asyncio.to_thread(
                self.controller.create_ephemeral_hidden_service,
                str(self.service_dir),
                ports=[f"{virtual_port} {target_address}:{target_port}"],
                await_publication=True
            )
            logger.info(f"Added port mapping: {virtual_port} -> {target_address}:{target_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to add port mapping: {e}")
            return False
    
    async def remove_port_mapping(self, virtual_port: int) -> bool:
        """
        Remove a port mapping from the hidden service.
        
        Args:
            virtual_port: The virtual port to remove.
            
        Returns:
            True if the mapping was removed successfully, False otherwise.
        """
        if not self.is_running or not self.service_id:
            logger.warning("Cannot remove port mapping: service not running")
            return False
            
        try:
            # To remove a port, we need to recreate the service without that port
            current_ports = await self.get_mapped_ports()
            if not current_ports:
                return False
                
            # Remove the specified port
            updated_ports = [
                f"{vport} {addr}" for vport, addr in current_ports.items()
                if vport != virtual_port
            ]
            
            if len(updated_ports) == len(current_ports):
                logger.warning(f"Port {virtual_port} not found in current mappings")
                return False
                
            # Recreate the service with the updated ports
            await asyncio.to_thread(
                self.controller.create_ephemeral_hidden_service,
                str(self.service_dir),
                ports=updated_ports,
                await_publication=True
            )
            
            logger.info(f"Removed port mapping for {virtual_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove port mapping: {e}")
            return False
    
    async def get_mapped_ports(self) -> Dict[int, str]:
        """
        Get all mapped ports for this hidden service.
        
        Returns:
            A dictionary mapping virtual ports to target addresses.
        """
        if not self.is_running or not self.service_id:
            return {}
            
        try:
            # Get the current hidden service configuration
            hs_descriptor = await self.get_service_descriptor()
            if not hs_descriptor:
                return {}
                
            # Extract port mappings
            port_mappings = {}
            for introduction_point in hs_descriptor.introduction_points():
                for port, address in introduction_point.ip_port_mappings():
                    port_mappings[port] = address
                    
            return port_mappings
            
        except Exception as e:
            logger.warning(f"Failed to get mapped ports: {e}")
            return {}
    
    def _save_private_key(self) -> None:
        """Save the private key to a file."""
        if not self.private_key:
            return
            
        try:
            with open(self.key_file, 'w') as f:
                f.write(self.private_key)
            
            # Set appropriate permissions
            os.chmod(self.key_file, 0o600)
            logger.info(f"Saved private key to {self.key_file}")
            
        except Exception as e:
            logger.error(f"Failed to save private key: {e}")
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    def __str__(self) -> str:
        """String representation of the service."""
        status = "running" if self.is_running else "stopped"
        return f"OnionService(name='{self.config.name}', status='{status}', hostname='{self.hostname}')"
