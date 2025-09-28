"""
Tor Manager for Scrambled Eggs

This module provides a high-level interface for managing Tor connections and
processes in the Scrambled Eggs application.
"""

import asyncio
import logging
import os
import platform
import shutil
import subprocess
import tempfile
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

import psutil
from stem import process
from stem.control import Controller, EventType, Signal
from stem.util import system

from .exceptions import (
    TorError, TorConnectionError, TorStartupError, TorConfigurationError
)

logger = logging.getLogger(__name__)

class TorState(Enum):
    """Represents the state of the Tor process."""
    STOPPED = 0
    STARTING = 1
    RUNNING = 2
    STOPPING = 3
    ERROR = 4

class TorManager:
    """Manages the Tor process and provides an interface to control it."""
    
    def __init__(
        self,
        tor_path: Optional[str] = None,
        data_dir: Optional[str] = None,
        control_port: int = 9051,
        socks_port: int = 9050,
        use_system_tor: bool = True,
        torrc: Optional[Dict[str, Union[str, int, bool, List[str]]]] = None
    ) -> None:
        """
        Initialize the Tor manager.
        
        Args:
            tor_path: Path to the Tor executable. If None, will try to find it.
            data_dir: Directory to store Tor data. If None, a temp directory will be used.
            control_port: Port for Tor control connection.
            socks_port: Port for Tor SOCKS proxy.
            use_system_tor: Whether to try using the system Tor if available.
            torrc: Additional Tor configuration options.
        """
        self.tor_path = tor_path
        self.control_port = control_port
        self.socks_port = socks_port
        self.use_system_tor = use_system_tor
        self.torrc = torrc or {}
        self.state = TorState.STOPPED
        self.process: Optional[process.launch_tor_with_config] = None
        self.controller: Optional[Controller] = None
        self._temp_dir = None
        
        # Set up data directory
        if data_dir:
            self.data_dir = Path(data_dir)
            self.data_dir.mkdir(parents=True, exist_ok=True)
        else:
            # Create a temporary directory that will be cleaned up on exit
            self._temp_dir = tempfile.TemporaryDirectory(prefix='scrambled-eggs-tor-')
            self.data_dir = Path(self._temp_dir.name)
        
        # Ensure Tor binary is available
        if not self.tor_path:
            self.tor_path = self._find_tor_binary()
        
        if not self.tor_path:
            raise TorError("Could not find Tor binary. Please install Tor or specify the path.")
        
        logger.info(f"Using Tor binary at: {self.tor_path}")
    
    def _find_tor_binary(self) -> Optional[str]:
        """Find the Tor binary on the system."""
        # Check common locations
        common_paths = [
            '/usr/bin/tor',
            '/usr/local/bin/tor',
            '/usr/sbin/tor',
            '/usr/local/sbin/tor',
            'C:\\Program Files\\Tor\\tor.exe',
            'C:\\Program Files (x86)\\Tor\\tor.exe'
        ]
        
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
        
        # Try 'which' or 'where' command
        try:
            if platform.system() == 'Windows':
                result = subprocess.run(['where', 'tor'], 
                                      capture_output=True, text=True, check=False)
            else:
                result = subprocess.run(['which', 'tor'], 
                                      capture_output=True, text=True, check=False)
            
            if result.returncode == 0 and os.path.isfile(result.stdout.strip()):
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return None
    
    async def start(self) -> None:
        """Start the Tor process."""
        if self.state != TorState.STOPPED:
            logger.warning("Tor is already running or starting up")
            return
        
        self.state = TorState.STARTING
        logger.info("Starting Tor...")
        
        try:
            # Prepare Tor configuration
            config = {
                'SocksPort': str(self.socks_port),
                'ControlPort': str(self.control_port),
                'DataDirectory': str(self.data_dir),
                'CookieAuthentication': '1',
                'Log': ['notice stdout', 'err stderr'],
            }
            
            # Add custom Tor configuration
            config.update(self.torrc)
            
            # Start Tor process
            self.process = await asyncio.to_thread(
                process.launch_tor_with_config,
                config=config,
                tor_cmd=self.tor_path,
                init_msg_handler=self._tor_status_callback,
                take_ownership=True,
                timeout=120,  # 2 minutes timeout
                completion_percent=100  # Wait for 100% bootstrap
            )
            
            # Create controller
            self.controller = await asyncio.to_thread(
                Controller.from_port,
                port=self.control_port
            )
            
            # Authenticate with the controller
            await asyncio.to_thread(self.controller.authenticate)
            
            # Set up event listeners
            self.controller.add_event_listener(
                self._handle_tor_event,
                EventType.STATUS_CLIENT,
                EventType.STATUS_GENERAL,
                EventType.STATUS_SERVER,
                EventType.WARN,
                EventType.ERR
            )
            
            self.state = TorState.RUNNING
            logger.info("Tor started successfully")
            
            # Get Tor version
            try:
                version = await asyncio.to_thread(
                    self.controller.get_version
                )
                logger.info(f"Tor version: {version}")
            except Exception as e:
                logger.warning(f"Could not get Tor version: {e}")
            
        except Exception as e:
            self.state = TorState.ERROR
            error_msg = f"Failed to start Tor: {str(e)}"
            logger.error(error_msg)
            await self.stop()
            raise TorStartupError(error_msg) from e
    
    async def stop(self) -> None:
        """Stop the Tor process."""
        if self.state in [TorState.STOPPED, TorState.STOPPING]:
            return
        
        self.state = TorState.STOPPING
        logger.info("Stopping Tor...")
        
        try:
            # Try to shut down Tor gracefully
            if self.controller:
                try:
                    await asyncio.to_thread(
                        self.controller.signal,
                        Signal.HALT
                    )
                except Exception as e:
                    logger.warning(f"Error sending HALT signal to Tor: {e}")
                
                try:
                    await asyncio.to_thread(self.controller.close)
                except Exception as e:
                    logger.warning(f"Error closing Tor controller: {e}")
            
            # If process is still running, terminate it
            if self.process and self.process.poll() is None:
                try:
                    # Try to terminate gracefully first
                    self.process.terminate()
                    try:
                        # Wait for process to terminate
                        await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None, self.process.wait
                            ),
                            timeout=10
                        )
                    except asyncio.TimeoutError:
                        # Force kill if it doesn't terminate
                        self.process.kill()
                        await asyncio.get_event_loop().run_in_executor(
                            None, self.process.wait
                        )
                except Exception as e:
                    logger.warning(f"Error stopping Tor process: {e}")
            
            # Clean up any remaining processes
            self._cleanup_tor_processes()
            
        except Exception as e:
            logger.error(f"Error during Tor shutdown: {e}")
        finally:
            self.process = None
            self.controller = None
            self.state = TorState.STOPPED
            logger.info("Tor stopped")
    
    def _cleanup_tor_processes(self) -> None:
        """Clean up any remaining Tor processes."""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    # Look for Tor processes started by us
                    if ('tor' in proc.info['name'].lower() or 
                        'tor.exe' in proc.info['name'].lower()) and \
                        any('DataDirectory' in ' '.join(cmd) for cmd in proc.info.get('cmdline', [])):
                        
                        logger.warning(f"Found orphaned Tor process (PID: {proc.pid}), terminating...")
                        proc.terminate()
                        try:
                            proc.wait(timeout=5)
                        except (psutil.TimeoutExpired, psutil.NoSuchProcess):
                            proc.kill()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception as e:
            logger.warning(f"Error during Tor process cleanup: {e}")
    
    def _tor_status_callback(self, line: str) -> None:
        """Callback for Tor status messages during startup."""
        if 'Bootstrapped' in line and '%' in line:
            percent = int(line.split('%')[0].split()[-1])
            logger.info(f"Tor bootstrap progress: {percent}%")
        elif 'Bootstrapped 100%' in line:
            logger.info("Tor bootstrap completed")
        elif 'WARN' in line or 'ERR' in line:
            logger.warning(f"Tor: {line.strip()}")
        else:
            logger.debug(f"Tor: {line.strip()}")
    
    def _handle_tor_event(self, event: 'stem.response.events.Event') -> None:
        """Handle Tor control port events."""
        logger.debug(f"Tor event: {event}")
        
        if event.action == 'CIRC' and 'BUILT' in event.status:
            logger.info("Tor circuit established")
        elif event.action == 'CIRC' and 'CLOSED' in event.status:
            logger.info("Tor circuit closed")
        elif event.action == 'NOTICE' and 'Tor has successfully opened a circuit' in event.status:
            logger.info("Tor circuit established successfully")
        elif event.action == 'WARN':
            logger.warning(f"Tor warning: {event.status}")
        elif event.action == 'ERR':
            logger.error(f"Tor error: {event.status}")
    
    async def is_connected(self) -> bool:
        """Check if Tor is connected to the network."""
        if not self.controller or self.state != TorState.RUNNING:
            return False
        
        try:
            # Check if we can get the network status
            await asyncio.to_thread(self.controller.get_network_statuses)
            return True
        except Exception as e:
            logger.warning(f"Tor connection check failed: {e}")
            return False
    
    async def new_identity(self) -> bool:
        """Request a new Tor circuit."""
        if not self.controller or self.state != TorState.RUNNING:
            return False
        
        try:
            await asyncio.to_thread(
                self.controller.signal,
                Signal.NEWNYM
            )
            logger.info("Requested new Tor identity")
            return True
        except Exception as e:
            logger.error(f"Failed to request new Tor identity: {e}")
            return False
    
    async def get_info(self, key: str) -> Optional[str]:
        """Get information from the Tor control port."""
        if not self.controller or self.state != TorState.RUNNING:
            return None
        
        try:
            return await asyncio.to_thread(
                self.controller.get_info,
                key
            )
        except Exception as e:
            logger.warning(f"Failed to get Tor info '{key}': {e}")
            return None
    
    async def get_external_ip(self) -> Optional[str]:
        """Get the external IP address through Tor."""
        return await self.get_info('address')
    
    async def get_circuit_info(self) -> List[Dict]:
        """Get information about active Tor circuits."""
        if not self.controller or self.state != TorState.RUNNING:
            return []
        
        try:
            circuits = await asyncio.to_thread(
                self.controller.get_circuits
            )
            
            result = []
            for circ in circuits:
                circuit_info = {
                    'id': circ.id,
                    'status': circ.status,
                    'purpose': circ.purpose,
                    'flags': circ.flags,
                    'build_flags': circ.build_flags,
                    'path': []
                }
                
                # Get the path (routers) for this circuit
                for node_fp, nick in circ.path:
                    try:
                        desc = await asyncio.to_thread(
                            self.controller.get_network_status,
                            node_fp
                        )
                        circuit_info['path'].append({
                            'fingerprint': node_fp,
                            'nickname': nick,
                            'address': desc.address if desc else None,
                            'country': desc.country if desc else None,
                            'bandwidth': desc.bandwidth if desc else None
                        })
                    except Exception as e:
                        logger.warning(f"Failed to get node info for {node_fp}: {e}")
                        circuit_info['path'].append({
                            'fingerprint': node_fp,
                            'nickname': nick,
                            'error': str(e)
                        })
                
                result.append(circuit_info)
            
            return result
        except Exception as e:
            logger.error(f"Failed to get circuit info: {e}")
            return []
    
    def get_socks_proxy(self) -> Optional[Tuple[str, int]]:
        """Get the SOCKS proxy address and port."""
        if self.state != TorState.RUNNING:
            return None
        return ('127.0.0.1', self.socks_port)
    
    def get_control_port(self) -> int:
        """Get the control port number."""
        return self.control_port
    
    def get_data_directory(self) -> Path:
        """Get the Tor data directory."""
        return self.data_dir
    
    def is_running(self) -> bool:
        """Check if Tor is running."""
        return self.state == TorState.RUNNING and self.process is not None and self.process.poll() is None
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.stop()
    
    def __del__(self):
        """Ensure Tor is stopped when the object is garbage collected."""
        if hasattr(self, 'state') and self.state != TorState.STOPPED:
            try:
                if self._temp_dir:
                    self._temp_dir.cleanup()
            except Exception as e:
                logger.warning(f"Error cleaning up temporary directory: {e}")
