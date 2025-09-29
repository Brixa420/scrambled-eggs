"""
Tor Integration for Anonymous Communication
"""

import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional

import stem
from stem.control import Controller
from stem.process import launch_tor_with_config

logger = logging.getLogger(__name__)


class TorManager:
    """Manages Tor process and hidden services."""

    def __init__(
        self,
        tor_path: Optional[str] = None,
        tor_control_port: int = 9051,
        tor_socks_port: int = 9050,
        tor_data_dir: Optional[str] = None,
        tor_log: Optional[str] = None,
    ):
        """Initialize the Tor manager."""
        self.tor_path = tor_path or self._find_tor_binary()
        self.tor_control_port = tor_control_port
        self.tor_socks_port = tor_socks_port
        self.tor_process = None
        self.controller = None
        self.is_running = False

        # Set up directories
        if tor_data_dir:
            self.tor_data_dir = Path(tor_data_dir)
        else:
            self.tor_data_dir = Path(tempfile.mkdtemp(prefix="scrambled_eggs_tor_"))

        if tor_log:
            self.tor_log = Path(tor_log)
        else:
            self.tor_log = self.tor_data_dir / "tor.log"

        # Ensure directories exist
        self.tor_data_dir.mkdir(parents=True, exist_ok=True)
        self.tor_log.parent.mkdir(parents=True, exist_ok=True)

        # Hidden services configuration
        self.hidden_services: Dict[str, Dict[str, Any]] = {}

    def _find_tor_binary(self) -> Optional[str]:
        """Find the Tor binary in common locations."""
        common_paths = [
            "/usr/bin/tor",
            "/usr/local/bin/tor",
            "/usr/sbin/tor",
            "/usr/local/sbin/tor",
            "C:\\Program Files\\Tor\\tor.exe",
            "C:\\Program Files (x86)\\Tor\\tor.exe",
        ]

        for path in common_paths:
            if os.path.exists(path):
                return path

        # Try to find tor in PATH
        try:
            tor_path = (
                subprocess.check_output(["which", "tor"], stderr=subprocess.PIPE).decode().strip()
            )
            if tor_path:
                return tor_path
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass

        return None

    def start_tor(self) -> bool:
        """Start the Tor process."""
        if self.is_running:
            logger.warning("Tor is already running")
            return True

        if not self.tor_path or not os.path.exists(self.tor_path):
            logger.error(f"Tor binary not found at {self.tor_path}")
            return False

        try:
            # Configure Tor
            torrc_config = {
                "ControlPort": str(self.tor_control_port),
                "SOCKSPort": str(self.tor_socks_port),
                "DataDirectory": str(self.tor_data_dir),
                "Log": ["NOTICE file " + str(self.tor_log), "ERR file " + str(self.tor_log)],
                "ExitPolicy": "reject *:*",  # This is a client-only Tor
                "CookieAuthentication": "1",
                "AvoidDiskWrites": "1",
            }

            # Add hidden services configuration
            for service_name, service_config in self.hidden_services.items():
                hidden_service_dir = self.tor_data_dir / f"{service_name}_hidden_service"
                hidden_service_dir.mkdir(exist_ok=True, mode=0o700)

                torrc_config[f"HiddenServiceDir"] = str(hidden_service_dir)
                torrc_config[f"HiddenServicePort"] = (
                    f"{service_config['virtual_port']} {service_config['target']}"
                )

            logger.info("Starting Tor...")
            self.tor_process = launch_tor_with_config(
                config=torrc_config,
                init_msg_handler=self._log_tor_output,
                tor_cmd=self.tor_path,
                take_ownership=True,
                timeout=300,  # 5 minutes
            )

            # Connect to the control port
            self.controller = Controller.from_port(port=self.tor_control_port)
            self.controller.authenticate()

            self.is_running = True
            logger.info(f"Tor started successfully (PID: {self.tor_process.pid})")

            # Wait for the control port to be ready
            self._wait_for_control_port()

            return True

        except Exception as e:
            logger.error(f"Failed to start Tor: {e}")
            self.stop_tor()
            return False

    def stop_tor(self):
        """Stop the Tor process."""
        if not self.is_running:
            return

        try:
            # Try to shut down gracefully
            if self.controller:
                self.controller.close()
                self.controller = None

            if self.tor_process:
                if sys.platform == "win32":
                    self.tor_process.terminate()
                else:
                    os.kill(self.tor_process.pid, signal.SIGTERM)

                try:
                    self.tor_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.tor_process.kill()
                    self.tor_process.wait()

                self.tor_process = None

            self.is_running = False
            logger.info("Tor stopped successfully")

        except Exception as e:
            logger.error(f"Error stopping Tor: {e}")
            if self.tor_process:
                try:
                    self.tor_process.kill()
                except:
                    pass

            self.tor_process = None
            self.is_running = False

    def _wait_for_control_port(self, timeout: int = 30):
        """Wait for the Tor control port to be ready."""
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                if self.controller.is_alive():
                    return True
                time.sleep(0.1)
            except:
                time.sleep(0.1)

        raise TimeoutError("Timed out waiting for Tor control port")

    def _log_tor_output(self, line: str):
        """Log Tor output."""
        if "Bootstrapped" in line and "100%" in line:
            logger.info(f"Tor: {line.strip()}")
        elif "WARN" in line:
            logger.warning(f"Tor: {line.strip()}")
        elif "ERR" in line:
            logger.error(f"Tor: {line.strip()}")
        else:
            logger.debug(f"Tor: {line.strip()}")

    def add_hidden_service(
        self, service_name: str, virtual_port: int, target: str
    ) -> Optional[str]:
        """Add a hidden service.

        Args:
            service_name: A unique name for the service
            virtual_port: The port the service will be available on
            target: The target address (e.g., '127.0.0.1:8080')

        Returns:
            The .onion address if successful, None otherwise
        """
        if not service_name or not virtual_port or not target:
            logger.error("Invalid hidden service configuration")
            return None

        self.hidden_services[service_name] = {
            "virtual_port": virtual_port,
            "target": target,
            "onion_address": None,
        }

        # If Tor is already running, we need to restart it for the changes to take effect
        if self.is_running:
            logger.info("Restarting Tor to apply hidden service configuration...")
            self.stop_tor()
            self.start_tor()

        # Get the .onion address
        if self.is_running:
            try:
                service_dir = self.tor_data_dir / f"{service_name}_hidden_service"
                hostname_file = service_dir / "hostname"

                if hostname_file.exists():
                    with open(hostname_file, "r") as f:
                        onion_address = f.read().strip()
                        self.hidden_services[service_name]["onion_address"] = onion_address
                        return onion_address
            except Exception as e:
                logger.error(f"Failed to get .onion address: {e}")

        return None

    def get_onion_address(self, service_name: str) -> Optional[str]:
        """Get the .onion address for a hidden service."""
        service = self.hidden_services.get(service_name)
        if service:
            return service.get("onion_address")
        return None

    def get_socks_proxy(self) -> Dict[str, str]:
        """Get the SOCKS proxy configuration."""
        return {
            "http": f"socks5h://127.0.0.1:{self.tor_socks_port}",
            "https": f"socks5h://127.0.0.1:{self.tor_socks_port}",
        }

    def is_connected(self) -> bool:
        """Check if Tor is connected to the network."""
        if not self.is_running or not self.controller:
            return False

        try:
            # Try a simple operation to check connectivity
            self.controller.get_info("version")
            return True
        except:
            return False

    def new_identity(self) -> bool:
        """Request a new Tor circuit."""
        if not self.is_connected():
            return False

        try:
            self.controller.signal(stem.Signal.NEWNYM)
            logger.info("Requested new Tor circuit")
            return True
        except Exception as e:
            logger.error(f"Failed to request new Tor circuit: {e}")
            return False

    def get_network_status(self) -> Dict[str, Any]:
        """Get Tor network status information."""
        if not self.is_connected():
            return {"status": "disconnected"}

        try:
            info = {
                "status": "connected",
                "version": self.controller.get_version().version_str,
                "circuit_established": self.controller.is_circuit_established(),
                "exit_policy": self.controller.get_exit_policy(),
                "bandwidth_used": self.controller.get_info("traffic/read"),
                "uptime": self.controller.get_info("uptime"),
                "hidden_services": {},
            }

            # Add hidden service information
            for name, service in self.hidden_services.items():
                info["hidden_services"][name] = {
                    "onion_address": service.get("onion_address"),
                    "virtual_port": service.get("virtual_port"),
                    "target": service.get("target"),
                }

            return info

        except Exception as e:
            logger.error(f"Failed to get Tor status: {e}")
            return {"status": "error", "error": str(e)}

    def __del__(self):
        """Clean up resources."""
        self.stop_tor()


class TorBrowser:
    """Tor Browser integration for the application."""

    def __init__(self, tor_manager: TorManager):
        """Initialize the Tor Browser integration."""
        self.tor_manager = tor_manager
        self.browser_process = None

    def launch_browser(self, url: str = "about:blank"):
        """Launch the Tor Browser with the specified URL."""
        # This is a placeholder for actual Tor Browser integration
        # In a real implementation, this would launch the Tor Browser bundle
        # with the appropriate configuration to use the embedded Tor process

        logger.info(f"Launching Tor Browser with URL: {url}")

        # Check if Tor is running
        if not self.tor_manager.is_connected():
            logger.error("Tor is not connected. Cannot launch Tor Browser.")
            return False

        # This is a simplified example - in a real implementation, you would:
        # 1. Locate the Tor Browser bundle
        # 2. Configure it to use the embedded Tor process
        # 3. Launch it with the specified URL

        logger.warning("Tor Browser launch not fully implemented in this example")
        return False

    def close_browser(self):
        """Close the Tor Browser."""
        if self.browser_process:
            try:
                self.browser_process.terminate()
                self.browser_process.wait(timeout=5)
            except:
                try:
                    self.browser_process.kill()
                except:
                    pass
            finally:
                self.browser_process = None


# Example usage
if __name__ == "__main__":
    import logging

    logging.basicConfig(level=logging.INFO)

    # Create a temporary directory for Tor data
    import tempfile

    temp_dir = tempfile.mkdtemp(prefix="tor_test_")

    # Initialize Tor manager
    tor = TorManager(
        tor_data_dir=os.path.join(temp_dir, "tor_data"), tor_log=os.path.join(temp_dir, "tor.log")
    )

    try:
        # Start Tor
        if tor.start_tor():
            print("Tor started successfully!")

            # Add a hidden service
            onion_address = tor.add_hidden_service("scrambled_eggs", 80, "127.0.0.1:8080")
            if onion_address:
                print(f"Hidden service available at: {onion_address}")

            # Print network status
            print("\nTor Network Status:")
            import pprint

            pprint.pprint(tor.get_network_status())

            # Keep running until interrupted
            print("\nPress Ctrl+C to stop...")
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        # Clean up
        tor.stop_tor()
        print("Tor stopped")
