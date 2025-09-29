"""
Threat Response
--------------
Implements automated response actions for detected threats.
"""

import logging
import os
import platform
import signal
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional


class ThreatResponder:
    """Automated threat response system."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the threat responder.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.response_actions = self._load_response_actions()
        self.alert_history: List[Dict[str, Any]] = []
        self._setup_os_specific_handlers()

    def _setup_os_specific_handlers(self) -> None:
        """Setup OS-specific response handlers."""
        system = platform.system().lower()
        if "windows" in system:
            self._setup_windows_handlers()
        elif "linux" in system:
            self._setup_linux_handlers()
        elif "darwin" in system:
            self._setup_macos_handlers()

    def _setup_windows_handlers(self) -> None:
        """Setup Windows-specific response handlers."""
        self.terminate_process = self._terminate_process_windows
        self.block_ip = self._block_ip_windows
        self.isolate_host = self._isolate_host_windows

    def _setup_linux_handlers(self) -> None:
        """Setup Linux-specific response handlers."""
        self.terminate_process = self._terminate_process_linux
        self.block_ip = self._block_ip_linux
        self.isolate_host = self._isolate_host_linux

    def _setup_macos_handlers(self) -> None:
        """Setup macOS-specific response handlers."""
        self.terminate_process = self._terminate_process_macos
        self.block_ip = self._block_ip_macos
        self.isolate_host = self._isolate_host_macos

    def _load_response_actions(self) -> List[Dict[str, Any]]:
        """Load response actions from configuration."""
        return self.config.get(
            "response_actions",
            [
                {
                    "name": "terminate_malicious_process",
                    "description": "Terminate processes identified as malicious",
                    "severity": "high",
                    "enabled": True,
                    "action": self.terminate_malicious_process,
                },
                {
                    "name": "block_suspicious_ip",
                    "description": "Block suspicious IP addresses",
                    "severity": "medium",
                    "enabled": True,
                    "action": self.block_suspicious_ip,
                },
                {
                    "name": "quarantine_file",
                    "description": "Quarantine malicious files",
                    "severity": "high",
                    "enabled": True,
                    "action": self.quarantine_file,
                },
                {
                    "name": "alert_admin",
                    "description": "Send alert to administrator",
                    "severity": "low",
                    "enabled": True,
                    "action": self.alert_admin,
                },
                {
                    "name": "isolate_host",
                    "description": "Isolate the host from the network",
                    "severity": "critical",
                    "enabled": True,
                    "action": self.isolate_host,
                },
            ],
        )

    def handle_threat(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Handle a detected threat with appropriate response actions."""
        response = {
            "threat": threat,
            "actions_taken": [],
            "success": False,
            "timestamp": time.time(),
        }

        try:
            # Log the threat
            self.logger.warning(f"Handling threat: {threat}")
            self.alert_history.append(threat)

            # Determine appropriate response actions based on threat severity
            severity = threat.get("severity", "medium").lower()

            # Execute response actions based on severity
            for action in self.response_actions:
                if not action.get("enabled", True):
                    continue

                # Check if action severity matches or is below threat severity
                action_severity = action.get("severity", "medium").lower()
                if self._severity_to_level(severity) >= self._severity_to_level(action_severity):
                    try:
                        result = action["action"](threat)
                        response["actions_taken"].append({"name": action["name"], "result": result})
                    except Exception as e:
                        self.logger.error(f"Error executing response action {action['name']}: {e}")
                        response["actions_taken"].append(
                            {"name": action["name"], "error": str(e), "success": False}
                        )

            response["success"] = any(
                action.get("success", False) for action in response["actions_taken"]
            )

            return response

        except Exception as e:
            self.logger.error(f"Error handling threat: {e}")
            response["error"] = str(e)
            return response

    def _severity_to_level(self, severity: str) -> int:
        """Convert severity string to numeric level."""
        severity_levels = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        return severity_levels.get(severity.lower(), 0)

    # Response Actions

    def terminate_malicious_process(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Terminate a malicious process."""
        result = {"action": "terminate_process", "success": False}

        if "pid" not in threat:
            result["error"] = "No process ID provided"
            return result

        try:
            pid = threat["pid"]
            self.terminate_process(pid)
            result.update({"success": True, "message": f"Terminated process {pid}"})
        except Exception as e:
            result["error"] = str(e)

        return result

    def block_suspicious_ip(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Block a suspicious IP address."""
        result = {"action": "block_ip", "success": False}

        # Extract IP from threat
        ip = threat.get("ip")
        if not ip:
            # Try to extract from remote_address if available
            remote = threat.get("remote_address", "")
            if ":" in remote:
                ip = remote.split(":")[0]
            else:
                ip = remote

        if not ip or ip in ("localhost", "127.0.0.1", "::1"):
            result["error"] = "Invalid or local IP address"
            return result

        try:
            self.block_ip(ip)
            result.update({"success": True, "message": f"Blocked IP {ip}"})
        except Exception as e:
            result["error"] = str(e)

        return result

    def quarantine_file(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine a malicious file."""
        result = {"action": "quarantine_file", "success": False}

        file_path = threat.get("file_path")
        if not file_path or not os.path.exists(file_path):
            result["error"] = "File not found"
            return result

        try:
            # Create quarantine directory if it doesn't exist
            quarantine_dir = self.config.get("quarantine_dir", "/var/quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)

            # Generate a unique filename
            import hashlib
            import shutil

            file_hash = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
            base_name = os.path.basename(file_path)
            quarantined_path = os.path.join(quarantine_dir, f"{file_hash}_{base_name}")

            # Move file to quarantine
            shutil.move(file_path, quarantined_path)

            # Remove execute permissions
            os.chmod(quarantined_path, 0o400)

            result.update(
                {
                    "success": True,
                    "message": f"Quarantined file to {quarantined_path}",
                    "original_path": file_path,
                    "quarantined_path": quarantined_path,
                    "file_hash": file_hash,
                }
            )

        except Exception as e:
            result["error"] = str(e)

        return result

    def alert_admin(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Send an alert to the administrator."""
        result = {"action": "alert_admin", "success": False}

        try:
            # In a real implementation, this would send an email, SMS, or other notification
            self.logger.critical(f"SECURITY ALERT: {threat}")

            result.update(
                {
                    "success": True,
                    "message": "Alert sent to administrator",
                    "threat_details": threat,
                }
            )

        except Exception as e:
            result["error"] = str(e)

        return result

    # Platform-specific implementations

    def _terminate_process_windows(self, pid: int) -> None:
        """Terminate a process on Windows."""
        import ctypes

        PROCESS_TERMINATE = 0x0001
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        ctypes.windll.kernel32.TerminateProcess(handle, -1)
        ctypes.windll.kernel32.CloseHandle(handle)

    def _terminate_process_linux(self, pid: int) -> None:
        """Terminate a process on Linux."""
        os.kill(pid, signal.SIGKILL)

    def _terminate_process_macos(self, pid: int) -> None:
        """Terminate a process on macOS."""
        os.kill(pid, signal.SIGKILL)

    def _block_ip_windows(self, ip: str) -> None:
        """Block an IP address on Windows."""
        rule_name = f"Block_{ip}"
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={rule_name}",
                "dir=out",
                "action=block",
                f"remoteip={ip}",
            ],
            check=True,
        )

    def _block_ip_linux(self, ip: str) -> None:
        """Block an IP address on Linux."""
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"], check=True)

    def _block_ip_macos(self, ip: str) -> None:
        """Block an IP address on macOS."""
        subprocess.run(["pfctl", "-t", "blocked_ips", "-T", "add", ip], check=True)

    def _isolate_host_windows(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate the Windows host from the network."""
        result = {"action": "isolate_host", "success": False}

        try:
            # Disable all network adapters
            subprocess.run(["netsh", "interface", "set", "interface", "admin=disable"], check=True)

            # Block all outbound connections
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"], check=True
            )

            result.update(
                {
                    "success": True,
                    "message": "Host isolated from network",
                    "actions": ["disabled_network_adapters", "enabled_firewall"],
                }
            )

        except Exception as e:
            result["error"] = str(e)

        return result

    def _isolate_host_linux(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate the Linux host from the network."""
        result = {"action": "isolate_host", "success": False}

        try:
            # Block all incoming and outgoing traffic
            subprocess.run(["iptables", "-P", "INPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "OUTPUT", "DROP"], check=True)
            subprocess.run(["iptables", "-P", "FORWARD", "DROP"], check=True)

            # Flush all existing rules
            subprocess.run(["iptables", "-F"], check=True)

            result.update(
                {
                    "success": True,
                    "message": "Host isolated from network",
                    "actions": ["blocked_all_network_traffic"],
                }
            )

        except Exception as e:
            result["error"] = str(e)

        return result

    def _isolate_host_macos(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """Isolate the macOS host from the network."""
        result = {"action": "isolate_host", "success": False}

        try:
            # Disable all network services
            subprocess.run(["networksetup", "-setairportpower", "airport", "off"], check=True)
            subprocess.run(
                ["networksetup", "-setnetworkserviceenabled", "Ethernet", "off"], check=True
            )

            # Enable firewall with maximum settings
            subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"],
                check=True,
            )
            subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setblockall", "on"],
                check=True,
            )

            result.update(
                {
                    "success": True,
                    "message": "Host isolated from network",
                    "actions": ["disabled_network_adapters", "enabled_firewall"],
                }
            )

        except Exception as e:
            result["error"] = str(e)

        return result
