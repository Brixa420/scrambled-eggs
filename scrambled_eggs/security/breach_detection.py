"""
Breach Detection
----------------

Implements advanced breach detection using system call monitoring,
file integrity checking, and behavioral analysis.
"""
import os
import hashlib
import logging
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Callable, Any
import psutil

class BreachDetector:
    """Advanced breach detection system."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the breach detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.known_hashes: Dict[str, str] = {}
        self.suspicious_processes: Set[str] = set()
        self.detection_rules = self._load_detection_rules()
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.8)
        self._setup_os_specific_detectors()
    
    def _setup_os_specific_detectors(self) -> None:
        """Setup OS-specific detection mechanisms."""
        system = platform.system().lower()
        if 'windows' in system:
            self._setup_windows_detectors()
        elif 'linux' in system:
            self._setup_linux_detectors()
        elif 'darwin' in system:
            self._setup_macos_detectors()
    
    def _setup_windows_detectors(self) -> None:
        """Setup Windows-specific detection rules."""
        self.suspicious_processes.update([
            'mimikatz.exe', 'procdump.exe', 'psexec.exe',
            'powershell.exe -enc', 'certutil -decode',
            'wmic process call create', 'bitsadmin /transfer'
        ])
    
    def _setup_linux_detectors(self) -> None:
        """Setup Linux-specific detection rules."""
        self.suspicious_processes.update([
            'chmod 777', 'chattr -i', 'setuid', 'setgid',
            'nc -e /bin/bash', 'python -c', 'perl -e',
            'bash -i >& /dev/tcp', 'wget http', 'curl -s http'
        ])
    
    def _setup_macos_detectors(self) -> None:
        """Setup macOS-specific detection rules."""
        self.suspicious_processes.update([
            'osascript -e', 'pkill -f', 'sudo rm -rf',
            'chmod +x', 'launchctl load', 'kextload'
        ])
    
    def _load_detection_rules(self) -> List[Dict[str, Any]]:
        """Load detection rules from configuration."""
        return self.config.get('detection_rules', [
            {
                'name': 'suspicious_process',
                'description': 'Detect suspicious process execution',
                'severity': 'high',
                'enabled': True
            },
            {
                'name': 'file_modification',
                'description': 'Detect unauthorized file modifications',
                'severity': 'medium',
                'enabled': True
            },
            {
                'name': 'unusual_network_activity',
                'description': 'Detect unusual network connections',
                'severity': 'high',
                'enabled': True
            },
            {
                'name': 'privilege_escalation',
                'description': 'Detect privilege escalation attempts',
                'severity': 'critical',
                'enabled': True
            }
        ])
    
    def detect_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Detect suspicious processes."""
        alerts = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                for pattern in self.suspicious_processes:
                    if pattern.lower() in cmdline.lower():
                        alert = {
                            'type': 'suspicious_process',
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'cmdline': cmdline,
                            'user': proc.info['username'],
                            'severity': 'high',
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        alerts.append(alert)
                        self.logger.warning(f"Suspicious process detected: {alert}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return alerts
    
    def check_file_integrity(self, file_path: str) -> Dict[str, Any]:
        """Check file integrity using hash comparison."""
        try:
            file_hash = self._calculate_file_hash(file_path)
            
            if file_path in self.known_hashes:
                if self.known_hashes[file_path] != file_hash:
                    return {
                        'status': 'modified',
                        'file': file_path,
                        'expected_hash': self.known_hashes[file_path],
                        'current_hash': file_hash,
                        'severity': 'high',
                        'timestamp': datetime.utcnow().isoformat()
                    }
                return {'status': 'ok', 'file': file_path}
            
            # First time seeing this file, store its hash
            self.known_hashes[file_path] = file_hash
            return {'status': 'new_file', 'file': file_path}
            
        except Exception as e:
            return {
                'status': 'error',
                'file': file_path,
                'error': str(e),
                'severity': 'medium',
                'timestamp': datetime.utcnow().isoformat()
            }
    
    def _calculate_file_hash(self, file_path: str, algorithm: str = 'sha256') -> str:
        """Calculate file hash using specified algorithm."""
        hash_func = getattr(hashlib, algorithm.lower(), hashlib.sha256)
        hasher = hash_func()
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        
        return hasher.hexdigest()
    
    def detect_unusual_network_activity(self) -> List[Dict[str, Any]]:
        """Detect unusual network connections."""
        alerts = []
        known_ports = {80, 443, 53, 22, 3389}  # Common ports
        suspicious_ports = {4444, 31337, 666, 1337}  # Common malicious ports
        
        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.status == 'ESTABLISHED' and hasattr(conn, 'raddr') and conn.raddr:
                    port = conn.raddr.port
                    
                    # Check for suspicious ports
                    if port in suspicious_ports:
                        alert = {
                            'type': 'suspicious_port',
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'port': port,
                            'severity': 'high',
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        alerts.append(alert)
                        self.logger.warning(f"Suspicious network connection: {alert}")
                    
                    # Check for unusual ports (not in known_ports)
                    elif port not in known_ports and port > 1024:  # Non-privileged ports
                        alert = {
                            'type': 'unusual_port',
                            'local_address': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}",
                            'port': port,
                            'severity': 'medium',
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        alerts.append(alert)
                        self.logger.info(f"Unusual network connection: {alert}")
            except (psutil.NoSuchProcess, AttributeError):
                continue
        
        return alerts
    
    def detect_privilege_escalation(self) -> List[Dict[str, Any]]:
        """Detect privilege escalation attempts."""
        alerts = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'uids', 'gids']):
            try:
                # Check for processes running as root/Administrator
                if proc.info['username'] in ('root', 'SYSTEM', 'NT AUTHORITY\\SYSTEM'):
                    # Get parent process
                    parent = proc.parent()
                    if parent and parent.username() != proc.info['username']:
                        alert = {
                            'type': 'privilege_escalation',
                            'process': proc.info['name'],
                            'pid': proc.info['pid'],
                            'user': proc.info['username'],
                            'parent_pid': parent.pid,
                            'parent_name': parent.name(),
                            'parent_user': parent.username(),
                            'severity': 'critical',
                            'timestamp': datetime.utcnow().isoformat()
                        }
                        alerts.append(alert)
                        self.logger.critical(f"Possible privilege escalation: {alert}")
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        
        return alerts
    
    def run_detection(self) -> Dict[str, List[Dict[str, Any]] ]:
        """Run all enabled detection rules."""
        results = {}
        
        for rule in self.detection_rules:
            if not rule.get('enabled', True):
                continue
                
            if rule['name'] == 'suspicious_process':
                results['suspicious_processes'] = self.detect_suspicious_processes()
            
            elif rule['name'] == 'file_modification':
                # Check critical system files
                critical_files = [
                    '/etc/passwd', '/etc/shadow', '/etc/hosts',  # Linux
                    'C:\\Windows\\System32\\drivers\\etc\\hosts',  # Windows
                    '/System/Library/CoreServices/SystemVersion.plist'  # macOS
                ]
                results['file_integrity'] = [
                    self.check_file_integrity(f) 
                    for f in critical_files 
                    if os.path.exists(f)
                ]
            
            elif rule['name'] == 'unusual_network_activity':
                results['network_alerts'] = self.detect_unusual_network_activity()
            
            elif rule['name'] == 'privilege_escalation':
                results['privilege_alerts'] = self.detect_privilege_escalation()
        
        return results
