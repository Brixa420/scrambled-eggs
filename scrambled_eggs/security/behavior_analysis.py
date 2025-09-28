"""
Behavior Analysis
----------------
Implements behavioral analysis for detecting anomalies in process behavior,
user activity, and system interactions.
"""
import os
import time
import json
import logging
import psutil
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Any, Callable
from collections import defaultdict, deque

class BehaviorAnalyzer:
    """Behavioral analysis engine for anomaly detection."""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the behavior analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Behavioral baselines
        self.process_baseline: Dict[str, Dict] = {}
        self.user_baseline: Dict[str, Dict] = {}
        self.network_baseline: Dict[str, Dict] = {}
        
        # Activity tracking
        self.process_activity: Dict[int, Dict] = {}
        self.user_activity: Dict[str, Dict] = {}
        self.network_activity: Dict[str, List] = defaultdict(list)
        
        # Thresholds (can be configured)
        self.anomaly_threshold = self.config.get('anomaly_threshold', 0.8)
        self.learning_period = self.config.get('learning_period', 7)  # days
        self.window_size = self.config.get('window_size', 60)  # seconds
        
        # Initialize baselines
        self._initialize_baselines()
    
    def _initialize_baselines(self) -> None:
        """Initialize behavioral baselines."""
        # Load baselines from file if they exist
        baseline_file = self.config.get('baseline_file', 'behavior_baseline.json')
        if os.path.exists(baseline_file):
            try:
                with open(baseline_file, 'r') as f:
                    baselines = json.load(f)
                    self.process_baseline = baselines.get('process', {})
                    self.user_baseline = baselines.get('user', {})
                    self.network_baseline = baselines.get('network', {})
                self.logger.info("Loaded behavioral baselines from file")
            except Exception as e:
                self.logger.error(f"Error loading baselines: {e}")
    
    def save_baselines(self) -> None:
        """Save current baselines to file."""
        baseline_file = self.config.get('baseline_file', 'behavior_baseline.json')
        try:
            with open(baseline_file, 'w') as f:
                json.dump({
                    'process': self.process_baseline,
                    'user': self.user_baseline,
                    'network': self.network_baseline,
                    'last_updated': datetime.utcnow().isoformat()
                }, f, indent=2)
            self.logger.info("Saved behavioral baselines to file")
        except Exception as e:
            self.logger.error(f"Error saving baselines: {e}")
    
    def analyze_process_behavior(self, process: psutil.Process) -> Dict[str, Any]:
        """Analyze process behavior against baseline."""
        try:
            pid = process.pid
            name = process.name()
            exe = process.exe()
            cmdline = ' '.join(process.cmdline())
            
            # Get process metrics
            cpu_percent = process.cpu_percent(interval=0.1)
            memory_info = process.memory_info()
            memory_percent = process.memory_percent()
            
            # Create process signature
            process_sig = {
                'name': name,
                'exe': exe,
                'cmdline': cmdline,
                'cpu_usage': cpu_percent,
                'memory_usage': memory_percent,
                'rss': memory_info.rss,
                'vms': memory_info.vms,
                'num_threads': process.num_threads(),
                'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0,
                'num_handles': process.num_handles() if hasattr(process, 'num_handles') else 0,
                'create_time': process.create_time(),
                'timestamp': time.time()
            }
            
            # Check against baseline
            baseline = self.process_baseline.get(name, {})
            anomalies = self._detect_anomalies(process_sig, baseline)
            
            # Update baseline if in learning mode
            if self.config.get('learning_mode', False):
                self._update_baseline('process', name, process_sig)
            
            return {
                'process': name,
                'pid': pid,
                'baseline': baseline,
                'current': process_sig,
                'anomalies': anomalies,
                'is_anomaly': len(anomalies) > 0
            }
            
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
            return {'error': str(e), 'process': process.pid if 'process' in locals() else 'unknown'}
    
    def analyze_user_behavior(self, username: str) -> Dict[str, Any]:
        """Analyze user behavior against baseline."""
        try:
            # Get user processes
            user_processes = []
            for proc in psutil.process_iter(['username', 'name', 'cmdline', 'create_time']):
                try:
                    if proc.info['username'] == username:
                        user_processes.append({
                            'name': proc.info['name'],
                            'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                            'create_time': proc.info['create_time']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Get user logins
            logins = []
            if hasattr(psutil, 'users'):
                for user in psutil.users():
                    if user.name == username:
                        logins.append({
                            'terminal': user.terminal,
                            'host': user.host,
                            'started': user.started,
                            'pid': user.pid
                        })
            
            # Create user activity signature
            user_sig = {
                'username': username,
                'processes': user_processes,
                'logins': logins,
                'active_sessions': len(logins),
                'timestamp': time.time()
            }
            
            # Check against baseline
            baseline = self.user_baseline.get(username, {})
            anomalies = self._detect_anomalies(user_sig, baseline)
            
            # Update baseline if in learning mode
            if self.config.get('learning_mode', False):
                self._update_baseline('user', username, user_sig)
            
            return {
                'username': username,
                'baseline': baseline,
                'current': user_sig,
                'anomalies': anomalies,
                'is_anomaly': len(anomalies) > 0
            }
            
        except Exception as e:
            return {'error': str(e), 'username': username}
    
    def analyze_network_behavior(self, host: str, port: int) -> Dict[str, Any]:
        """Analyze network behavior against baseline."""
        try:
            # Track network activity
            conn_key = f"{host}:{port}"
            timestamp = time.time()
            
            # Add to activity log
            self.network_activity[conn_key].append(timestamp)
            
            # Remove old entries (outside of window)
            window_start = timestamp - self.window_size
            self.network_activity[conn_key] = [t for t in self.network_activity[conn_key] if t >= window_start]
            
            # Calculate metrics
            connection_count = len(self.network_activity[conn_key])
            connection_rate = connection_count / self.window_size  # connections per second
            
            # Create network signature
            network_sig = {
                'host': host,
                'port': port,
                'connection_count': connection_count,
                'connection_rate': connection_rate,
                'timestamp': timestamp
            }
            
            # Check against baseline
            baseline = self.network_baseline.get(conn_key, {})
            anomalies = self._detect_anomalies(network_sig, baseline)
            
            # Update baseline if in learning mode
            if self.config.get('learning_mode', False):
                self._update_baseline('network', conn_key, network_sig)
            
            return {
                'connection': conn_key,
                'baseline': baseline,
                'current': network_sig,
                'anomalies': anomalies,
                'is_anomaly': len(anomalies) > 0
            }
            
        except Exception as e:
            return {'error': str(e), 'host': host, 'port': port}
    
    def _detect_anomalies(self, current: Dict[str, Any], baseline: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies between current and baseline behavior."""
        anomalies = []
        
        # Skip if no baseline yet
        if not baseline:
            return anomalies
        
        # Check each metric in the baseline
        for metric, baseline_value in baseline.items():
            if metric not in current:
                continue
                
            current_value = current[metric]
            
            # Skip non-numeric comparisons for now
            if not isinstance(baseline_value, (int, float)) or not isinstance(current_value, (int, float)):
                continue
            
            # Calculate deviation from baseline
            if baseline_value != 0:
                deviation = abs(current_value - baseline_value) / baseline_value
            else:
                deviation = abs(current_value)
            
            # Check if deviation exceeds threshold
            if deviation > self.anomaly_threshold:
                anomalies.append({
                    'metric': metric,
                    'baseline': baseline_value,
                    'current': current_value,
                    'deviation': deviation,
                    'threshold': self.anomaly_threshold
                })
        
        return anomalies
    
    def _update_baseline(self, baseline_type: str, key: str, current: Dict[str, Any]) -> None:
        """Update the baseline with current values (exponential moving average)."""
        alpha = self.config.get('learning_rate', 0.1)  # Learning rate
        
        if baseline_type == 'process':
            baseline = self.process_baseline.setdefault(key, {})
        elif baseline_type == 'user':
            baseline = self.user_baseline.setdefault(key, {})
        elif baseline_type == 'network':
            baseline = self.network_baseline.setdefault(key, {})
        else:
            return
        
        # Update each metric in the baseline
        for metric, value in current.items():
            if not isinstance(value, (int, float)):
                continue
                
            if metric in baseline:
                baseline[metric] = (alpha * value) + ((1 - alpha) * baseline[metric])
            else:
                baseline[metric] = value
    
    def run_analysis(self) -> Dict[str, List[Dict[str, Any]]]:
        """Run all behavior analysis checks."""
        results = {
            'process_anomalies': [],
            'user_anomalies': [],
            'network_anomalies': []
        }
        
        # Analyze running processes
        for proc in psutil.process_iter():
            try:
                result = self.analyze_process_behavior(proc)
                if result.get('is_anomaly', False):
                    results['process_anomalies'].append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Analyze user behavior
        users = set()
        for proc in psutil.process_iter(['username']):
            try:
                users.add(proc.info['username'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, KeyError):
                continue
        
        for username in users:
            if username:
                result = self.analyze_user_behavior(username)
                if result.get('is_anomaly', False):
                    results['user_anomalies'].append(result)
        
        # Analyze network connections
        for conn in psutil.net_connections(kind='inet'):
            try:
                if hasattr(conn, 'raddr') and conn.raddr:
                    result = self.analyze_network_behavior(conn.raddr.ip, conn.raddr.port)
                    if result.get('is_anomaly', False):
                        results['network_anomalies'].append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                continue
        
        return results
