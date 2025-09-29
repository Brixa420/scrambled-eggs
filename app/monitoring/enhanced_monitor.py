""
Enhanced Monitoring Service with advanced metrics and threat detection.
"""
import time
import json
import logging
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
import asyncio
import psutil
import platform

from prometheus_client import start_http_server, Gauge, Counter, Histogram
from prometheus_client.core import REGISTRY

from app.core.config import settings
from app.core.security import SecurityManager

logger = logging.getLogger(__name__)

@dataclass
class MetricThreshold:
    """Threshold configuration for alerting."""
    warning: float
    critical: float
    duration: int = 60  # seconds

@dataclass
class NetworkMetrics:
    """Network-related metrics."""
    bytes_sent: int = 0
    bytes_recv: int = 0
    packets_sent: int = 0
    packets_recv: int = 0
    errors_in: int = 0
    errors_out: int = 0
    drops_in: int = 0
    drops_out: int = 0
    connections: int = 0
    tcp_connections: int = 0
    udp_connections: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

@dataclass
class SystemMetrics:
    """System resource metrics."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_usage: float = 0.0
    disk_read_bytes: int = 0
    disk_write_bytes: int = 0
    process_count: int = 0
    thread_count: int = 0
    
    def to_dict(self) -> Dict[str, float]:
        return asdict(self)

@dataclass
class SecurityMetrics:
    """Security-related metrics."""
    failed_logins: int = 0
    successful_logins: int = 0
    auth_attempts: int = 0
    encryption_ops: int = 0
    decryption_ops: int = 0
    key_rotations: int = 0
    security_events: int = 0
    threat_detections: int = 0
    
    def to_dict(self) -> Dict[str, int]:
        return asdict(self)

class EnhancedMonitor:
    """Enhanced monitoring service with advanced metrics and threat detection."""
    
    def __init__(self, security_manager: Optional[SecurityManager] = None):
        """Initialize the monitoring service."""
        self.security_manager = security_manager or SecurityManager()
        self.running = False
        self.metrics_interval = settings.MONITORING_INTERVAL or 5  # seconds
        self.retention_days = settings.METRICS_RETENTION_DAYS or 30
        
        # Initialize metrics storage
        self.network_metrics = NetworkMetrics()
        self.system_metrics = SystemMetrics()
        self.security_metrics = SecurityMetrics()
        
        # Historical data storage (circular buffer)
        self.historical_data = deque(maxlen=10080)  # 1 week of 1-minute metrics
        
        # Alert configuration
        self.alerts_enabled = getattr(settings, 'ALERTS_ENABLED', True)
        self.alert_handlers = []
        
        # Initialize Prometheus metrics
        self._init_prometheus_metrics()
        
        # Threat detection patterns
        self.threat_patterns = [
            (self._detect_brute_force, "Brute force attack detected"),
            (self._detect_data_exfiltration, "Possible data exfiltration detected"),
            (self._detect_crypto_activity, "Suspicious cryptographic activity"),
            (self._detect_network_anomalies, "Network anomaly detected")
        ]
        
        # Machine learning model for anomaly detection (placeholder)
        self.anomaly_detector = None
        self._init_anomaly_detector()
    
    def _init_prometheus_metrics(self) -> None:
        """Initialize Prometheus metrics."""
        # Network metrics
        self.network_metrics_gauges = {
            'bytes_sent': Gauge('network_bytes_sent', 'Total bytes sent'),
            'bytes_recv': Gauge('network_bytes_received', 'Total bytes received'),
            'connections': Gauge('network_connections', 'Active network connections'),
            'tcp_connections': Gauge('network_tcp_connections', 'Active TCP connections'),
            'udp_connections': Gauge('network_udp_connections', 'Active UDP connections')
        }
        
        # System metrics
        self.system_metrics_gauges = {
            'cpu_percent': Gauge('system_cpu_percent', 'CPU usage percentage'),
            'memory_percent': Gauge('system_memory_percent', 'Memory usage percentage'),
            'disk_usage': Gauge('system_disk_usage', 'Disk usage percentage'),
            'process_count': Gauge('system_process_count', 'Number of running processes')
        }
        
        # Security metrics
        self.security_metrics_counters = {
            'failed_logins': Counter('security_failed_logins', 'Number of failed login attempts'),
            'successful_logins': Counter('security_successful_logins', 'Number of successful logins'),
            'encryption_ops': Counter('security_encryption_operations', 'Number of encryption operations'),
            'decryption_ops': Counter('security_decryption_operations', 'Number of decryption operations'),
            'key_rotations': Counter('security_key_rotations', 'Number of key rotations'),
            'threat_detections': Counter('security_threat_detections', 'Number of threat detections')
        }
        
        # Histograms for request latencies
        self.request_latency = Histogram(
            'request_latency_seconds',
            'Request latency in seconds',
            ['endpoint', 'method']
        )
    
    def _init_anomaly_detector(self) -> None:
        """Initialize the anomaly detection model."""
        try:
            # In a real implementation, this would load a pre-trained model
            # For now, we'll use a simple threshold-based approach
            self.anomaly_detector = {
                'network_threshold': 3.0,  # Standard deviations from mean
                'cpu_threshold': 90.0,     # Percentage
                'memory_threshold': 90.0,  # Percentage
                'disk_threshold': 90.0     # Percentage
            }
            logger.info("Anomaly detector initialized with default thresholds")
        except Exception as e:
            logger.error(f"Failed to initialize anomaly detector: {e}")
    
    async def start(self) -> None:
        """Start the monitoring service."""
        if self.running:
            logger.warning("Monitoring service already running")
            return
        
        self.running = True
        
        # Start Prometheus metrics server
        start_http_server(settings.METRICS_PORT or 8000)
        
        # Start background tasks
        asyncio.create_task(self._monitor_loop())
        asyncio.create_task(self._check_anomalies())
        
        logger.info(f"Monitoring service started on port {settings.METRICS_PORT or 8000}")
    
    async def stop(self) -> None:
        """Stop the monitoring service."""
        self.running = False
        logger.info("Monitoring service stopped")
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        last_net_io = psutil.net_io_counters()
        last_disk_io = psutil.disk_io_counters()
        
        while self.running:
            try:
                # Update network metrics
                net_io = psutil.net_io_counters()
                net_connections = psutil.net_connections()
                
                self.network_metrics = NetworkMetrics(
                    bytes_sent=net_io.bytes_sent,
                    bytes_recv=net_io.bytes_recv,
                    packets_sent=net_io.packets_sent,
                    packets_recv=net_io.packets_recv,
                    errors_in=net_io.errin,
                    errors_out=net_io.errout,
                    drops_in=net_io.dropin,
                    drops_out=net_io.dropout,
                    connections=len(net_connections),
                    tcp_connections=len([c for c in net_connections if c.type == 1]),  # SOCK_STREAM
                    udp_connections=len([c for c in net_connections if c.type == 2])   # SOCK_DGRAM
                )
                
                # Update system metrics
                disk_io = psutil.disk_io_counters()
                
                self.system_metrics = SystemMetrics(
                    cpu_percent=psutil.cpu_percent(interval=1),
                    memory_percent=psutil.virtual_memory().percent,
                    disk_usage=psutil.disk_usage('/').percent,
                    disk_read_bytes=disk_io.read_bytes - last_disk_io.read_bytes,
                    disk_write_bytes=disk_io.write_bytes - last_disk_io.write_bytes,
                    process_count=len(psutil.pids()),
                    thread_count=psutil.Process().num_threads()
                )
                
                # Update Prometheus metrics
                self._update_prometheus_metrics()
                
                # Store historical data
                self._store_historical_data()
                
                # Update last counters
                last_net_io = net_io
                last_disk_io = disk_io
                
                # Sleep until next interval
                await asyncio.sleep(self.metrics_interval)
                
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}", exc_info=True)
                await asyncio.sleep(5)  # Avoid tight loop on error
    
    def _update_prometheus_metrics(self) -> None:
        """Update Prometheus metrics with current values."""
        # Update network metrics
        for metric, value in self.network_metrics.to_dict().items():
            if metric in self.network_metrics_gauges:
                self.network_metrics_gauges[metric].set(value)
        
        # Update system metrics
        for metric, value in self.system_metrics.to_dict().items():
            if metric in self.system_metrics_gauges:
                self.system_metrics_gauges[metric].set(value)
        
        # Security metrics are updated via the increment_* methods
    
    def _store_historical_data(self) -> None:
        """Store current metrics in historical data."""
        timestamp = datetime.utcnow().isoformat()
        
        data = {
            'timestamp': timestamp,
            'network': self.network_metrics.to_dict(),
            'system': self.system_metrics.to_dict(),
            'security': self.security_metrics.to_dict()
        }
        
        self.historical_data.append(data)
    
    async def _check_anomalies(self) -> None:
        """Check for anomalies in the collected metrics."""
        while self.running:
            try:
                # Check system resource usage
                if self.system_metrics.cpu_percent > self.anomaly_detector['cpu_threshold']:
                    await self.trigger_alert(
                        level='warning',
                        message=f"High CPU usage: {self.system_metrics.cpu_percent}%",
                        metric='cpu_percent',
                        value=self.system_metrics.cpu_percent
                    )
                
                if self.system_metrics.memory_percent > self.anomaly_detector['memory_threshold']:
                    await self.trigger_alert(
                        level='warning',
                        message=f"High memory usage: {self.system_metrics.memory_percent}%",
                        metric='memory_percent',
                        value=self.system_metrics.memory_percent
                    )
                
                if self.system_metrics.disk_usage > self.anomaly_detector['disk_threshold']:
                    await self.trigger_alert(
                        level='warning',
                        message=f"High disk usage: {self.system_metrics.disk_usage}%",
                        metric='disk_usage',
                        value=self.system_metrics.disk_usage
                    )
                
                # Check for security anomalies
                await self._check_security_anomalies()
                
                # Sleep before next check
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}", exc_info=True)
                await asyncio.sleep(30)  # Recover from errors
    
    async def _check_security_anomalies(self) -> None:
        """Check for security-related anomalies."""
        # Check for brute force attempts
        if self.security_metrics.failed_logins > 5:  # More than 5 failed logins per minute
            await self.trigger_alert(
                level='critical',
                message=f"Possible brute force attack detected: {self.security_metrics.failed_logins} failed logins",
                metric='failed_logins',
                value=self.security_metrics.failed_logins
            )
        
        # Check for unusual encryption patterns
        if self.security_metrics.encryption_ops > 1000:  # More than 1000 encryptions per minute
            await self.trigger_alert(
                level='warning',
                message=f"Unusually high encryption activity: {self.security_metrics.encryption_ops} operations",
                metric='encryption_ops',
                value=self.security_metrics.encryption_ops
            )
    
    async def trigger_alert(self, 
                          level: str, 
                          message: str, 
                          metric: Optional[str] = None,
                          value: Any = None) -> None:
        """
        Trigger an alert.
        
        Args:
            level: Alert level (info, warning, critical)
            message: Alert message
            metric: Optional metric name
            value: Optional metric value
        """
        alert = {
            'id': f"alert_{int(time.time())}",
            'timestamp': datetime.utcnow().isoformat(),
            'level': level,
            'message': message,
            'metric': metric,
            'value': value,
            'status': 'active',
            'acknowledged': False,
            'acknowledged_by': None,
            'acknowledged_at': None
        }
        
        # Log the alert
        logger.log(
            logging.WARNING if level == 'warning' else logging.ERROR,
            f"[{level.upper()}] {message}"
        )
        
        # Increment threat detections counter
        if level in ('warning', 'critical'):
            self.increment_metric('threat_detections')
        
        # Call alert handlers
        for handler in self.alert_handlers:
            try:
                await handler(alert)
            except Exception as e:
                logger.error(f"Error in alert handler: {e}", exc_info=True)
    
    def register_alert_handler(self, handler: Callable) -> None:
        """Register an alert handler function."""
        self.alert_handlers.append(handler)
    
    # Metric increment methods
    def increment_metric(self, metric: str, value: int = 1) -> None:
        """Increment a security metric."""
        if hasattr(self.security_metrics, metric):
            current = getattr(self.security_metrics, metric)
            setattr(self.security_metrics, metric, current + value)
            
            # Update Prometheus counter if it exists
            if metric in self.security_metrics_counters:
                self.security_metrics_counters[metric].inc(value)
    
    # Threat detection methods
    async def _detect_brute_force(self) -> Optional[Dict[str, Any]]:
        """Detect brute force login attempts."""
        if self.security_metrics.failed_logins > 10:  # Threshold
            return {
                'type': 'brute_force',
                'severity': 'high',
                'details': {
                    'failed_attempts': self.security_metrics.failed_logins,
                    'timeframe': '1m'
                }
            }
        return None
    
    async def _detect_data_exfiltration(self) -> Optional[Dict[str, Any]]:
        """Detect potential data exfiltration."""
        # Check for unusual outbound data transfers
        if len(self.historical_data) > 1:
            last = self.historical_data[-1]
            prev = self.historical_data[-2]
            
            bytes_sent = last['network']['bytes_sent'] - prev['network']['bytes_sent']
            
            # If more than 10MB sent in the last minute, could be exfiltration
            if bytes_sent > 10 * 1024 * 1024:  # 10MB
                return {
                    'type': 'data_exfiltration',
                    'severity': 'critical',
                    'details': {
                        'bytes_sent': bytes_sent,
                        'timeframe': '1m'
                    }
                }
        return None
    
    async def _detect_crypto_activity(self) -> Optional[Dict[str, Any]]:
        """Detect suspicious cryptographic activity."""
        # Check for unusual encryption patterns
        if self.security_metrics.encryption_ops > 1000:  # More than 1000 encryptions per minute
            return {
                'type': 'crypto_activity',
                'severity': 'medium',
                'details': {
                    'encryption_ops': self.security_metrics.encryption_ops,
                    'timeframe': '1m'
                }
            }
        return None
    
    async def _detect_network_anomalies(self) -> Optional[Dict[str, Any]]:
        """Detect network anomalies."""
        # Check for unusual network patterns
        if len(self.historical_data) > 5:  # Need at least 5 data points
            recent = list(self.historical_data)[-5:]
            
            # Calculate average network traffic
            avg_bytes = sum(d['network']['bytes_sent'] for d in recent) / len(recent)
            current = self.network_metrics.bytes_sent
            
            # If current traffic is 3x the average, could be an attack
            if current > avg_bytes * 3 and avg_bytes > 0:
                return {
                    'type': 'network_anomaly',
                    'severity': 'high',
                    'details': {
                        'current_bytes': current,
                        'average_bytes': avg_bytes,
                        'timeframe': '5m'
                    }
                }
        return None
    
    # API methods
    def get_current_metrics(self) -> Dict[str, Any]:
        """Get current metrics."""
        return {
            'timestamp': datetime.utcnow().isoformat(),
            'network': self.network_metrics.to_dict(),
            'system': self.system_metrics.to_dict(),
            'security': self.security_metrics.to_dict()
        }
    
    def get_historical_metrics(self, 
                             start_time: Optional[datetime] = None,
                             end_time: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """
        Get historical metrics within a time range.
        
        Args:
            start_time: Start time (default: 1 hour ago)
            end_time: End time (default: now)
            
        Returns:
            List of metric snapshots
        """
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=1)
        if end_time is None:
            end_time = datetime.utcnow()
        
        return [
            data for data in self.historical_data
            if start_time <= datetime.fromisoformat(data['timestamp']) <= end_time
        ]

# Create a default instance for easy import
monitor = EnhancedMonitor()
