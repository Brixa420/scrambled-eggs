"""
Tor integration module for anonymous communication and circuit management.
"""
from .manager import TorManager, TorCircuit, TorCircuitState
from .metrics import MetricsStorage
from .dashboard import MetricsDashboard

# Create a singleton instance
tor_manager = TorManager()

__all__ = ['TorManager', 'TorCircuit', 'TorCircuitState', 'MetricsStorage', 'MetricsDashboard', 'tor_manager']
