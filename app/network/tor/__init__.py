"""
Tor integration module for anonymous communication and circuit management.
"""

from .dashboard import MetricsDashboard
from .manager import TorCircuit, TorCircuitState, TorManager
from .metrics import MetricsStorage

# Create a singleton instance
tor_manager = TorManager()

__all__ = [
    "TorManager",
    "TorCircuit",
    "TorCircuitState",
    "MetricsStorage",
    "MetricsDashboard",
    "tor_manager",
]
