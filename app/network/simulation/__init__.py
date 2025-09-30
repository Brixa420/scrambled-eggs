""
Network Simulation Environment for Scrambled Eggs P2P Network.

This module provides tools to simulate various network conditions for testing
and validating the P2P network's behavior under different scenarios.
"""

from .simulator import NetworkSimulator
from .scenarios import (
    NetworkScenario,
    StableNetwork,
    HighLatencyNetwork,
    LossyNetwork,
    CongestedNetwork,
    FlakyConnection
)

__all__ = [
    'NetworkSimulator',
    'NetworkScenario',
    'StableNetwork',
    'HighLatencyNetwork',
    'LossyNetwork',
    'CongestedNetwork',
    'FlakyConnection'
]
