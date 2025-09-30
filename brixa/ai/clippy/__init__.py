"""
Clippy - Your AI Assistant

This module provides the core functionality for Clippy, an AI assistant
that helps users with coding tasks, documentation, and more.
"""

__version__ = "0.1.0"

from .core import Clippy
from .skills import (
    code_generation,
    code_analysis,
    documentation,
    debugging,
    testing
)

__all__ = [
    'Clippy',
    'code_generation',
    'code_analysis', 
    'documentation',
    'debugging',
    'testing'
]
