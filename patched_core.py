"""
Patched version of the ScrambledEggs core module.
"""

import logging

from scrambled_eggs.breach_detection import BreachDetector as OriginalBreachDetector
from scrambled_eggs.core import ScrambledEggs as OriginalScrambledEggs

logger = logging.getLogger(__name__)


class PatchedBreachDetector(OriginalBreachDetector):
    """Patched version of BreachDetector that ignores the threshold parameter."""

    def __init__(self, *args, **kwargs):
        # Remove the threshold parameter if it exists
        kwargs.pop("threshold", None)
        super().__init__(*args, **kwargs)


class ScrambledEggs(OriginalScrambledEggs):
    """Patched version of ScrambledEggs that uses our patched BreachDetector."""

    def __init__(self, password: str, initial_layers: int = 1):
        # Replace the BreachDetector class with our patched version
        import scrambled_eggs.breach_detection

        original_breach_detector = scrambled_eggs.breach_detection.BreachDetector
        scrambled_eggs.breach_detection.BreachDetector = PatchedBreachDetector

        try:
            # Call the original __init__ with the modified BreachDetector
            super().__init__(password, initial_layers)
        finally:
            # Restore the original BreachDetector
            scrambled_eggs.breach_detection.BreachDetector = original_breach_detector


# Replace the original ScrambledEggs class with our patched version
import sys

import scrambled_eggs.core

scrambled_eggs.core.ScrambledEggs = ScrambledEggs
