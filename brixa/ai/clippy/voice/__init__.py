"""
Voice interaction module for Clippy AI.

This module provides text-to-speech, speech-to-text, and voice command
capabilities for Clippy's voice interaction features.
"""

from .tts import TextToSpeech
from .stt import SpeechToText
from .commands import (
    CommandType,
    Command,
    CommandRegistry,
    command_registry,
    register_command,
    process_voice_command
)

__all__ = [
    'TextToSpeech',
    'SpeechToText',
    'CommandType',
    'Command',
    'CommandRegistry',
    'command_registry',
    'register_command',
    'process_voice_command'
]
