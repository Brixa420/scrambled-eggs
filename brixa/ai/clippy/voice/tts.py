"""
Text-to-Speech (TTS) module for Clippy AI.

Provides text-to-speech functionality using various backends.
"""

import os
import tempfile
from typing import Optional, Union
import logging

logger = logging.getLogger(__name__)

class TextToSpeech:
    """
    Text-to-speech conversion for Clippy AI.
    
    Supports multiple TTS backends and provides a simple interface
    for converting text to speech.
    """
    
    def __init__(self, backend: str = 'pyttsx3', **kwargs):
        """
        Initialize the TTS engine.
        
        Args:
            backend: TTS backend to use ('pyttsx3', 'gtts', or 'win32')
            **kwargs: Additional backend-specific parameters
        """
        self.backend = backend.lower()
        self.engine = None
        self._init_engine(**kwargs)
        
    def _init_engine(self, **kwargs):
        """Initialize the TTS engine based on the selected backend."""
        try:
            if self.backend == 'pyttsx3':
                import pyttsx3
                self.engine = pyttsx3.init()
                # Set default rate a bit slower
                self.engine.setProperty('rate', 150)
                
            elif self.backend == 'gtts':
                from gtts import gTTS
                self.engine = gTTS
                self.temp_dir = tempfile.mkdtemp(prefix='clippy_tts_')
                
            elif self.backend == 'win32':
                import win32com.client
                self.engine = win32com.client.Dispatch("SAPI.SpVoice")
                
            else:
                raise ValueError(f"Unsupported TTS backend: {self.backend}")
                
        except ImportError as e:
            logger.warning(f"Failed to initialize {self.backend} TTS backend: {e}")
            self.engine = None
    
    def speak(self, text: str, wait: bool = False) -> Optional[str]:
        """
        Convert text to speech and speak it.
        
        Args:
            text: Text to speak
            wait: If True, block until speech is complete
            
        Returns:
            Path to the generated audio file if saved, None otherwise
        """
        if not text or not self.engine:
            return None
            
        try:
            if self.backend == 'pyttsx3':
                self.engine.say(text)
                if wait:
                    self.engine.runAndWait()
                    
            elif self.backend == 'gtts':
                import os
                import pygame
                from io import BytesIO
                
                # Generate speech to a bytes buffer
                audio_buffer = BytesIO()
                tts = self.engine(text=text, lang='en')
                tts.write_to_fp(audio_buffer)
                audio_buffer.seek(0)
                
                # Initialize pygame mixer if not already done
                if not pygame.mixer.get_init():
                    pygame.mixer.init()
                
                # Load and play the audio from buffer
                audio_buffer.seek(0)
                pygame.mixer.music.load(audio_buffer, 'mp3')
                pygame.mixer.music.play()
                
                # Wait for playback to finish if needed
                if wait:
                    while pygame.mixer.music.get_busy():
                        pygame.time.Clock().tick(10)
                else:
                    return "In-memory audio buffer"
                    
                # Clean up
                audio_buffer.close()
                
            elif self.backend == 'win32':
                self.engine.Speak(text)
                
            return None
            
        except Exception as e:
            logger.error(f"Error in TTS: {e}", exc_info=True)
            return None
    
    def set_voice(self, voice_id: str = None):
        """
        Set the voice to use for speech.
        
        Args:
            voice_id: ID of the voice to use. If None, use default voice.
        """
        if not self.engine:
            return
            
        if self.backend == 'pyttsx3':
            voices = self.engine.getProperty('voices')
            if voice_id and voice_id < len(voices):
                self.engine.setProperty('voice', voices[voice_id].id)
                
        elif self.backend == 'win32':
            # Windows SAPI voice selection
            voices = self.engine.GetVoices()
            if voice_id is not None and 0 <= voice_id < voices.Count:
                self.engine.Voice = voices.Item(voice_id)
    
    def set_rate(self, rate: int):
        """
        Set the speech rate (words per minute).
        
        Args:
            rate: Speech rate in words per minute
        """
        if not self.engine:
            return
            
        if self.backend == 'pyttsx3':
            # pyttsx3 rate is typically between 0-200
            self.engine.setProperty('rate', rate)
            
        elif self.backend == 'win32':
            # Windows SAPI rate is -10 to 10
            rate = max(-10, min(10, (rate - 150) / 15))
            self.engine.Rate = int(rate)
    
    def stop(self):
        """Stop any ongoing speech."""
        if self.engine and self.backend == 'pyttsx3':
            self.engine.stop()


# Example usage
if __name__ == "__main__":
    import time
    
    # Initialize TTS with default backend
    tts = TextToSpeech(backend='pyttsx3')
    
    # Set a slower rate
    tts.set_rate(120)
    
    # Speak some text
    print("Clippy says:", "Hello! I'm Clippy, your AI assistant.")
    tts.speak("Hello! I'm Clippy, your AI assistant.")
    
    # Wait a moment
    time.sleep(1)
    
    # Change voice if available
    tts.set_voice(0)  # Try first available voice
    
    # Speak with the new voice
    print("Clippy says:", "How can I help you today?")
    tts.speak("How can I help you today?")
