"""
Speech-to-Text (STT) module for Clippy AI.

Provides speech recognition functionality using various backends with wake word detection.
"""

import array
import audioop
import logging
import os
import queue
import re
import tempfile
import threading
import time
import wave
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Callable, Dict, Any, List, Tuple

import numpy as np
import pyaudio

logger = logging.getLogger(__name__)

class AudioDeviceError(Exception):
    """Exception raised for audio device related errors."""
    pass

class AudioQuality(Enum):
    """Audio quality presets for recording."""
    LOW = (16000, 1, 1)  # 16kHz, mono, 16-bit
    HIGH = (48000, 2, 2)  # 48kHz, stereo, 16-bit

@dataclass
class AudioConfig:
    """Configuration for audio recording and processing."""
    # Audio format settings
    sample_rate: int = 16000      # 16kHz sample rate
    channels: int = 1             # Mono audio
    chunk_size: int = 2048        # Balanced chunk size for performance and latency
    sample_width: int = 2         # 16-bit audio (2 bytes per sample)
    
    # Energy and silence detection
    energy_threshold: int = 300   # Initial energy threshold
    pause_threshold: float = 0.8  # Seconds of silence to mark end of phrase
    silence_duration: float = 0.5 # Seconds of silence to keep at beginning/end
    
    # Dynamic energy adjustment
    dynamic_energy_threshold: bool = True
    dynamic_energy_adjustment_damping: float = 0.15  # Smoother adjustment
    dynamic_energy_ratio: float = 1.5  # Sensitivity to loud sounds
    
    # Audio processing
    phrase_threshold: float = 0.3  # Minimum seconds of speech before considering phrase
    non_speaking_duration: float = 0.5  # Seconds of non-speaking audio to keep around phrases
    min_audio_length: float = 0.5  # Minimum audio length in seconds to process
    max_audio_length: float = 10.0  # Maximum audio length in seconds before forcing processing
    
    # Performance
    process_audio_in_background: bool = True  # Process audio in separate thread
    max_audio_queue_size: int = 10  # Maximum number of audio chunks in queue

class SpeechToText:
    """
    Speech recognition for Clippy AI with wake word detection.
    
    Features:
    - Multiple STT backends (Google, Whisper, Sphinx)
    - Wake word detection with configurable sensitivity
    - Background audio processing
    - Dynamic energy threshold adjustment
    - Real-time audio streaming
    """
    
    def __init__(self, 
                 backend: str = 'google', 
                 wake_word: str = 'clippy',
                 audio_config: Optional[AudioConfig] = None,
                 **kwargs):
        """
        Initialize the speech recognition engine with wake word detection.
        
        Args:
            backend: STT backend to use ('whisper', 'sphinx', or 'google')
            wake_word: The wake word to listen for (e.g., 'clippy')
            audio_config: Audio configuration settings
            **kwargs: Additional backend-specific parameters
        """
        # Core configuration
        self.backend = backend.lower()
        self.wake_word = wake_word.lower()
        self.wake_word_pattern = re.compile(
            r'\b' + re.escape(wake_word) + r'\b', 
            re.IGNORECASE
        )
        self.wake_word_detected = False
        self.on_wake_word_detected = None
        self.on_utterance = None
        
        # Audio processing state
        self._audio_queue = queue.Queue(maxsize=audio_config.max_audio_queue_size if audio_config else 10)
        self._audio_buffer = bytearray()
        self._last_audio_time = 0
        self._is_processing = False
        self._processing_lock = threading.Lock()
        
        # Energy detection
        self._energy_threshold = 300  # Will be adjusted if dynamic_energy_threshold is True
        self._dynamic_energy_threshold = True
        self._dynamic_energy_adjustment_damping = 0.15
        self._dynamic_energy_ratio = 1.5
        self._energy_threshold_initialized = False
        
        # Thread management
        self._stop_event = threading.Event()
        self._audio_thread = None
        self._processing_thread = None
        
        # Listening state
        self.is_listening = False
        
        # Audio configuration
        self.config = audio_config or AudioConfig()
        
        # Initialize VAD (Voice Activity Detection) if available
        self._vad = None
        try:
            import webrtcvad
            self._vad = webrtcvad.Vad(3)  # Aggressiveness mode 3 (0-3)
        except ImportError:
            logger.warning("webrtcvad not available. Voice activity detection will be disabled.")
        
        # Performance metrics
        self._last_audio_time = time.time()
        self._audio_processing_time = 0
        self._audio_processing_count = 0
        
        # Initialize audio device and recognizer
        self._init_audio_device()
        self._init_recognizer(**kwargs)
    
    def _init_audio_device(self):
        """Initialize the audio input device with the specified configuration."""
        try:
            import pyaudio
            self._audio = pyaudio.PyAudio()
            
            # Calculate buffer sizes based on desired audio length
            bytes_per_sample = self.config.sample_width
            samples_per_chunk = int(self.config.sample_rate * 0.1)  # 100ms chunks
            self.config.chunk_size = samples_per_chunk * bytes_per_sample * self.config.channels
            
            # Calculate buffer sizes
            min_buffer_size = int(self.config.sample_rate * self.config.min_audio_length * bytes_per_sample * self.config.channels)
            max_buffer_size = int(self.config.sample_rate * self.config.max_audio_length * bytes_per_sample * self.config.channels)
            
            # Update instance variables
            self._min_audio_length = min_buffer_size
            self._max_audio_length = max_buffer_size
            
            # Open audio stream with optimized settings
            self._stream = self._audio.open(
                format=pyaudio.paInt16,
                channels=self.config.channels,
                rate=self.config.sample_rate,
                input=True,
                frames_per_buffer=self.config.chunk_size,
                input_device_index=None,  # Use default device
                stream_callback=self._audio_callback,
                start=False  # Start the stream manually
            )
            
            logger.info("Audio device initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize audio device: {e}", exc_info=True)
            raise AudioDeviceError(f"Failed to initialize audio device: {e}")
    
    def _init_recognizer(self, **kwargs):
        """Initialize the speech recognizer with the configured backend."""
        try:
            import speech_recognition as sr
            self.recognizer = sr.Recognizer()
            
            # Configure recognizer settings
            self.recognizer.energy_threshold = self.config.energy_threshold
            self.recognizer.dynamic_energy_threshold = self.config.dynamic_energy_threshold
            self.recognizer.pause_threshold = self.config.pause_threshold
            
            # Set the appropriate recognition function based on the backend
            if self.backend == 'whisper':
                try:
                    import whisper
                    self.whisper_model = whisper.load_model("base")  # or "small", "medium", etc.
                    self._recognize_func = self._recognize_whisper
                    logger.info("Initialized Whisper speech recognition")
                except ImportError:
                    logger.warning("Whisper not available. Falling back to Google.")
                    self.backend = 'google'
                    self._recognize_func = self._recognize_google
            
            if self.backend == 'google':
                self._recognize_func = self._recognize_google
                logger.info("Initialized Google Speech Recognition")
            
            elif self.backend == 'sphinx':
                self._recognize_func = self._recognize_sphinx
                logger.info("Initialized Sphinx speech recognition")
            
            # Default to Google if no valid backend was set
            if not hasattr(self, '_recognize_func'):
                logger.warning(f"Unsupported backend: {self.backend}. Defaulting to Google.")
                self.backend = 'google'
                self._recognize_func = self._recognize_google
            
            logger.info(f"Using {self.backend} for speech recognition")
            
        except Exception as e:
            logger.error(f"Failed to initialize speech recognizer: {e}", exc_info=True)
            raise
    
    def _is_speech(self, audio_data: bytes) -> bool:
        """
        Check if the audio data contains speech using energy-based voice activity detection.
        
        Args:
            audio_data: Raw audio data in bytes
            
        Returns:
            bool: True if speech is detected, False otherwise
        """
        if not audio_data or len(audio_data) < 2:
            return False
        
        try:
            # Convert bytes to 16-bit integers
            samples = []
            for i in range(0, len(audio_data), 2):
                if i + 1 < len(audio_data):
                    sample = int.from_bytes(audio_data[i:i+2], byteorder='little', signed=True)
                    samples.append(sample)
            
            if not samples:
                return False
                
            # Calculate energy (RMS)
            sum_squares = sum(s * s for s in samples)
            rms = (sum_squares / len(samples)) ** 0.5
            
            # Dynamic energy threshold adjustment
            if self._dynamic_energy_threshold and rms > 0:
                if not self._energy_threshold_initialized:
                    self._energy_threshold = rms * self._dynamic_energy_ratio
                    self._energy_threshold_initialized = True
                    logger.debug(f"Initial energy threshold: {self._energy_threshold:.2f}")
                else:
                    # Smooth the threshold adjustment
                    self._energy_threshold = (
                        self._energy_threshold * (1 - self._dynamic_energy_adjustment_damping) +
                        rms * self._dynamic_energy_adjustment_damping
                    )
            
            # Check if energy is above threshold
            is_speech = rms > self._energy_threshold * 1.2  # Add 20% buffer
            
            # Debug logging (less verbose)
            if is_speech and logger.isEnabledFor(logging.DEBUG):
                logger.debug(f"Speech detected - RMS: {rms:.2f}, Threshold: {self._energy_threshold:.2f}")
                
            return is_speech
            
        except Exception as e:
            logger.error(f"Error in VAD: {e}", exc_info=True)
            return False
    
    def _audio_callback(self, in_data, frame_count, time_info, status):
        """
        Callback function for the audio stream that processes incoming audio data.
        
        Args:
            in_data: Audio data as a byte string
            frame_count: Number of frames in the buffer
            time_info: Dictionary with audio timing information
            status: Audio stream status flags
            
        Returns:
            tuple: (None, pyaudio.paContinue) to continue streaming
        """
        try:
            if status:
                logger.debug(f"Audio stream status: {status}")
                
            # Add audio data to queue if not full
            if not self._audio_queue.full():
                self._audio_queue.put(in_data, block=False)
                
            # Update last audio time for timeout handling
            self._last_audio_time = time.time()
            
            # Start processing thread if not already running
            if (self.config.process_audio_in_background and 
                not self._is_processing and 
                (self._processing_thread is None or not self._processing_thread.is_alive())):
                self._start_processing_thread()
                
        except Exception as e:
            logger.error(f"Error in audio callback: {e}", exc_info=True)
            
        return (None, pyaudio.paContinue)
        
    def _start_processing_thread(self):
        """Start the background audio processing thread."""
        if self._processing_thread and self._processing_thread.is_alive():
            return
            
        self._processing_thread = threading.Thread(
            target=self._process_audio_loop,
            daemon=True,
            name="AudioProcessingThread"
        )
        self._processing_thread.start()
        
    def _process_audio_loop(self):
        """
        Main audio processing loop that runs in a background thread.
        
        This method continuously processes audio chunks from the queue,
        handles voice activity detection, and manages the audio buffer.
        """
        logger.info("Starting audio processing loop")
        self._is_processing = True
        last_activity_time = time.time()
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Process audio chunks with timeout for clean shutdown
                    chunk = self._audio_queue.get(timeout=0.1)
                    if not chunk:
                        continue
                        
                    # Process the audio chunk
                    with self._processing_lock:
                        is_speech = self._process_audio_chunk(chunk)
                        
                    # Update last activity time if speech was detected
                    if is_speech:
                        last_activity_time = time.time()
                    
                    # Check for timeout if we have buffered audio
                    current_time = time.time()
                    buffer_duration = len(self._audio_buffer) / (self.config.sample_rate * self.config.sample_width)
                    
                    # Process audio if we've timed out or buffer is too large
                    if (buffer_duration >= self.config.max_audio_length or 
                        (buffer_duration >= self.config.min_audio_length and 
                         current_time - last_activity_time > self.config.pause_threshold)):
                        self._process_buffered_audio()
                        
                except queue.Empty:
                    # Check if we should process any remaining audio
                    if len(self._audio_buffer) > 0:
                        current_time = time.time()
                        buffer_duration = len(self._audio_buffer) / (self.config.sample_rate * self.config.sample_width)
                        
                        if (current_time - last_activity_time > self.config.pause_threshold and 
                            buffer_duration >= self.config.min_audio_length):
                            self._process_buffered_audio()
                    continue
                    
                except Exception as e:
                    logger.error(f"Error in audio processing loop: {e}", exc_info=True)
                    # Small delay to prevent tight loop on error
                    time.sleep(0.1)
        except Exception as e:
            logger.critical(f"Fatal error in audio processing loop: {e}", exc_info=True)
            raise
        finally:
            self._is_processing = False
            logger.info("Audio processing loop stopped")
        
    def _process_audio_chunk(self, chunk: bytes) -> bool:
        """
        Process a single chunk of audio data for wake word detection.
        
        This method performs the following operations:
        1. Adds the chunk to the audio buffer
        2. Checks if we have enough audio to process
        3. Detects speech using energy-based VAD
        4. Manages buffer size and trimming
        
        Args:
            chunk: Raw audio data chunk from the microphone
            
        Returns:
            bool: True if speech was detected, False otherwise
        """
        if not chunk or len(chunk) == 0:
            return False
            
        try:
            with self._processing_lock:
                # Add chunk to buffer
                self._audio_buffer.extend(chunk)
                buffer_size = len(self._audio_buffer)
                
                # Calculate buffer metrics
                bytes_per_second = self.config.sample_rate * self.config.sample_width * self.config.channels
                min_required = int(self.config.min_audio_length * bytes_per_second)
                max_buffer_size = int(self.config.max_audio_length * bytes_per_second)
                
                # If we don't have enough audio yet, keep collecting
                if buffer_size < min_required:
                    return False
                
                # Check for speech in the current chunk (faster than checking entire buffer)
                is_speech = self._is_speech(chunk)
                
                # Debug logging
                if logger.isEnabledFor(logging.DEBUG):
                    audio_secs = buffer_size / bytes_per_second
                    logger.debug(f"Processed {len(chunk)}b chunk (total: {audio_secs:.2f}s, speech: {is_speech})")
                
                # Trim buffer if it gets too large
                if buffer_size > max_buffer_size:
                    # Keep the most recent audio that's at least min_required
                    keep_bytes = max(min_required, max_buffer_size // 2)
                    self._audio_buffer = self._audio_buffer[-keep_bytes:]
                    logger.debug(f"Trimmed audio buffer to {len(self._audio_buffer)} bytes")
                
                return is_speech
                
        except Exception as e:
            logger.error(f"Error in audio chunk processing: {e}", exc_info=True)
            with self._processing_lock:
                self._audio_buffer = bytearray()  # Reset buffer on error
            return False
    
    def _process_buffered_audio(self):
        """Process the current audio buffer and start speech recognition."""
        if not self._audio_buffer:
            return
            
        try:
            with self._processing_lock:
                if not self._audio_buffer:
                    return
                    
                # Make a copy of the buffer and clear it
                audio_data = bytes(self._audio_buffer)
                buffer_size = len(audio_data)
                self._audio_buffer = bytearray()
                
                # Calculate duration for logging
                duration = buffer_size / (self.config.sample_rate * self.config.sample_width * self.config.channels)
                
                if duration >= self.config.min_audio_length:
                    logger.info(f"Processing {duration:.2f}s of buffered audio")
                    
                    # Start recognition in a separate thread to avoid blocking
                    threading.Thread(
                        target=self._recognize_speech,
                        args=(audio_data,),
                        daemon=True,
                        name=f"RecognitionThread-{time.time()}"
                    ).start()
                else:
                    logger.debug(f"Discarding {duration:.2f}s of audio (too short)")
                    
        except Exception as e:
            logger.error(f"Error processing buffered audio: {e}", exc_info=True)
    
    def _detect_wake_word(self, text: str) -> bool:
        """
        Check if the wake word is present in the recognized text.
        
        Args:
            text: The recognized text to check
            
        Returns:
            bool: True if wake word is detected, False otherwise
        """
        if not text or not text.strip():
            return False
            
        text_lower = text.lower()
        wake_lower = self.wake_word.lower()
        
        # Check for exact match (fast path)
        if wake_lower in text_lower:
            logger.debug(f"Potential wake word match in: '{text}'")
            
            # Check for whole word match using regex
            if self.wake_word_pattern.search(text):
                logger.info(f"Wake word '{self.wake_word}' detected in: '{text}'")
                return True
                
            # Check for partial matches with high confidence
            words = text_lower.split()
            if any(wake_lower in word for word in words):
                logger.info(f"Partial wake word match in: '{text}'")
                return True
                
        return False
    
    def _recognize_speech(self, audio_data: bytes) -> None:
        """
        Recognize speech from audio data and handle the result.
        
        Args:
            audio_data: Raw audio data in bytes
        """
        if not audio_data or len(audio_data) < 1024:  # Minimum audio length check
            logger.debug("Audio data too short or empty")
            return
            
        try:
            # Log audio stats for debugging
            audio_duration = len(audio_data) / (self.config.sample_rate * 2)  # 2 bytes per sample
            logger.debug(f"Processing {len(audio_data)} bytes of audio ({audio_duration:.2f}s) with {self.backend}")
            
            # Convert audio data to the format expected by the recognizer
            text = None
            if self.backend == 'whisper':
                text = self._recognize_whisper(audio_data)
            elif self.backend == 'google':
                text = self._recognize_google(audio_data)
            elif self.backend == 'sphinx':
                text = self._recognize_sphinx(audio_data)
            else:
                logger.error(f"Unsupported backend: {self.backend}")
                return
                
            if not text or not text.strip():
                logger.debug("No speech detected in audio")
                return
                
            text = text.strip()
            logger.info(f"Recognized text: {text}")
            
            # Check for wake word if not already detected
            if not self.wake_word_detected:
                logger.debug(f"Checking for wake word in: {text}")
                if self._detect_wake_word(text):
                    self.wake_word_detected = True
                    logger.info(f"Wake word '{self.wake_word}' detected!")
                    if self.on_wake_word_detected:
                        logger.debug("Calling wake word callback")
                        self.on_wake_word_detected()
                    return
                else:
                    logger.debug("No wake word detected")
            
            # If wake word was detected, process the utterance
            elif self.on_utterance:
                logger.debug("Processing utterance after wake word")
                # Remove the wake word from the beginning of the text if present
                clean_text = re.sub(
                    f'^{re.escape(self.wake_word)}\\b\\s*',  # Match whole word only at start
                    '', 
                    text, 
                    flags=re.IGNORECASE
                ).strip()
                
                if clean_text:  # Only process if there's text after removing wake word
                    logger.info(f"Processing utterance: {clean_text}")
                    self.on_utterance(clean_text)
                else:
                    logger.debug("No text after removing wake word")
                    
        except Exception as e:
            logger.error(f"Error in speech recognition: {e}", exc_info=True)
        finally:
            # Reset buffer after processing
            self._audio_buffer = bytearray()
            
    def _recognize_whisper(self, audio_data: bytes) -> str:
        """Recognize speech using Whisper."""
        try:
            # Convert audio data to numpy array and normalize
            audio_np = np.frombuffer(audio_data, np.int16).astype(np.float32) / 32768.0
            
            # Create a temporary file for Whisper
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as f:
                with wave.open(f.name, 'wb') as wf:
                    wf.setnchannels(self.config.channels)
                    wf.setsampwidth(self.config.sample_width)
                    wf.setframerate(self.config.sample_rate)
                    wf.writeframes(audio_data)
                temp_filename = f.name
            
            try:
                # Transcribe using Whisper
                result = self.recognizer.transcribe(temp_filename)
                return result.get("text", "")
                
            except Exception as e:
                logger.error(f"Error in Whisper transcription: {e}")
                return ""
                
            finally:
                # Clean up the temporary file
                import os
                try:
                    os.remove(temp_filename)
                except Exception as e:
                    logger.warning(f"Failed to remove temporary file: {e}")
                    
        except Exception as e:
            logger.error(f"Error in Whisper audio processing: {e}")
            return ""
    
    def _recognize_google(self, audio_data, **kwargs):
        """Recognize speech using Google Speech Recognition with enhanced audio processing."""
        try:
            if not audio_data or len(audio_data) < 1024:  # Minimum length check
                logger.debug("Audio data too short or empty")
                return ""
                
            import speech_recognition as sr
            import wave
            import io
            import struct
            
            # Log audio data info for debugging
            logger.debug(f"Audio data length: {len(audio_data)} bytes, sample rate: {self.config.sample_rate}, sample width: {self.config.sample_width}")
            
            try:
                # Create an in-memory WAV file
                with io.BytesIO() as wav_file:
                    with wave.open(wav_file, 'wb') as wf:
                        wf.setnchannels(1)  # Mono
                        wf.setsampwidth(2)  # 16-bit
                        wf.setframerate(16000)  # 16kHz sample rate
                        wf.writeframes(audio_data)
                    
                    # Convert to AudioData
                    wav_data = wav_file.getvalue()
                    audio_data_obj = sr.AudioData(
                        wav_data[44:],  # Skip WAV header
                        sample_rate=16000,
                        sample_width=2
                    )
                
                # Adjust recognizer settings for better accuracy
                self.recognizer.energy_threshold = 300  # Lower for better sensitivity
                self.recognizer.dynamic_energy_threshold = True
                self.recognizer.pause_threshold = 0.8
                
                # Try to recognize speech with language hint
                result = self.recognizer.recognize_google(
                    audio_data_obj,
                    language="en-US",  # Explicitly set language
                    show_all=False  # Return only the most likely result
                )
                
                if result and isinstance(result, str):
                    logger.debug(f"Speech recognized: {result}")
                    return result.lower()
                return ""
                
            except sr.UnknownValueError:
                # This is normal when there's no speech
                return ""
            except sr.RequestError as e:
                logger.error(f"Google Speech Recognition request error: {e}")
                return ""
            except Exception as e:
                logger.error(f"Error in speech recognition: {e}", exc_info=True)
                return ""
                
        except Exception as e:
            logger.error(f"Unexpected error in _recognize_google: {e}", exc_info=True)
            return ""
    
    def _recognize_sphinx(self, audio_data, **kwargs):
        """Recognize speech using CMU Sphinx."""
        try:
            import speech_recognition as sr
            
            # Convert raw audio data to AudioData object
            audio_data_obj = sr.AudioData(
                audio_data,
                sample_rate=self.config.sample_rate,
                sample_width=self.config.sample_width
            )
            
            return self.recognizer.recognize_sphinx(audio_data_obj, **kwargs)
            
        except Exception as e:
            logger.warning(f"Sphinx Recognition error: {e}")
            return ""
    
    def listen(self, timeout: float = None, phrase_time_limit: float = 5.0, **kwargs) -> Optional[str]:
        """
        Listen for speech and convert it to text.
        
        Args:
            timeout: Maximum seconds to wait for speech (None for no timeout)
            phrase_time_limit: Maximum seconds of speech to record
            **kwargs: Additional arguments for the recognizer
            
        Returns:
            Recognized text, or None if no speech was detected
        """
        if not self.recognizer:
            logger.error("Speech recognizer not initialized")
            return None
            
        try:
            import speech_recognition as sr
            
            with sr.Microphone() as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source)
                
                try:
                    # Listen for audio input
                    audio = self.recognizer.listen(
                        source, 
                        timeout=timeout,
                        phrase_time_limit=phrase_time_limit
                    )
                    
                    # Recognize speech
                    text = self._recognize_func(audio, **kwargs)
                    return text if text else None
                    
                except sr.WaitTimeoutError:
                    return None
                except sr.UnknownValueError:
                    logger.debug("Speech not understood")
                    return ""
                    
        except Exception as e:
            logger.error(f"Error in speech recognition: {e}", exc_info=True)
            return None
    
    def listen(self, *args, **kwargs):
        """
        Listen for speech and convert it to text with wake word detection.
        
        This method has two signatures:
        1. listen(timeout=None, phrase_time_limit=5.0, **kwargs) -> Optional[str]
        2. listen(on_text=None, on_wake_word=None, timeout=None) -> None
        
        The first signature is for basic speech recognition without wake word detection.
        The second signature is for wake word detection with callbacks.
        """
        # Check which signature is being used
        has_callbacks = any(key in kwargs for key in ['on_text', 'on_wake_word']) or \
                      (len(args) > 0 and callable(args[0])) or \
                      (len(args) > 1 and callable(args[1]))
        
        if has_callbacks:
            # Handle wake word detection with callbacks
            return self._listen_with_wake_word(*args, **kwargs)
        else:
            # Handle basic speech recognition
            return self.listen_basic(*args, **kwargs)
    
    def listen_basic(self, timeout: float = None, phrase_time_limit: float = 5.0, **kwargs) -> Optional[str]:
        """Basic speech recognition without wake word detection."""
        if not self.recognizer:
            logger.error("Speech recognizer not initialized")
            return None
        try:
            import speech_recognition as sr
            
            with sr.Microphone() as source:
                # Adjust for ambient noise
                self.recognizer.adjust_for_ambient_noise(source)
                
                try:
                    # Listen for audio input
                    audio = self.recognizer.listen(
                        source, 
                        timeout=timeout,
                        phrase_time_limit=phrase_time_limit
                    )
                    
                    # Recognize speech
                    text = self._recognize_func(audio, **kwargs)
                    return text if text else None
                    
                except sr.WaitTimeoutError:
                    return None
                except sr.UnknownValueError:
                    logger.debug("Speech not understood")
                    return ""
                    
        except Exception as e:
            logger.error(f"Error in speech recognition: {e}", exc_info=True)
            return None
    
    def _listen_with_wake_word(self, 
                             on_utterance: Callable[[bytes], bool] = None,
                             on_text: Callable[[str], None] = None,
                             on_wake_word: Callable[[], None] = None,
                             timeout: float = None) -> None:
        """Listen for speech with wake word detection.
        
        Args:
            on_utterance: Callback function that processes audio data and returns True if processed
            on_text: Callback function that processes recognized text
            on_wake_word: Callback function called when wake word is detected
            timeout: Maximum time in seconds to listen for
        """
        # For backward compatibility, if on_utterance is not provided but on_text is,
        # use on_text as the main callback
        if on_utterance is None and on_text is not None:
            on_utterance = lambda data: bool(on_text(self._recognize_func(data) if data else ""))
        if self.recognizer is None:
            raise RuntimeError("Speech recognizer not initialized")
            
        if self._audio is None:
            raise AudioDeviceError("Audio input device not available")
            
        self.is_listening = True
        self.wake_word_detected = False
        self.on_wake_word_detected = on_wake_word
        self.on_utterance = on_text
        self._stop_event.clear()
        self._audio_buffer = bytearray()
        self._last_audio_time = time.time()
        
        # Start the audio stream
        try:
            self._stream = self._audio.open(
                format=self._audio.get_format_from_width(self.config.sample_width),
                channels=self.config.channels,
                rate=self.config.sample_rate,
                input=True,
                frames_per_buffer=self.config.chunk_size,
                stream_callback=self._audio_callback
            )
            
            # Start processing audio in a separate thread
            self._process_thread = threading.Thread(
                target=self._process_audio_loop,
                daemon=True
            )
            self._process_thread.start()
            
            # Set up timeout if specified
            if timeout is not None:
                self._timeout_timer = threading.Timer(
                    timeout,
                    self.stop_listening
                )
                self._timeout_timer.start()
            
            logger.info("Started listening with wake word detection")
            
        except Exception as e:
            logger.error(f"Failed to start audio stream: {e}")
            self.is_listening = False
            raise
    
    def _listen_loop(self, on_utterance=None, on_wake_word=None, timeout=None):
        """Main listening loop with wake word detection.
        
        Args:
            on_utterance: Callback function that processes audio data and returns True if processed
            on_wake_word: Callback function called when wake word is detected
            timeout: Maximum time in seconds to listen for
        """
        import pyaudio
        FORMAT = pyaudio.paInt16
        CHANNELS = self.config.channels
        RATE = self.config.sample_rate
        CHUNK = self.config.chunk_size
        
        # Use existing audio instance if available
        audio = getattr(self, '_audio', pyaudio.PyAudio())
        
        # Configure stream with the same settings as in _init_audio_device
        stream = audio.open(
            format=FORMAT,
            channels=CHANNELS,
            rate=RATE,
            input=True,
            frames_per_buffer=CHUNK,
            input_device_index=None,  # Use default device
            stream_callback=self._audio_callback,
            start=True
        )
        
        try:
            while not self._stop_event.is_set():
                try:
                    # Read audio data
                    data = stream.read(CHUNK, exception_on_overflow=False)
                    
                    # Here you would process the audio data for wake word detection
                    # This is a simplified example - in a real implementation, you would:
                    # 1. Check for voice activity using the VAD
                    # 2. If voice is detected, record until silence
                    # 3. Process the recorded audio with the STT engine
                    # 4. Check if the wake word is present in the recognized text
                    # 5. Trigger the appropriate callbacks
                    
                    # For now, we'll just simulate the wake word detection
                    # In a real implementation, replace this with actual audio processing
                    if not self.wake_word_detected and random.random() < 0.01:  # Simulate wake word detection
                        self.wake_word_detected = True
                        if on_wake_word:
                            on_wake_word()
                        
                    # Simulate speech recognition
                    if self.wake_word_detected and random.random() < 0.05:  # Simulate speech detection
                        if on_utterance:
                            on_utterance("This is a simulated response")
                            
                except OSError as e:
                    logger.error(f"Audio stream error: {e}")
                    break
                    
                time.sleep(0.1)  # Small delay to prevent high CPU usage
                
            logger.error(f"Error in listen loop: {e}")
        finally:
            stream.stop_stream()
            stream.close()
            audio.terminate()
            self.is_listening = False
    
    def stop_listening(self) -> None:
        """Stop the background listening thread and clean up resources."""
        logger.info("Stopping speech recognition...")
        
        # Signal all threads to stop
        self._stop_event.set()
        self.is_listening = False
        
        # Cancel timeout timer if it exists
        if hasattr(self, '_timeout_timer') and self._timeout_timer:
            self._timeout_timer.cancel()
            self._timeout_timer = None
        
        # Stop the audio stream
        if hasattr(self, '_stream') and self._stream and self._stream.is_active():
            try:
                self._stream.stop_stream()
                self._stream.close()
            except Exception as e:
                logger.error(f"Error stopping audio stream: {e}")
        
        # Stop processing threads
        if hasattr(self, '_process_thread') and self._process_thread and self._process_thread.is_alive():
            self._process_thread.join(timeout=2.0)
            if self._process_thread.is_alive():
                logger.warning("Processing thread did not stop gracefully")
        
        # Stop audio device
        if hasattr(self, '_audio') and self._audio:
            try:
                self._audio.terminate()
            except Exception as e:
                logger.error(f"Error terminating audio device: {e}")
        
        # Clear audio buffer
        self._audio_buffer = bytearray()
        self.wake_word_detected = False
        
        logger.info("Speech recognition stopped")
    
# Example usage
if __name__ == "__main__":
    import logging
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    def on_text(text):
        print(f"Recognized: {text}")
    
    # Initialize speech recognition
    stt = SpeechToText(backend='google')
    
    print("Speak now (press Ctrl+C to stop)...")
    try:
        stt.listen(on_text=on_text)
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        stt.stop_listening()
