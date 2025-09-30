"""
Enhanced Wake Word Detection for Clippy AI.

This module provides advanced wake word detection with support for multiple wake words,
custom model training, and visual feedback.
"""

import numpy as np
import threading
import queue
import time
import logging
import os
import json
import re
import wave
import struct
import math
import difflib
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Union, Deque
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import deque

import webrtcvad  # For voice activity detection
import numpy as np
from scipy import signal, fftpack
import noisereduce as nr
import sounddevice as sd

logger = logging.getLogger(__name__)

class DetectionMethod(Enum):
    """Wake word detection methods."""
    SPEECH_RECOGNITION = auto()  # Uses speech recognition (slower but more accurate)
    EMBEDDING_MATCHING = auto()  # Uses pre-computed embeddings (faster)
    CUSTOM_MODEL = auto()       # Uses a custom trained model

@dataclass
class WakeWordConfig:
    """Configuration for a wake word."""
    phrase: str
    threshold: float = 0.5
    method: DetectionMethod = DetectionMethod.SPEECH_RECOGNITION
    model_path: Optional[str] = None
    embeddings: Optional[np.ndarray] = None
    sensitivity: float = 0.5
    fuzzy_threshold: float = 0.8  # Threshold for fuzzy matching (0-1)
    min_confidence: float = 0.7   # Minimum confidence score (0-1)
    noise_reduction: bool = True  # Whether to apply noise reduction
    context_window: int = 10      # Number of previous detections to consider

class WakeWordDetector:
    """
    Advanced wake word detector for the Clippy AI assistant.
    
    Supports multiple wake words/phrases, custom model training, and visual feedback.
    """
    
    def __init__(self, 
                 wake_words: Union[str, List[str], Dict[str, dict]] = "clippy",
                 sensitivity: float = 0.7,
                 sample_rate: int = 16000,
                 chunk_size: int = 1024,
                 channels: int = 1,
                 model_dir: Optional[str] = None):
        """
        Initialize the wake word detector with advanced features.
        
        Args:
            wake_words: Single wake word, list of wake words, or dict of {word: config_dict}
                       where config_dict can include:
                       - sensitivity: float (0.0 to 1.0)
                       - fuzzy_threshold: float (0.0 to 1.0)
                       - min_confidence: float (0.0 to 1.0)
                       - noise_reduction: bool
                       - context_window: int
            sensitivity: Default detection sensitivity (0.0 to 1.0, higher = more sensitive)
            sample_rate: Audio sample rate in Hz (16000, 22050, 44100, etc.)
            chunk_size: Number of audio frames per buffer (power of 2 recommended)
            channels: Number of audio channels (1=mono, 2=stereo)
            model_dir: Directory to load/save wake word models
        """
        self.sample_rate = sample_rate
        self.chunk_size = chunk_size
        self.channels = channels
        self.sensitivity = max(0.0, min(1.0, sensitivity))
        
        # Initialize wake words
        self.wake_words: Dict[str, WakeWordConfig] = {}
        self._init_wake_words(wake_words)
        
        # Audio processing
        self.audio_buffer = np.array([], dtype=np.float32)
        self.buffer_size = sample_rate * 5  # 5 seconds buffer
        self.vad = webrtcvad.Vad(3)  # Aggressiveness mode 0-3
        
        # Threading
        self.is_listening = False
        self._stop_event = threading.Event()
        self.audio_queue = queue.Queue()
        self.callbacks = {}
        
        # Model directory
        self.model_dir = model_dir or str(Path.home() / '.clippy' / 'models')
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Initialize components
        self._init_speech_recognition()
        self._init_audio_processing()
        
        # Load any pre-trained models
        self._load_models()
    
    def _init_wake_words(self, wake_words):
        """Initialize wake words from various input formats."""
        if isinstance(wake_words, str):
            self.add_wake_word(wake_words, self.sensitivity)
        elif isinstance(wake_words, list):
            for word in wake_words:
                self.add_wake_word(word, self.sensitivity)
        elif isinstance(wake_words, dict):
            for word, sens in wake_words.items():
                self.add_wake_word(word, sens)
    
    def add_wake_word(self, phrase: str, sensitivity: float = None, 
                     method: DetectionMethod = None, model_path: str = None,
                     fuzzy_threshold: float = 0.8, min_confidence: float = 0.7,
                     noise_reduction: bool = True, context_window: int = 10):
        """
        Add a wake word to detect.
        
        Args:
            phrase: The wake word or phrase to detect
            sensitivity: Detection sensitivity (0.0 to 1.0)
            method: Detection method to use
            model_path: Path to custom model (if using CUSTOM_MODEL)
            fuzzy_threshold: Minimum similarity score for fuzzy matching (0-1)
            min_confidence: Minimum confidence score (0-1)
            noise_reduction: Whether to apply noise reduction
            context_window: Number of previous detections to consider for context
        """
        sensitivity = sensitivity if sensitivity is not None else self.sensitivity
        method = method or DetectionMethod.SPEECH_RECOGNITION
        
        self.wake_words[phrase.lower()] = WakeWordConfig(
            phrase=phrase,
            threshold=1.0 - (sensitivity * 0.5),  # Map 0-1 to 1.0-0.5
            method=method,
            model_path=model_path,
            sensitivity=sensitivity,
            fuzzy_threshold=max(0.1, min(1.0, fuzzy_threshold)),
            min_confidence=max(0.1, min(1.0, min_confidence)),
            noise_reduction=noise_reduction,
            context_window=max(1, context_window)
        )
        
        # Initialize detection history if needed
        if not hasattr(self, 'detection_history'):
            self.detection_history = {}
        self.detection_history[phrase.lower()] = deque(maxlen=context_window)
        
        logger.info(f"Added wake word: '{phrase}' (sensitivity: {sensitivity:.2f}, method: {method.name})")
    
    def remove_wake_word(self, phrase: str):
        """Remove a wake word from detection."""
        if phrase.lower() in self.wake_words:
            del self.wake_words[phrase.lower()]
            logger.info(f"Removed wake word: '{phrase}'")
    
    def _load_models(self):
        """Load pre-trained wake word models."""
        if not os.path.exists(self.model_dir):
            return
            
        for filename in os.listdir(self.model_dir):
            if filename.endswith('.wakeword'):
                model_path = os.path.join(self.model_dir, filename)
                try:
                    with open(model_path, 'r') as f:
                        model_data = json.load(f)
                    
                    phrase = model_data.get('phrase')
                    if phrase:
                        self.add_wake_word(
                            phrase=phrase,
                            sensitivity=model_data.get('sensitivity', 0.7),
                            method=DetectionMethod.CUSTOM_MODEL,
                            model_path=model_path
                        )
                        logger.info(f"Loaded wake word model: {phrase}")
                        
                except Exception as e:
                    logger.error(f"Error loading model {filename}: {e}")
    
    def train_wake_word(self, phrase: str, audio_samples: List[np.ndarray], 
                       test_samples: List[np.ndarray] = None, epochs: int = 10):
        """
        Train a custom wake word detection model.
        
        Args:
            phrase: The wake word phrase to train on
            audio_samples: List of numpy arrays containing audio samples
            test_samples: Optional test samples for validation
            epochs: Number of training epochs
            
        Returns:
            dict: Training results and model metrics
        """
        try:
            import tensorflow as tf
            from tensorflow.keras import layers, models
            
            # Preprocess audio samples
            X_train = [self._extract_features(audio) for audio in audio_samples]
            y_train = np.ones(len(X_train))  # Positive samples
            
            # Generate negative samples (optional)
            # This is a simplified example - in practice, you'd want more sophisticated augmentation
            X_neg = []
            for audio in audio_samples:
                # Add noise
                noise = np.random.normal(0, 0.005, audio.shape)
                X_neg.append(self._extract_features(audio + noise))
                
                # Time stretch
                if len(audio) > self.chunk_size:
                    stretched = signal.resample(audio, int(len(audio) * 1.1))
                    X_neg.append(self._extract_features(stretched[:len(audio)]))
            
            y_neg = np.zeros(len(X_neg))
            
            # Combine and shuffle
            X = np.vstack(X_train + X_neg)
            y = np.concatenate([y_train, y_neg])
            
            # Simple CNN model for wake word detection
            model = models.Sequential([
                layers.Input(shape=X[0].shape),
                layers.Conv1D(64, 3, activation='relu', padding='same'),
                layers.MaxPooling1D(2),
                layers.Dropout(0.3),
                layers.Conv1D(128, 3, activation='relu', padding='same'),
                layers.MaxPooling1D(2),
                layers.Dropout(0.3),
                layers.Flatten(),
                layers.Dense(64, activation='relu'),
                layers.Dropout(0.3),
                layers.Dense(1, activation='sigmoid')
            ])
            
            model.compile(
                optimizer='adam',
                loss='binary_crossentropy',
                metrics=['accuracy']
            )
            
            # Train the model
            history = model.fit(
                X, y,
                epochs=epochs,
                batch_size=32,
                validation_split=0.2,
                verbose=1
            )
            
            # Save the model
            model_path = os.path.join(self.model_dir, f"{phrase.lower().replace(' ', '_')}.wakeword")
            model.save(model_path)
            
            # Save model metadata
            with open(f"{model_path}.json", 'w') as f:
                json.dump({
                    'phrase': phrase,
                    'input_shape': X[0].shape,
                    'sample_rate': self.sample_rate,
                    'sensitivity': self.sensitivity,
                    'metrics': history.history
                }, f)
            
            # Update wake word config
            self.add_wake_word(
                phrase=phrase,
                sensitivity=self.sensitivity,
                method=DetectionMethod.CUSTOM_MODEL,
                model_path=model_path
            )
            
            return {
                'success': True,
                'model_path': model_path,
                'metrics': history.history,
                'phrase': phrase
            }
            
        except Exception as e:
            logger.error(f"Error training wake word model: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _extract_features(self, audio: np.ndarray) -> np.ndarray:
        """Extract audio features for model training/inference."""
        if self.mel_basis is not None:
            # Compute Mel spectrogram
            import librosa
            S = np.abs(librosa.stft(audio, n_fft=self.n_fft, hop_length=self.hop_length))
            mel = np.dot(self.mel_basis, S)
            return librosa.power_to_db(mel, ref=np.max)
        else:
            # Fallback to MFCC
            import python_speech_features
            return python_speech_features.mfcc(
                audio,
                samplerate=self.sample_rate,
                winlen=0.025,
                winstep=0.01,
                numcep=13,
                nfilt=26,
                nfft=512,
                preemph=0.97
            )
    
    def _detect_with_model(self, audio: np.ndarray, model_path: str) -> float:
        """Detect wake word using a trained model."""
        try:
            import tensorflow as tf
            model = tf.keras.models.load_model(model_path)
            
            # Extract features and predict
            features = self._extract_features(audio)
            if len(features.shape) == 2:  # Add batch dimension if needed
                features = np.expand_dims(features, axis=0)
                
            confidence = model.predict(features, verbose=0)[0][0]
            return float(confidence)
            
        except Exception as e:
            logger.error(f"Error in model detection: {e}")
            return 0.0
    
    def _detect_with_embeddings(self, audio: np.ndarray, config: WakeWordConfig) -> float:
        """Detect wake word using embedding similarity."""
        if config.embeddings is None:
            return 0.0
            
        try:
            # Extract features
            features = self._extract_features(audio)
            
            # Compare with stored embeddings (simplified)
            # In practice, you'd use a proper similarity metric
            similarity = np.mean([
                np.corrcoef(features.flatten(), emb.flatten())[0, 1]
                for emb in config.embeddings
            ])
            
            return max(0.0, min(1.0, (similarity + 1) / 2))  # Convert to [0, 1] range
            
        except Exception as e:
            logger.error(f"Error in embedding detection: {e}")
            return 0.0
    
    def _process_audio_chunk(self, audio_chunk: np.ndarray) -> Dict[str, float]:
        """Process an audio chunk and return detection results."""
        results = {}
        
        for phrase, config in self.wake_words.items():
            confidence = 0.0
            
            if config.method == DetectionMethod.SPEECH_RECOGNITION:
                # Use speech recognition (slower but more accurate)
                text = self._recognize_speech(audio_chunk)
                if text and config.phrase.lower() in text.lower():
                    confidence = 0.8  # High confidence if recognized
                    
            elif config.method == DetectionMethod.EMBEDDING_MATCHING:
                # Use pre-computed embeddings
                confidence = self._detect_with_embeddings(audio_chunk, config)
                
            elif config.method == DetectionMethod.CUSTOM_MODEL and config.model_path:
                # Use custom trained model
                confidence = self._detect_with_model(audio_chunk, config.model_path)
            
            # Apply sensitivity threshold
            if confidence >= config.threshold:
                results[phrase] = confidence
        
        return results
    
    def _recognize_speech(self, audio_data: np.ndarray) -> Optional[str]:
        """Convert speech to text using the configured recognizer."""
        if not hasattr(self, 'recognizer') or self.recognizer is None:
            return None
            
        try:
            import speech_recognition as sr
            
            # Convert to 16-bit PCM
            audio_data = (audio_data * 32767).astype(np.int16)
            audio = sr.AudioData(
                audio_data.tobytes(),
                sample_rate=self.sample_rate,
                sample_width=2  # 16-bit
            )
            
            return self.recognizer.recognize_google(audio)
            
        except Exception as e:
            logger.debug(f"Speech recognition error: {e}")
            return None
    
    def add_detection_callback(self, phrase: str, callback: Callable[[float], None]):
        """Add a callback for when a specific wake word is detected."""
        self.callbacks[phrase.lower()] = callback
    
    def remove_detection_callback(self, phrase: str):
        """Remove a detection callback."""
        self.callbacks.pop(phrase.lower(), None)
    
    def start(self, audio_callback: Callable[[Dict[str, float]], None] = None):
        """
        Start the wake word detection.
        
        Args:
            audio_callback: Optional callback that receives detection results
        """
        if self.is_listening:
            logger.warning("Wake word detector is already running")
            return
            
        self.is_listening = True
        self._stop_event.clear()
        self.audio_callback = audio_callback
        
        # Start audio capture thread
        self.audio_thread = threading.Thread(
            target=self._audio_capture_loop,
            daemon=True
        )
        self.audio_thread.start()
        
        # Start processing thread
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True
        )
        self.processing_thread.start()
        
        logger.info("Wake word detection started")
    
    def stop(self):
        """Stop the wake word detection."""
        if not self.is_listening:
            return
            
        self.is_listening = False
        self._stop_event.set()
        
        # Wait for threads to finish
        if hasattr(self, 'audio_thread'):
            self.audio_thread.join(timeout=1.0)
        if hasattr(self, 'processing_thread'):
            self.processing_thread.join(timeout=1.0)
            
        logger.info("Wake word detection stopped")
    
    def _audio_capture_loop(self):
        """Capture audio from the microphone in a loop."""
        import sounddevice as sd
        
        def audio_callback(indata, frames, time, status):
            """Callback for audio stream."""
            if status:
                logger.debug(f"Audio status: {status}")
            
            # Add audio data to the queue
            self.audio_queue.put(indata.copy())
        
        try:
            with sd.InputStream(
                samplerate=self.sample_rate,
                blocksize=self.chunk_size,
                channels=self.channels,
                dtype='float32',
                callback=audio_callback
            ) as stream:
                while self.is_listening and not self._stop_event.is_set():
                    time.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error in audio capture: {e}")
            self.is_listening = False
    
    def _processing_loop(self):
        """Process audio data to detect wake words."""
        import sounddevice as sd
        
        # Buffer for accumulating audio
        audio_buffer = np.array([], dtype=np.float32)
        min_buffer_size = self.sample_rate  # 1 second of audio
        
        while self.is_listening and not self._stop_event.is_set():
            try:
                # Get audio data from queue
                try:
                    audio_chunk = self.audio_queue.get(timeout=0.1)
                    audio_buffer = np.concatenate([audio_buffer, audio_chunk.flatten()])
                except queue.Empty:
                    continue
                
                # Process in chunks of min_buffer_size
                while len(audio_buffer) >= min_buffer_size:
                    # Extract chunk to process
                    process_chunk = audio_buffer[:min_buffer_size]
                    audio_buffer = audio_buffer[min_buffer_size:]
                    
                    # Detect wake words
                    detections = self._process_audio_chunk(process_chunk)
                    
                    # Call callbacks for each detection
                    for phrase, confidence in detections.items():
                        logger.debug(f"Detected '{phrase}' with confidence {confidence:.2f}")
                        
                        # Call specific phrase callback if registered
                        if phrase.lower() in self.callbacks:
                            try:
                                self.callbacks[phrase.lower()](confidence)
                            except Exception as e:
                                logger.error(f"Error in detection callback: {e}")
                    
                    # Call general audio callback if provided
                    if self.audio_callback and detections:
                        try:
                            self.audio_callback(detections)
                        except Exception as e:
                            logger.error(f"Error in audio callback: {e}")
                
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                time.sleep(0.1)  # Prevent tight loop on error
    
    def _init_audio_processing(self):
        """Initialize audio processing components."""
        # Pre-compute FFT parameters
        self.n_fft = 512
        self.hop_length = 160
        self.n_mels = 40
        
        # Pre-compute Mel filterbank
        try:
            import librosa
            self.mel_basis = librosa.filters.mel(
                sr=self.sample_rate,
                n_fft=self.n_fft,
                n_mels=self.n_mels
            )
        except ImportError:
            logger.warning("Librosa not found, using basic FFT features")
            self.mel_basis = None
    
    def _init_speech_recognition(self):
        """Initialize the speech recognition backend."""
        try:
            import speech_recognition as sr
            self.recognizer = sr.Recognizer()
            self.recognizer.pause_threshold = 0.5
            self.recognizer.energy_threshold = 300
            self.recognizer.dynamic_energy_threshold = True
            
        except ImportError:
            logger.error("SpeechRecognition package not found. Install with: pip install SpeechRecognition")
            self.recognizer = None
    
    def _init_wake_word_model(self):
        """Initialize the wake word detection model."""
        # This is a placeholder for actual wake word detection
        # In a real implementation, you might use a pre-trained model like Porcupine, Snowboy, etc.
        self.wake_word_model = {
            'threshold': 0.5 * (1.0 + self.sensitivity),  # Adjust threshold based on sensitivity
            'phrase': self.wake_word.lower()
        }
        
        logger.info(f"Wake word detection initialized for: '{self.wake_word}'")
    
    def start(self, callback: Callable[[], None]):
        """
        Start listening for the wake word.
        
        Args:
            callback: Function to call when the wake word is detected
        """
        if self.is_listening:
            logger.warning("Wake word detector is already running")
            return
            
        if not self.recognizer:
            logger.error("Speech recognition not initialized")
            return
            
        self.callback = callback
        self.is_listening = True
        self._stop_event.clear()
        
        # Start the audio processing thread
        self.audio_thread = threading.Thread(
            target=self._audio_capture_loop,
            daemon=True
        )
        self.audio_thread.start()
        
        # Start the processing thread
        self.processing_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True
        )
        self.processing_thread.start()
        
        logger.info("Wake word detection started")
    
    def stop(self):
        """Stop listening for the wake word."""
        if not self.is_listening:
            return
            
        self.is_listening = False
        self._stop_event.set()
        
        # Wait for threads to finish
        if hasattr(self, 'audio_thread'):
            self.audio_thread.join(timeout=1.0)
        if hasattr(self, 'processing_thread'):
            self.processing_thread.join(timeout=1.0)
            
        logger.info("Wake word detection stopped")
    
    def _audio_capture_loop(self):
        """Capture audio from the microphone in a loop."""
        import sounddevice as sd
        
        def audio_callback(indata, frames, time, status):
            """Callback for audio stream."""
            if status:
                logger.warning(f"Audio status: {status}")
            
            # Add audio data to the queue
            self.audio_queue.put(indata.copy())
        
        try:
            with sd.InputStream(
                samplerate=self.sample_rate,
                blocksize=self.chunk_size,
                channels=self.channels,
                dtype='float32',
                callback=audio_callback
            ) as stream:
                while self.is_listening and not self._stop_event.is_set():
                    time.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error in audio capture: {e}")
            self.is_listening = False
    
    def _processing_loop(self):
        """Process audio data to detect the wake word."""
        while self.is_listening and not self._stop_event.is_set():
            try:
                # Get audio data from the queue
                try:
                    audio_data = self.audio_queue.get(timeout=1.0)
                except queue.Empty:
                    continue
                
                # Process the audio data
                detected = self._detect_wake_word(audio_data)
                
                # If wake word detected, call the callback
                if detected and callable(getattr(self, 'callback', None)):
                    logger.info(f"Wake word '{self.wake_word}' detected!")
                    self.callback()
                    
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
    
    def _detect_wake_word(self, audio_data: np.ndarray) -> bool:
        """
        Detect if the wake word is present in the audio data.
        
        This is a simplified implementation. In a real application, you would use
        a proper wake word detection model like Porcupine, Snowboy, etc.
        
        Args:
            audio_data: Audio data as a numpy array
            
        Returns:
            bool: True if wake word is detected, False otherwise
        """
        try:
            # Convert numpy array to audio data
            import speech_recognition as sr
            audio = sr.AudioData(
                (audio_data * 32767).astype(np.int16).tobytes(),
                self.sample_rate,
                2  # 16-bit audio
            )
            
            # Use speech recognition to transcribe the audio
            text = self.recognizer.recognize_google(audio, show_all=True)
            
            # Check if the wake word is in the transcription
            if isinstance(text, dict) and 'alternative' in text:
                for alt in text['alternative']:
                    if 'transcript' in alt:
                        transcript = alt['transcript'].lower()
                        if self.wake_word in transcript:
                            confidence = alt.get('confidence', 0.5)
                            return confidence >= self.wake_word_model['threshold']
            
            return False
            
        except Exception as e:
            # Ignore recognition errors (common for background noise)
            return False
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()


def test_wake_word():
    """Test the wake word detection."""
    print(f"Testing wake word detection for 'clippy'...")
    print("Say 'clippy' to trigger detection (Ctrl+C to exit)")
    
    def on_wake_word_detected():
        print("\nWake word detected!")
    
    # Create and start the detector
    detector = WakeWordDetector(wake_word="clippy", sensitivity=0.7)
    
    try:
        detector.start(on_wake_word_detected)
        
        # Keep the main thread alive
        while True:
            time.sleep(0.1)
            
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        detector.stop()


if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO)
    test_wake_word()
