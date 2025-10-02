"""
Clippy AI Demo with Wake Word Detection

This script demonstrates the enhanced wake word detection system with a Tkinter UI.
It shows how to use multiple wake words, visualize detection confidence in real-time,
and integrate with the TTS system.
"""

import os
import sys
import time
import logging
import numpy as np
from pathlib import Path
import threading
import tkinter as tk
from tkinter import ttk
import matplotlib
matplotlib.use('TkAgg')  # Set the backend before importing pyplot
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from brixa.ai.clippy.voice.wake_word import WakeWordDetector, DetectionMethod
from brixa.ai.clippy.voice.tts import TextToSpeech

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ClippyDemo:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Clippy AI Demo")
        self.root.geometry("1000x700")
        
        # Initialize TTS with fallback to Windows TTS if available
        try:
            # Try Windows TTS first (most reliable on Windows)
            self.tts = TextToSpeech(backend='win32')
            logger.info("Using Windows TTS backend")
        except Exception as e:
            try:
                # Fall back to gTTS if Windows TTS fails
                self.tts = TextToSpeech(backend='gtts')
                logger.info("Using gTTS backend")
            except Exception as e:
                # Fall back to pyttsx3 as last resort
                logger.warning(f"Falling back to pyttsx3: {e}")
                self.tts = TextToSpeech(backend='pyttsx3')
        
        # Test TTS
        self.root.after(1000, lambda: self.tts.speak("Clippy is ready!"))
        
        # Initialize wake word detector with multiple wake words
        self.wake_words = {
            "hey clippy": 0.7,
            "computer": 0.6,
            "assistant": 0.6
        }
        
        # Initialize wake word detector with Razer Kraken headset
        self.wake_detector = WakeWordDetector(
            wake_words=self.wake_words,
            sensitivity=0.7,
            sample_rate=16000,
            input_device_index=2  # Using Razer Kraken headset
        )
        
        # Print debug info
        import sounddevice as sd
        device_info = sd.query_devices(2)
        print(f"Using audio input device: {device_info['name']}")
        print(f"  Max input channels: {device_info['max_input_channels']}")
        print(f"  Default sample rate: {device_info['default_samplerate']}")
        
        # Set up the UI
        self._setup_ui()
        
        # Start with wake word detection disabled
        self.wake_word_enabled = False
        self.update_wake_word_state()
        
    def _setup_ui(self):
        """Set up the main UI components."""
        # Configure main window
        self.root.title("Clippy AI - Voice Control Demo")
        
        # Create main container
        main_frame = ttk.Frame(self.root, padding="20 20 20 20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Add title
        title = ttk.Label(main_frame, text="Clippy Voice Control", font=('Helvetica', 16, 'bold'))
        title.pack(pady=(0, 20))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10 10 10 10")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar(value="Wake word detection: OFF")
        status_label = ttk.Label(status_frame, textvariable=self.status_var, font=('Helvetica', 12))
        status_label.pack(pady=5)
        
        # Controls frame
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10 10 10 10")
        control_frame.pack(fill=tk.X, pady=5)
        
        # Wake word toggle button
        self.wake_word_btn = ttk.Button(
            control_frame,
            text="Enable Wake Word",
            command=self.toggle_wake_word,
            width=20
        )
        self.wake_word_btn.pack(pady=10)
        
        # Instructions
        instr_frame = ttk.LabelFrame(main_frame, text="How to Use", padding="10 10 10 10")
        instr_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        instructions = """1. Click 'Enable Wake Word' to start listening
2. Try saying one of these wake words:
   - "Hey Clippy"
   - "Computer"
   - "Assistant"
3. Wait for Clippy to respond"""
        
        ttk.Label(instr_frame, text=instructions, justify=tk.LEFT).pack(anchor=tk.W, pady=5)
        
        # Simple log area
        log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="10 10 10 10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = tk.Text(log_frame, height=6, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        # Configure grid weights
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_rowconfigure(0, weight=1)
        
        self.log_text = tk.Text(log_frame, height=10, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        # Add scrollbar to the log frame
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def log(self, message: str):
        """Add a message to the log."""
        self.log_text.insert(tk.END, f"{message}\n")
        self.log_text.see(tk.END)
        logger.info(message)
    
    def toggle_wake_word(self):
        """Toggle wake word detection on/off."""
        self.wake_word_enabled = not self.wake_word_enabled
        self.update_wake_word_state()
    
    def update_wake_word_state(self):
        """Update the UI and internal state based on wake word detection state."""
        if self.wake_word_enabled:
            self.wake_word_btn.config(text="Disable Wake Word")
            self.status_var.set("Status: Listening for wake words...")
            self.start_wake_word_detection()
        else:
            self.wake_word_btn.config(text="Enable Wake Word")
            self.status_var.set("Status: Wake word detection disabled")
            self.stop_wake_word_detection()
    
    def start_wake_word_detection(self):
        """Start the wake word detector."""
        # Clear previous callbacks
        for word in self.wake_words:
            self.wake_detector.remove_detection_callback(word)
            self.wake_detector.add_detection_callback(word, self.on_wake_word_detected)
        
        # Start the detector
        self.wake_detector.start(self.on_audio_processed)
        self.log("Wake word detection started")
    
    def stop_wake_word_detection(self):
        """Stop the wake word detector."""
        self.wake_detector.stop()
        self.log("Wake word detection stopped")
    
    def on_wake_word_detected(self, confidence: float):
        """Handle wake word detection."""
        self.root.after(0, self._handle_wake_word, confidence)
    
    def _handle_wake_word(self, confidence: float):
        """Handle wake word detection in the main thread."""
        self.log(f"Wake word detected! (Confidence: {confidence:.2f})")
        self.tts.speak("Yes? How can I help you?")
    
    def on_audio_processed(self, detections: dict):
        """Handle processed audio data with detection results."""
        self.root.after(0, self._update_plot, detections)
    
    def _update_plot(self, detections: dict):
        """Update the confidence plot."""
        if not detections:
            return
        
        # Update plot data
        x = list(range(len(detections)))
        y = list(detections.values())
        
        self.confidence_plot.set_data(x, y)
        self.ax.set_xlim(0, max(10, len(x)))
        self.ax.set_xticks(range(0, max(10, len(x)), max(1, len(x)//10)))
        self.canvas.draw()
    
    def on_close(self):
        """Handle window close event."""
        self.stop_wake_word_detection()
        self.root.quit()
        self.root.destroy()
    
    def run(self):
        """Run the application."""
        self.root.mainloop()

if __name__ == "__main__":
    try:
        # Create and run the demo
        app = ClippyDemo()
        app.run()
    except Exception as e:
        logger.error(f"Error in Clippy demo: {e}", exc_info=True)
        input("Press Enter to exit...")
