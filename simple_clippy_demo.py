"""
Simple Clippy Demo with Wake Word Detection

A simplified version of the Clippy demo with basic UI.
"""

import tkinter as tk
from tkinter import ttk
import logging
from pathlib import Path
import sys

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent.absolute()))

from brixa.ai.clippy.voice.wake_word import WakeWordDetector
from brixa.ai.clippy.voice.tts import TextToSpeech

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SimpleClippyDemo:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Clippy AI - Simple Demo")
        self.root.geometry("800x600")
        
        # Initialize TTS
        try:
            self.tts = TextToSpeech(backend='win32')
            logger.info("Using Windows TTS backend")
        except Exception as e:
            logger.error(f"Failed to initialize TTS: {e}")
            self.tts = None
        
        # Set up the UI
        self._setup_ui()
        
        # Initialize wake word detector
        self.wake_words = {
            "hey clippy": 0.7,
            "computer": 0.6,
            "assistant": 0.6
        }
        
        # Set up audio device (using Razer Kraken headset - device 22)
        import sounddevice as sd
        self.audio_device = 22  # Razer Kraken headset
        
        # List available input devices for debugging
        self.log("Available input devices:")
        for i, dev in enumerate(sd.query_devices()):
            if dev['max_input_channels'] > 0:
                self.log(f"  {i}: {dev['name']} (in: {dev['max_input_channels']} channels)")
        
        # Verify selected device
        try:
            device_info = sd.query_devices(self.audio_device)
            self.log(f"Using audio device: {self.audio_device} - {device_info['name']}")
            self.log(f"  Max input channels: {device_info['max_input_channels']}")
            self.log(f"  Default sample rate: {device_info['default_samplerate']}")
        except Exception as e:
            self.log(f"Error with audio device {self.audio_device}: {e}")
            self.audio_device = None  # Fall back to default
        self.wake_detector = None
        self.wake_word_enabled = False
        
    def _setup_ui(self):
        """Set up the main UI components."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="20 20 20 20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title = ttk.Label(main_frame, 
                         text="Clippy Voice Control", 
                         font=('Helvetica', 16, 'bold'))
        title.pack(pady=(0, 20))
        
        # Status frame
        status_frame = ttk.LabelFrame(main_frame, text="Status", padding="10 10 10 10")
        status_frame.pack(fill=tk.X, pady=5)
        
        self.status_var = tk.StringVar(value="Wake word detection: OFF")
        status_label = ttk.Label(status_frame, 
                               textvariable=self.status_var, 
                               font=('Helvetica', 12))
        status_label.pack(pady=5)
        
        # Controls frame
        control_frame = ttk.LabelFrame(main_frame, 
                                     text="Controls", 
                                     padding="10 10 10 10")
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
        instr_frame = ttk.LabelFrame(main_frame, 
                                   text="How to Use", 
                                   padding="10 10 10 10")
        instr_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        instructions = """1. Click 'Enable Wake Word' to start listening
2. Try saying one of these wake words:
   - "Hey Clippy"
   - "Computer"
   - "Assistant"
3. Wait for Clippy to respond"""
        
        ttk.Label(instr_frame, 
                 text=instructions, 
                 justify=tk.LEFT).pack(anchor=tk.W, pady=5)
        
        # Log area
        log_frame = ttk.LabelFrame(main_frame, 
                                 text="Activity Log", 
                                 padding="10 10 10 10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.log_text = tk.Text(log_frame, 
                              height=6, 
                              wrap=tk.WORD,
                              state='disabled')
        scrollbar = ttk.Scrollbar(log_frame, 
                                orient="vertical", 
                                command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def log(self, message, clear_after=None):
        """Add a message to the log."""
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        if clear_after:
            self.root.after(clear_after * 1000, lambda: self._clear_last_log())
        self.log_text.config(state='disabled')
    
    def _clear_last_log(self):
        """Clear the last line from the log."""
        self.log_text.config(state='normal')
        self.log_text.delete("end-2l", "end-1l")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def toggle_wake_word(self):
        """Toggle wake word detection on/off."""
        if self.wake_word_enabled:
            self.stop_wake_word_detection()
        else:
            self.start_wake_word_detection()
    
    def start_wake_word_detection(self):
        """Start listening for wake words."""
        try:
            import sounddevice as sd
            import numpy as np
            
            # Get the selected device info
            device_info = sd.query_devices(self.audio_device)
            sample_rate = int(device_info['default_samplerate'])
            
            self.log(f"Starting wake word detection with device {self.audio_device}: {device_info['name']}")
            
            # Simple audio callback to show it's working
            def audio_callback(indata, frames, time, status):
                if status:
                    self.log(f"Audio status: {status}")
                volume = int(np.linalg.norm(indata) * 10)
                self.log(f"Audio level: {volume}/100", clear_after=5)  # Show for 5 seconds
            
            # Start a simple audio stream to verify it works
            self.log("Testing microphone...")
            with sd.InputStream(callback=audio_callback, 
                             samplerate=sample_rate,
                             channels=1,
                             device=self.audio_device):
                self.log("Microphone is working! Listening for wake words...")
                
                # Initialize wake word detector
                self.wake_detector = WakeWordDetector(
                    wake_words=self.wake_words,
                    sensitivity=0.5,
                    sample_rate=sample_rate,
                    input_device_index=self.audio_device
                )
                
                # Add detection callbacks
                for word in self.wake_words:
                    self.wake_detector.add_detection_callback(word, self.on_wake_word_detected)
                
                # Start detection
                self.wake_detector.start()
                self.wake_word_enabled = True
                self.status_var.set("Wake word detection: ON")
                self.wake_word_btn.config(text="Disable Wake Word")
                
                # Keep the stream open
                while self.wake_word_enabled:
                    sd.sleep(100)
                
        except Exception as e:
            self.log(f"Error in wake word detection: {e}")
            import traceback
            self.log(traceback.format_exc())
            
            # Provide specific guidance for common errors
            if "PortAudioError" in str(e):
                self.log("Error: Could not access the audio device. Make sure your microphone is not in use by another application.")
            elif "NoDefaultInputDevice" in str(e):
                self.log("Error: No default input device found. Please check your audio settings.")
            elif "Invalid input device" in str(e):
                self.log(f"Error: Invalid input device {self.audio_device}. Please check the device number.")
    
    def stop_wake_word_detection(self):
        """Stop listening for wake words."""
        if self.wake_detector:
            self.wake_detector.stop()
        self.wake_word_enabled = False
        self.status_var.set("Wake word detection: OFF")
        self.wake_word_btn.config(text="Enable Wake Word")
        self.log("Wake word detection stopped")
    
    def on_wake_word_detected(self, confidence: float):
        """Handle wake word detection."""
        self.root.after(0, lambda: self._handle_wake_word(confidence))
    
    def _handle_wake_word(self, confidence: float):
        """Handle wake word detection in the main thread."""
        self.log(f"Wake word detected! (Confidence: {confidence:.2f})")
        if self.tts:
            self.tts.speak("Yes? How can I help you?")
    
    def on_close(self):
        """Handle window close event."""
        self.stop_wake_word_detection()
        self.root.destroy()
    
    def run(self):
        """Run the application."""
        self.log("Clippy AI Demo started")
        if self.tts:
            self.root.after(1000, lambda: self.tts.speak("Clippy is ready!"))
        self.root.mainloop()

if __name__ == "__main__":
    try:
        app = SimpleClippyDemo()
        app.run()
    except Exception as e:
        logger.error(f"Error in SimpleClippyDemo: {e}", exc_info=True)
        input("Press Enter to exit...")
