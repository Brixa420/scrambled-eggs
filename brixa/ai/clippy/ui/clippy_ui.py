"""
Clippy UI - Modern Tkinter interface for the Clippy AI assistant.

Features:
- Chat interface with message history
- Voice interaction controls
- Visual feedback for listening/speaking states
- Customizable appearance
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, font as tkfont
import threading
import queue
import json
import os
from pathlib import Path
from typing import Optional, Callable, Dict, Any
from PIL import Image, ImageTk

# Import Clippy voice modules
from ..voice import TextToSpeech, SpeechToText

class ClippyUI:
    """Modern Tkinter UI for the Clippy AI assistant."""
    
    def __init__(self, root: tk.Tk, on_send_message: Callable[[str], str] = None):
        """
        Initialize the Clippy UI.
        
        Args:
            root: Tkinter root window
            on_send_message: Callback function that takes a message and returns a response
        """
        self.root = root
        self.on_send_message = on_send_message or self._default_response_handler
        self.message_queue = queue.Queue()
        self.is_listening = False
        self.settings = self._load_settings()
        
        # Initialize voice modules
        self.tts = TextToSpeech(backend=self.settings.get('tts_backend', 'pyttsx3'))
        self.stt = SpeechToText(backend=self.settings.get('stt_backend', 'google'))
        
        # Set up the UI
        self._setup_ui()
        
        # Start processing the message queue
        self._process_queue()
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from file or use defaults."""
        default_settings = {
            'theme': 'light',
            'tts_enabled': True,
            'stt_enabled': True,
            'tts_backend': 'pyttsx3',
            'stt_backend': 'google',
            'voice_rate': 150,
            'wake_word': 'clippy',
            'font_family': 'Segoe UI',
            'font_size': 10
        }
        
        settings_file = Path.home() / '.clippy' / 'settings.json'
        if settings_file.exists():
            try:
                with open(settings_file, 'r') as f:
                    loaded = json.load(f)
                    default_settings.update(loaded)
            except Exception as e:
                print(f"Error loading settings: {e}")
        
        return default_settings
    
    def _save_settings(self):
        """Save settings to file."""
        settings_dir = Path.home() / '.clippy'
        settings_dir.mkdir(exist_ok=True)
        settings_file = settings_dir / 'settings.json'
        
        try:
            with open(settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def _setup_ui(self):
        """Set up the main UI components."""
        # Configure the root window
        self.root.title("Clippy AI Assistant")
        self.root.geometry("800x600")
        self.root.minsize(400, 300)
        
        # Set application icon if available
        self._set_window_icon()
        
        # Configure styles
        self._setup_styles()
        
        # Create main container
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create chat display
        self._create_chat_display()
        
        # Create input area
        self._create_input_area()
        
        # Start with input focused
        self.input_text.focus_set()
        
        # Bind keyboard shortcuts
        self._bind_shortcuts()
    
    def _set_window_icon(self):
        """Set the application window icon if available."""
        try:
            # Try to load icon from package resources
            import pkg_resources
            icon_path = pkg_resources.resource_filename('brixa.ai.clippy', 'assets/clippy.ico')
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except:
            # Fallback to default icon or skip if not available
            pass
    
    def _setup_styles(self):
        """Configure ttk styles."""
        style = ttk.Style()
        
        # Configure theme
        if 'winnative' in style.theme_names():
            style.theme_use('winnative')
        
        # Configure colors based on theme
        bg_color = '#ffffff' if self.settings['theme'] == 'light' else '#2d2d2d'
        fg_color = '#000000' if self.settings['theme'] == 'light' else '#ffffff'
        
        # Configure styles
        style.configure('TFrame', background=bg_color)
        style.configure('TLabel', background=bg_color, foreground=fg_color)
        style.configure('TButton', padding=5)
        
        # Custom styles
        style.configure('User.TLabel', 
                       background='#e3f2fd' if self.settings['theme'] == 'light' else '#0d47a1',
                       foreground=fg_color,
                       padding=5,
                       relief='raised',
                       borderwidth=1)
        
        style.configure('Assistant.TLabel',
                      background='#f5f5f5' if self.settings['theme'] == 'light' else '#424242',
                      foreground=fg_color,
                      padding=5,
                      relief='sunken',
                      borderwidth=1)
    
    def _create_chat_display(self):
        """Create the chat display area."""
        # Chat container
        chat_frame = ttk.Frame(self.main_frame)
        chat_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Chat history
        self.chat_display = scrolledtext.ScrolledText(
            chat_frame,
            wrap=tk.WORD,
            state='disabled',
            font=(self.settings['font_family'], self.settings['font_size']),
            bg='white' if self.settings['theme'] == 'light' else '#2d2d2d',
            fg='black' if self.settings['theme'] == 'light' else '#ffffff',
            insertbackground='black' if self.settings['theme'] == 'light' else '#ffffff',
            padx=10,
            pady=10
        )
        self.chat_display.pack(fill=tk.BOTH, expand=True)
        
        # Add welcome message
        self._add_message("assistant", "Hello! I'm Clippy, your AI assistant. How can I help you today?")
    
    def _create_input_area(self):
        """Create the input area with text entry and buttons."""
        # Input frame
        input_frame = ttk.Frame(self.main_frame)
        input_frame.pack(fill=tk.X, pady=(5, 0))
        
        # Voice button
        self.voice_btn = ttk.Button(
            input_frame,
            text="🎤",
            width=3,
            command=self.toggle_voice_input
        )
        self.voice_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        # Text input
        self.input_text = ttk.Entry(input_frame)
        self.input_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.input_text.bind('<Return>', lambda e: self.send_message())
        
        # Send button
        self.send_btn = ttk.Button(
            input_frame,
            text="Send",
            command=self.send_message
        )
        self.send_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(
            input_frame,
            textvariable=self.status_var,
            foreground='gray'
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
    
    def _bind_shortcuts(self):
        """Bind keyboard shortcuts."""
        # Toggle voice input with Ctrl+Space
        self.root.bind('<Control-space>', lambda e: self.toggle_voice_input())
        
        # Focus input with Escape
        self.root.bind('<Escape>', lambda e: self.input_text.focus())
    
    def _add_message(self, sender: str, message: str):
        """Add a message to the chat display."""
        self.chat_display.config(state='normal')
        
        # Configure tags for different senders
        self.chat_display.tag_configure('user', justify='right')
        self.chat_display.tag_configure('assistant', justify='left')
        
        # Add the message
        self.chat_display.insert(tk.END, f"{sender.capitalize()}:\n{message}\n\n", 
                               'user' if sender == 'user' else 'assistant')
        
        # Auto-scroll to bottom
        self.chat_display.see(tk.END)
        self.chat_display.config(state='disabled')
    
    def send_message(self, message: str = None):
        """Send a message and get a response."""
        # Get message from input if not provided
        if message is None:
            message = self.input_text.get().strip()
            if not message:
                return
            
            # Clear input
            self.input_text.delete(0, tk.END)
        
        # Add user message to chat
        self._add_message("user", message)
        
        # Disable input while processing
        self._set_input_state(False)
        
        # Process message in a separate thread
        threading.Thread(
            target=self._process_message,
            args=(message,),
            daemon=True
        ).start()
    
    def _process_message(self, message: str):
        """Process a message and get a response."""
        try:
            # Get response from the callback
            response = self.on_send_message(message)
            
            # Add response to the queue
            self.message_queue.put(('response', response))
            
            # Speak the response if TTS is enabled
            if self.settings.get('tts_enabled', True):
                self.message_queue.put(('speak', response))
                
        except Exception as e:
            error_msg = f"Sorry, I encountered an error: {str(e)}"
            self.message_queue.put(('response', error_msg))
            
        finally:
            # Re-enable input
            self.message_queue.put(('enable_input', True))
    
    def toggle_voice_input(self):
        """Toggle voice input on/off."""
        if self.is_listening:
            self.stop_voice_input()
        else:
            self.start_voice_input()
    
    def start_voice_input(self):
        """Start listening for voice input."""
        if not self.settings.get('stt_enabled', True):
            self._show_status("Speech recognition is disabled in settings")
            return
            
        self.is_listening = True
        self.voice_btn.config(text="🔴", style='Danger.TButton' if 'Danger.TButton' in ttk.Style().map('TButton') else '')
        self._show_status("Listening...")
        
        # Start listening in a separate thread
        threading.Thread(
            target=self._listen_for_voice,
            daemon=True
        ).start()
    
    def stop_voice_input(self):
        """Stop listening for voice input."""
        self.is_listening = False
        self.voice_btn.config(text="🎤")
        self._show_status("")
    
    def _listen_for_voice(self):
        """Listen for voice input and process it."""
        try:
            text = self.stt.listen(timeout=5, phrase_time_limit=10)
            if text:
                # Update UI on the main thread
                self.message_queue.put(('message', text))
                
        except Exception as e:
            self.message_queue.put(('status', f"Error: {str(e)}"))
            
        finally:
            self.message_queue.put(('stop_voice', None))
    
    def _process_queue(self):
        """Process messages from the queue."""
        try:
            while True:
                try:
                    msg_type, data = self.message_queue.get_nowait()
                    
                    if msg_type == 'message':
                        self.send_message(data)
                    elif msg_type == 'response':
                        self._add_message("assistant", data)
                    elif msg_type == 'speak':
                        self.tts.speak(data)
                    elif msg_type == 'status':
                        self._show_status(data)
                    elif msg_type == 'stop_voice':
                        self.stop_voice_input()
                    elif msg_type == 'enable_input':
                        self._set_input_state(data)
                        
                except queue.Empty:
                    break
                    
        except Exception as e:
            print(f"Error processing queue: {e}")
            
        # Schedule the next check
        self.root.after(100, self._process_queue)
    
    def _show_status(self, message: str, timeout: int = 3000):
        """Show a status message."""
        self.status_var.set(message)
        
        # Clear the status after timeout if provided
        if message and timeout > 0:
            self.root.after(timeout, lambda: self.status_var.get() == message and self.status_var.set(""))
    
    def _set_input_state(self, enabled: bool):
        """Enable or disable the input controls."""
        state = 'normal' if enabled else 'disabled'
        self.input_text.config(state=state)
        self.send_btn.config(state=state)
        self.voice_btn.config(state=state)
    
    def _default_response_handler(self, message: str) -> str:
        """Default response handler if none is provided."""
        return f"You said: {message}"


def run_clippy_ui(on_send_message: Callable[[str], str] = None):
    """Run the Clippy UI."""
    root = tk.Tk()
    app = ClippyUI(root, on_send_message)
    root.mainloop()


if __name__ == "__main__":
    # Example usage
    def handle_message(message: str) -> str:
        """Example message handler."""
        return f"You said: {message}"
    
    run_clippy_ui(handle_message)
