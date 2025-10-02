"""
Enhanced Clippy UI - Modern, interactive UI for the Clippy AI assistant.

Features:
- Smooth animations and transitions
- Context-aware suggestions
- Customizable appearance
- Enhanced visual feedback
- Interactive assistant avatar
"""

import asyncio
import json
import math
import os
import queue
import random
import threading
import time
import webbrowser
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, scrolledtext, font as tkfont, colorchooser, messagebox
from PIL import Image, ImageTk, ImageDraw

# Import Clippy voice modules
from ..voice import TextToSpeech, SpeechToText
from ...memory.enhanced import EnhancedMemoryManager

class AnimationType(Enum):
    FADE = "fade"
    SLIDE = "slide"
    BOUNCE = "bounce"

@dataclass
class UISettings:
    """UI settings and theme configuration."""
    theme: str = "light"
    font_family: str = "Segoe UI"
    font_size: int = 10
    animation_speed: float = 0.2  # seconds
    animation_style: AnimationType = AnimationType.FADE
    tts_enabled: bool = True
    stt_enabled: bool = True
    tts_backend: str = "pyttsx3"
    stt_backend: str = "google"
    voice_rate: int = 150
    wake_word: str = "clippy"
    
    # Theme colors
    colors: Dict[str, str] = field(default_factory=lambda: {
        'light': {
            'bg': '#ffffff',
            'fg': '#000000',
            'accent': '#0078d7',
            'accent_light': '#e5f1fb',
            'text': '#000000',
            'text_secondary': '#666666',
            'border': '#e0e0e0',
            'success': '#4caf50',
            'warning': '#ff9800',
            'error': '#f44336',
            'user_bg': '#e3f2fd',
            'assistant_bg': '#f5f5f5',
            'suggestion_bg': '#f0f0f0',
            'suggestion_hover': '#e0e0e0',
        },
        'dark': {
            'bg': '#2d2d2d',
            'fg': '#ffffff',
            'accent': '#4a90e2',
            'accent_light': '#1a365d',
            'text': '#ffffff',
            'text_secondary': '#b0b0b0',
            'border': '#444444',
            'success': '#66bb6a',
            'warning': '#ffa726',
            'error': '#ef5350',
            'user_bg': '#0d47a1',
            'assistant_bg': '#424242',
            'suggestion_bg': '#3a3a3a',
            'suggestion_hover': '#4a4a4a',
        },
        'high_contrast': {
            'bg': '#000000',
            'fg': '#ffffff',
            'accent': '#ffff00',
            'accent_light': '#333300',
            'text': '#ffffff',
            'text_secondary': '#cccccc',
            'border': '#ffffff',
            'success': '#00ff00',
            'warning': '#ffff00',
            'error': '#ff0000',
            'user_bg': '#0000ff',
            'assistant_bg': '#333333',
            'suggestion_bg': '#222222',
            'suggestion_hover': '#444444',
        }
    })
    
    def get_color(self, color_name: str) -> str:
        """Get a color from the current theme."""
        return self.colors.get(self.theme, {}).get(color_name, '#000000')

class EnhancedClippyUI:
    """Enhanced UI for the Clippy AI assistant with modern features."""
    
    def __init__(self, root: tk.Tk, on_send_message: Callable[[str], Dict[str, Any]]):
        """
        Initialize the enhanced Clippy UI.
        
        Args:
            root: Tkinter root window
            on_send_message: Async callback function that takes a message and returns a response dict
        """
        self.root = root
        self.on_send_message = on_send_message
        self.message_queue = queue.Queue()
        self.is_listening = False
        self.is_typing = False
        self.is_visible = False
        self.animation_in_progress = False
        self.typing_indicator_id = None
        self.current_theme = "light"
        
        # Load settings
        self.settings = self._load_settings()
        
        # Initialize voice modules
        self.tts = TextToSpeech(backend=self.settings.tts_backend)
        self.stt = SpeechToText(backend=self.settings.stt_backend)
        
        # Initialize memory manager
        self.memory = EnhancedMemoryManager()
        
        # UI state
        self.suggestions: List[Dict[str, Any]] = []
        self.conversation_history: List[Dict[str, Any]] = []
        
        # Set up the UI
        self._setup_ui()
        
        # Start processing the message queue
        self._process_queue()
        
        # Start with the UI hidden
        self.toggle_visibility(animate=False)
    
    def _load_settings(self) -> UISettings:
        """Load settings from file or use defaults."""
        settings_file = Path.home() / '.clippy' / 'ui_settings.json'
        if settings_file.exists():
            try:
                with open(settings_file, 'r') as f:
                    data = json.load(f)
                    return UISettings(**data)
            except Exception as e:
                print(f"Error loading settings: {e}")
        
        return UISettings()
    
    def _save_settings(self):
        """Save settings to file."""
        settings_dir = Path.home() / '.clippy'
        settings_dir.mkdir(exist_ok=True)
        settings_file = settings_dir / 'ui_settings.json'
        
        try:
            with open(settings_file, 'w') as f:
                json.dump(self.settings.__dict__, f, indent=2)
        except Exception as e:
            print(f"Error saving settings: {e}")
    
    def _setup_ui(self):
        """Set up the main UI components."""
        # Configure the root window
        self.root.title("Clippy AI Assistant")
        self.root.geometry("400x600")
        self.root.minsize(300, 400)
        self.root.configure(bg=self.settings.get_color('bg'))
        
        # Make window draggable
        self.root.overrideredirect(True)
        self.root.attributes('-topmost', True)
        self.root.attributes('-alpha', 0.95)
        
        # Position in bottom right
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = screen_width - 450  # 400px width + 50px margin
        y = screen_height - 650  # 600px height + 50px margin
        self.root.geometry(f"400x600+{x}+{y}")
        
        # Bind mouse events for dragging
        self.root.bind('<Button-1>', self._start_move)
        self.root.bind('<B1-Motion>', self._on_drag)
        
        # Create main container with rounded corners
        self.main_frame = tk.Canvas(
            self.root, 
            bg=self.settings.get_color('bg'),
            highlightthickness=0
        )
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create rounded rectangle for the window
        self._draw_rounded_rect(self.main_frame, 0, 0, 400, 600, 15, 
                              fill=self.settings.get_color('bg'), 
                              outline=self.settings.get_color('border'))
        
        # Create header with title and controls
        self._create_header()
        
        # Create chat display
        self._create_chat_display()
        
        # Create input area
        self._create_input_area()
        
        # Create settings panel (initially hidden)
        self._create_settings_panel()
        
        # Create suggestion bar
        self._create_suggestion_bar()
        
        # Create assistant avatar (initially hidden)
        self._create_assistant_avatar()
        
        # Add welcome message
        self._add_message(
            "assistant",
            "Hello! I'm Clippy, your AI assistant. How can I help you today?",
            animate=True
        )
    
    def _draw_rounded_rect(self, canvas: tk.Canvas, x1: int, y1: int, x2: int, y2: int, radius: int, **kwargs):
        """Draw a rounded rectangle on the canvas."""
        points = [
            x1 + radius, y1,
            x2 - radius, y1,
            x2, y1,
            x2, y1 + radius,
            x2, y2 - radius,
            x2, y2,
            x2 - radius, y2,
            x1 + radius, y2,
            x1, y2,
            x1, y2 - radius,
            x1, y1 + radius,
            x1, y1
        ]
        
        return canvas.create_polygon(points, **kwargs, smooth=True)
    
    def _create_header(self):
        """Create the header with title and controls."""
        header_frame = tk.Frame(
            self.main_frame,
            bg=self.settings.get_color('bg'),
            height=40
        )
        header_frame.place(x=0, y=0, width=400, height=40)
        
        # Title
        title_label = tk.Label(
            header_frame,
            text="Clippy AI",
            font=(self.settings.font_family, 12, 'bold'),
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('accent')
        )
        title_label.place(x=15, y=10)
        
        # Settings button
        settings_btn = tk.Button(
            header_frame,
            text="⚙️",
            command=self.toggle_settings,
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg'),
            borderwidth=0,
            font=(self.settings.font_family, 14)
        )
        settings_btn.place(x=360, y=5, width=30, height=30)
        
        # Minimize button
        minimize_btn = tk.Button(
            header_frame,
            text="_",
            command=self.toggle_visibility,
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg'),
            borderwidth=0,
            font=(self.settings.font_family, 14, 'bold')
        )
        minimize_btn.place(x=320, y=5, width=30, height=30)
    
    def _create_chat_display(self):
        """Create the chat display area."""
        # Chat container with scrollbar
        chat_frame = tk.Frame(
            self.main_frame,
            bg=self.settings.get_color('bg')
        )
        chat_frame.place(x=0, y=40, width=400, height=460)
        
        # Canvas for chat messages
        self.chat_canvas = tk.Canvas(
            chat_frame,
            bg=self.settings.get_color('bg'),
            highlightthickness=0
        )
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(
            chat_frame,
            orient="vertical",
            command=self.chat_canvas.yview
        )
        
        # Configure canvas scrolling
        self.chat_canvas.configure(yscrollcommand=scrollbar.set)
        
        # Create a frame inside the canvas to hold messages
        self.messages_frame = tk.Frame(
            self.chat_canvas,
            bg=self.settings.get_color('bg')
        )
        
        # Add the frame to the canvas
        self.chat_canvas.create_window((0, 0), window=self.messages_frame, anchor='nw')
        
        # Pack everything
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.chat_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Bind mousewheel for scrolling
        self.chat_canvas.bind("<Configure>", self._on_canvas_configure)
        self.chat_canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        
        # Keep track of message positions
        self.message_widgets = []
    
    def _create_input_area(self):
        """Create the input area with text entry and buttons."""
        # Input frame
        input_frame = tk.Frame(
            self.main_frame,
            bg=self.settings.get_color('bg'),
            height=100
        )
        input_frame.place(x=0, y=500, width=400, height=100)
        
        # Text input with rounded corners
        input_bg = tk.Canvas(
            input_frame,
            bg=self.settings.get_color('suggestion_bg'),
            highlightthickness=0
        )
        input_bg.place(x=10, y=10, width=380, height=40)
        self._draw_rounded_rect(
            input_bg, 0, 0, 380, 40, 20, 
            fill=self.settings.get_color('suggestion_bg'),
            outline=self.settings.get_color('border')
        )
        
        # Text entry
        self.input_text = tk.Text(
            input_bg,
            bg=self.settings.get_color('suggestion_bg'),
            fg=self.settings.get_color('text'),
            font=(self.settings.font_family, self.settings.font_size),
            relief='flat',
            padx=15,
            pady=8,
            wrap=tk.WORD,
            height=1
        )
        self.input_text.place(x=0, y=0, width=340, height=40)
        
        # Send button
        send_btn = tk.Button(
            input_bg,
            text="➤",
            command=self._on_send_click,
            bg=self.settings.get_color('accent'),
            fg='white',
            font=(self.settings.font_family, 12, 'bold'),
            relief='flat',
            borderwidth=0
        )
        send_btn.place(x=340, y=0, width=40, height=40)
        
        # Bind Enter key to send message
        self.input_text.bind('<Return>', lambda e: self._on_send_click())
        self.input_text.bind('<KeyRelease>', self._on_input_change)
        
        # Voice input button
        self.voice_btn = tk.Button(
            input_frame,
            text="🎤",
            command=self.toggle_voice_input,
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg'),
            font=(self.settings.font_family, 14),
            relief='flat',
            borderwidth=0
        )
        self.voice_btn.place(x=10, y=55, width=40, height=40)
    
    def _create_suggestion_bar(self):
        """Create the suggestion bar for quick actions."""
        self.suggestion_frame = tk.Frame(
            self.main_frame,
            bg=self.settings.get_color('suggestion_bg'),
            height=50
        )
        self.suggestion_frame.place(x=0, y=450, width=400, height=50)
        
        # Add some default suggestions
        self._update_suggestions([
            {"text": "What can you do?", "action": "what_can_you_do"},
            {"text": "Tell a joke", "action": "tell_joke"},
            {"text": "Set a reminder", "action": "set_reminder"}
        ])
    
    def _create_settings_panel(self):
        """Create the settings panel (initially hidden)."""
        self.settings_panel = tk.Frame(
            self.main_frame,
            bg=self.settings.get_color('bg'),
            width=400,
            height=500
        )
        
        # Settings title
        title = tk.Label(
            self.settings_panel,
            text="Settings",
            font=(self.settings.font_family, 14, 'bold'),
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg')
        )
        title.pack(pady=10)
        
        # Theme selection
        theme_frame = tk.Frame(self.settings_panel, bg=self.settings.get_color('bg'))
        theme_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            theme_frame,
            text="Theme:",
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg')
        ).pack(side=tk.LEFT)
        
        theme_var = tk.StringVar(value=self.settings.theme)
        
        for theme in ["light", "dark", "high_contrast"]:
            rb = tk.Radiobutton(
                theme_frame,
                text=theme.capitalize(),
                variable=theme_var,
                value=theme,
                command=lambda t=theme: self._change_theme(t),
                bg=self.settings.get_color('bg'),
                fg=self.settings.get_color('fg'),
                selectcolor=self.settings.get_color('bg')
            )
            rb.pack(side=tk.LEFT, padx=10)
        
        # Font settings
        font_frame = tk.Frame(self.settings_panel, bg=self.settings.get_color('bg'))
        font_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            font_frame,
            text="Font:",
            bg=self.settings.get_color('bg'),
            fg=self.settings.get_color('fg')
        ).pack(side=tk.LEFT)
        
        font_family = tk.StringVar(value=self.settings.font_family)
        font_family.trace('w', lambda *args: self._change_font(font_family.get(), self.settings.font_size))
        
        font_menu = ttk.Combobox(
            font_frame,
            textvariable=font_family,
            values=['Arial', 'Segoe UI', 'Helvetica', 'Times New Roman', 'Courier New'],
            state='readonly',
            width=15
        )
        font_menu.pack(side=tk.LEFT, padx=5)
        
        # Font size
        font_size = tk.IntVar(value=self.settings.font_size)
        font_size.trace('w', lambda *args: self._change_font(self.settings.font_family, font_size.get()))
        
        size_menu = ttk.Spinbox(
            font_frame,
            from_=8,
            to=24,
            textvariable=font_size,
            width=3
        )
        size_menu.pack(side=tk.LEFT, padx=5)
        
        # Close button
        close_btn = tk.Button(
            self.settings_panel,
            text="Close",
            command=self.toggle_settings,
            bg=self.settings.get_color('accent'),
            fg='white',
            relief='flat',
            padx=20,
            pady=5
        )
        close_btn.pack(pady=20)
        
        # Initially hide settings panel
        self.settings_panel.place_forget()
    
    def _create_assistant_avatar(self):
        """Create the assistant avatar that can be shown/hidden."""
        self.avatar_window = tk.Toplevel(self.root)
        self.avatar_window.overrideredirect(True)
        self.avatar_window.attributes('-topmost', True)
        self.avatar_window.attributes('-transparentcolor', 'white')
        self.avatar_window.attributes('-alpha', 0.9)
        
        # Position in bottom right
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = screen_width - 150
        y = screen_height - 200
        self.avatar_window.geometry(f"100x100+{x}+{y}")
        
        # Create canvas for animation
        self.avatar_canvas = tk.Canvas(
            self.avatar_window,
            width=100,
            height=100,
            bg='white',
            highlightthickness=0
        )
        self.avatar_canvas.pack()
        
        # Draw default avatar (clip art)
        self._draw_avatar()
        
        # Make draggable
        self.avatar_canvas.bind('<Button-1>', self._start_avatar_drag)
        self.avatar_canvas.bind('<B1-Motion>', self._on_avatar_drag)
        
        # Hide initially
        self.avatar_window.withdraw()
    
    def _draw_avatar(self, expression: str = "neutral"):
        """Draw the assistant avatar with the given expression."""
        self.avatar_canvas.delete("all")
        
        # Draw face
        self.avatar_canvas.create_oval(10, 10, 90, 90, fill='#FFD700', outline='#DAA520', width=2)
        
        # Draw eyes
        self.avatar_canvas.create_oval(30, 35, 45, 50, fill='black')
        self.avatar_canvas.create_oval(55, 35, 70, 50, fill='black')
        
        # Draw mouth based on expression
        if expression == "smile":
            self.avatar_canvas.create_arc(30, 40, 70, 80, start=0, extent=-180, style=tk.ARC, width=2)
        elif expression == "neutral":
            self.avatar_canvas.create_line(30, 65, 70, 65, width=2)
        else:  # thinking
            self.avatar_canvas.create_arc(30, 50, 70, 80, start=0, extent=180, style=tk.ARC, width=2)
    
    def _start_avatar_drag(self, event):
        """Start dragging the avatar."""
        self.avatar_drag_data = {
            'x': event.x,
            'y': event.y
        }
    
    def _on_avatar_drag(self, event):
        """Handle avatar dragging."""
        x = self.avatar_window.winfo_x() + (event.x - self.avatar_drag_data['x'])
        y = self.avatar_window.winfo_y() + (event.y - self.avatar_drag_data['y'])
        self.avatar_window.geometry(f"+{x}+{y}")
    
    def _on_canvas_configure(self, event):
        """Configure the canvas scroll region."""
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
    
    def _on_mousewheel(self, event):
        """Handle mousewheel scrolling."""
        self.chat_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
    
    def _on_input_change(self, event):
        """Handle changes to the input field."""
        # Auto-resize the input field
        self.input_text.config(height=1)
        self.input_text.update_idletasks()
        
        # Calculate required height
        lines = self.input_text.get('1.0', 'end-1c').split('\n')
        height = len(lines)
        
        # Limit height
        if height > 5:
            height = 5
        
        # Update height if changed
        if height != int(self.input_text['height']):
            self.input_text.config(height=height)
            
            # Adjust window size
            self._adjust_window_height()
    
    def _adjust_window_height(self):
        """Adjust the window height based on content."""
        # Calculate required height
        input_height = self.input_text.winfo_height() + 100  # Add padding
        window_height = min(800, 500 + input_height)  # Max height 800px
        
        # Update window size
        x = self.root.winfo_x()
        y = self.root.winfo_y() - (window_height - self.root.winfo_height())
        self.root.geometry(f"400x{window_height}+{x}+{y}")
        
        # Update chat display height
        chat_height = window_height - 140  # Account for header and input
        self.chat_canvas.place(height=chat_height)
        
        # Update input position
        self.input_text.master.place(y=window_height - 100)
        
        # Update suggestion bar position
        self.suggestion_frame.place(y=window_height - 150)
    
    def _on_send_click(self, event=None):
        """Handle send button click or Enter key press."""
        message = self.input_text.get("1.0", tk.END).strip()
        if not message:
            return
            
        # Clear input
        self.input_text.delete("1.0", tk.END)
        
        # Add user message to chat
        self._add_message("user", message)
        
        # Show typing indicator
        self._show_typing_indicator()
        
        # Process message in a separate thread with asyncio
        async def process_message():
            try:
                # Call the message handler
                response = await self.on_send_message(message)
                
                # Handle the response in the main thread
                self.root.after(0, lambda: asyncio.create_task(self._handle_response(response)))
            except Exception as e:
                print(f"Error processing message: {e}")
                self.root.after(0, self._show_error, "Sorry, I encountered an error processing your message.")
        
        # Start the async task
        asyncio.create_task(process_message())
    
    async def _process_user_message(self, message: str):
        """Process a user message and get a response."""
        try:
            # Call the message handler
            response = await self.on_send_message(message)
            
            # Handle the response
            await self._handle_response(response)
        except Exception as e:
            print(f"Error processing message: {e}")
            self.root.after(0, self._show_error, "Sorry, I encountered an error processing your message.")
    
    async def _handle_response(self, response: Dict[str, Any]):
        """Handle the response from the message handler."""
        # Hide typing indicator
        self._hide_typing_indicator()
        
        # Add response to chat
        if 'text' in response:
            self._add_message("assistant", response['text'])
            
            # Speak the response if TTS is enabled
            if self.settings.tts_enabled and response.get('speak', True):
                self.tts.speak(response['text'])
        
        # Generate context-aware suggestions if none provided
        if 'suggestions' not in response or not response['suggestions']:
            try:
                # Get the conversation history for context
                history = [
                    {"role": "user" if msg.startswith("You: ") else "assistant",
                     "content": msg.replace("You: ", "").replace("Assistant: ", "")}
                    for msg in self.chat_display.get("1.0", tk.END).split("\n") 
                    if msg.strip() and ": " in msg
                ]
                
                # Generate suggestions based on conversation context
                suggestions = await self.memory.generate_suggestions(history)
                response['suggestions'] = suggestions
                
            except Exception as e:
                print(f"Error generating suggestions: {e}")
                # Fallback to default suggestions
                response['suggestions'] = [
                    {"text": "What can you do?", "action": "what_can_you_do"},
                    {"text": "Tell me a joke", "action": "tell_joke"},
                    {"text": "Help", "action": "help"}
                ]
        
        # Update suggestions
        self._update_suggestions(response.get('suggestions', []))
        
        # Handle any actions
        if 'action' in response:
            await self._handle_action(response['action'], response.get('data'))
    
    def _handle_action(self, action: str, data: Any = None):
        """Handle an action from the response."""
        if action == "open_url" and data:
            webbrowser.open(data)
        elif action == "show_image" and data:
            self._show_image(data)
        # Add more actions as needed
    
    def _show_error(self, message: str):
        """Show an error message in the chat."""
        self._add_message("assistant", message, is_error=True)
    
    def _show_typing_indicator(self):
        """Show a typing indicator in the chat."""
        if self.typing_indicator_id is not None:
            self.chat_canvas.delete(self.typing_indicator_id)
        
        self.typing_indicator_id = self.chat_canvas.create_text(
            20, 0,  # Position will be updated in _update_typing_indicator
            text="Clippy is typing...",
            anchor='nw',
            font=(self.settings.font_family, self.settings.font_size, 'italic'),
            fill=self.settings.get_color('text_secondary')
        )
        
        # Position the indicator below the last message
        self._update_typing_indicator()
        
        # Start animation
        self.typing_dots = 0
        self._animate_typing_indicator()
    
    def _update_typing_indicator(self):
        """Update the position of the typing indicator."""
        if not hasattr(self, 'typing_indicator_id') or self.typing_indicator_id is None:
            return
        
        # Find the bottom of the last message
        last_y = 10
        if self.message_widgets:
            last_widget = self.message_widgets[-1]
            last_y = last_widget.winfo_y() + last_widget.winfo_height() + 10
        
        # Update position
        self.chat_canvas.coords(self.typing_indicator_id, 20, last_y)
        self.chat_canvas.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        self.chat_canvas.yview_moveto(1.0)  # Scroll to bottom
    
    def _animate_typing_indicator(self):
        """Animate the typing indicator dots."""
        if not hasattr(self, 'typing_indicator_id') or self.typing_indicator_id is None:
            return
        
        self.typing_dots = (self.typing_dots + 1) % 4
        dots = '.' * self.typing_dots
        self.chat_canvas.itemconfig(
            self.typing_indicator_id,
            text=f"Clippy is typing{dots}"
        )
        
        # Schedule next animation frame
        if hasattr(self, 'typing_indicator_id') and self.typing_indicator_id is not None:
            self.root.after(500, self._animate_typing_indicator)
    
    def _hide_typing_indicator(self):
        """Hide the typing indicator."""
        if hasattr(self, 'typing_indicator_id') and self.typing_indicator_id is not None:
            self.chat_canvas.delete(self.typing_indicator_id)
            self.typing_indicator_id = None
    
    def _add_message(self, sender: str, text: str, is_error: bool = False, animate: bool = True):
        """Add a message to the chat display."""
        # Create message frame
        message_frame = tk.Frame(
            self.messages_frame,
            bg=self.settings.get_color('bg'),
            padx=10,
            pady=5
        )
        
        # Determine alignment and colors based on sender
        if sender == "user":
            bg = self.settings.get_color('user_bg')
            fg = self.settings.get_color('text')
            anchor = 'e'
            padx = (100, 10)
        else:  # assistant or error
            if is_error:
                bg = self.settings.get_color('error')
                fg = 'white'
            else:
                bg = self.settings.get_color('assistant_bg')
                fg = self.settings.get_color('text')
            anchor = 'w'
            padx = (10, 100)
        
        # Create message label with word wrap
        message_label = tk.Label(
            message_frame,
            text=text,
            wraplength=280,  # Max width before wrapping
            justify=tk.LEFT,
            bg=bg,
            fg=fg,
            font=(self.settings.font_family, self.settings.font_size),
            padx=15,
            pady=10,
            bd=0,
            relief='flat',
            anchor='w'
        )
        
        # Add rounded corners
        message_label.bind(
            "<Configure>",
            lambda e, w=message_label: self._round_rectangle(w)
        )
        
        # Pack the label
        message_label.pack(anchor=anchor, padx=padx, pady=2)
        
        # Add timestamp
        timestamp = tk.Label(
            message_frame,
            text=time.strftime("%H:%M"),
            font=(self.settings.font_family, 8),
            fg=self.settings.get_color('text_secondary'),
            bg=self.settings.get_color('bg')
        )
        timestamp.pack(anchor=anchor, padx=padx)
        
        # Add to messages frame
        message_frame.pack(fill=tk.X, pady=5)
        self.message_widgets.append(message_frame)
        
        # Update canvas scroll region
        self.messages_frame.update_idletasks()
        self.chat_canvas.configure(scrollregion=self.chat_canvas.bbox("all"))
        
        # Scroll to bottom
        self.chat_canvas.yview_moveto(1.0)
        
        # Animate if needed
        if animate:
            self._animate_message(message_frame, anchor == 'e')
    
    def _round_rectangle(self, widget):
        """Add rounded corners to a widget."""
        # This is a placeholder - in a real implementation, you would
        # create a rounded rectangle image and use it as the widget's background
        pass
    
    def _animate_message(self, widget, is_user: bool):
        """Animate a message entering the chat."""
        # Initial state (invisible and offset)
        widget.place_forget()
        widget.update_idletasks()
        
        # Animate based on settings
        if self.settings.animation_style == AnimationType.FADE:
            widget.place(relx=0.5 if is_user else 0, rely=0, anchor='n' if is_user else 'nw')
            widget.place_forget()
            widget.place(relx=0.5 if is_user else 0, rely=0, anchor='n' if is_user else 'nw')
            widget.update_idletasks()
        # Add more animation styles as needed
    
    def _update_suggestions(self, suggestions: List[Dict[str, Any]]):
        """Update the suggestion buttons."""
        # Clear existing suggestions
        for widget in self.suggestion_frame.winfo_children():
            widget.destroy()
        
        # Add new suggestions
        for i, suggestion in enumerate(suggestions):
            btn = tk.Button(
                self.suggestion_frame,
                text=suggestion['text'],
                command=lambda s=suggestion: self._on_suggestion_click(s),
                bg=self.settings.get_color('suggestion_bg'),
                fg=self.settings.get_color('fg'),
                relief='flat',
                padx=10,
                pady=5,
                font=(self.settings.font_family, self.settings.font_size - 1)
            )
            
            # Hover effects
            btn.bind(
                "<Enter>",
                lambda e, b=btn: b.config(bg=self.settings.get_color('suggestion_hover'))
            )
            btn.bind(
                "<Leave>",
                lambda e, b=btn: b.config(bg=self.settings.get_color('suggestion_bg'))
            )
            
            btn.pack(side=tk.LEFT, padx=5)
    
    def _on_suggestion_click(self, suggestion: Dict[str, Any]):
        """Handle suggestion button click."""
        if 'action' in suggestion:
            # Handle built-in actions
            if suggestion['action'] == 'what_can_you_do':
                self._add_message("user", "What can you do?")
                self._handle_response({
                    'text': "I can help with a variety of tasks! Here are some things I can do:\n"
                           "- Answer questions\n"
                           "- Set reminders\n"
                           "- Tell jokes\n"
                           "- And much more!"
                })
            elif suggestion['action'] == 'tell_joke':
                self._add_message("user", "Tell me a joke")
                self._handle_response({
                    'text': "Why don't scientists trust atoms?\nBecause they make up everything!"
                })
            elif suggestion['action'] == 'set_reminder':
                self._add_message("user", "Set a reminder")
                self._handle_response({
                    'text': "What would you like me to remind you about?"
                })
        elif 'text' in suggestion:
            # Use the suggestion text as a message
            self._add_message("user", suggestion['text'])
            
            # Process the message
            threading.Thread(
                target=self._process_user_message,
                args=(suggestion['text'],),
                daemon=True
            ).start()
    
    def toggle_voice_input(self):
        """Toggle voice input on/off."""
        if not self.is_listening:
            self._start_listening()
        else:
            self._stop_listening()
    
    def _on_wake_word_detected(self):
        """Handle wake word detection."""
        self.root.after(0, self._show_status, "Wake word detected, listening...")
        self.voice_btn.config(bg=self.settings.get_color('accent'))
        self._draw_avatar("listening")
    
    def _on_utterance(self, text: str):
        """Handle recognized speech input."""
        self.root.after(0, self._on_voice_input, text)
    
    def _start_listening(self):
        """Start listening for voice input with wake word detection."""
        if not self.settings.stt_enabled:
            self._show_error("Speech-to-text is disabled in settings")
            return
        
        self.is_listening = True
        self.voice_btn.config(bg=self.settings.get_color('accent_light'))
        
        # Show listening animation
        self._draw_avatar("thinking")
        self._show_status("Listening for wake word...")
        
        # Start listening for wake word
        self.stt.listen(
            on_text=self._on_utterance,
            on_wake_word=self._on_wake_word_detected
        )
    
    def _on_voice_input(self, text: str):
        """Handle recognized speech input."""
        if not text.strip():
            return
            
        # Add user message to chat
        self._add_message("user", text)
        
        # Process the message
        self._process_user_message(text)
        
        # Reset wake word detection for next command
        self.stt.wake_word_detected = False
        
        # Update UI
        self.voice_btn.config(bg=self.settings.get_color('accent_light'))
        self._draw_avatar("thinking")
        self._show_status("Listening for wake word...")
    
    def _stop_listening(self):
        """Stop listening for voice input."""
        self.stt.stop_listening()
        self.is_listening = False
        self.voice_btn.config(bg=self.settings.get_color('bg'))
        self._draw_avatar("neutral")
        self._show_status("")
    
    def _show_status(self, message: str):
        """Show a status message in the input field."""
        if not hasattr(self, 'status_label'):
            self.status_label = tk.Label(
                self.input_frame,
                text=message,
                bg=self.settings.get_color('bg'),
                fg=self.settings.get_color('text_secondary'),
                font=(self.settings.font_family, 8)
            )
        else:
            self.status_label.config(text=message)
        self.status_label.place(x=60, y=55, width=300, height=20)
    
    def toggle_settings(self):
        """Toggle the settings panel."""
        if self.settings_panel.winfo_ismapped():
            self.settings_panel.place_forget()
            self.chat_canvas.pack(fill=tk.BOTH, expand=True)
        else:
            self.chat_canvas.pack_forget()
            self.settings_panel.place(x=0, y=40, width=400, height=460)
    
    def toggle_visibility(self, animate: bool = True):
        """Toggle the visibility of the main window."""
        if self.is_visible:
            self._hide_window(animate)
        else:
            self._show_window(animate)
    
    def _show_window(self, animate: bool = True):
        """Show the main window with animation."""
        if self.is_visible or self.animation_in_progress:
            return
        
        self.is_visible = True
        self.animation_in_progress = True
        
        # Show the window
        self.root.deiconify()
        
        if animate:
            # Animate window appearing
            for i in range(0, 101, 5):
                alpha = i / 100
                self.root.attributes('-alpha', alpha)
                self.root.update()
                time.sleep(0.01)
        else:
            self.root.attributes('-alpha', 1.0)
        
        self.animation_in_progress = False
    
    def _hide_window(self, animate: bool = True):
        """Hide the main window with animation."""
        if not self.is_visible or self.animation_in_progress:
            return
        
        self.is_visible = False
        self.animation_in_progress = True
        
        if animate:
            # Animate window disappearing
            for i in range(100, -1, -5):
                alpha = i / 100
                self.root.attributes('-alpha', alpha)
                self.root.update()
                time.sleep(0.01)
        
        # Hide the window
        self.root.withdraw()
        self.animation_in_progress = False
    
    def _change_theme(self, theme: str):
        """Change the UI theme."""
        self.settings.theme = theme
        self._update_theme()
    
    def _change_font(self, font_family: str, font_size: int):
        """Change the UI font."""
        self.settings.font_family = font_family
        self.settings.font_size = font_size
        self._update_fonts()
    
    def _update_theme(self):
        """Update the UI colors based on the current theme."""
        # Update main window
        self.root.configure(bg=self.settings.get_color('bg'))
        self.main_frame.configure(bg=self.settings.get_color('bg'))
        
        # Update chat display
        self.chat_canvas.configure(bg=self.settings.get_color('bg'))
        self.messages_frame.configure(bg=self.settings.get_color('bg'))
        
        # Update message widgets
        for widget in self.message_widgets:
            widget.configure(bg=self.settings.get_color('bg'))
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    if 'timestamp' in str(child):
                        child.configure(
                            bg=self.settings.get_color('bg'),
                            fg=self.settings.get_color('text_secondary')
                        )
        
        # Update input area
        self.input_text.configure(
            bg=self.settings.get_color('suggestion_bg'),
            fg=self.settings.get_color('text')
        )
        
        # Update suggestion bar
        self.suggestion_frame.configure(bg=self.settings.get_color('suggestion_bg'))
        
        # Redraw the avatar
        self._draw_avatar("neutral" if not self.is_listening else "thinking")
        
        # Save settings
        self._save_settings()
    
    def _update_fonts(self):
        """Update all UI fonts."""
        # Update input field
        self.input_text.configure(
            font=(self.settings.font_family, self.settings.font_size)
        )
        
        # Update message widgets
        for widget in self.message_widgets:
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    if 'timestamp' in str(child):
                        child.configure(font=(self.settings.font_family, 8))
                    else:
                        child.configure(
                            font=(self.settings.font_family, self.settings.font_size)
                        )
        
        # Save settings
        self._save_settings()
    
    def _start_move(self, event):
        """Start moving the window."""
        self._drag_data = {
            'x': event.x,
            'y': event.y
        }
    
    def _on_drag(self, event):
        """Handle window dragging."""
        x = self.root.winfo_x() + (event.x - self._drag_data['x'])
        y = self.root.winfo_y() + (event.y - self._drag_data['y'])
        self.root.geometry(f"+{x}+{y}")
    
    def _process_queue(self):
        """Process messages from the queue."""
        try:
            while True:
                func, args, kwargs = self.message_queue.get_nowait()
                func(*args, **kwargs)
        except queue.Empty:
            pass
        
        # Schedule the next check
        self.root.after(100, self._process_queue)
    
    def run(self):
        """Run the main event loop."""
        self.root.mainloop()


def run_enhanced_clippy_ui(on_send_message: Callable[[str], Awaitable[Dict[str, Any]]]):
    """
    Run the enhanced Clippy UI.
    
    Args:
        on_send_message: Async callback function that takes a message and returns a response dict
    """
    # Create and configure the root window
    root = tk.Tk()
    root.title("Clippy AI Assistant")
    
    # Create the app
    app = EnhancedClippyUI(root, on_send_message)
    
    # Set up the asyncio event loop
    def run_async():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Run the Tkinter main loop in a separate thread
        def run_tk():
            root.mainloop()
            
        # Start Tkinter in a separate thread
        import threading
        threading.Thread(target=run_tk, daemon=True).start()
        
        # Run the asyncio event loop
        try:
            loop.run_forever()
        finally:
            loop.close()
    
    # Start the application
    run_async()


if __name__ == "__main__":
    # Example usage
    def example_message_handler(message: str) -> Dict[str, Any]:
        """Example message handler."""
        import random
        
        responses = [
            f"I received your message: {message}",
            f"You said: {message}",
            f"Interesting point about '{message}'. Can you tell me more?",
            f"I'm thinking about '{message}'..."
        ]
        
        # Randomly decide to include suggestions
        if random.random() > 0.5:
            return {
                'text': random.choice(responses),
                'suggestions': [
                    {'text': 'Tell me more', 'action': 'tell_more'},
                    {'text': 'That\'s all', 'action': 'end_conversation'}
                ]
            }
        else:
            return {'text': random.choice(responses)}
    
    # Run the UI with the example handler
    run_enhanced_clippy_ui(example_message_handler)
