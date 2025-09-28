"""
Scrambled Eggs System Tray Application
-------------------------------------
Provides a system tray icon for controlling the security service.
"""
import sys
import os
import signal
import threading
import webbrowser
from pathlib import Path
from typing import Dict, Any, Optional, Callable

try:
    import pystray
    from PIL import Image, ImageDraw
    HAS_GUI = True
except ImportError:
    HAS_GUI = False

from .config import get_config
from .service import SecurityService

class ScrambledEggsTray:
    """System tray application for Scrambled Eggs security service."""
    
    def __init__(self, password: str, config_path: Optional[str] = None):
        """
        Initialize the system tray application.
        
        Args:
            password: Master password for encryption
            config_path: Optional path to config file
        """
        if not HAS_GUI:
            raise RuntimeError("GUI dependencies not installed. Install with: pip install pystray pillow")
            
        self.password = password
        self.config = get_config()
        self.icon = None
        self.service = None
        self.status = "stopped"
        self.status_callbacks = []
        
        # Create app data directory if it doesn't exist
        self.app_dir = Path.home() / ".scrambled_eggs"
        self.app_dir.mkdir(exist_ok=True)
        
        # Create the system tray icon
        self._create_icon()
    
    def _create_icon(self):
        """Create the system tray icon with menu items."""
        # Create a simple icon with a lock symbol
        image = Image.new('RGB', (64, 64), 'white')
        dc = ImageDraw.Draw(image)
        dc.rectangle([0, 0, 63, 63], fill='#2c3e50')
        dc.ellipse([10, 10, 54, 54], outline='#e74c3c', width=3)
        dc.rectangle([26, 30, 38, 50], fill='#e74c3c')
        
        # Create menu items
        menu_items = [
            pystray.MenuItem(
                'Status: Stopped', 
                lambda: None,  # No action on click
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                'Start Protection', 
                self._on_start_clicked,
                default=True
            ),
            pystray.MenuItem(
                'Stop Protection',
                self._on_stop_clicked,
                enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                'Protect File...',
                self._on_protect_file_clicked
            ),
            pystray.MenuItem(
                'Security Dashboard',
                self._on_dashboard_clicked
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                'Settings',
                self._on_settings_clicked
            ),
            pystray.MenuItem(
                'View Logs',
                self._on_view_logs_clicked
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                'Exit',
                self._on_exit_clicked
            )
        ]
        
        # Create the icon
        self.icon = pystray.Icon(
            'scrambled_eggs',
            image,
            'Scrambled Eggs Security',
            menu=pystray.Menu(*menu_items)
        )
        
        # Update status in the menu
        self._update_status_menu()
    
    def _update_status_menu(self, status: Optional[str] = None):
        """Update the status in the menu."""
        if status:
            self.status = status
            
        if not self.icon:
            return
            
        # Update the status menu item
        self.icon.menu = pystray.Menu(
            pystray.MenuItem(
                f'Status: {self.status.title()}',
                lambda: None,
                enabled=False
            ),
            *self.icon.menu.items[1:]  # Keep other items the same
        )
        
        # Update start/stop buttons
        is_running = self.status == 'running'
        self.icon.menu.items[2].enabled = not is_running  # Start button
        self.icon.menu.items[3].enabled = is_running      # Stop button
        
        # Update icon color based on status
        self._update_icon_color()
        
        # Notify status change callbacks
        for callback in self.status_callbacks:
            try:
                callback(self.status)
            except Exception as e:
                print(f"Error in status callback: {e}")
    
    def _update_icon_color(self):
        """Update the icon color based on the current status."""
        if not self.icon:
            return
            
        # Create a new image with appropriate color
        image = Image.new('RGB', (64, 64), 'white')
        dc = ImageDraw.Draw(image)
        
        # Set color based on status
        if self.status == 'running':
            color = '#2ecc71'  # Green
            status_text = 'Active'
        elif self.status == 'error':
            color = '#e74c3c'  # Red
            status_text = 'Error'
        else:
            color = '#95a5a6'  # Gray
            status_text = 'Inactive'
        
        # Draw the icon
        dc.rectangle([0, 0, 63, 63], fill='#2c3e50')
        dc.ellipse([10, 10, 54, 54], outline=color, width=3)
        dc.rectangle([26, 30, 38, 50], fill=color)
        
        # Update the icon
        self.icon.icon = image
        self.icon.title = f'Scrambled Eggs: {status_text}'
    
    def on_status_change(self, callback: Callable[[str], None]):
        """Register a callback for status changes."""
        self.status_callbacks.append(callback)
    
    def _on_start_clicked(self, icon, item):
        """Handle start protection click."""
        if self.service:
            return
            
        self._update_status_menu('starting')
        
        # Start the service in a separate thread
        def start_service():
            try:
                self.service = SecurityService(self.password)
                self._update_status_menu('running')
                self.service.start()
            except Exception as e:
                print(f"Failed to start service: {e}")
                self._update_status_menu('error')
        
        thread = threading.Thread(target=start_service, daemon=True)
        thread.start()
    
    def _on_stop_clicked(self, icon, item):
        """Handle stop protection click."""
        if not self.service:
            return
            
        self._update_status_menu('stopping')
        
        # Stop the service in a separate thread
        def stop_service():
            try:
                self.service.stop()
                self.service = None
                self._update_status_menu('stopped')
            except Exception as e:
                print(f"Error stopping service: {e}")
                self._update_status_menu('error')
        
        thread = threading.Thread(target=stop_service, daemon=True)
        thread.start()
    
    def _on_protect_file_clicked(self, icon, item):
        """Handle protect file click."""
        # In a real implementation, this would open a file dialog
        # For now, we'll just show a notification
        if self.icon:
            self.icon.notify(
                "Select a file to protect",
                "File Protection"
            )
    
    def _on_dashboard_clicked(self, icon, item):
        """Handle dashboard click."""
        # In a real implementation, this would open a web-based dashboard
        # For now, we'll just show a notification
        if self.icon:
            self.icon.notify(
                "Opening Security Dashboard...",
                "Dashboard"
            )
    
    def _on_settings_clicked(self, icon, item):
        """Handle settings click."""
        # In a real implementation, this would open a settings dialog
        # For now, we'll just show a notification
        if self.icon:
            self.icon.notify(
                "Opening Settings...",
                "Settings"
            )
    
    def _on_view_logs_clicked(self, icon, item):
        """Handle view logs click."""
        log_file = self.app_dir / "logs" / "service.log"
        if log_file.exists():
            try:
                # Try to open with default text editor
                os.startfile(str(log_file))
            except Exception as e:
                print(f"Failed to open log file: {e}")
    
    def _on_exit_clicked(self, icon, item):
        """Handle exit click."""
        # Stop the service if it's running
        if self.service:
            self.service.stop()
        
        # Stop the icon
        if self.icon:
            self.icon.stop()
    
    def run(self):
        """Run the system tray application."""
        if not self.icon:
            raise RuntimeError("Icon not created")
            
        print("Scrambled Eggs is running in the system tray.")
        print("Right-click the icon to access the menu.")
        
        # Run the icon
        self.icon.run()

def run_tray_app(password: str):
    """
    Run the Scrambled Eggs system tray application.
    
    Args:
        password: Master password for encryption
    """
    if not HAS_GUI:
        print("GUI dependencies not installed. Running in console mode.")
        print("Install with: pip install pystray pillow")
        return
        
    try:
        app = ScrambledEggsTray(password)
        app.run()
    except Exception as e:
        print(f"Failed to start tray application: {e}")
        sys.exit(1)

if __name__ == "__main__":
    import getpass
    
    print("Scrambled Eggs System Tray")
    print("-------------------------")
    
    # Get password securely
    password = getpass.getpass("Enter master password: ")
    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)
    
    # Start the tray application
    run_tray_app(password)
