"""
Security Dashboard Component

Provides a comprehensive view of security-related information and controls.
"""

import asyncio
from typing import Callable

import ipywidgets as widgets
from IPython.display import display


class SecurityDashboard:
    """Security Dashboard for monitoring and managing security settings."""

    def __init__(self, security_manager, p2p_manager):
        """Initialize the security dashboard.

        Args:
            security_manager: Instance of SecurityManager
            p2p_manager: Instance of P2PManager
        """
        self.security_manager = security_manager
        self.p2p_manager = p2p_manager
        self._on_update_callbacks = []

        # Initialize UI components
        self._init_ui()

        # Start auto-refresh
        self._refresh_task = asyncio.create_task(self._auto_refresh())

    def _init_ui(self):
        """Initialize the UI components."""
        # Security status
        self.status_indicator = widgets.Valid(
            value=False, description="Security Status:", style={"description_width": "initial"}
        )

        # Security score
        self.security_score = widgets.IntSlider(
            value=0,
            min=0,
            max=100,
            step=1,
            description="Security Score:",
            disabled=True,
            style={"description_width": "initial"},
        )

        # Security events table
        self.events_table = widgets.Output()

        # Security settings
        self.encryption_toggle = widgets.ToggleButton(
            value=True,
            description="Enable Encryption",
            icon="lock",
            tooltip="Toggle message encryption",
        )

        self.auto_update = widgets.ToggleButton(
            value=True, description="Auto-Refresh", icon="refresh", tooltip="Auto-refresh dashboard"
        )

        self.refresh_button = widgets.Button(description="Refresh", icon="refresh")

        # Layout
        self.dashboard = widgets.VBox(
            [
                widgets.HBox(
                    [
                        self.status_indicator,
                        self.security_score,
                        self.auto_update,
                        self.refresh_button,
                    ]
                ),
                widgets.HTML("<h3>Security Events</h3>"),
                self.events_table,
                widgets.HTML("<h3>Security Settings</h3>"),
                self.encryption_toggle,
            ]
        )

        # Event handlers
        self.refresh_button.on_click(self.refresh)
        self.auto_update.observe(self._on_auto_update_change, names="value")
        self.encryption_toggle.observe(self._on_encryption_toggle, names="value")

    def display(self):
        """Display the dashboard."""
        display(self.dashboard)
        self.refresh()

    async def _auto_refresh(self):
        """Auto-refresh the dashboard."""
        while True:
            try:
                if self.auto_update.value:
                    self.refresh()
                await asyncio.sleep(5)  # Update every 5 seconds
            except Exception as e:
                print(f"Error in auto-refresh: {e}")
                await asyncio.sleep(5)

    def refresh(self, _=None):
        """Refresh the dashboard data."""
        try:
            # Update security status
            status = self.security_manager.get_security_status()
            self.status_indicator.value = status["is_secure"]
            self.status_indicator.description = f"Security Status: {status['status']}"

            # Update security score
            self.security_score.value = status["score"]

            # Update events table
            self._update_events_table()

            # Notify callbacks
            for callback in self._on_update_callbacks:
                callback()

        except Exception as e:
            print(f"Error refreshing dashboard: {e}")

    def _update_events_table(self):
        """Update the security events table."""
        events = self.security_manager.get_recent_events(limit=10)

        # Clear the table
        self.events_table.clear_output()

        # Create a new table
        with self.events_table:
            if not events:
                print("No security events to display.")
                return

            # Create a table header
            header = f"{'Time':<25} | {'Type':<20} | {'Severity':<10} | {'Message'}\n"
            header += "-" * 80
            print(header)

            # Add each event to the table
            for event in events:
                timestamp = event.get("timestamp", "").strftime("%Y-%m-%d %H:%M:%S")
                event_type = event.get("type", "UNKNOWN")
                severity = event.get("severity", "INFO")
                message = event.get("message", "No message")
                print(f"{timestamp:<25} | {event_type:<20} | {severity:<10} | {message}")

    def _on_auto_update_change(self, change):
        """Handle auto-update toggle change."""
        if change["new"]:
            self.refresh()

    def _on_encryption_toggle(self, change):
        """Handle encryption toggle change."""
        self.security_manager.set_encryption_enabled(change["new"])
        self.refresh()

    def on_update(self, callback: Callable[[], None]):
        """Register a callback to be called when the dashboard is updated."""
        self._on_update_callbacks.append(callback)

    def close(self):
        """Clean up resources."""
        if hasattr(self, "_refresh_task") and not self._refresh_task.done():
            self._refresh_task.cancel()
        self._on_update_callbacks.clear()


def create_security_dashboard(security_manager, p2p_manager):
    """Create and display a security dashboard.

    Args:
        security_manager: Instance of SecurityManager
        p2p_manager: Instance of P2PManager

    Returns:
        SecurityDashboard: The created dashboard instance
    """
    dashboard = SecurityDashboard(security_manager, p2p_manager)
    dashboard.display()
    return dashboard
