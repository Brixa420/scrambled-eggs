"""
Location Widget for Brixa

Displays current location information with special features for Antarctica.
"""

from typing import Any, Dict

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QSize,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from app.features.location_service import LocationService


class LocationWidget(QWidget):
    """Widget for displaying location information with Antarctica support."""

    refresh_requested = Signal()

    def __init__(self, parent=None):
        """Initialize the location widget."""
        super().__init__(parent)
        self.location_service = LocationService()
        self.current_location = None
        self.weather_data = {}
        self.antarctic_base = None

        self.setup_ui()
        self.update_styles()

        # Update timer for time-sensitive information
        self.update_timer = QTimer(self)
        self.update_timer.timeout.connect(self.update_dynamic_content)
        self.update_timer.start(60000)  # Update every minute

    def setup_ui(self):
        """Set up the user interface."""
        self.setMinimumWidth(280)

        # Main layout
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header
        header = QLabel("Location")
        header.setStyleSheet("font-size: 16px; font-weight: bold;")

        # Location display
        self.location_frame = QFrame()
        self.location_frame.setFrameShape(QFrame.StyledPanel)
        self.location_frame.setStyleSheet(
            """
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                border: 1px solid #dee2e6;
                padding: 10px;
            }
        """
        )

        location_layout = QVBoxLayout(self.location_frame)
        location_layout.setContentsMargins(5, 5, 5, 5)
        location_layout.setSpacing(8)

        # Current location
        self.location_icon = QLabel()
        self.location_icon.setPixmap(QIcon(":/icons/location.png").pixmap(24, 24))

        self.location_label = QLabel("Acquiring location...")
        self.location_label.setWordWrap(True)
        self.location_label.setStyleSheet("font-weight: bold;")

        self.coordinates_label = QLabel()
        self.coordinates_label.setStyleSheet("color: #6c757d; font-size: 12px;")

        # Weather information
        self.weather_icon = QLabel()
        self.weather_icon.setPixmap(QIcon(":/icons/weather.png").pixmap(24, 24))

        self.weather_label = QLabel("Weather data loading...")
        self.weather_label.setWordWrap(True)

        # Antarctic base info
        self.base_frame = QFrame()
        self.base_frame.setFrameShape(QFrame.StyledPanel)
        self.base_frame.setStyleSheet(
            """
            QFrame {
                background-color: #e7f5ff;
                border-radius: 8px;
                border: 1px solid #d0ebff;
                padding: 10px;
                margin-top: 10px;
            }
        """
        )

        base_layout = QVBoxLayout(self.base_frame)
        base_layout.setContentsMargins(5, 5, 5, 5)
        base_layout.setSpacing(5)

        self.base_icon = QLabel()
        self.base_icon.setPixmap(QIcon(":/icons/research.png").pixmap(20, 20))

        self.base_title = QLabel("Nearest Research Base")
        self.base_title.setStyleSheet("font-weight: bold; color: #1971c2;")

        self.base_name = QLabel("Searching...")
        self.base_distance = QLabel()
        self.base_distance.setStyleSheet("color: #495057; font-size: 12px;")

        base_header = QHBoxLayout()
        base_header.addWidget(self.base_icon)
        base_header.addWidget(self.base_title)
        base_header.addStretch()

        base_layout.addLayout(base_header)
        base_layout.addWidget(self.base_name)
        base_layout.addWidget(self.base_distance)

        # Layout organization
        location_header = QHBoxLayout()
        location_header.addWidget(self.location_icon)
        location_header.addWidget(self.location_label)
        location_header.addStretch()

        weather_header = QHBoxLayout()
        weather_header.addWidget(self.weather_icon)
        weather_header.addWidget(self.weather_label)
        weather_header.addStretch()

        location_layout.addLayout(location_header)
        location_layout.addWidget(self.coordinates_label)
        location_layout.addSpacing(10)
        location_layout.addLayout(weather_header)

        # Add refresh button
        refresh_btn = QToolButton()
        refresh_btn.setIcon(QIcon(":/icons/refresh.png"))
        refresh_btn.setToolTip("Refresh location")
        refresh_btn.setIconSize(QSize(16, 16))
        refresh_btn.setStyleSheet(
            """
            QToolButton {
                border: none;
                background: transparent;
                padding: 2px;
                border-radius: 12px;
            }
            QToolButton:hover {
                background: #e9ecef;
            }
        """
        )
        refresh_btn.clicked.connect(self.refresh_location)

        header_layout = QHBoxLayout()
        header_layout.addWidget(header)
        header_layout.addStretch()
        header_layout.addWidget(refresh_btn)

        # Add widgets to main layout
        layout.addLayout(header_layout)
        layout.addWidget(self.location_frame)
        layout.addWidget(self.base_frame)
        layout.addStretch()

        # Context menu
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)

    def update_styles(self):
        """Update widget styles based on theme."""
        # This would be connected to theme changes

    def update_location(self, latitude: float, longitude: float, accuracy: float = 0.0):
        """Update the displayed location information."""
        self.current_location = self.location_service.update_location(latitude, longitude, accuracy)
        self.update_display()

    def update_display(self):
        """Update all displayed information."""
        if not self.current_location:
            return

        # Update location info
        self.location_label.setText(self.current_location.name)
        self.coordinates_label.setText(
            f"{abs(self.current_location.latitude):.4f}°{'S' if self.current_location.latitude < 0 else 'N'}, "
            f"{abs(self.current_location.longitude):.4f}°{'W' if self.current_location.longitude < 0 else 'E'}"
        )

        # Update weather
        self.weather_data = self.location_service.get_weather_conditions(self.current_location)
        if self.weather_data:
            temp = self.weather_data.get("temperature", "N/A")
            conditions = self.weather_data.get("conditions", "Unknown")
            self.weather_label.setText(f"{conditions}, {temp}°C")
        else:
            self.weather_label.setText("Weather data not available")

        # Update Antarctic base info if in Antarctica
        if self.current_location.is_in_antarctica():
            self.antarctic_base = self.location_service.get_nearest_antarctic_base(
                self.current_location
            )
            if self.antarctic_base:
                self.base_name.setText(
                    f"{self.antarctic_base['name']} ({self.antarctic_base['country']})"
                )
                self.base_distance.setText(
                    f"{self.antarctic_base['distance_km']} km away\n"
                    f"{self.antarctic_base['description']}"
                )
                self.base_frame.show()
            else:
                self.base_frame.hide()
        else:
            self.base_frame.hide()

    def update_dynamic_content(self):
        """Update time-sensitive content."""
        # Update any time-dependent information
        if self.current_location:
            self.update_display()

    def refresh_location(self):
        """Request a location refresh."""
        self.location_label.setText("Updating location...")
        self.refresh_requested.emit()

    def show_context_menu(self, position):
        """Show the context menu."""
        menu = QMenu(self)

        refresh_action = menu.addAction("Refresh")
        refresh_action.triggered.connect(self.refresh_location)

        if self.current_location and self.current_location.is_in_antarctica():
            menu.addSeparator()
            view_map_action = menu.addAction("View on Map")
            view_map_action.triggered.connect(self.view_on_map)

            if self.antarctic_base:
                view_base_action = menu.addAction(f"About {self.antarctic_base['name']}")
                view_base_action.triggered.connect(lambda: self.show_base_info(self.antarctic_base))

        menu.exec_(self.mapToGlobal(position))

    def view_on_map(self):
        """Open the current location in the system's default map application."""
        if not self.current_location:
            return

        lat, lon = self.current_location.coordinates
        url = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}&zoom=8"
        # In a real implementation, use QDesktopServices.openUrl(QUrl(url))
        print(f"Opening map: {url}")

    def show_base_info(self, base_info: Dict[str, Any]):
        """Show detailed information about an Antarctic base."""
        # In a real implementation, this would show a dialog with detailed info
        print(f"Showing info for {base_info['name']}")

    def sizeHint(self) -> QSize:
        """Return the recommended size for this widget."""
        return QSize(300, 400)
