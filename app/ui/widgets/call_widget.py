"""
Widget for handling voice and video calls.
"""

from PySide6.QtCore import QSize, Qt, QTimer, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from app.models.contact import Contact


class VideoWidget(QFrame):
    """Widget for displaying video streams."""

    def __init__(self, parent=None):
        """Initialize the video widget."""
        super().__init__(parent)
        self.setFrameShape(QFrame.Box)
        self.setStyleSheet(
            """
            QFrame {
                background-color: #1a1a1a;
                border: 1px solid #333333;
                border-radius: 5px;
            }
        """
        )

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)

        # Placeholder for video content
        self.video_placeholder = QLabel("No video")
        self.video_placeholder.setAlignment(Qt.AlignCenter)
        self.video_placeholder.setStyleSheet(
            """
            QLabel {
                color: #888888;
                font-size: 14px;
            }
        """
        )

        self.layout.addWidget(self.video_placeholder)

        # Overlay for controls
        self.overlay = QWidget(self)
        self.overlay.setStyleSheet(
            """
            QWidget {
                background-color: rgba(0, 0, 0, 100);
                border-radius: 5px;
            }
        """
        )
        self.overlay.hide()

        # Name label
        self.name_label = QLabel()
        self.name_label.setStyleSheet(
            """
            QLabel {
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 5px 10px;
            }
        """
        )

        # Status label
        self.status_label = QLabel()
        self.status_label.setStyleSheet(
            """
            QLabel {
                color: #cccccc;
                font-size: 12px;
                padding: 0 10px 5px 10px;
            }
        """
        )

        overlay_layout = QVBoxLayout(self.overlay)
        overlay_layout.setContentsMargins(0, 0, 0, 0)
        overlay_layout.addWidget(self.name_label)
        overlay_layout.addWidget(self.status_label)
        overlay_layout.addStretch()

        # Timer to hide overlay after delay
        self.hide_timer = QTimer(self)
        self.hide_timer.setSingleShot(True)
        self.hide_timer.timeout.connect(self.hide_overlay)

        # Show overlay on mouse move
        self.setMouseTracking(True)

    def set_contact(self, contact: Contact):
        """Set the contact for this video widget."""
        self.name_label.setText(contact.name)
        self.status_label.setText("Call in progress")

    def set_status(self, status: str):
        """Set the status text."""
        self.status_label.setText(status)

    def show_overlay(self):
        """Show the overlay with controls."""
        self.overlay.show()
        self.hide_timer.start(3000)  # Hide after 3 seconds

    def hide_overlay(self):
        """Hide the overlay."""
        self.overlay.hide()

    def enterEvent(self, event):
        """Handle mouse enter event."""
        self.show_overlay()
        super().enterEvent(event)

    def mouseMoveEvent(self, event):
        """Handle mouse move event."""
        self.show_overlay()
        super().mouseMoveEvent(event)


class CallWidget(QWidget):
    """Widget for handling voice and video calls."""

    # Signals
    call_ended = Signal()
    toggle_mute = Signal()
    toggle_video = Signal()
    toggle_speaker = Signal()

    def __init__(self, parent=None):
        """Initialize the call widget."""
        super().__init__(parent)
        self.contact = None
        self.is_video_call = False
        self.call_duration = 0
        self.call_timer = QTimer(self)
        self.call_timer.timeout.connect(self.update_call_timer)

        self.setup_ui()

    def setup_ui(self):
        """Set up the user interface."""
        self.setStyleSheet(
            """
            QWidget {
                background-color: #121212;
                color: #ffffff;
            }
            QPushButton {
                background-color: rgba(255, 255, 255, 0.1);
                border: none;
                border-radius: 25px;
                min-width: 50px;
                min-height: 50px;
                margin: 5px;
            }
            QPushButton:hover {
                background-color: rgba(255, 255, 255, 0.2);
            }
            QPushButton:pressed {
                background-color: rgba(255, 255, 255, 0.3);
            }
            QPushButton:disabled {
                background-color: rgba(255, 255, 255, 0.05);
            }
            QLabel {
                color: #ffffff;
            }
        """
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Main video area
        self.video_container = QWidget()
        video_layout = QHBoxLayout(self.video_container)
        video_layout.setContentsMargins(0, 0, 0, 0)
        video_layout.setSpacing(0)

        # Remote video
        self.remote_video = VideoWidget()
        video_layout.addWidget(self.remote_video)

        # Local video (picture-in-picture)
        self.local_video = VideoWidget()
        self.local_video.setFixedSize(160, 120)
        self.local_video.setStyleSheet(
            """
            QFrame {
                border: 2px solid #4a90e2;
                border-radius: 5px;
            }
        """
        )

        # Add local video to bottom-right corner
        video_layout.addWidget(self.local_video, 0, Qt.AlignBottom | Qt.AlignRight)

        layout.addWidget(self.video_container, 1)

        # Call info
        self.call_info = QWidget()
        call_info_layout = QVBoxLayout(self.call_info)
        call_info_layout.setContentsMargins(0, 20, 0, 20)
        call_info_layout.setSpacing(5)

        self.contact_name = QLabel()
        self.contact_name.setAlignment(Qt.AlignCenter)
        self.contact_name.setStyleSheet("font-size: 24px; font-weight: bold;")

        self.call_status = QLabel("Calling...")
        self.call_status.setAlignment(Qt.AlignCenter)
        self.call_status.setStyleSheet("font-size: 16px; color: #cccccc;")

        call_info_layout.addWidget(self.contact_name)
        call_info_layout.addWidget(self.call_status)

        # Add to layout (centered)
        layout.addWidget(self.call_info, 0, Qt.AlignCenter)

        # Call controls
        controls = QWidget()
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(20, 20, 20, 30)
        controls_layout.setSpacing(10)

        # Mute button
        self.mute_btn = self.create_call_button("Mute", ":/icons/mic.png", ":/icons/mic_off.png")
        self.mute_btn.setCheckable(True)
        self.mute_btn.toggled.connect(self.on_mute_toggled)

        # Video button
        self.video_btn = self.create_call_button(
            "Video", ":/icons/videocam.png", ":/icons/videocam_off.png"
        )
        self.video_btn.setCheckable(True)
        self.video_btn.toggled.connect(self.on_video_toggled)

        # Speaker button
        self.speaker_btn = self.create_call_button(
            "Speaker", ":/icons/volume_up.png", ":/icons/volume_off.png"
        )
        self.speaker_btn.setCheckable(True)
        self.speaker_btn.toggled.connect(self.on_speaker_toggled)

        # End call button (larger and red)
        self.end_call_btn = QPushButton()
        self.end_call_btn.setIcon(QIcon(":/icons/call_end.png"))
        self.end_call_btn.setIconSize(QSize(32, 32))
        self.end_call_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #f44336;
                min-width: 60px;
                min-height: 60px;
                border-radius: 30px;
                margin: 0 20px;
            }
            QPushButton:hover {
                background-color: #e53935;
            }
            QPushButton:pressed {
                background-color: #d32f2f;
            }
        """
        )
        self.end_call_btn.clicked.connect(self.on_end_call_clicked)

        # Add buttons to layout
        controls_layout.addStretch()
        controls_layout.addWidget(self.mute_btn)
        controls_layout.addWidget(self.video_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.end_call_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.speaker_btn)
        controls_layout.addStretch()

        # Volume control (initially hidden)
        self.volume_slider = QSlider(Qt.Horizontal)
        self.volume_slider.setRange(0, 100)
        self.volume_slider.setValue(80)
        self.volume_slider.setFixedWidth(100)
        self.volume_slider.hide()

        # Show volume slider when speaker button is hovered
        self.speaker_btn.enterEvent = lambda e: self.volume_slider.show()
        self.speaker_btn.leaveEvent = lambda e: self.volume_slider.hide()

        # Add volume slider to layout
        volume_layout = QHBoxLayout()
        volume_layout.addStretch()
        volume_layout.addWidget(self.volume_slider)
        volume_layout.addStretch()

        # Add controls to main layout
        layout.addStretch()
        layout.addLayout(volume_layout)
        layout.addWidget(controls)

    def create_call_button(
        self, tooltip: str, icon_path: str, icon_checked_path: str = ""
    ) -> QPushButton:
        """Create a call control button."""
        btn = QPushButton()
        btn.setIcon(QIcon(icon_path))
        btn.setIconSize(QSize(24, 24))
        btn.setToolTip(tooltip)

        if icon_checked_path:
            btn.setProperty("iconUnchecked", QIcon(icon_path))
            btn.setProperty("iconChecked", QIcon(icon_checked_path))
            btn.toggled.connect(
                lambda checked, b=btn: b.setIcon(
                    b.property("iconChecked") if checked else b.property("iconUnchecked")
                )
            )

        return btn

    def start_outgoing_call(self, contact: Contact, video_enabled: bool):
        """Start an outgoing call."""
        self.contact = contact
        self.is_video_call = video_enabled

        # Update UI
        self.contact_name.setText(contact.name)
        self.call_status.setText("Calling...")

        # Show/hide video elements
        self.video_btn.setChecked(not video_enabled)
        self.update_video_ui()

        # Start call timer when connected
        self.call_duration = 0
        self.call_timer.start(1000)  # Update every second

    def start_incoming_call(self, contact: Contact, video_enabled: bool):
        """Handle an incoming call."""
        self.contact = contact
        self.is_video_call = video_enabled

        # Update UI
        self.contact_name.setText(contact.name)
        self.call_status.setText("Incoming call...")

        # Show/hide video elements
        self.video_btn.setChecked(not video_enabled)
        self.update_video_ui()

        # Add answer/decline buttons
        # (In a real app, these would be shown conditionally for incoming calls)

    def update_call_timer(self):
        """Update the call duration timer."""
        self.call_duration += 1
        minutes = self.call_duration // 60
        seconds = self.call_duration % 60
        self.call_status.setText(f"{minutes:02d}:{seconds:02d}")

    def update_video_ui(self):
        """Update the UI based on video call status."""
        if self.is_video_call and not self.video_btn.isChecked():
            # Video call
            self.remote_video.show()
            self.local_video.show()
            self.call_info.hide()
        else:
            # Audio call
            self.remote_video.hide()
            self.local_video.hide()
            self.call_info.show()

    def on_mute_toggled(self, checked: bool):
        """Handle mute button toggle."""
        self.toggle_mute.emit()

    def on_video_toggled(self, checked: bool):
        """Handle video button toggle."""
        self.update_video_ui()
        self.toggle_video.emit()

    def on_speaker_toggled(self, checked: bool):
        """Handle speaker button toggle."""
        self.toggle_speaker.emit()

    def on_end_call_clicked(self):
        """Handle end call button click."""
        self.call_timer.stop()
        self.call_ended.emit()

    def set_call_status(self, status: str):
        """Set the call status text."""
        self.call_status.setText(status)

        # Update remote video status
        if self.remote_video.isVisible():
            self.remote_video.set_status(status)

    def set_remote_video(self, video_frame):
        """Set the remote video frame."""
        # In a real app, this would display the actual video frame

    def set_local_video(self, video_frame):
        """Set the local video frame."""
        # In a real app, this would display the local video preview
