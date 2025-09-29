"""
Screen Sharing Module for Brixa
Enables secure screen sharing between peers.
"""

import asyncio
import base64
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

import cv2
import numpy as np
from mss import mss
from PIL import Image

from ..p2p.p2p_manager import P2PManager
from ..security.scrambled_eggs_crypto import ScrambledEggsCrypto


class ScreenShareStatus(Enum):
    """Status of a screen sharing session."""

    IDLE = "idle"
    SHARING = "sharing"
    VIEWING = "viewing"
    PAUSED = "paused"
    ERROR = "error"


@dataclass
class ScreenShareSession:
    """Represents a screen sharing session."""

    session_id: str
    sharer_id: str
    viewer_ids: List[str] = field(default_factory=list)
    status: ScreenShareStatus = ScreenShareStatus.IDLE
    frame_rate: int = 10
    quality: int = 70  # 0-100
    region: Optional[Dict[str, int]] = None  # {x, y, width, height}
    last_frame: Optional[bytes] = None
    last_frame_time: float = 0

    def add_viewer(self, peer_id: str) -> bool:
        """Add a viewer to the session."""
        if peer_id not in self.viewer_ids:
            self.viewer_ids.append(peer_id)
            return True
        return False

    def remove_viewer(self, peer_id: str) -> bool:
        """Remove a viewer from the session."""
        if peer_id in self.viewer_ids:
            self.viewer_ids.remove(peer_id)
            return True
        return False


class ScreenShareManager:
    """Manages screen sharing sessions."""

    def __init__(self, p2p_manager: P2PManager, crypto: ScrambledEggsCrypto):
        """Initialize the screen share manager."""
        self.p2p = p2p_manager
        self.crypto = crypto
        self.sessions: Dict[str, ScreenShareSession] = {}
        self.active_session: Optional[ScreenShareSession] = None
        self.screen_capture = mss()
        self.logger = logging.getLogger(__name__)
        self._capture_task: Optional[asyncio.Task] = None
        self._is_capturing = False

        # Register message handlers
        self.p2p.register_message_handler("screen_share_offer", self._handle_offer)
        self.p2p.register_message_handler("screen_share_frame", self._handle_frame)
        self.p2p.register_message_handler("screen_share_control", self._handle_control)

    async def start_sharing(
        self,
        peer_ids: List[str],
        region: Optional[Dict[str, int]] = None,
        frame_rate: int = 10,
        quality: int = 70,
    ) -> Optional[str]:
        """Start a new screen sharing session."""
        if self.active_session and self.active_session.status == ScreenShareStatus.SHARING:
            await self.stop_sharing()

        session_id = f"screen_{int(time.time())}"
        session = ScreenShareSession(
            session_id=session_id,
            sharer_id=self.p2p.peer_id,
            viewer_ids=peer_ids.copy(),
            status=ScreenShareStatus.SHARING,
            frame_rate=frame_rate,
            quality=quality,
            region=region,
        )

        self.sessions[session_id] = session
        self.active_session = session

        # Send offer to viewers
        await self._send_offer(session, peer_ids)

        # Start screen capture
        self._is_capturing = True
        self._capture_task = asyncio.create_task(self._capture_screen(session))

        return session_id

    async def stop_sharing(self) -> bool:
        """Stop the current screen sharing session."""
        if not self.active_session:
            return False

        session_id = self.active_session.session_id
        self._is_capturing = False

        if self._capture_task and not self._capture_task.done():
            self._capture_task.cancel()
            try:
                await self._capture_task
            except asyncio.CancelledError:
                pass

        # Notify viewers
        await self._broadcast_control(session_id, "stop")

        # Clean up
        if session_id in self.sessions:
            del self.sessions[session_id]

        self.active_session = None
        return True

    async def view_share(self, sharer_id: str, session_id: str) -> bool:
        """Start viewing a screen sharing session."""
        # Send join request
        await self.p2p.send_message(
            sharer_id,
            {
                "type": "screen_share_control",
                "session_id": session_id,
                "action": "join",
                "viewer_id": self.p2p.peer_id,
            },
        )

        # Create a new session for viewing
        session = ScreenShareSession(
            session_id=session_id, sharer_id=sharer_id, status=ScreenShareStatus.VIEWING
        )

        self.sessions[session_id] = session
        self.active_session = session

        return True

    async def stop_viewing(self, session_id: str) -> bool:
        """Stop viewing a screen sharing session."""
        if session_id not in self.sessions:
            return False

        session = self.sessions[session_id]

        # Notify the sharer
        await self.p2p.send_message(
            session.sharer_id,
            {
                "type": "screen_share_control",
                "session_id": session_id,
                "action": "leave",
                "viewer_id": self.p2p.peer_id,
            },
        )

        # Clean up
        if self.active_session and self.active_session.session_id == session_id:
            self.active_session = None

        del self.sessions[session_id]
        return True

    async def set_region(self, region: Dict[str, int]) -> bool:
        """Set the screen capture region."""
        if not self.active_session or self.active_session.status != ScreenShareStatus.SHARING:
            return False

        self.active_session.region = region
        return True

    async def set_frame_rate(self, frame_rate: int) -> bool:
        """Set the frame rate for screen sharing."""
        if not self.active_session or self.active_session.status != ScreenShareStatus.SHARING:
            return False

        self.active_session.frame_rate = max(1, min(30, frame_rate))  # Clamp between 1-30 FPS
        return True

    async def set_quality(self, quality: int) -> bool:
        """Set the image quality for screen sharing."""
        if not self.active_session or self.active_session.status != ScreenShareStatus.SHARING:
            return False

        self.active_session.quality = max(10, min(100, quality))  # Clamp between 10-100
        return True

    # Internal methods

    async def _capture_screen(self, session: ScreenShareSession):
        """Capture and send screen frames at the specified frame rate."""
        frame_interval = 1.0 / session.frame_rate

        try:
            while self._is_capturing and session.status == ScreenShareStatus.SHARING:
                start_time = time.time()

                # Capture screen
                frame = await self._capture_frame(session.region)

                if frame is not None:
                    # Compress and encode frame
                    _, buffer = cv2.imencode(
                        ".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), session.quality]
                    )

                    frame_data = buffer.tobytes()
                    session.last_frame = frame_data
                    session.last_frame_time = time.time()

                    # Send to all viewers
                    await self._broadcast_frame(session, frame_data)

                # Maintain frame rate
                elapsed = time.time() - start_time
                await asyncio.sleep(max(0, frame_interval - elapsed))

        except Exception as e:
            self.logger.error(f"Screen capture error: {str(e)}")
            session.status = ScreenShareStatus.ERROR
        finally:
            self._is_capturing = False

    async def _capture_frame(self, region: Optional[Dict[str, int]] = None) -> Optional[np.ndarray]:
        """Capture a single frame from the screen."""
        try:
            # If no region specified, capture primary monitor
            if not region:
                monitor = self.screen_capture.monitors[1]  # Primary monitor
                region = {
                    "top": monitor["top"],
                    "left": monitor["left"],
                    "width": monitor["width"],
                    "height": monitor["height"],
                }

            # Capture the screen
            screenshot = self.screen_capture.grab(region)

            # Convert to OpenCV format (BGR)
            img = Image.frombytes("RGB", screenshot.size, screenshot.rgb)
            frame = cv2.cvtColor(np.array(img), cv2.COLOR_RGB2BGR)

            return frame

        except Exception as e:
            self.logger.error(f"Frame capture failed: {str(e)}")
            return None

    async def _send_offer(self, session: ScreenShareSession, peer_ids: List[str]):
        """Send a screen share offer to peers."""
        offer = {
            "type": "screen_share_offer",
            "session_id": session.session_id,
            "sharer_id": self.p2p.peer_id,
            "frame_rate": session.frame_rate,
            "quality": session.quality,
            "region": session.region or {},
        }

        for peer_id in peer_ids:
            await self.p2p.send_message(peer_id, offer)

    async def _broadcast_frame(self, session: ScreenShareSession, frame_data: bytes):
        """Send a frame to all viewers."""
        if not session.viewer_ids:
            return

        # Split large frames into chunks if needed
        max_chunk_size = 16 * 1024  # 16KB chunks
        frame_str = base64.b64encode(frame_data).decode("utf-8")
        chunks = [
            frame_str[i : i + max_chunk_size] for i in range(0, len(frame_str), max_chunk_size)
        ]

        for viewer_id in session.viewer_ids:
            for i, chunk in enumerate(chunks):
                await self.p2p.send_message(
                    viewer_id,
                    {
                        "type": "screen_share_frame",
                        "session_id": session.session_id,
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                        "data": chunk,
                        "timestamp": time.time(),
                    },
                )

    async def _broadcast_control(self, session_id: str, action: str, data: Optional[Dict] = None):
        """Send a control message to all viewers."""
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        message = {
            "type": "screen_share_control",
            "session_id": session_id,
            "action": action,
            "timestamp": time.time(),
        }

        if data:
            message.update(data)

        for viewer_id in session.viewer_ids:
            await self.p2p.send_message(viewer_id, message)

    # Message handlers

    async def _handle_offer(self, data: Dict[str, Any]):
        """Handle incoming screen share offer."""
        session_id = data.get("session_id")
        sharer_id = data.get("sharer_id")

        if not all([session_id, sharer_id]):
            return

        # Create or update session
        if session_id not in self.sessions:
            self.sessions[session_id] = ScreenShareSession(
                session_id=session_id,
                sharer_id=sharer_id,
                status=ScreenShareStatus.VIEWING,
                frame_rate=data.get("frame_rate", 10),
                quality=data.get("quality", 70),
                region=data.get("region"),
            )

        # Notify UI
        if hasattr(self, "on_offer_received"):
            await self.on_offer_received(self.sessions[session_id])

    async def _handle_frame(self, data: Dict[str, Any]):
        """Handle incoming screen share frame."""
        session_id = data.get("session_id")
        chunk_index = data.get("chunk_index", 0)
        total_chunks = data.get("total_chunks", 1)

        if not session_id or session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        # Initialize frame buffer if needed
        if not hasattr(session, "_frame_buffer"):
            session._frame_buffer = {}

        # Store chunk
        session._frame_buffer[chunk_index] = data["data"]

        # If we have all chunks, process the frame
        if len(session._frame_buffer) >= total_chunks:
            # Reassemble frame
            frame_str = "".join([session._frame_buffer[i] for i in range(total_chunks)])
            frame_data = base64.b64decode(frame_str)

            # Convert to OpenCV format
            nparr = np.frombuffer(frame_data, np.uint8)
            frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

            # Update session
            session.last_frame = frame
            session.last_frame_time = time.time()

            # Notify UI
            if hasattr(self, "on_frame_received"):
                await self.on_frame_received(session_id, frame)

            # Clear buffer
            session._frame_buffer = {}

    async def _handle_control(self, data: Dict[str, Any]):
        """Handle screen share control messages."""
        session_id = data.get("session_id")
        action = data.get("action")

        if not all([session_id, action]) or session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        if action == "join":
            # Add viewer to the session
            viewer_id = data.get("viewer_id")
            if viewer_id and viewer_id not in session.viewer_ids:
                session.viewer_ids.append(viewer_id)

                # Send current frame if available
                if session.last_frame is not None:
                    await self._broadcast_frame(session, session.last_frame)

        elif action == "leave":
            # Remove viewer from the session
            viewer_id = data.get("viewer_id")
            if viewer_id in session.viewer_ids:
                session.viewer_ids.remove(viewer_id)

        elif action == "stop":
            # Stop the session
            if hasattr(self, "on_session_ended"):
                await self.on_session_ended(session_id)

            if session_id in self.sessions:
                del self.sessions[session_id]

    # Callback methods (to be implemented by the UI)

    async def on_offer_received(self, session: ScreenShareSession):
        """Called when a screen share offer is received."""

    async def on_frame_received(self, session_id: str, frame: np.ndarray):
        """Called when a new frame is received."""

    async def on_session_ended(self, session_id: str):
        """Called when a screen sharing session ends."""
