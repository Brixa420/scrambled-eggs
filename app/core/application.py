"""
Main application class that ties together all components.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, Signal

from app.crypto.encryption_manager import EncryptionManager
from app.db.database import DatabaseManager
from app.models.contact import Contact, ContactStatus
from app.models.message import Message, MessageStatus, MessageType
from app.signaling.signaling_server import SignalingServer
from app.webrtc.webrtc_manager import WebRTCConfig, WebRTCManager

logger = logging.getLogger(__name__)


class ApplicationSignals(QObject):
    """Signals for the application."""

    # Contact signals
    contact_added = Signal(Contact)
    contact_removed = Signal(str)  # contact_id
    contact_status_changed = Signal(str, str)  # contact_id, status

    # Message signals
    message_received = Signal(Message)
    message_sent = Signal(Message)
    message_status_changed = Signal(str, str)  # message_id, status

    # Call signals
    incoming_call = Signal(str, str, dict)  # caller_id, call_type, offer
    call_ended = Signal(str, str)  # peer_id, reason
    call_status_changed = Signal(str, str)  # peer_id, status

    # Connection signals
    connection_state_changed = Signal(str)  # state
    error_occurred = Signal(str, str)  # context, error


class Application(QObject):
    """Main application class."""

    def __init__(self, config: Optional[dict] = None):
        """Initialize the application."""
        super().__init__()

        # Configuration
        self.config = config or {}
        self.data_dir = Path(self.config.get("data_dir", Path.home() / ".scrambled-eggs"))
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.signals = ApplicationSignals()
        self.db = DatabaseManager(str(self.data_dir / "scrambled_eggs.db"))
        self.encryption = EncryptionManager()

        # WebRTC
        webrtc_config = WebRTCConfig()
        self.webrtc = WebRTCManager(webrtc_config)
        self.webrtc.on_connection_state_change = self._on_connection_state_change
        self.webrtc.on_ice_candidate = self._on_ice_candidate

        # Signaling
        self.signaling_server = None
        self.signaling_task = None
        self.signaling_connected = False
        self.peer_connections: Dict[str, dict] = {}

        # Message queue for sending messages when peer is offline
        self.message_queue: Dict[str, List[dict]] = {}

        # Register message handler
        self.webrtc.register_message_callback(self._handle_webrtc_message)

        # Load data from database
        self._load_data()

    def _load_data(self):
        """Load data from the database."""
        # Load contacts
        contacts = self.db.get_contacts()
        for contact in contacts:
            # Convert database model to Contact
            contact_obj = Contact(
                id=contact.id,
                name=contact.name,
                public_key=contact.public_key,
                status=ContactStatus(contact.status),
                last_seen=contact.last_seen,
                avatar=contact.avatar,
            )
            self.signals.contact_added.emit(contact_obj)

            # Load queued messages
            if contact.id not in self.message_queue:
                self.message_queue[contact.id] = []

            # Load pending messages from database
            pending_messages = self.db.get_messages(
                contact_id=contact.id, status=MessageStatus.PENDING
            )
            for msg in pending_messages:
                self.message_queue[contact.id].append(
                    {
                        "type": "message",
                        "content": msg.content,
                        "message_id": msg.id,
                        "timestamp": msg.timestamp,
                    }
                )

    def start(self):
        """Start the application."""
        # Start signaling server if configured
        if self.config.get("start_signaling_server", False):
            self._start_signaling_server()

        # Connect to signaling server if configured
        if "signaling_server" in self.config:
            self._connect_to_signaling_server()

    def stop(self):
        """Stop the application and clean up resources."""
        # Disconnect from signaling server
        self._disconnect_from_signaling_server()

        # Stop signaling server if running
        if self.signaling_server and self.signaling_task:
            self.signaling_task.cancel()

        # Close all peer connections
        for peer_id in list(self.peer_connections.keys()):
            self._close_peer_connection(peer_id)

    # Contact Management

    def add_contact(self, contact: Contact) -> bool:
        """Add a new contact."""
        try:
            # Save to database
            contact_id = self.db.add_contact(
                name=contact.name,
                public_key=contact.public_key,
                status=contact.status.value,
                last_seen=contact.last_seen,
                avatar=contact.avatar,
            )

            if not contact_id:
                return False

            contact.id = contact_id

            # Add to in-memory cache
            self.signals.contact_added.emit(contact)

            # Initialize message queue
            if contact.id not in self.message_queue:
                self.message_queue[contact.id] = []

            return True

        except Exception as e:
            logger.error(f"Error adding contact: {e}")
            self.signals.error_occurred.emit("add_contact", str(e))
            return False

    def remove_contact(self, contact_id: str) -> bool:
        """Remove a contact."""
        try:
            # Remove from database
            success = self.db.delete_contact(contact_id)

            if not success:
                return False

            # Remove from in-memory cache
            self.signals.contact_removed.emit(contact_id)

            # Clean up message queue
            if contact_id in self.message_queue:
                del self.message_queue[contact_id]

            # Close peer connection if exists
            if contact_id in self.peer_connections:
                self._close_peer_connection(contact_id)

            return True

        except Exception as e:
            logger.error(f"Error removing contact: {e}")
            self.signals.error_occurred.emit("remove_contact", str(e))
            return False

    def update_contact_status(self, contact_id: str, status: ContactStatus) -> bool:
        """Update a contact's status."""
        try:
            # Update in database
            success = self.db.update_contact_status(contact_id, status.value)

            if not success:
                return False

            # Notify UI
            self.signals.contact_status_changed.emit(contact_id, status.value)

            # If contact came online, send queued messages
            if status == ContactStatus.ONLINE and contact_id in self.message_queue:
                self._process_message_queue(contact_id)

            return True

        except Exception as e:
            logger.error(f"Error updating contact status: {e}")
            self.signals.error_occurred.emit("update_contact_status", str(e))
            return False

    # Message Handling

    def send_message(
        self, contact_id: str, content: str, message_type: MessageType = MessageType.TEXT
    ) -> Optional[Message]:
        """Send a message to a contact."""
        try:
            # Create message
            message = Message(
                id=str(len(self.db.get_messages()) + 1),  # Temporary ID
                contact_id=contact_id,
                content=content,
                message_type=message_type,
                status=MessageStatus.SENDING,
                timestamp=time.time(),
                is_outgoing=True,
            )

            # Save to database
            message_id = self.db.add_message(
                contact_id=contact_id,
                content=content,
                message_type=message_type.value,
                status=MessageStatus.SENDING.value,
                timestamp=message.timestamp,
                is_outgoing=True,
            )

            if not message_id:
                return None

            message.id = message_id

            # Encrypt the message
            encrypted_content = self.encryption.encrypt_message(contact_id, content.encode("utf-8"))

            # Send via WebRTC if peer is connected
            if (
                contact_id in self.peer_connections
                and self.peer_connections[contact_id]["connected"]
            ):
                success = self.webrtc.send_message(
                    contact_id,
                    {
                        "type": "message",
                        "content": encrypted_content,
                        "message_id": message_id,
                        "timestamp": message.timestamp,
                    },
                )

                if success:
                    # Update status to sent
                    message.status = MessageStatus.SENT
                    self.db.update_message_status(message_id, MessageStatus.SENT.value)
                else:
                    # Queue for later
                    message.status = MessageStatus.PENDING
                    self.db.update_message_status(message_id, MessageStatus.PENDING.value)

                    if contact_id not in self.message_queue:
                        self.message_queue[contact_id] = []
                    self.message_queue[contact_id].append(
                        {
                            "type": "message",
                            "content": encrypted_content,
                            "message_id": message_id,
                            "timestamp": message.timestamp,
                        }
                    )
            else:
                # Queue for later
                message.status = MessageStatus.PENDING
                self.db.update_message_status(message_id, MessageStatus.PENDING.value)

                if contact_id not in self.message_queue:
                    self.message_queue[contact_id] = []
                self.message_queue[contact_id].append(
                    {
                        "type": "message",
                        "content": encrypted_content,
                        "message_id": message_id,
                        "timestamp": message.timestamp,
                    }
                )

            # Notify UI
            self.signals.message_sent.emit(message)

            return message

        except Exception as e:
            logger.error(f"Error sending message: {e}")
            self.signals.error_occurred.emit("send_message", str(e))
            return None

    async def _handle_webrtc_message(self, peer_id: str, data: dict):
        """Handle an incoming WebRTC data channel message."""
        try:
            message_type = data.get("type")

            if message_type == "message":
                # Decrypt the message
                decrypted_content = self.encryption.decrypt_message(
                    peer_id, data["content"]
                ).decode("utf-8")

                # Create message object
                message = Message(
                    id=data["message_id"],
                    contact_id=peer_id,
                    content=decrypted_content,
                    message_type=MessageType.TEXT,
                    status=MessageStatus.DELIVERED,
                    timestamp=data.get("timestamp", time.time()),
                    is_outgoing=False,
                )

                # Save to database
                self.db.add_message(
                    contact_id=peer_id,
                    content=decrypted_content,
                    message_type=MessageType.TEXT.value,
                    status=MessageStatus.DELIVERED.value,
                    timestamp=message.timestamp,
                    is_outgoing=False,
                )

                # Notify UI
                self.signals.message_received.emit(message)

                # Send delivery receipt
                await self.webrtc.send_message(
                    peer_id,
                    {"type": "delivery-receipt", "message_id": message.id, "status": "delivered"},
                )

            elif message_type == "delivery-receipt":
                # Update message status
                message_id = data["message_id"]
                status = MessageStatus[data["status"].upper()]

                self.db.update_message_status(message_id, status.value)
                self.signals.message_status_changed.emit(message_id, status.value)

            elif message_type == "call-offer":
                # Handle incoming call
                call_type = data.get("call_type", "audio")
                offer = data.get("offer")

                if not offer:
                    logger.error("No offer in call-offer message")
                    return

                # Notify UI
                self.signals.incoming_call.emit(peer_id, call_type, offer)

            elif message_type == "call-answer":
                # Handle call answer
                answer = data.get("answer")

                if not answer:
                    logger.error("No answer in call-answer message")
                    return

                # Forward to WebRTC manager
                await self.webrtc.set_remote_description(peer_id, answer)

                # Update call status
                self.signals.call_status_changed.emit(peer_id, "connected")

            elif message_type == "call-ice-candidate":
                # Handle ICE candidate for call
                candidate = data.get("candidate")

                if not candidate:
                    logger.error("No candidate in call-ice-candidate message")
                    return

                # Forward to WebRTC manager
                await self.webrtc.add_ice_candidate(peer_id, candidate)

            elif message_type == "end-call":
                # Handle call end
                reason = data.get("reason", "Call ended")
                self.signals.call_ended.emit(peer_id, reason)

        except Exception as e:
            logger.error(f"Error handling WebRTC message: {e}")
            self.signals.error_occurred.emit("handle_webrtc_message", str(e))

    def _process_message_queue(self, contact_id: str):
        """Process queued messages for a contact."""
        if contact_id not in self.message_queue or not self.message_queue[contact_id]:
            return

        # Process messages in the queue
        for message in list(self.message_queue[contact_id]):
            try:
                # Try to send the message
                if self.webrtc.send_message(contact_id, message):
                    # Remove from queue if sent successfully
                    self.message_queue[contact_id].remove(message)

                    # Update message status in database
                    if "message_id" in message:
                        self.db.update_message_status(
                            message["message_id"], MessageStatus.SENT.value
                        )
            except Exception as e:
                logger.error(f"Error processing queued message: {e}")

    # Call Management

    async def start_call(self, contact_id: str, call_type: str = "audio") -> bool:
        """Start a call with a contact."""
        try:
            # Create WebRTC peer connection if it doesn't exist
            if contact_id not in self.peer_connections:
                await self.webrtc.create_peer_connection(contact_id)
                self.peer_connections[contact_id] = {"connected": False, "call_active": False}

            # Create data channel if it doesn't exist
            if contact_id not in self.webrtc.data_channels:
                await self.webrtc.create_data_channel(contact_id, "call-control")

            # Create and send offer
            offer = await self.webrtc.create_offer(contact_id)
            if not offer:
                logger.error("Failed to create offer")
                return False

            # Send offer via signaling server or WebRTC data channel
            await self.webrtc.send_message(
                contact_id, {"type": "call-offer", "call_type": call_type, "offer": offer}
            )

            # Update call status
            self.peer_connections[contact_id]["call_active"] = True
            self.signals.call_status_changed.emit(contact_id, "calling")

            return True

        except Exception as e:
            logger.error(f"Error starting call: {e}")
            self.signals.error_occurred.emit("start_call", str(e))
            return False

    async def answer_call(self, contact_id: str, answer: dict) -> bool:
        """Answer an incoming call."""
        try:
            # Send answer via WebRTC data channel
            success = await self.webrtc.send_message(
                contact_id, {"type": "call-answer", "answer": answer}
            )

            if success:
                self.peer_connections[contact_id]["call_active"] = True
                self.signals.call_status_changed.emit(contact_id, "connected")

            return success

        except Exception as e:
            logger.error(f"Error answering call: {e}")
            self.signals.error_occurred.emit("answer_call", str(e))
            return False

    async def end_call(self, contact_id: str, reason: str = "Call ended") -> bool:
        """End an ongoing call."""
        try:
            # Send end-call message
            success = await self.webrtc.send_message(
                contact_id, {"type": "end-call", "reason": reason}
            )

            # Update call status
            if contact_id in self.peer_connections:
                self.peer_connections[contact_id]["call_active"] = False

            # Notify UI
            self.signals.call_ended.emit(contact_id, reason)

            return success

        except Exception as e:
            logger.error(f"Error ending call: {e}")
            self.signals.error_occurred.emit("end_call", str(e))
            return False

    # WebRTC Event Handlers

    def _on_connection_state_change(self, peer_id: str, state: str):
        """Handle WebRTC connection state changes."""
        logger.info(f"Connection state for {peer_id}: {state}")

        if peer_id not in self.peer_connections:
            self.peer_connections[peer_id] = {"connected": False, "call_active": False}

        # Update connection status
        self.peer_connections[peer_id]["connected"] = state == "connected"

        # Notify UI
        self.signals.connection_state_changed.emit(state)

        # If connected, process any queued messages
        if state == "connected":
            self._process_message_queue(peer_id)

    def _on_ice_candidate(self, peer_id: str, candidate: dict):
        """Handle ICE candidate generation."""
        logger.debug(f"ICE candidate for {peer_id}: {candidate}")

        # Send ICE candidate to peer via signaling server or WebRTC data channel
        asyncio.create_task(
            self.webrtc.send_message(
                peer_id, {"type": "call-ice-candidate", "candidate": candidate}
            )
        )

    # Signaling Server Management

    def _start_signaling_server(self):
        """Start the signaling server in a separate thread."""
        try:
            self.signaling_server = SignalingServer(
                host=self.config.get("signaling_host", "0.0.0.0"),
                port=self.config.get("signaling_port", 8765),
            )

            # Start the server in a separate thread
            self.signaling_task = asyncio.create_task(self.signaling_server.start())
            logger.info(
                f"Signaling server started on {self.config.get('signaling_host', '0.0.0.0')}:"
                f"{self.config.get('signaling_port', 8765)}"
            )

        except Exception as e:
            logger.error(f"Error starting signaling server: {e}")
            self.signals.error_occurred.emit("start_signaling_server", str(e))

    def _connect_to_signaling_server(self):
        """Connect to the signaling server."""
        # TODO: Implement signaling client connection

    def _disconnect_from_signaling_server(self):
        """Disconnect from the signaling server."""
        # TODO: Implement signaling client disconnection

    def _close_peer_connection(self, peer_id: str):
        """Close a peer connection and clean up resources."""
        if peer_id in self.peer_connections:
            # Close WebRTC connection
            asyncio.create_task(self.webrtc.close_peer_connection(peer_id))

            # Remove from peer connections
            del self.peer_connections[peer_id]

            # Notify UI
            self.signals.connection_state_changed.emit("disconnected")


# Example usage
if __name__ == "__main__":
    import sys

    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication

    # Set up logging
    logging.basicConfig(level=logging.INFO)

    # Create Qt application
    app = QApplication(sys.argv)

    # Create and start the application
    config = {
        "start_signaling_server": True,
        "signaling_host": "0.0.0.0",
        "signaling_port": 8765,
        "data_dir": "./data",
    }

    application = Application(config)
    application.start()

    # Set up signal handlers for clean shutdown
    def signal_handler(sig, frame):
        print("Shutting down...")
        application.stop()
        QCoreApplication.quit()

    import signal

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run the application
    sys.exit(app.exec())
