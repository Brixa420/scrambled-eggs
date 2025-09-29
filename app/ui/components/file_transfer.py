"""
File Transfer Component

Provides a user interface for sending and receiving files over the P2P network.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional

import ipywidgets as widgets
from IPython.display import display


@dataclass
class FileTransfer:
    """Represents a file transfer."""

    transfer_id: str
    filename: str
    size: int
    peer_id: str
    direction: str  # 'send' or 'receive'
    status: str = "pending"  # 'pending', 'in_progress', 'completed', 'failed'
    progress: float = 0.0
    speed: float = 0.0  # bytes per second
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    error: Optional[str] = None


class FileTransferManager:
    """Manages file transfers in the UI."""

    def __init__(self, p2p_manager):
        """Initialize the file transfer manager.

        Args:
            p2p_manager: Instance of P2PManager
        """
        self.p2p_manager = p2p_manager
        self.transfers: Dict[str, FileTransfer] = {}
        self.transfer_widgets: Dict[str, Dict] = {}
        self._init_ui()

        # Register file transfer handlers
        self.p2p_manager.on_file_offer(self._on_file_offer)
        self.p2p_manager.on_file_chunk(self._on_file_chunk)
        self.p2p_manager.on_file_complete(self._on_file_complete)
        self.p2p_manager.on_file_error(self._on_file_error)

    def _init_ui(self):
        """Initialize the UI components."""
        # Transfer list
        self.transfer_list = widgets.VBox([])

        # Buttons
        self.send_button = widgets.Button(
            description="Send File", icon="upload", tooltip="Send a file to a contact"
        )
        self.send_button.on_click(self._on_send_click)

        self.clear_completed_button = widgets.Button(
            description="Clear Completed", tooltip="Clear completed transfers"
        )
        self.clear_completed_button.on_click(self._on_clear_completed_click)

        # Layout
        self.manager = widgets.VBox(
            [
                widgets.HTML("<h3>File Transfers</h3>"),
                self.transfer_list,
                widgets.HBox([self.send_button, self.clear_completed_button]),
            ]
        )

    def display(self):
        """Display the file transfer manager."""
        display(self.manager)

    def _on_send_click(self, _):
        """Handle send file button click."""
        # Create a dialog to select a file and recipient
        file_upload = widgets.FileUpload(description="Select File")

        # Get list of contacts for the dropdown
        contacts = self.p2p_manager.get_contacts()
        contact_options = [(f"{c.get('name', cid)} ({cid})", cid) for cid, c in contacts.items()]

        contact_dropdown = widgets.Dropdown(
            options=contact_options, description="To:", disabled=not contact_options
        )

        send_button = widgets.Button(description="Send")
        cancel_button = widgets.Button(description="Cancel")

        status = widgets.HTML("")

        def on_send_click(_):
            if not file_upload.value:
                status.value = '<span style="color: red;">Please select a file</span>'
                return

            if not contact_options:
                status.value = '<span style="color: red;">No contacts available</span>'
                return

            # Get the file data
            file_info = list(file_upload.value.values())[0]
            filename = file_info["name"]
            file_data = file_info["content"]

            # Get the recipient
            recipient_id = contact_dropdown.value

            try:
                # Start the file transfer
                transfer_id = self.p2p_manager.send_file(
                    recipient_id=recipient_id, filename=filename, file_data=file_data
                )

                # Create a transfer object
                transfer = FileTransfer(
                    transfer_id=transfer_id,
                    filename=filename,
                    size=len(file_data),
                    peer_id=recipient_id,
                    direction="send",
                    status="pending",
                )

                # Add to the UI
                self._add_transfer(transfer)

                # Close the dialog
                dialog.close()

            except Exception as e:
                status.value = f'<span style="color: red;">Error: {str(e)}</span>'

        def on_cancel_click(_):
            dialog.close()

        send_button.on_click(on_send_click)
        cancel_button.on_click(on_cancel_click)

        # Create the dialog
        dialog = widgets.VBox(
            [
                widgets.HTML("<h4>Send File</h4>"),
                file_upload,
                contact_dropdown if contact_options else widgets.HTML("No contacts available"),
                widgets.HBox([send_button, cancel_button]),
                status,
            ]
        )

        # Display the dialog
        display(dialog)

    def _on_clear_completed_click(self, _):
        """Handle clear completed button click."""
        completed_ids = [
            tid
            for tid, t in self.transfers.items()
            if t.status in ["completed", "failed", "cancelled"]
        ]

        for tid in completed_ids:
            self._remove_transfer(tid)

    def _add_transfer(self, transfer: FileTransfer):
        """Add a transfer to the UI."""
        self.transfers[transfer.transfer_id] = transfer

        # Create UI elements for the transfer
        filename_label = widgets.HTML(f"<b>{transfer.filename}</b>")
        peer_label = widgets.HTML(
            f"To: {transfer.peer_id}"
            if transfer.direction == "send"
            else f"From: {transfer.peer_id}"
        )

        progress = widgets.FloatProgress(
            value=0,
            min=0,
            max=100,
            description="Progress:",
            bar_style="info",
            orientation="horizontal",
        )

        status_label = widgets.HTML("Pending...")
        speed_label = widgets.HTML("")

        # Action buttons
        cancel_button = widgets.Button(
            icon="times", tooltip="Cancel transfer", layout={"width": "40px"}
        )
        cancel_button.on_click(lambda _, tid=transfer.transfer_id: self._on_cancel_transfer(tid))

        open_button = widgets.Button(
            icon="folder-open", tooltip="Open file", disabled=True, layout={"width": "40px"}
        )

        # Container for the transfer
        transfer_container = widgets.VBox(
            [
                widgets.HBox([filename_label, peer_label]),
                progress,
                widgets.HBox([status_label, speed_label]),
                widgets.HBox([cancel_button, open_button]),
            ],
            layout=widgets.Layout(border="1px solid #ccc", padding="5px", margin="5px 0"),
        )

        # Store the widgets for later updates
        self.transfer_widgets[transfer.transfer_id] = {
            "container": transfer_container,
            "progress": progress,
            "status": status_label,
            "speed": speed_label,
            "cancel_button": cancel_button,
            "open_button": open_button,
        }

        # Add to the UI
        self.transfer_list.children = (transfer_container,) + self.transfer_list.children

        # Start the transfer if needed
        if transfer.status == "pending" and transfer.direction == "send":
            self._start_transfer(transfer.transfer_id)

    def _remove_transfer(self, transfer_id: str):
        """Remove a transfer from the UI."""
        if transfer_id in self.transfers:
            del self.transfers[transfer_id]

        if transfer_id in self.transfer_widgets:
            # Remove from the UI
            transfer_widget = self.transfer_widgets[transfer_id]["container"]
            self.transfer_list.children = tuple(
                c for c in self.transfer_list.children if c != transfer_widget
            )
            del self.transfer_widgets[transfer_id]

    def _update_transfer(self, transfer: FileTransfer):
        """Update a transfer in the UI."""
        if transfer.transfer_id not in self.transfer_widgets:
            return

        widgets = self.transfer_widgets[transfer.transfer_id]

        # Update progress
        widgets["progress"].value = transfer.progress * 100

        # Update status
        status_text = transfer.status.replace("_", " ").title()
        if transfer.error:
            status_text = f"<span style='color: red;'>{status_text}: {transfer.error}</span>"
        widgets["status"].value = status_text

        # Update speed
        if transfer.speed > 0:
            speed_text = f"{self._format_speed(transfer.speed)}"
            if transfer.status == "in_progress":
                # Estimate time remaining
                remaining_bytes = (1 - transfer.progress) * transfer.size
                if transfer.speed > 0:
                    seconds = remaining_bytes / transfer.speed
                    speed_text += f" - {self._format_time(seconds)} remaining"
            widgets["speed"].value = speed_text

        # Update button states
        widgets["cancel_button"].disabled = transfer.status in ["completed", "failed", "cancelled"]
        widgets["open_button"].disabled = (
            transfer.status != "completed" or transfer.direction != "receive"
        )

        # Update progress bar style
        if transfer.status == "completed":
            widgets["progress"].bar_style = "success"
        elif transfer.status in ["failed", "cancelled"]:
            widgets["progress"].bar_style = "danger"
        else:
            widgets["progress"].bar_style = "info"

    def _start_transfer(self, transfer_id: str):
        """Start a file transfer."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]
        transfer.status = "in_progress"
        transfer.start_time = datetime.now()

        # Update the UI
        self._update_transfer(transfer)

        # Start the actual transfer (this would be an async operation)
        asyncio.create_task(self._do_transfer(transfer_id))

    async def _do_transfer(self, transfer_id: str):
        """Perform the actual file transfer (simulated)."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]
        chunk_size = 1024 * 1024  # 1MB chunks
        total_chunks = (transfer.size + chunk_size - 1) // chunk_size

        try:
            for i in range(total_chunks):
                # Simulate transfer delay
                await asyncio.sleep(0.1)

                # Update progress
                chunk_start = i * chunk_size
                chunk_end = min((i + 1) * chunk_size, transfer.size)
                transfer.progress = chunk_end / transfer.size

                # Update speed (simulated)
                if transfer.start_time:
                    elapsed = (datetime.now() - transfer.start_time).total_seconds()
                    if elapsed > 0:
                        transfer.speed = chunk_end / elapsed

                # Update the UI
                self._update_transfer(transfer)

                # Check for cancellation
                if transfer_id not in self.transfers:
                    return

            # Transfer complete
            transfer.status = "completed"
            transfer.end_time = datetime.now()

        except Exception as e:
            transfer.status = "failed"
            transfer.error = str(e)
            transfer.end_time = datetime.now()

        # Final update
        self._update_transfer(transfer)

    def _on_cancel_transfer(self, transfer_id: str):
        """Handle transfer cancellation."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]
        transfer.status = "cancelled"
        transfer.end_time = datetime.now()

        # Update the UI
        self._update_transfer(transfer)

        # TODO: Actually cancel the transfer in the P2P manager
        # self.p2p_manager.cancel_transfer(transfer_id)

    def _on_file_offer(self, peer_id: str, transfer_id: str, filename: str, size: int):
        """Handle incoming file offer."""
        # Create a transfer object
        transfer = FileTransfer(
            transfer_id=transfer_id,
            filename=filename,
            size=size,
            peer_id=peer_id,
            direction="receive",
            status="pending",
        )

        # Add to the UI
        self._add_transfer(transfer)

        # Show accept/reject dialog
        self._show_file_offer_dialog(transfer)

    def _show_file_offer_dialog(self, transfer: FileTransfer):
        """Show a dialog to accept/reject an incoming file."""
        dialog = widgets.VBox(
            [
                widgets.HTML(f"<h4>Incoming File</h4>"),
                widgets.HTML(
                    f"<p><b>{transfer.filename}</b> ({self._format_size(transfer.size)})</p>"
                ),
                widgets.HTML(f"<p>From: {transfer.peer_id}</p>"),
                widgets.HBox(
                    [
                        widgets.Button(description="Accept", button_style="success"),
                        widgets.Button(description="Reject", button_style="danger"),
                    ]
                ),
            ]
        )

        def on_accept(_):
            # Accept the file
            self.p2p_manager.accept_file(transfer.transfer_id)
            transfer.status = "in_progress"
            transfer.start_time = datetime.now()
            self._update_transfer(transfer)
            dialog.close()

            # Start receiving the file
            asyncio.create_task(self._do_transfer(transfer.transfer_id))

        def on_reject(_):
            # Reject the file
            self.p2p_manager.reject_file(transfer.transfer_id)
            transfer.status = "rejected"
            self._update_transfer(transfer)
            dialog.close()

            # Remove the transfer after a delay
            asyncio.get_event_loop().call_later(5, self._remove_transfer, transfer.transfer_id)

        dialog.children[3].children[0].on_click(on_accept)
        dialog.children[3].children[1].on_click(on_reject)

        display(dialog)

    def _on_file_chunk(self, transfer_id: str, chunk_size: int):
        """Handle file chunk received/uploaded."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]

        # Update progress based on chunk size
        if transfer.size > 0:
            transfer.progress = min(1.0, transfer.progress + (chunk_size / transfer.size))

            # Update speed
            if transfer.start_time:
                elapsed = (datetime.now() - transfer.start_time).total_seconds()
                if elapsed > 0:
                    transfer.speed = (transfer.progress * transfer.size) / elapsed

        # Update the UI
        self._update_transfer(transfer)

    def _on_file_complete(self, transfer_id: str):
        """Handle file transfer completion."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]
        transfer.status = "completed"
        transfer.progress = 1.0
        transfer.end_time = datetime.now()

        # Update the UI
        self._update_transfer(transfer)

    def _on_file_error(self, transfer_id: str, error: str):
        """Handle file transfer error."""
        if transfer_id not in self.transfers:
            return

        transfer = self.transfers[transfer_id]
        transfer.status = "failed"
        transfer.error = error
        transfer.end_time = datetime.now()

        # Update the UI
        self._update_transfer(transfer)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format file size in a human-readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    @staticmethod
    def _format_speed(bytes_per_sec: float) -> str:
        """Format transfer speed in a human-readable format."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if bytes_per_sec < 1024.0:
                return f"{bytes_per_sec:.1f} {unit}"
            bytes_per_sec /= 1024.0
        return f"{bytes_per_sec:.1f} TB/s"

    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format time in a human-readable format."""
        if seconds < 1:
            return "<1s"

        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)

        parts = []
        if h > 0:
            parts.append(f"{int(h)}h")
        if m > 0 or h > 0:
            parts.append(f"{int(m)}m")
        parts.append(f"{int(s)}s")

        return " ".join(parts[:2])  # Show at most two units


def create_file_transfer_manager(p2p_manager):
    """Create and display a file transfer manager.

    Args:
        p2p_manager: Instance of P2PManager

    Returns:
        FileTransferManager: The created file transfer manager instance
    """
    manager = FileTransferManager(p2p_manager)
    manager.display()
    return manager
