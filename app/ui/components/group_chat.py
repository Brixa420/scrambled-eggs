"""
Group Chat Component

Provides a user interface for group messaging in the P2P network.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Optional

import ipywidgets as widgets
from IPython.display import clear_output, display


@dataclass
class GroupMessage:
    """Represents a message in a group chat."""

    message_id: str
    sender_id: str
    sender_name: str
    content: str
    timestamp: datetime
    status: str = "sent"  # 'sending', 'sent', 'delivered', 'read', 'failed'
    is_own: bool = False


@dataclass
class GroupInfo:
    """Represents a group chat."""

    group_id: str
    name: str
    members: Dict[str, str]  # member_id -> member_name
    created_at: datetime
    is_admin: bool = False
    unread_count: int = 0


class GroupChatManager:
    """Manages group chats in the UI."""

    def __init__(self, p2p_manager, on_group_select: Optional[Callable[[str], None]] = None):
        """Initialize the group chat manager.

        Args:
            p2p_manager: Instance of P2PManager
            on_group_select: Callback when a group is selected
        """
        self.p2p_manager = p2p_manager
        self.on_group_select = on_group_select
        self.groups: Dict[str, GroupInfo] = {}
        self.messages: Dict[str, List[GroupMessage]] = {}  # group_id -> list of messages
        self._selected_group_id: Optional[str] = None
        self._init_ui()

        # Register group message handler
        self.p2p_manager.on_group_message(self._on_group_message)

        # Load initial groups
        self.refresh_groups()

    def _init_ui(self):
        """Initialize the UI components."""
        # Group list
        self.group_list = widgets.Select(
            options=[], description="Groups:", layout={"width": "300px", "height": "300px"}
        )

        # Create group button
        self.create_group_button = widgets.Button(
            description="New Group", icon="plus", tooltip="Create a new group chat"
        )
        self.create_group_button.on_click(self._on_create_group_click)

        # Group info
        self.group_name_label = widgets.HTML("<h3>No group selected</h3>")
        self.member_list = widgets.HTML("<p>Members: None</p>")

        # Message display
        self.message_display = widgets.Output(layout={"height": "400px", "overflow_y": "auto"})

        # Message input
        self.message_input = widgets.Textarea(
            placeholder="Type a message...", layout={"width": "100%", "height": "80px"}
        )

        # Send button
        self.send_button = widgets.Button(
            description="Send", button_style="primary", tooltip="Send message"
        )
        self.send_button.on_click(self._on_send_click)

        # Message controls
        self.attachment_button = widgets.Button(
            icon="paperclip", tooltip="Attach file", layout={"width": "40px"}
        )
        self.attachment_button.on_click(self._on_attachment_click)

        # Layout
        self.group_list_panel = widgets.VBox(
            [
                widgets.HBox([widgets.HTML("<h3>Groups</h3>"), self.create_group_button]),
                self.group_list,
            ],
            layout={"width": "350px"},
        )

        self.chat_panel = widgets.VBox(
            [
                self.group_name_label,
                self.member_list,
                self.message_display,
                widgets.HBox([self.attachment_button, self.message_input, self.send_button]),
            ],
            layout={"width": "100%"},
        )

        self.container = widgets.HBox([self.group_list_panel, self.chat_panel])

        # Event handlers
        self.group_list.observe(self._on_group_selected, names="value")
        self.message_input.on_submit(self._on_send_click)

    def display(self):
        """Display the group chat manager."""
        display(self.container)

    def refresh_groups(self):
        """Refresh the list of groups."""
        # Get groups from the P2P manager
        groups_data = self.p2p_manager.get_groups()

        # Update groups
        self.groups = {}
        for group_id, group_data in groups_data.items():
            self.groups[group_id] = GroupInfo(
                group_id=group_id,
                name=group_data.get("name", f"Group {group_id[:6]}"),
                members=group_data.get("members", {}),
                created_at=group_data.get("created_at", datetime.now()),
                is_admin=group_data.get("is_admin", False),
                unread_count=group_data.get("unread_count", 0),
            )

        # Update the group list
        self._update_group_list()

        # If no group is selected, select the first one
        if not self._selected_group_id and self.groups:
            self._select_group(next(iter(self.groups.keys())))

    def _update_group_list(self):
        """Update the group list widget."""
        group_items = []
        selected_index = None

        for i, (group_id, group) in enumerate(self.groups.items()):
            # Format the group name with unread count
            unread = f" ({group.unread_count})" if group.unread_count > 0 else ""
            display_name = f"{group.name}{unread}"

            # Add to the list
            group_items.append((display_name, group_id))

            # Track the selected group
            if group_id == self._selected_group_id:
                selected_index = i

        # Update the group list
        self.group_list.options = group_items

        # Restore the selected group
        if selected_index is not None and selected_index < len(group_items):
            self.group_list.index = selected_index

    def _select_group(self, group_id: str):
        """Select a group and load its messages."""
        if group_id not in self.groups:
            return

        self._selected_group_id = group_id
        group = self.groups[group_id]

        # Update the UI
        self.group_name_label.value = f"<h3>{group.name}</h3>"

        # Update member list
        members = ", ".join([name for name in group.members.values()])
        self.member_list.value = f'<p>Members: {members or "None"}</p>'

        # Load messages
        self._load_messages(group_id)

        # Mark as read
        self._mark_as_read(group_id)

        # Notify the callback
        if self.on_group_select:
            self.on_group_select(group_id)

    def _load_messages(self, group_id: str):
        """Load messages for a group."""
        if group_id not in self.messages:
            # Load messages from the P2P manager
            messages_data = self.p2p_manager.get_group_messages(group_id)

            # Convert to GroupMessage objects
            self.messages[group_id] = []
            for msg_data in messages_data:
                self.messages[group_id].append(
                    GroupMessage(
                        message_id=msg_data["message_id"],
                        sender_id=msg_data["sender_id"],
                        sender_name=msg_data.get("sender_name", "Unknown"),
                        content=msg_data["content"],
                        timestamp=msg_data["timestamp"],
                        status=msg_data.get("status", "sent"),
                        is_own=msg_data.get("is_own", False),
                    )
                )

        # Display the messages
        self._display_messages(group_id)

    def _display_messages(self, group_id: str):
        """Display messages for a group."""
        if group_id not in self.messages:
            return

        with self.message_display:
            clear_output(wait=True)

            for msg in self.messages[group_id]:
                # Format the message
                time_str = msg.timestamp.strftime("%H:%M")

                # Different styles for own vs others' messages
                if msg.is_own:
                    print(f"<div style='text-align: right; margin: 5px;'>")
                    print(
                        f"  <div style='background-color: #e3f2fd; display: inline-block; padding: 8px 12px; border-radius: 15px; max-width: 70%;'>"
                    )
                    print(
                        f"    <div style='font-size: 0.9em; color: #666;'>{msg.sender_name} • {time_str}</div>"
                    )
                    print(f"    <div>{msg.content}</div>")

                    # Show status indicator
                    status_icon = ""
                    if msg.status == "sending":
                        status_icon = "🔄"
                    elif msg.status == "sent":
                        status_icon = "✓"
                    elif msg.status == "delivered":
                        status_icon = "✓✓"
                    elif msg.status == "read":
                        status_icon = "✓✓✓"
                    elif msg.status == "failed":
                        status_icon = "✗"

                    if status_icon:
                        print(
                            f"    <div style='text-align: right; font-size: 0.8em;'>{status_icon}</div>"
                        )

                    print("  </div>")
                    print("</div>")
                else:
                    print(f"<div style='text-align: left; margin: 5px;'>")
                    print(
                        f"  <div><strong>{msg.sender_name}</strong> <span style='font-size: 0.8em; color: #666;'>{time_str}</span></div>"
                    )
                    print(
                        f"  <div style='background-color: #f5f5f5; display: inline-block; padding: 8px 12px; border-radius: 15px; max-width: 70%;'>"
                    )
                    print(f"    {msg.content}")
                    print("  </div>")
                    print("</div>")

            # Auto-scroll to bottom
            display(
                HTML(
                    """
                <script>
                    var element = document.querySelector('.output_scroll');
                    if (element) element.scrollTop = element.scrollHeight;
                </script>
            """
                )
            )
