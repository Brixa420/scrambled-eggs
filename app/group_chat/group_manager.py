"""
Group Chat Manager for Brixa
Handles group creation, management, and secure group messaging.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ..p2p.p2p_manager import P2PManager
from ..security.scrambled_eggs_crypto import ScrambledEggsCrypto


@dataclass
class GroupMember:
    """Represents a member in a group chat."""

    peer_id: str
    is_admin: bool = False
    joined_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)


@dataclass
class GroupMessage:
    """Represents a message in a group chat."""

    message_id: str
    sender_id: str
    content: str
    timestamp: datetime
    encrypted: bool = True
    edited: bool = False
    deleted: bool = False
    replies_to: Optional[str] = None
    reactions: Dict[str, List[str]] = field(default_factory=dict)  # emoji -> list of peer_ids


class GroupChat:
    """Represents a group chat with multiple participants."""

    def __init__(self, group_id: str, name: str, creator_id: str):
        self.group_id = group_id
        self.name = name
        self.creator_id = creator_id
        self.created_at = datetime.utcnow()
        self.members: Dict[str, GroupMember] = {}  # peer_id -> GroupMember
        self.messages: List[GroupMessage] = []
        self.admins: Set[str] = {creator_id}
        self.encryption_key: Optional[bytes] = None
        self.is_private: bool = True
        self.topic: str = ""
        self.avatar: Optional[bytes] = None
        self.muted: bool = False

        # Add creator as first member
        self.add_member(creator_id, is_admin=True)

    def add_member(self, peer_id: str, is_admin: bool = False) -> bool:
        """Add a member to the group."""
        if peer_id in self.members:
            return False

        self.members[peer_id] = GroupMember(
            peer_id=peer_id, is_admin=is_admin, joined_at=datetime.utcnow()
        )

        if is_admin:
            self.admins.add(peer_id)

        return True

    def remove_member(self, peer_id: str) -> bool:
        """Remove a member from the group."""
        if peer_id not in self.members:
            return False

        self.members.pop(peer_id, None)
        self.admins.discard(peer_id)
        return True

    def promote_to_admin(self, peer_id: str) -> bool:
        """Promote a member to admin."""
        if peer_id not in self.members:
            return False

        self.members[peer_id].is_admin = True
        self.admins.add(peer_id)
        return True

    def add_message(self, sender_id: str, content: str, encrypted: bool = True) -> GroupMessage:
        """Add a new message to the group chat."""
        if sender_id not in self.members:
            raise ValueError("Only group members can send messages")

        message = GroupMessage(
            message_id=f"msg_{len(self.messages) + 1}_{datetime.utcnow().timestamp()}",
            sender_id=sender_id,
            content=content,
            timestamp=datetime.utcnow(),
            encrypted=encrypted,
        )

        self.messages.append(message)
        return message

    def get_messages(
        self, limit: int = 100, before: Optional[datetime] = None
    ) -> List[GroupMessage]:
        """Get recent messages from the group chat."""
        messages = self.messages

        if before:
            messages = [m for m in messages if m.timestamp < before]

        return messages[-limit:]

    def add_reaction(self, message_id: str, peer_id: str, emoji: str) -> bool:
        """Add a reaction to a message."""
        for message in self.messages:
            if message.message_id == message_id:
                if emoji not in message.reactions:
                    message.reactions[emoji] = []
                if peer_id not in message.reactions[emoji]:
                    message.reactions[emoji].append(peer_id)
                return True
        return False


class GroupManager:
    """Manages all group chats in the application."""

    def __init__(self, p2p_manager: P2PManager, crypto: ScrambledEggsCrypto):
        self.p2p = p2p_manager
        self.crypto = crypto
        self.groups: Dict[str, GroupChat] = {}
        self.logger = logging.getLogger(__name__)

        # Register message handlers
        self.p2p.register_message_handler("group_create", self._handle_group_create)
        self.p2p.register_message_handler("group_join", self._handle_group_join)
        self.p2p.register_message_handler("group_leave", self._handle_group_leave)
        self.p2p.register_message_handler("group_message", self._handle_group_message)
        self.p2p.register_message_handler("group_update", self._handle_group_update)

    async def create_group(
        self, name: str, peer_ids: List[str], is_private: bool = True
    ) -> GroupChat:
        """Create a new group chat."""
        group_id = f"group_{len(self.groups) + 1}_{int(datetime.utcnow().timestamp())}"
        group = GroupChat(group_id, name, self.p2p.peer_id)
        group.is_private = is_private

        # Add initial members
        for peer_id in peer_ids:
            group.add_member(peer_id)

        # Generate encryption key for the group
        group.encryption_key = self.crypto.generate_key()

        # Store the group
        self.groups[group_id] = group

        # Notify members
        await self._broadcast_group_update(
            group_id,
            "group_created",
            {
                "group_id": group_id,
                "name": name,
                "creator_id": self.p2p.peer_id,
                "members": peer_ids + [self.p2p.peer_id],
                "is_private": is_private,
            },
        )

        return group

    async def join_group(self, group_id: str, invite_code: Optional[str] = None) -> bool:
        """Join an existing group."""
        if group_id not in self.groups:
            # Request group info from peers
            await self.p2p.broadcast(
                {"type": "group_info_request", "group_id": group_id, "invite_code": invite_code}
            )
            return False

        group = self.groups[group_id]

        # Check if already a member
        if self.p2p.peer_id in group.members:
            return True

        # Add to group
        group.add_member(self.p2p.peer_id)

        # Notify other members
        await self._broadcast_group_update(
            group_id, "member_joined", {"group_id": group_id, "peer_id": self.p2p.peer_id}
        )

        return True

    async def leave_group(self, group_id: str) -> bool:
        """Leave a group."""
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]

        # Remove from members
        group.remove_member(self.p2p.peer_id)

        # If no members left, delete the group
        if not group.members:
            del self.groups[group_id]
        else:
            # Notify other members
            await self._broadcast_group_update(
                group_id, "member_left", {"group_id": group_id, "peer_id": self.p2p.peer_id}
            )

        return True

    async def send_message(self, group_id: str, content: str) -> Optional[GroupMessage]:
        """Send a message to a group."""
        if group_id not in self.groups:
            return None

        group = self.groups[group_id]

        # Encrypt the message for the group
        encrypted_content = self.crypto.encrypt(content.encode("utf-8"), group.encryption_key)

        # Add to local message history
        message = group.add_message(
            sender_id=self.p2p.peer_id, content=encrypted_content, encrypted=True
        )

        # Broadcast to group members
        await self._broadcast_group_update(
            group_id,
            "new_message",
            {
                "message_id": message.message_id,
                "sender_id": self.p2p.peer_id,
                "content": encrypted_content,
                "timestamp": message.timestamp.isoformat(),
                "encrypted": True,
            },
        )

        return message

    async def _broadcast_group_update(self, group_id: str, update_type: str, data: Dict[str, Any]):
        """Broadcast a group update to all members."""
        if group_id not in self.groups:
            return

        group = self.groups[group_id]

        # Prepare update message
        message = {
            "type": "group_update",
            "group_id": group_id,
            "update_type": update_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Send to all group members
        for member_id in group.members:
            if member_id != self.p2p.peer_id:  # Don't send to self
                await self.p2p.send_message(member_id, message)

    # Message handlers

    async def _handle_group_create(self, data: Dict[str, Any]):
        """Handle group creation request."""
        group_id = data.get("group_id")
        name = data.get("name")
        creator_id = data.get("creator_id")

        if not all([group_id, name, creator_id]):
            return

        # Create the group if it doesn't exist
        if group_id not in self.groups:
            group = GroupChat(group_id, name, creator_id)
            self.groups[group_id] = group

            # Add initial members
            for member_id in data.get("members", []):
                group.add_member(member_id, member_id == creator_id)

    async def _handle_group_join(self, data: Dict[str, Any]):
        """Handle group join request."""
        group_id = data.get("group_id")
        peer_id = data.get("peer_id")

        if not all([group_id, peer_id]) or group_id not in self.groups:
            return

        group = self.groups[group_id]

        # Add the peer to the group
        if peer_id not in group.members:
            group.add_member(peer_id)

            # Notify other members
            await self._broadcast_group_update(
                group_id, "member_joined", {"group_id": group_id, "peer_id": peer_id}
            )

    async def _handle_group_leave(self, data: Dict[str, Any]):
        """Handle group leave request."""
        group_id = data.get("group_id")
        peer_id = data.get("peer_id")

        if not all([group_id, peer_id]) or group_id not in self.groups:
            return

        group = self.groups[group_id]

        # Remove the peer from the group
        if peer_id in group.members:
            group.remove_member(peer_id)

            # Notify other members
            await self._broadcast_group_update(
                group_id, "member_left", {"group_id": group_id, "peer_id": peer_id}
            )

    async def _handle_group_message(self, data: Dict[str, Any]):
        """Handle incoming group message."""
        group_id = data.get("group_id")
        message_data = data.get("message", {})

        if not group_id or group_id not in self.groups:
            return

        group = self.groups[group_id]

        # Verify the sender is a group member
        sender_id = message_data.get("sender_id")
        if not sender_id or sender_id not in group.members:
            return

        # Add the message to the group
        message = group.add_message(
            sender_id=sender_id,
            content=message_data.get("content", ""),
            encrypted=message_data.get("encrypted", True),
        )

        # Notify UI or other components
        if hasattr(self, "on_group_message"):
            await self.on_group_message(group_id, message)

    async def _handle_group_update(self, data: Dict[str, Any]):
        """Handle group update messages."""
        group_id = data.get("group_id")
        update_type = data.get("update_type")
        update_data = data.get("data", {})

        if not all([group_id, update_type]) or group_id not in self.groups:
            return

        group = self.groups[group_id]

        # Handle different update types
        if update_type == "member_joined":
            peer_id = update_data.get("peer_id")
            if peer_id and peer_id not in group.members:
                group.add_member(peer_id)

        elif update_type == "member_left":
            peer_id = update_data.get("peer_id")
            if peer_id and peer_id in group.members:
                group.remove_member(peer_id)

        elif update_type == "new_message":
            # Add message to the group
            message = GroupMessage(
                message_id=update_data.get("message_id", ""),
                sender_id=update_data["sender_id"],
                content=update_data["content"],
                timestamp=datetime.fromisoformat(update_data["timestamp"]),
                encrypted=update_data.get("encrypted", True),
            )
            group.messages.append(message)

            # Notify UI or other components
            if hasattr(self, "on_group_message"):
                await self.on_group_message(group_id, message)

        # Notify UI of the update
        if hasattr(self, "on_group_update"):
            await self.on_group_update(group_id, update_type, update_data)

    # Callback methods (to be implemented by the UI)

    async def on_group_message(self, group_id: str, message: GroupMessage):
        """Called when a new message is received in a group."""

    async def on_group_update(self, group_id: str, update_type: str, data: Dict[str, Any]):
        """Called when a group is updated."""
