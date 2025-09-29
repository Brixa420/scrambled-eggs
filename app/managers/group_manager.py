"""
Group Manager

Handles group-related operations including creating, updating, and managing groups.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class GroupMember:
    """Represents a member in a group."""

    user_id: str
    joined_at: str
    role: str = "member"  # 'admin' or 'member'
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Group:
    """Represents a group in the application."""

    group_id: str
    name: str
    description: str = ""
    created_at: str = ""
    created_by: str = ""
    is_public: bool = False
    members: Dict[str, GroupMember] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


class GroupManager:
    """Manages group operations for the application."""

    def __init__(self):
        """Initialize the GroupManager."""
        self.groups: Dict[str, Group] = {}
        logger.info("GroupManager initialized")

    def create_group(
        self, name: str, creator_id: str, description: str = "", is_public: bool = False, **metadata
    ) -> Group:
        """
        Create a new group.

        Args:
            name: Name of the group
            creator_id: ID of the user creating the group
            description: Optional group description
            is_public: Whether the group is public
            **metadata: Additional group metadata

        Returns:
            Group: The newly created group
        """
        group_id = f"group_{uuid.uuid4().hex}"
        created_at = datetime.now().isoformat()

        group = Group(
            group_id=group_id,
            name=name,
            description=description,
            created_at=created_at,
            created_by=creator_id,
            is_public=is_public,
            metadata=metadata,
        )

        # Add creator as the first member and admin
        self.add_member(group_id=group_id, user_id=creator_id, role="admin")

        self.groups[group_id] = group
        logger.info(f"Created group {group_id}: {name}")
        return group

    def get_group(self, group_id: str) -> Optional[Group]:
        """
        Get a group by its ID.

        Args:
            group_id: ID of the group to retrieve

        Returns:
            Optional[Group]: The group if found, None otherwise
        """
        return self.groups.get(group_id)

    def update_group(
        self,
        group_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_public: Optional[bool] = None,
        **metadata,
    ) -> Optional[Group]:
        """
        Update group information.

        Args:
            group_id: ID of the group to update
            name: New name for the group
            description: New description for the group
            is_public: New public/private status
            **metadata: Additional metadata to update

        Returns:
            Optional[Group]: The updated group if found, None otherwise
        """
        if group_id not in self.groups:
            return None

        group = self.groups[group_id]

        if name is not None:
            group.name = name
        if description is not None:
            group.description = description
        if is_public is not None:
            group.is_public = is_public

        # Update metadata
        group.metadata.update(metadata)

        logger.info(f"Updated group {group_id}")
        return group

    def delete_group(self, group_id: str) -> bool:
        """
        Delete a group.

        Args:
            group_id: ID of the group to delete

        Returns:
            bool: True if the group was deleted, False otherwise
        """
        if group_id in self.groups:
            del self.groups[group_id]
            logger.info(f"Deleted group {group_id}")
            return True
        return False

    def add_member(self, group_id: str, user_id: str, role: str = "member", **metadata) -> bool:
        """
        Add a member to a group.

        Args:
            group_id: ID of the group
            user_id: ID of the user to add
            role: Role of the user in the group ('admin' or 'member')
            **metadata: Additional member metadata

        Returns:
            bool: True if the member was added, False otherwise
        """
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]

        # Check if user is already a member
        if user_id in group.members:
            return False

        # Add the new member
        group.members[user_id] = GroupMember(
            user_id=user_id, joined_at=datetime.now().isoformat(), role=role, metadata=metadata
        )

        logger.info(f"Added user {user_id} to group {group_id} as {role}")
        return True

    def remove_member(self, group_id: str, user_id: str) -> bool:
        """
        Remove a member from a group.

        Args:
            group_id: ID of the group
            user_id: ID of the user to remove

        Returns:
            bool: True if the member was removed, False otherwise
        """
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]

        # Don't allow removing the last admin
        if group.members[user_id].role == "admin":
            admin_count = sum(1 for m in group.members.values() if m.role == "admin")
            if admin_count <= 1:
                logger.warning("Cannot remove the last admin from a group")
                return False

        if user_id in group.members:
            del group.members[user_id]
            logger.info(f"Removed user {user_id} from group {group_id}")
            return True

        return False

    def update_member_role(self, group_id: str, user_id: str, role: str, **metadata) -> bool:
        """
        Update a member's role in a group.

        Args:
            group_id: ID of the group
            user_id: ID of the user
            role: New role ('admin' or 'member')
            **metadata: Additional metadata to update

        Returns:
            bool: True if the role was updated, False otherwise
        """
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]

        if user_id not in group.members:
            return False

        member = group.members[user_id]
        member.role = role
        member.metadata.update(metadata)

        logger.info(f"Updated role of user {user_id} in group {group_id} to {role}")
        return True

    def list_groups(self, user_id: Optional[str] = None) -> List[Group]:
        """
        List all groups, optionally filtered by user membership.

        Args:
            user_id: If provided, only return groups this user is a member of

        Returns:
            List of groups
        """
        if user_id is None:
            return list(self.groups.values())

        return [
            group for group in self.groups.values() if user_id in group.members or group.is_public
        ]

    def get_group_members(self, group_id: str) -> List[Dict[str, Any]]:
        """
        Get all members of a group.

        Args:
            group_id: ID of the group

        Returns:
            List of member information dictionaries
        """
        if group_id not in self.groups:
            return []

        group = self.groups[group_id]
        return [
            {
                "user_id": member.user_id,
                "role": member.role,
                "joined_at": member.joined_at,
                **member.metadata,
            }
            for member in group.members.values()
        ]

    def is_member(self, group_id: str, user_id: str) -> bool:
        """
        Check if a user is a member of a group.

        Args:
            group_id: ID of the group
            user_id: ID of the user

        Returns:
            bool: True if the user is a member, False otherwise
        """
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]
        return user_id in group.members or group.is_public

    def is_admin(self, group_id: str, user_id: str) -> bool:
        """
        Check if a user is an admin of a group.

        Args:
            group_id: ID of the group
            user_id: ID of the user

        Returns:
            bool: True if the user is an admin, False otherwise
        """
        if group_id not in self.groups:
            return False

        group = self.groups[group_id]
        return user_id in group.members and group.members[user_id].role == "admin"
