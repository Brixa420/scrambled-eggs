"""
Additional models for message-related features.
"""

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

from ..extensions import db


class MessageEdit(db.Model):
    """Tracks edits made to messages."""

    __tablename__ = "message_edits"

    id = Column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=db.text("gen_random_uuid()")
    )
    message_id = Column(
        PG_UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    previous_content = Column(Text, nullable=False)
    edited_by = Column(PG_UUID(as_uuid=True), nullable=False)
    edited_at = Column(DateTime, server_default=db.text("now()"), nullable=False)
    reason = Column(String(255), nullable=True)

    __table_args__ = (
        Index("ix_message_edits_message_id", "message_id"),
        Index("ix_message_edits_edited_at", "edited_at"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": str(self.id),
            "message_id": str(self.message_id),
            "previous_content": self.previous_content,
            "edited_by": str(self.edited_by),
            "edited_at": self.edited_at.isoformat(),
            "reason": self.reason,
        }


class MessageReaction(db.Model):
    """Tracks reactions to messages."""

    __tablename__ = "message_reactions"

    id = Column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=db.text("gen_random_uuid()")
    )
    message_id = Column(
        PG_UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    user_id = Column(PG_UUID(as_uuid=True), nullable=False)
    reaction = Column(String(32), nullable=False)  # Emoji or reaction code
    created_at = Column(DateTime, server_default=db.text("now()"), nullable=False)

    __table_args__ = (
        db.UniqueConstraint("message_id", "user_id", "reaction", name="uq_message_user_reaction"),
        Index("ix_message_reactions_message_id", "message_id"),
        Index("ix_message_reactions_user_id", "user_id"),
    )

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": str(self.id),
            "message_id": str(self.message_id),
            "user_id": str(self.user_id),
            "reaction": self.reaction,
            "created_at": self.created_at.isoformat(),
        }


class MessageMention(db.Model):
    """Tracks user mentions in messages."""

    __tablename__ = "message_mentions"

    id = Column(
        PG_UUID(as_uuid=True), primary_key=True, server_default=db.text("gen_random_uuid()")
    )
    message_id = Column(
        PG_UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), nullable=False
    )
    mentioned_user_id = Column(PG_UUID(as_uuid=True), nullable=False)
    mentioned_at = Column(DateTime, server_default=db.text("now()"), nullable=False)
    read = Column(db.Boolean, server_default="false", nullable=False)

    __table_args__ = (
        Index("ix_message_mentions_message_id", "message_id"),
        Index("ix_message_mentions_mentioned_user_id", "mentioned_user_id"),
    )

    def mark_as_read(self):
        """Mark the mention as read."""
        self.read = True
        return self

    def to_dict(self) -> dict:
        """Convert to dictionary for API response."""
        return {
            "id": str(self.id),
            "message_id": str(self.message_id),
            "mentioned_user_id": str(self.mentioned_user_id),
            "mentioned_at": self.mentioned_at.isoformat(),
            "read": self.read,
        }
