"""
Room model for chat rooms.
"""

from datetime import datetime

from ..extensions import db


class Room(db.Model):
    """Chat room model."""

    __tablename__ = "rooms"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    is_private = db.Column(db.Boolean, default=False)
    password_hash = db.Column(db.String(256), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    created_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    messages = db.relationship(
        "Message", backref="room", lazy="dynamic", cascade="all, delete-orphan"
    )
    members = db.relationship(
        "RoomMember", backref="room", lazy="dynamic", cascade="all, delete-orphan"
    )

    def set_password(self, password):
        """Set room password."""
        from werkzeug.security import generate_password_hash

        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check room password."""
        from werkzeug.security import check_password_hash

        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def add_member(self, user_id, is_admin=False):
        """Add a member to the room."""
        from .room_member import RoomMember

        # Check if user is already a member
        if not self.members.filter_by(user_id=user_id).first():
            member = RoomMember(room_id=self.id, user_id=user_id, is_admin=is_admin)
            db.session.add(member)
            db.session.commit()
            return True
        return False

    def remove_member(self, user_id):
        """Remove a member from the room."""
        member = self.members.filter_by(user_id=user_id).first()
        if member:
            db.session.delete(member)
            db.session.commit()
            return True
        return False

    def is_member(self, user_id):
        """Check if a user is a member of the room."""
        return self.members.filter_by(user_id=user_id).first() is not None

    def is_admin(self, user_id):
        """Check if a user is an admin of the room."""
        member = self.members.filter_by(user_id=user_id).first()
        return member.is_admin if member else False

    def to_dict(self):
        """Convert room to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "is_private": self.is_private,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "member_count": self.members.count(),
            "message_count": self.messages.count(),
        }

    def __repr__(self):
        return f"<Room {self.name}>"
