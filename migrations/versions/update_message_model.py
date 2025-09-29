"""Update Message model for new features

Revision ID: 8a2b3c4d5e6f
Revises: 7z9y8x7w6v5u
Create Date: 2025-09-29 01:51:00.000000

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "8a2b3c4d5e6f"
down_revision = "7z9y8x7w6v5u"
branch_labels = None
depends_on = None


def upgrade():
    # Add new columns for message editing
    op.add_column(
        "messages", sa.Column("edited", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("messages", sa.Column("edited_at", sa.DateTime(), nullable=True))
    op.add_column("messages", sa.Column("original_content", sa.Text(), nullable=True))

    # Add columns for message deletion
    op.add_column(
        "messages", sa.Column("deleted", sa.Boolean(), server_default="false", nullable=False)
    )
    op.add_column("messages", sa.Column("deleted_at", sa.DateTime(), nullable=True))

    # Add columns for reactions
    op.add_column(
        "messages", sa.Column("reactions", postgresql.JSONB(), server_default="{}", nullable=True)
    )

    # Add columns for mentions
    op.add_column(
        "messages",
        sa.Column(
            "mentions", postgresql.ARRAY(postgresql.UUID()), server_default="{}", nullable=True
        ),
    )

    # Add index for faster message search
    op.create_index(
        "ix_messages_search",
        "messages",
        ["content"],
        postgresql_using="gin",
        postgresql_ops={"content": "gin_trgm_ops"},
        postgresql_where=sa.text("deleted = false"),
    )

    # Create message_edits table for edit history
    op.create_table(
        "message_edits",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "message_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("previous_content", sa.Text(), nullable=False),
        sa.Column("edited_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("edited_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("reason", sa.String(255), nullable=True),
        sa.Index("ix_message_edits_message_id", "message_id"),
        sa.Index("ix_message_edits_edited_at", "edited_at"),
    )

    # Create message_reactions table for tracking reactions
    op.create_table(
        "message_reactions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "message_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reaction", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.UniqueConstraint("message_id", "user_id", "reaction", name="uq_message_user_reaction"),
        sa.Index("ix_message_reactions_message_id", "message_id"),
        sa.Index("ix_message_reactions_user_id", "user_id"),
    )

    # Create message_mentions table for tracking mentions
    op.create_table(
        "message_mentions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "message_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("mentioned_user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("mentioned_at", sa.DateTime(), server_default=sa.text("now()"), nullable=False),
        sa.Column("read", sa.Boolean(), server_default="false", nullable=False),
        sa.Index("ix_message_mentions_message_id", "message_id"),
        sa.Index("ix_message_mentions_mentioned_user_id", "mentioned_user_id"),
    )


def downgrade():
    # Drop tables and columns in reverse order
    op.drop_table("message_mentions")
    op.drop_table("message_reactions")
    op.drop_table("message_edits")
    op.drop_index("ix_messages_search", table_name="messages")
    op.drop_column("messages", "mentions")
    op.drop_column("messages", "reactions")
    op.drop_column("messages", "deleted_at")
    op.drop_column("messages", "deleted")
    op.drop_column("messages", "original_content")
    op.drop_column("messages", "edited_at")
    op.drop_column("messages", "edited")
