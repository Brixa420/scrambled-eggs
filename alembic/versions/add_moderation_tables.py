"""Add moderation tables

Revision ID: 1a2b3c4d5e6f
Revises: <previous_migration_id>
Create Date: 2025-09-29 15:23:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1a2b3c4d5e6f'
down_revision = '<previous_migration_id>'
branch_labels = None
depends_on = None

def upgrade():
    # Create enums first
    content_type = sa.Enum('image', 'video', 'text', 'stream', 'profile', 'comment', name='contenttype')
    violation_type = sa.Enum(
        'csam', 'bestiality', 'violence', 'hate_speech', 'harassment', 
        'nudity', 'self_harm', 'spam', 'copyright', 'other', 
        name='violationtype'
    )
    moderation_action = sa.Enum(
        'warning', 'takedown', 'suspension', 'ban', 'no_action', 'under_review',
        name='moderationaction'
    )
    moderation_status = sa.Enum(
        'pending', 'in_review', 'resolved', 'appealed', 'rejected',
        name='moderationstatus'
    )
    
    # Create the enums in the database
    content_type.create(op.get_bind(), checkfirst=True)
    violation_type.create(op.get_bind(), checkfirst=True)
    moderation_action.create(op.get_bind(), checkfirst=True)
    moderation_status.create(op.get_bind(), checkfirst=True)
    
    # Create content_violations table
    op.create_table('content_violations',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('content_id', sa.String(length=255), nullable=False, index=True),
        sa.Column('content_type', content_type, nullable=False),
        sa.Column('content_url', sa.String(length=512), nullable=True),
        sa.Column('content_preview', sa.Text(), nullable=True),
        sa.Column('violation_type', violation_type, nullable=False),
        sa.Column('confidence_score', sa.Integer(), nullable=False),
        sa.Column('detected_objects', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('violation_details', postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('status', moderation_status, server_default='pending', nullable=False),
        sa.Column('action_taken', moderation_action, server_default='under_review', nullable=True),
        sa.Column('action_details', sa.Text(), nullable=True),
        sa.Column('detected_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('reviewed_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create moderation_reviews table
    op.create_table('moderation_reviews',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('violation_id', sa.Integer(), nullable=False),
        sa.Column('moderator_id', sa.Integer(), nullable=False),
        sa.Column('decision', moderation_action, nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('is_confirmed', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['violation_id'], ['content_violations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['moderator_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create moderation_appeals table
    op.create_table('moderation_appeals',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('violation_id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('status', moderation_status, server_default='pending', nullable=False),
        sa.Column('resolution', sa.Text(), nullable=True),
        sa.Column('resolved_by', sa.Integer(), nullable=True),
        sa.Column('submitted_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['violation_id'], ['content_violations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resolved_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('violation_id')
    )
    
    # Create user_warnings table
    op.create_table('user_warnings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, index=True),
        sa.Column('issued_by', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('violation_type', violation_type, nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('content_id', sa.String(length=255), nullable=True),
        sa.Column('content_type', content_type, nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['issued_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create user_suspensions table
    op.create_table('user_suspensions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, unique=True, index=True),
        sa.Column('issued_by', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, index=True),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('violation_ids', postgresql.ARRAY(sa.Integer()), server_default='{}', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('lifted_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['issued_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create user_bans table
    op.create_table('user_bans',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, unique=True, index=True),
        sa.Column('issued_by', sa.Integer(), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False, index=True),
        sa.Column('is_permanent', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('violation_ids', postgresql.ARRAY(sa.Integer()), server_default='{}', nullable=False),
        sa.Column('previous_bans', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('lifted_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['issued_by'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create content_filters table
    op.create_table('content_filters',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False, index=True),
        sa.Column('filter_name', sa.String(length=100), nullable=False),
        sa.Column('filter_type', sa.String(length=50), nullable=False),
        sa.Column('filter_value', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'filter_type', 'filter_value', name='ix_content_filters_user_type_value')
    )
    
    # Create moderation_settings table with default values
    op.create_table('moderation_settings',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('auto_mod_enabled', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('auto_remove_csam', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('auto_remove_bestiality', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('auto_remove_violence', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('warnings_before_suspension', sa.Integer(), server_default='3', nullable=False),
        sa.Column('suspensions_before_ban', sa.Integer(), server_default='3', nullable=False),
        sa.Column('first_suspension_days', sa.Integer(), server_default='1', nullable=False),
        sa.Column('second_suspension_days', sa.Integer(), server_default='7', nullable=False),
        sa.Column('third_suspension_days', sa.Integer(), server_default='30', nullable=False),
        sa.Column('notify_on_violation', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('notify_on_appeal', sa.Boolean(), server_default='true', nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=sa.text('now()'), onupdate=sa.text('now()'), nullable=False),
        sa.Column('updated_by', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['updated_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Insert default moderation settings
    op.execute("""
        INSERT INTO moderation_settings (
            id, auto_mod_enabled, auto_remove_csam, auto_remove_bestiality, 
            auto_remove_violence, warnings_before_suspension, suspensions_before_ban,
            first_suspension_days, second_suspension_days, third_suspension_days,
            notify_on_violation, notify_on_appeal, updated_by
        ) VALUES (
            1, true, true, true, false, 3, 3, 1, 7, 30, true, true, NULL
        )
    """)
    
    # Create indexes
    op.create_index('ix_content_violations_user_id', 'content_violations', ['user_id'])
    op.create_index('ix_moderation_reviews_violation_id', 'moderation_reviews', ['violation_id'])
    op.create_index('ix_moderation_reviews_moderator_id', 'moderation_reviews', ['moderator_id'])
    op.create_index('ix_moderation_appeals_user_id', 'moderation_appeals', ['user_id'])
    op.create_index('ix_moderation_appeals_resolved_by', 'moderation_appeals', ['resolved_by'])
    op.create_index('ix_user_warnings_issued_by', 'user_warnings', ['issued_by'])


def downgrade():
    # Drop tables in reverse order of creation
    op.drop_table('moderation_settings')
    op.drop_table('content_filters')
    op.drop_table('user_bans')
    op.drop_table('user_suspensions')
    op.drop_table('user_warnings')
    op.drop_table('moderation_appeals')
    op.drop_table('moderation_reviews')
    op.drop_table('content_violations')
    
    # Drop enums
    content_type = sa.Enum(name='contenttype')
    violation_type = sa.Enum(name='violationtype')
    moderation_action = sa.Enum(name='moderationaction')
    moderation_status = sa.Enum(name='moderationstatus')
    
    content_type.drop(op.get_bind())
    violation_type.drop(op.get_bind())
    moderation_action.drop(op.get_bind())
    moderation_status.drop(op.get_bind())
