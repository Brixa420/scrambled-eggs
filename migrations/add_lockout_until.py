"""
Migration script to add lockout_until column to user_two_factor table.
"""
from datetime import datetime
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_lockout_until'
down_revision = None  # Replace with the previous migration ID
branch_labels = None
depends_on = None

def upgrade():
    """Add lockout_until column to user_two_factor table."""
    # Add the lockout_until column as nullable at first
    op.add_column(
        'user_two_factor',
        sa.Column('lockout_until', sa.DateTime(), nullable=True)
    )
    
    # If you need to perform any data migration, do it here
    # For example, setting default values for existing rows
    # op.execute("""
    #     UPDATE user_two_factor 
    #     SET lockout_until = NULL
    #     WHERE lockout_until IS NULL
    # """)

def downgrade():
    """Remove lockout_until column from user_two_factor table."""
    op.drop_column('user_two_factor', 'lockout_until')
