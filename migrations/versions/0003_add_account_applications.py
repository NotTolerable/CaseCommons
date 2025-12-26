"""add account application table

Revision ID: 0003_add_account_applications
Revises: 0002_add_upload_metadata
Create Date: 2025-01-17 01:00:00.000000
"""

from alembic import op
import sqlalchemy as sa
from datetime import datetime


# revision identifiers, used by Alembic.
revision = '0003_add_account_applications'
down_revision = '0002_add_upload_metadata'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'account_application',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('full_name', sa.String(length=200), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=False),
        sa.Column('statement', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('created_at', sa.DateTime(), nullable=True, default=datetime.utcnow),
        sa.Column('decided_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_account_application_email', 'account_application', ['email'])


def downgrade():
    op.drop_index('ix_account_application_email', table_name='account_application')
    op.drop_table('account_application')
