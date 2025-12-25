"""add upload metadata columns

Revision ID: 0002_add_upload_metadata
Revises: 0001_initial
Create Date: 2025-01-17 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0002_add_upload_metadata'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('report_image', sa.Column('original_name', sa.String(length=255), nullable=True))
    op.add_column('report_image', sa.Column('mime_type', sa.String(length=128), nullable=True))
    op.add_column('report_image', sa.Column('size_bytes', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('report_image', 'size_bytes')
    op.drop_column('report_image', 'mime_type')
    op.drop_column('report_image', 'original_name')
