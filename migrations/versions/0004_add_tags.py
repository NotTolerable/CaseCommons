"""add tags and associations

Revision ID: 0004_add_tags
Revises: 0003_add_account_applications
Create Date: 2025-01-18 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0004_add_tags'
down_revision = '0003_add_account_applications'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'tag',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    op.create_table(
        'report_tags',
        sa.Column('report_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['report_id'], ['report.id'], ),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], ),
        sa.PrimaryKeyConstraint('report_id', 'tag_id')
    )
    op.create_table(
        'discussion_tags',
        sa.Column('discussion_id', sa.Integer(), nullable=False),
        sa.Column('tag_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['discussion_id'], ['discussion.id'], ),
        sa.ForeignKeyConstraint(['tag_id'], ['tag.id'], ),
        sa.PrimaryKeyConstraint('discussion_id', 'tag_id')
    )


def downgrade():
    op.drop_table('discussion_tags')
    op.drop_table('report_tags')
    op.drop_table('tag')
