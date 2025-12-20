"""initial tables"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('username', sa.String(length=80), nullable=False, unique=True),
        sa.Column('email', sa.String(length=120), nullable=False, unique=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('email_verified', sa.Boolean(), default=False),
        sa.Column('role', sa.String(length=20), default='user'),
        sa.Column('status', sa.String(length=20), default='active'),
        sa.Column('created_at', sa.DateTime(), nullable=True)
    )
    op.create_table('report',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('slug', sa.String(length=220), nullable=False),
        sa.Column('body_html', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('updated_by', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('published', sa.Boolean(), default=True)
    )
    op.create_index('ix_report_slug', 'report', ['slug'], unique=True)
    op.create_table('report_image',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('report_id', sa.Integer(), sa.ForeignKey('report.id')),
        sa.Column('file_path', sa.String(length=255), nullable=False),
        sa.Column('uploaded_by', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('created_at', sa.DateTime())
    )
    op.create_table('discussion',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('title', sa.String(length=200), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime())
    )
    op.create_table('comment',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('parent_type', sa.String(length=20), nullable=False),
        sa.Column('parent_id', sa.Integer(), nullable=False),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('created_by', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('is_deleted', sa.Boolean(), default=False)
    )
    op.create_table('email_token',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('token', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime())
    )
    op.create_table('moderation_log',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.Integer(), nullable=False),
        sa.Column('actor_id', sa.Integer(), sa.ForeignKey('user.id')),
        sa.Column('reason', sa.String(length=255)),
        sa.Column('created_at', sa.DateTime())
    )


def downgrade():
    op.drop_table('moderation_log')
    op.drop_table('email_token')
    op.drop_table('comment')
    op.drop_table('discussion')
    op.drop_table('report_image')
    op.drop_index('ix_report_slug', table_name='report')
    op.drop_table('report')
    op.drop_table('user')
