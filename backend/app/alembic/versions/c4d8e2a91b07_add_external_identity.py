"""Add external identity links and optional passwords

Revision ID: c4d8e2a91b07
Revises: fe56fa70289e
Create Date: 2026-11-20 13:30:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision = 'c4d8e2a91b07'
down_revision = 'fe56fa70289e'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('user', 'hashed_password', existing_type=sa.String(), nullable=True)
    op.create_table(
        'external_identity',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('identity_type', sa.String(length=32), nullable=False),
        sa.Column('provider', sa.String(length=64), nullable=False),
        sa.Column('subject', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint(
            'identity_type',
            'provider',
            'subject',
            name='uq_external_identity_subject',
        ),
    )
    op.create_index(
        'ix_external_identity_user_id', 'external_identity', ['user_id'], unique=False
    )


def downgrade():
    op.drop_index('ix_external_identity_user_id', table_name='external_identity')
    op.drop_table('external_identity')
    op.execute(
        "UPDATE \"user\" SET hashed_password = '' WHERE hashed_password IS NULL"
    )
    op.alter_column('user', 'hashed_password', existing_type=sa.String(), nullable=False)
