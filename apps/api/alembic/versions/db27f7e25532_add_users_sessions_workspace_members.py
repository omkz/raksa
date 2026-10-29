"""add_users_sessions_workspace_members

Revision ID: db27f7e25532
Revises: 706265f0e0b3
Create Date: 2026-10-29 17:22:04.966710

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'db27f7e25532'
down_revision: str | Sequence[str] | None = '706265f0e0b3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'users',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('github_user_id', sa.BigInteger(), nullable=False),
        sa.Column('github_login', sa.String(length=255), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=True),
        sa.Column('email', sa.String(length=255), nullable=True),
        sa.Column('avatar_url', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_users_github_login'), 'users', ['github_login'], unique=False)
    op.create_index(op.f('ix_users_github_user_id'), 'users', ['github_user_id'], unique=True)

    op.add_column('workspaces', sa.Column('installation_id', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_workspaces_installation_id'), 'workspaces', ['installation_id'], unique=False)

    # Clean up any legacy/orphan owner_id references in workspaces before applying FK constraint
    op.execute("UPDATE workspaces SET owner_id = NULL WHERE owner_id IS NOT NULL AND owner_id NOT IN (SELECT id FROM users)")

    op.create_foreign_key(
        'fk_workspaces_owner_id_users',
        'workspaces',
        'users',
        ['owner_id'],
        ['id'],
        ondelete='SET NULL',
    )

    op.create_table(
        'workspace_members',
        sa.Column('workspace_id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=False),
        sa.Column('role', sa.String(length=32), nullable=False, server_default='owner'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['workspace_id'], ['workspaces.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('workspace_id', 'user_id'),
    )

    op.create_table(
        'user_sessions',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=64), nullable=False),
        sa.Column('active_workspace_id', sa.String(length=64), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('last_active_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['active_workspace_id'], ['workspaces.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_user_sessions_expires_at'), 'user_sessions', ['expires_at'], unique=False)
    op.create_index(op.f('ix_user_sessions_user_id'), 'user_sessions', ['user_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_user_sessions_user_id'), table_name='user_sessions')
    op.drop_index(op.f('ix_user_sessions_expires_at'), table_name='user_sessions')
    op.drop_table('user_sessions')

    op.drop_table('workspace_members')

    op.drop_constraint('fk_workspaces_owner_id_users', 'workspaces', type_='foreignkey')
    op.drop_index(op.f('ix_workspaces_installation_id'), table_name='workspaces')
    op.drop_column('workspaces', 'installation_id')

    op.drop_index(op.f('ix_users_github_user_id'), table_name='users')
    op.drop_index(op.f('ix_users_github_login'), table_name='users')
    op.drop_table('users')
