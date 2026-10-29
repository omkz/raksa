"""add pr review fields to scan_jobs

Revision ID: 706265f0e0b3
Revises: 10d819eb2769
Create Date: 2026-10-29 16:06:02.831143

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '706265f0e0b3'
down_revision: str | Sequence[str] | None = '10d819eb2769'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scan_jobs', sa.Column('scan_type', sa.String(length=32), server_default='repository', nullable=False))
    op.add_column('scan_jobs', sa.Column('pr_number', sa.Integer(), nullable=True))
    op.add_column('scan_jobs', sa.Column('head_sha', sa.String(length=64), nullable=True))
    op.add_column('scan_jobs', sa.Column('check_run_id', sa.BigInteger(), nullable=True))
    op.add_column('scan_jobs', sa.Column('delivery_id', sa.String(length=64), nullable=True))
    op.create_index(op.f('ix_scan_jobs_delivery_id'), 'scan_jobs', ['delivery_id'], unique=False)
    op.create_index(op.f('ix_scan_jobs_head_sha'), 'scan_jobs', ['head_sha'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_scan_jobs_head_sha'), table_name='scan_jobs')
    op.drop_index(op.f('ix_scan_jobs_delivery_id'), table_name='scan_jobs')
    op.drop_column('scan_jobs', 'delivery_id')
    op.drop_column('scan_jobs', 'check_run_id')
    op.drop_column('scan_jobs', 'head_sha')
    op.drop_column('scan_jobs', 'pr_number')
    op.drop_column('scan_jobs', 'scan_type')
