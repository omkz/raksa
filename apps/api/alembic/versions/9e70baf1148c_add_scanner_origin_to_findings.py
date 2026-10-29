"""Record scanner origin and rule in persisted findings.

Revision ID: 9e70baf1148c
Revises: db27f7e25532
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "9e70baf1148c"
down_revision: str | Sequence[str] | None = "db27f7e25532"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("scanner", sa.String(32), server_default="raksa", nullable=False))
    op.add_column("findings", sa.Column("rule_id", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("findings", "rule_id")
    op.drop_column("findings", "scanner")
