import os

import pytest
from sqlalchemy import delete

# Configure pytest environment: use isolated test database and disable background worker loop by default
os.environ["DATABASE_URL"] = "postgresql+asyncpg://raksa:raksa@localhost:5432/raksa_test"
os.environ["WORKER_ENABLED"] = "false"


@pytest.fixture(autouse=True)
async def clean_database_jobs() -> None:
    from app.db.models import ScanJob, User, UserSession, Workspace, WorkspaceMember
    from app.db.session import async_session_scope
    from app.services.worker import stop_embedded_worker

    await stop_embedded_worker()
    async with async_session_scope() as session:
        await session.execute(delete(UserSession))
        await session.execute(delete(WorkspaceMember))
        await session.execute(delete(ScanJob))
        await session.execute(delete(Workspace).where(Workspace.id != "default"))
        await session.execute(delete(User))
    yield
    await stop_embedded_worker()
    async with async_session_scope() as session:
        await session.execute(delete(UserSession))
        await session.execute(delete(WorkspaceMember))
        await session.execute(delete(ScanJob))
        await session.execute(delete(Workspace).where(Workspace.id != "default"))
        await session.execute(delete(User))
