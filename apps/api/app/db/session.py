import asyncio
import logging
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import pool, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings
from app.db.base import Base
from app.db.models import Workspace

logger = logging.getLogger("raksa.db")

_ENGINE: AsyncEngine | None = None
_SESSION_FACTORY: async_sessionmaker[AsyncSession] | None = None
_ENGINE_LOOP: asyncio.AbstractEventLoop | None = None


def get_engine(database_url: str | None = None) -> AsyncEngine:
    global _ENGINE, _SESSION_FACTORY, _ENGINE_LOOP
    try:
        current_loop = asyncio.get_running_loop()
    except RuntimeError:
        current_loop = None

    if (
        _ENGINE is not None
        and current_loop is not None
        and _ENGINE_LOOP is not None
        and _ENGINE_LOOP != current_loop
    ):
        _ENGINE = None
        _SESSION_FACTORY = None

    target_url = database_url or settings.async_database_url
    if _ENGINE is None:
        _ENGINE_LOOP = current_loop
        connect_args: dict[str, Any] = {}
        if "sqlite" in target_url:
            connect_args["check_same_thread"] = False

        # In testing environments, NullPool prevents closed-loop socket reuse issues
        use_null_pool = "pytest" in sys.modules or "sqlite" in target_url
        poolclass = pool.NullPool if use_null_pool else pool.AsyncAdaptedQueuePool

        _ENGINE = create_async_engine(
            target_url,
            echo=False,
            future=True,
            connect_args=connect_args,
            poolclass=poolclass,
            pool_pre_ping=True,
        )
        _SESSION_FACTORY = async_sessionmaker(
            _ENGINE,
            expire_on_commit=False,
            autoflush=False,
            class_=AsyncSession,
        )
    return _ENGINE


def get_session_factory(database_url: str | None = None) -> async_sessionmaker[AsyncSession]:
    global _SESSION_FACTORY
    if _SESSION_FACTORY is None:
        get_engine(database_url)
    assert _SESSION_FACTORY is not None
    return _SESSION_FACTORY


@asynccontextmanager
async def async_session_scope(database_url: str | None = None) -> AsyncGenerator[AsyncSession, None]:
    factory = get_session_factory(database_url)
    async with factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_scope() as session:
        yield session


def _run_alembic_upgrade(target_url: str) -> None:
    from pathlib import Path

    from alembic.config import Config

    from alembic import command

    root_dir = Path(__file__).resolve().parent.parent.parent
    ini_path = root_dir / "alembic.ini"
    if ini_path.exists():
        cfg = Config(str(ini_path))
        cfg.set_main_option("sqlalchemy.url", target_url)
        command.upgrade(cfg, "head")


async def init_db(database_url: str | None = None) -> None:
    """Ensure database schema is created and seed default workspace."""
    target_url = database_url or settings.async_database_url
    if "sqlite" in target_url:
        engine = get_engine(database_url)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    else:
        await asyncio.to_thread(_run_alembic_upgrade, target_url)

    # Seed default workspace
    async with async_session_scope(database_url) as session:
        result = await session.execute(select(Workspace).where(Workspace.id == "default"))
        if not result.scalar_one_or_none():
            session.add(Workspace(id="default", name="Default Workspace"))
            logger.info("Initialized default workspace.")


async def close_db() -> None:
    global _ENGINE, _SESSION_FACTORY
    if _ENGINE is not None:
        await _ENGINE.dispose()
        _ENGINE = None
        _SESSION_FACTORY = None
        logger.info("Database engine connections closed.")


async def check_db_health(database_url: str | None = None) -> bool:
    try:
        engine = get_engine(database_url)
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database health check failed: {exc}")
        return False
