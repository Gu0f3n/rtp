"""数据库引擎与会话管理。"""
from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings
from app.models import Base

engine = create_async_engine(
    settings.db_url,
    echo=False,
    future=True,
    # SQLite 在并发写入时会锁库，超时给长一点
    connect_args={"timeout": 30} if settings.db_url.startswith("sqlite") else {},
)

SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI 依赖注入用。"""
    async with SessionLocal() as session:
        yield session


from contextlib import asynccontextmanager  # noqa: E402


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """脚本/任务中手动管理事务。"""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
