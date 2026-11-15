"""
Database Connection and Session Manager for AI-NIDS.
Provides synchronous and asynchronous database engines for SQLite.
"""

from pathlib import Path
from typing import AsyncGenerator
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.database.models import Base

DB_PATH = Path("data/nids.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

SYNC_DATABASE_URL = f"sqlite:///{DB_PATH.resolve()}"
ASYNC_DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH.resolve()}"

# Sync Engine (for table creation, CLI scripts, and synchronous worker callbacks)
sync_engine = create_engine(
    SYNC_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)
SyncSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=sync_engine)

# Async Engine (for FastAPI async route handlers)
async_engine = create_async_engine(
    ASYNC_DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False
)

def init_db() -> None:
    """Creates all tables synchronously if they do not already exist."""
    Base.metadata.create_all(bind=sync_engine)

def get_sync_db() -> Session:
    """Returns a standalone sync database session."""
    return SyncSessionLocal()

async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for FastAPI route handlers."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
