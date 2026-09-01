
import os
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

from dotenv import dotenv_values
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_DATABASE_PATH = ROOT_DIR / "database" / "threatlens.db"
DEFAULT_DATABASE_URL = f"sqlite:///{DEFAULT_DATABASE_PATH.as_posix()}"


def normalize_database_url(value: str) -> str:
    """Normalize platform-provided PostgreSQL URLs for SQLAlchemy + psycopg 3."""

    url = value.strip()
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://") :]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://") :]
    return url


def psycopg_database_url(value: str) -> str:
    """Return a libpq/psycopg-compatible URL from a SQLAlchemy PostgreSQL URL."""

    url = value.strip()
    if url.startswith("postgresql+psycopg://"):
        return "postgresql://" + url[len("postgresql+psycopg://") :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def resolve_database_url(env_path: Path | None = None) -> str:
    """Resolve the database URL from process environment, .env, then the safe default."""

    explicit = os.getenv("THREATLENS_DATABASE_URL", "").strip()
    if explicit:
        return normalize_database_url(explicit)
    values = dotenv_values(env_path or (ROOT_DIR / ".env"))
    configured = str(values.get("THREATLENS_DATABASE_URL") or "").strip()
    return normalize_database_url(configured or DEFAULT_DATABASE_URL)


DATABASE_URL = resolve_database_url()


def create_database_engine(database_url: str = DATABASE_URL) -> Engine:
    """Create a configured SQLAlchemy engine for SQLite development or PostgreSQL production."""

    database_url = normalize_database_url(database_url)
    connect_args: dict = {}
    kwargs: dict = {"future": True, "pool_pre_ping": True}

    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    else:
        # Conservative defaults for Render/managed Postgres. They are configurable without
        # changing code and avoid unbounded application-side connections.
        kwargs.update(
            pool_size=int(os.getenv("THREATLENS_DB_POOL_SIZE", "5")),
            max_overflow=int(os.getenv("THREATLENS_DB_MAX_OVERFLOW", "5")),
            pool_recycle=int(os.getenv("THREATLENS_DB_POOL_RECYCLE_SECONDS", "900")),
            pool_timeout=int(os.getenv("THREATLENS_DB_POOL_TIMEOUT_SECONDS", "30")),
        )

    database_engine = create_engine(
        database_url,
        connect_args=connect_args,
        **kwargs,
    )

    if database_url.startswith("sqlite"):

        @event.listens_for(database_engine, "connect")
        def configure_sqlite(database_connection, _connection_record) -> None:
            cursor = database_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    return database_engine


def create_session_factory(database_engine: Engine) -> sessionmaker[Session]:
    """Create a reusable SQLAlchemy session factory."""

    return sessionmaker(
        bind=database_engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


engine = create_database_engine()
SessionLocal = create_session_factory(engine)


@contextmanager
def session_scope(
    session_factory: sessionmaker[Session] = SessionLocal,
) -> Generator[Session, None, None]:
    """Provide a transactional database session."""

    database_session = session_factory()
    try:
        yield database_session
        database_session.commit()
    except Exception:
        database_session.rollback()
        raise
    finally:
        database_session.close()
