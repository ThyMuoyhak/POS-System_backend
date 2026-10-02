"""SQLite / SQLAlchemy plumbing."""
from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import BASE_DIR, DATABASE_URL


class Base(DeclarativeBase):
    """Declarative base for every ORM model."""


def _sqlite_file(url: str) -> Path | None:
    """Return the file a ``sqlite://`` url points at (None for memory / others)."""
    try:
        parsed = make_url(url)
    except Exception:  # pragma: no cover - create_engine reports this instead
        return None
    if parsed.get_backend_name() != "sqlite":
        return None
    name = parsed.database or ""
    if not name or name == ":memory:":
        return None
    path = Path(name)
    return path if path.is_absolute() else BASE_DIR / path


def _prepare_sqlite_file() -> Path | None:
    """Create the folder that will hold the sqlite file, or explain why we cannot.

    A missing folder is the most confusing way this app can fail: sqlite only
    says ``unable to open database file`` and the traceback never mentions the
    real cause. On a hosted deployment the usual reason is a DATABASE_URL that
    points at a disk mount path (e.g. Render's ``/var/data``) while no disk is
    attached - a host only creates that folder once the disk exists.
    """
    db_file = _sqlite_file(DATABASE_URL)
    if db_file is None:
        return None

    folder = db_file.parent
    existed = folder.is_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise RuntimeError(
            f"Cannot use DATABASE_URL={DATABASE_URL!r}: the folder {folder} does "
            f"not exist and could not be created ({exc}).\n"
            "If that is a persistent disk mount path, attach the disk to the "
            "service first - the host creates the mount folder only once the "
            "disk is attached. Otherwise point DATABASE_URL at a writable "
            "folder, and remember the data only survives a redeploy if that "
            "folder lives on a persistent disk."
        ) from exc

    if db_file.exists():
        print(f"[db] using existing database file {db_file}")
    else:
        print(f"[db] creating database file {db_file}")
    if not existed and folder != BASE_DIR:
        print(
            f"[db] WARNING: {folder} did not exist and was just created. Anything "
            "written there is lost on the next deploy or restart unless a "
            "persistent disk is mounted at that path."
        )
    return db_file


SQLITE_FILE = _prepare_sqlite_file()

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    future=True,
)


@event.listens_for(engine, "connect")
def _enable_sqlite_fk(dbapi_connection, _connection_record):  # pragma: no cover
    """SQLite ignores foreign keys unless they are switched on per connection."""
    if DATABASE_URL.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a scoped database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create every table (import models first so they register themselves)."""
    import models  # noqa: F401  (side-effect: registers mappers)

    Base.metadata.create_all(bind=engine)
