"""SQLite helpers for the shared EdgeShield database."""
import os
import sqlite3
from pathlib import Path


def _repository_root() -> Path:
    source_path = Path(__file__).resolve()
    for candidate in source_path.parents:
        if (candidate / 'shared').is_dir():
            return candidate
    return source_path.parent


def _default_database_path() -> str:
    # In the container the shared volume is /data. On a local Windows/macOS/Linux
    # checkout, keep the database in the repository's data directory.
    if Path('/app').exists() and Path('/data').exists():
        return '/data/edgeshield.db'
    return str(_repository_root() / 'data' / 'edgeshield.db')


DATABASE_PATH = os.getenv('SQLITE_PATH', _default_database_path())


def get_connection():
    path = Path(DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    conn.execute('PRAGMA busy_timeout = 10000')
    return conn


def initialize_database() -> None:
    """Create the agreed shared schema if it is missing; keep existing data."""
    schema_path = Path('/app/shared/schema.sql')
    if not schema_path.is_file():
        project_root = _repository_root()
        schema_path = project_root / 'shared' / 'schema.sql'
    if not schema_path.is_file():
        raise FileNotFoundError(f'Cannot find shared/schema.sql (checked /app/shared/schema.sql and {schema_path})')
    with get_connection() as conn:
        conn.executescript(schema_path.read_text(encoding='utf-8'))
