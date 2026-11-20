"""
Shared SQLite helpers for EdgeShield agents.

WAL mode and busy_timeout reduce lock errors when sensor, analysis, defender,
and dashboard read/write the same volume-backed database concurrently.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


def connect(
    path: PathLike,
    *,
    check_same_thread: bool = True,
    timeout: float = 10.0,
) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(
        str(db_path),
        timeout=timeout,
        check_same_thread=check_same_thread,
    )
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn