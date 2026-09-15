import os
import sqlite3


# Docker Compose gives us:
# SQLITE_PATH=/data/edgeshield.db
DATABASE_PATH = os.getenv(
    "SQLITE_PATH",
    "/data/edgeshield.db"
)


def get_connection():
    """
    Create a connection to the shared EdgeShield SQLite database.
    """

    conn = sqlite3.connect(
        DATABASE_PATH,
        check_same_thread=False
    )

    # Allows us to access columns by name:
    # row["timestamp"]
    # row["attack_type"]
    # etc.
    conn.row_factory = sqlite3.Row

    return conn