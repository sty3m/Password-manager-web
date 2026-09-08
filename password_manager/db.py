import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("PYVAULT_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "pyvault.db"))
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    salt BLOB NOT NULL,
    iterations INTEGER NOT NULL,
    verifier BLOB NOT NULL,
    vault_data BLOB NOT NULL,
    created_at TEXT NOT NULL
);
"""

@contextmanager
def get_conn(db_path: str = None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()

def init_db(db_path: str = None) -> None:
    with get_conn(db_path) as conn:
        conn.executescript(SCHEMA)

def create_user(username, salt, iterations, verifier, vault_data, db_path=None):
    with get_conn(db_path) as conn:
        cur = conn.execute("INSERT INTO users (username,salt,iterations,verifier,vault_data,created_at) VALUES (?,?,?,?,?,?)", (username,salt,iterations,verifier,vault_data,datetime.now(timezone.utc).isoformat()))
        return cur.lastrowid

def get_user_by_username(username, db_path=None):
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id, db_path=None):
    with get_conn(db_path) as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None

def update_vault_data(user_id, vault_data, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE users SET vault_data = ? WHERE id = ?", (vault_data, user_id))

def update_master_credentials(user_id, salt, iterations, verifier, vault_data, db_path=None):
    with get_conn(db_path) as conn:
        conn.execute("UPDATE users SET salt=?,iterations=?,verifier=?,vault_data=? WHERE id=?", (salt,iterations,verifier,vault_data,user_id))

def username_exists(username, db_path=None):
    return get_user_by_username(username, db_path) is not None
