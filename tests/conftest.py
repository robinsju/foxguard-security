"""Test fixtures for the FoxGuard Security Portal.

The application talks to Cloud SQL (MySQL) via PyMySQL through a single
indirection point — ``app.get_db()`` — which returns a connection exposing
``cursor()`` (a context manager), ``commit()`` and ``close()``. The tests
swap that connection for a thin SQLite-backed shim so the full request/route
logic is exercised without a real MySQL server (works locally and in CI).
"""

import os
import sqlite3
import sys

import pytest

# Must be set before importing the app: skip the real MySQL init at import,
# and give Flask a deterministic signing key.
os.environ["SKIP_DB_INIT"] = "1"
os.environ["SECRET_KEY"] = "test-secret"

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as fgapp  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

DEMO_USER = "analyst"
DEMO_PASSWORD = "FoxGuard123!"


class _FakeCursor:
    """Mimics a PyMySQL DictCursor on top of an sqlite3 cursor."""

    def __init__(self, sqlite_conn):
        self._cur = sqlite_conn.cursor()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._cur.close()
        return False

    def execute(self, sql, params=()):
        # PyMySQL uses %s placeholders; sqlite3 uses ?.
        self._cur.execute(sql.replace("%s", "?"), tuple(params or ()))
        return self

    def fetchone(self):
        row = self._cur.fetchone()
        return dict(row) if row is not None else None

    def fetchall(self):
        return [dict(r) for r in self._cur.fetchall()]


class _FakeConn:
    def __init__(self, sqlite_conn):
        self._s = sqlite_conn

    def cursor(self):
        return _FakeCursor(self._s)

    def commit(self):
        self._s.commit()

    def close(self):  # connection lifecycle is owned by the fixture
        pass


@pytest.fixture
def client(monkeypatch):
    sconn = sqlite3.connect(":memory:")
    sconn.row_factory = sqlite3.Row
    sconn.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            severity TEXT NOT NULL DEFAULT 'Low',
            status TEXT NOT NULL DEFAULT 'Open',
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT
        );
        """
    )
    sconn.execute(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
        (DEMO_USER, generate_password_hash(DEMO_PASSWORD, method="pbkdf2:sha256")),
    )
    sconn.commit()

    fake = _FakeConn(sconn)
    # Every data-access helper funnels through get_db(); patch that one point.
    monkeypatch.setattr(fgapp, "get_db", lambda: fake)

    fgapp.app.config.update(TESTING=True)
    with fgapp.app.test_client() as c:
        yield c
    sconn.close()


@pytest.fixture
def auth_client(client):
    """A client already logged in as the demo analyst."""
    client.post(
        "/login",
        data={"username": DEMO_USER, "password": DEMO_PASSWORD},
    )
    return client
