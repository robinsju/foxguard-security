"""Test fixtures for the FoxGuard Security Portal.

The tests run against a real MySQL database through the same PyMySQL code
path the application uses in production (Cloud SQL for MySQL) — no alternate
database engine is substituted. Locally this expects a MySQL server reachable
via the DB_* environment variables; in CI a MySQL service container provides
one (see .github/workflows/tests.yml).
"""

import os
import sys

import pymysql
import pytest

# Must be set before importing the app: skip the real init at import time and
# give Flask a deterministic signing key. The DB_* values point the app (and
# this fixture) at the test MySQL instance; CI overrides them via env.
os.environ["SKIP_DB_INIT"] = "1"
os.environ["SECRET_KEY"] = "test-secret"
os.environ.setdefault("DB_HOST", "127.0.0.1")
os.environ.setdefault("DB_PORT", "3306")
os.environ.setdefault("DB_USER", "root")
os.environ.setdefault("DB_PASSWORD", "root")
os.environ.setdefault("DB_NAME", "foxguard_test")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import app as fgapp  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

DEMO_USER = "analyst"
DEMO_PASSWORD = "FoxGuard123!"

with open(os.path.join(fgapp.BASE_DIR, "schema.sql"), encoding="utf-8") as _f:
    _SCHEMA = _f.read()


def _admin_connection():
    """A direct MySQL connection used to reset state between tests."""
    return pymysql.connect(
        host=fgapp.DB_HOST,
        port=fgapp.DB_PORT,
        user=fgapp.DB_USER,
        password=fgapp.DB_PASSWORD,
        database=fgapp.DB_NAME,
        autocommit=True,
    )


@pytest.fixture(autouse=True)
def reset_database():
    """Recreate the schema and seed the demo analyst before each test.

    Dropping and recreating the tables gives every test a clean slate and
    resets AUTO_INCREMENT, so the first ticket created in a test has id 1.
    """
    conn = _admin_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            cur.execute("DROP TABLE IF EXISTS tickets")
            cur.execute("DROP TABLE IF EXISTS users")
            cur.execute("SET FOREIGN_KEY_CHECKS = 1")
            for statement in _SCHEMA.split(";"):
                if statement.strip():
                    cur.execute(statement)
            cur.execute(
                "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                (
                    DEMO_USER,
                    generate_password_hash(DEMO_PASSWORD, method="pbkdf2:sha256"),
                ),
            )
    finally:
        conn.close()
    yield


@pytest.fixture
def client():
    fgapp.app.config.update(TESTING=True)
    with fgapp.app.test_client() as c:
        yield c


@pytest.fixture
def auth_client(client):
    """A client already logged in as the demo analyst."""
    client.post(
        "/login",
        data={"username": DEMO_USER, "password": DEMO_PASSWORD},
    )
    return client
