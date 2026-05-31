-- FoxGuard Security Portal - database schema
-- Loaded automatically by init_db() in app.py on startup.
-- Using "IF NOT EXISTS" so re-running it is safe and never wipes data.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    UNIQUE NOT NULL,
    -- We store only the salted hash of the password, never the password.
    password_hash TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS tickets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    title       TEXT    NOT NULL,
    description TEXT,
    -- severity: Low / Medium / High / Critical
    severity    TEXT    NOT NULL DEFAULT 'Low',
    -- status: Open / In Progress / Resolved
    status      TEXT    NOT NULL DEFAULT 'Open',
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    -- set whenever the ticket is edited or its status changes
    updated_at  TEXT
);
