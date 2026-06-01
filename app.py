"""
FoxGuard Security Portal
========================
A small Flask web application that acts as an internal security support
portal for FoxGuard Security. Analysts log in and manage security tickets
(e.g. "suspicious login", "phishing report", "vulnerability found").

This file is intentionally written to be easy to read and explain during
the live demo. The key design decisions:

  * SQLite is used for storage so there is zero external setup -- the
    database is a single file created automatically on first run.
  * Passwords are NEVER stored in plain text. We use Werkzeug's
    password hashing (PBKDF2 under the hood).
  * Every SQL query uses parameter placeholders (?) so the app is not
    vulnerable to SQL injection.
  * Authentication is session based. Pages that show or create tickets
    require a logged-in user (see the @login_required decorator).
  * The secret key and port are read from environment variables so the
    same code runs locally (port 5000) and on Cloud Run (port 8080).

Routes (matches Week 10 issue #17):
  GET  /                -> redirect to dashboard (or login if not authed)
  GET/POST /login       -> Login page
  GET  /logout          -> Log the user out
  GET  /dashboard       -> Ticket Dashboard (list all tickets)
  GET/POST /tickets/new -> Ticket Creation form
  GET  /healthz         -> Health check used by Docker / Cloud Run
"""

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# The database lives next to this file. DATABASE can be overridden by an
# environment variable so the container can mount it elsewhere if needed.
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.environ.get("DATABASE", os.path.join(BASE_DIR, "foxguard.db"))

app = Flask(__name__)

# SECRET_KEY signs the session cookie. In production it MUST come from the
# environment (e.g. GCP Secret Manager). The fallback is only for local dev.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

# Valid status values for a ticket. Kept here so the dropdown in the form
# and the validation in the route stay in sync.
TICKET_STATUSES = ["Open", "In Progress", "Resolved"]
TICKET_SEVERITIES = ["Low", "Medium", "High", "Critical"]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a per-request SQLite connection.

    Flask's `g` object lives for the duration of one request, so we reuse
    the same connection across helper calls and close it automatically in
    `close_db` below.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        # row_factory lets us access columns by name (row["title"]) which
        # makes the templates much easier to read.
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """Close the database at the end of each request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def get_ticket_or_404(ticket_id):
    """Fetch a single ticket by id, or abort with 404 if it doesn't exist."""
    ticket = get_db().execute(
        "SELECT * FROM tickets WHERE id = ?", (ticket_id,)
    ).fetchone()
    if ticket is None:
        abort(404)
    return ticket


def init_db():
    """Create tables (if missing) and seed a default analyst account.

    Running this on startup means a fresh clone / fresh container "just
    works" with no manual database steps.
    """
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row

    # Load the table definitions from schema.sql.
    with open(os.path.join(BASE_DIR, "schema.sql"), "r", encoding="utf-8") as f:
        db.executescript(f.read())

    # Seed one analyst account so the team can log in during the demo.
    # The password is hashed before it ever touches the database.
    existing = db.execute(
        "SELECT id FROM users WHERE username = ?", ("analyst",)
    ).fetchone()
    if existing is None:
        db.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            # pbkdf2:sha256 is explicitly chosen because it is available on
            # every Python build (the Werkzeug 3 default, scrypt, needs an
            # OpenSSL feature that some minimal/container images lack).
            ("analyst", generate_password_hash("FoxGuard123!", method="pbkdf2:sha256")),
        )
        db.commit()

    db.close()


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def login_required(view):
    """Decorator that bounces anonymous users to the login page.

    Apply it to any route that should only be reachable by a logged-in
    user (the dashboard and ticket creation).
    """

    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Send people to the dashboard; login_required handles the redirect."""
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """Display and process the login form."""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Parameterized query -> safe from SQL injection.
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        # Verify the password against the stored hash. We deliberately give
        # the same generic error whether the username or password is wrong
        # so we don't leak which usernames exist.
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        # Success: store the user id in the signed session cookie.
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash(f"Welcome back, {user['username']}.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear the session and return to the login page."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Ticket Dashboard: list every ticket, newest first."""
    tickets = get_db().execute(
        "SELECT * FROM tickets ORDER BY created_at DESC"
    ).fetchall()
    return render_template("dashboard.html", tickets=tickets)


@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def create_ticket():
    """Ticket Creation form."""
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Low")
        status = request.form.get("status", "Open")

        # Basic server-side validation. Never trust the browser alone.
        errors = []
        if not title:
            errors.append("Title is required.")
        if severity not in TICKET_SEVERITIES:
            errors.append("Invalid severity.")
        if status not in TICKET_STATUSES:
            errors.append("Invalid status.")

        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "create_ticket.html",
                severities=TICKET_SEVERITIES,
                statuses=TICKET_STATUSES,
            ), 400

        db = get_db()
        db.execute(
            """INSERT INTO tickets
                   (title, description, severity, status, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                title,
                description,
                severity,
                status,
                session.get("username", "unknown"),
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        db.commit()
        flash("Ticket created.", "success")
        return redirect(url_for("dashboard"))

    return render_template(
        "create_ticket.html",
        severities=TICKET_SEVERITIES,
        statuses=TICKET_STATUSES,
    )


@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    """Ticket detail view: show one ticket and the management controls."""
    ticket = get_ticket_or_404(ticket_id)
    return render_template(
        "ticket_detail.html",
        ticket=ticket,
        statuses=TICKET_STATUSES,
    )


@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@login_required
def update_status(ticket_id):
    """Quick status change (e.g. mark a ticket Resolved) from the detail page.

    This is the "Ticket status updates" feature from the one-pager: change an
    existing ticket's status without editing the rest of its fields.
    """
    get_ticket_or_404(ticket_id)  # 404 if it doesn't exist
    status = request.form.get("status", "")

    if status not in TICKET_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    db = get_db()
    db.execute(
        "UPDATE tickets SET status = ?, updated_at = ? WHERE id = ?",
        (status, datetime.utcnow().isoformat(timespec="seconds"), ticket_id),
    )
    db.commit()
    flash(f"Ticket #{ticket_id} marked as {status}.", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(ticket_id):
    """Administrative ticket management: edit any field of an existing ticket."""
    ticket = get_ticket_or_404(ticket_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Low")
        status = request.form.get("status", "Open")

        # Same server-side validation as creation.
        errors = []
        if not title:
            errors.append("Title is required.")
        if severity not in TICKET_SEVERITIES:
            errors.append("Invalid severity.")
        if status not in TICKET_STATUSES:
            errors.append("Invalid status.")

        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "edit_ticket.html",
                ticket=ticket,
                severities=TICKET_SEVERITIES,
                statuses=TICKET_STATUSES,
            ), 400

        db = get_db()
        db.execute(
            """UPDATE tickets
                   SET title = ?, description = ?, severity = ?, status = ?, updated_at = ?
                 WHERE id = ?""",
            (
                title,
                description,
                severity,
                status,
                datetime.utcnow().isoformat(timespec="seconds"),
                ticket_id,
            ),
        )
        db.commit()
        flash(f"Ticket #{ticket_id} updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return render_template(
        "edit_ticket.html",
        ticket=ticket,
        severities=TICKET_SEVERITIES,
        statuses=TICKET_STATUSES,
    )


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    """Administrative ticket management: delete a ticket."""
    get_ticket_or_404(ticket_id)
    db = get_db()
    db.execute("DELETE FROM tickets WHERE id = ?", (ticket_id,))
    db.commit()
    flash(f"Ticket #{ticket_id} deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/healthz")
def healthz():
    """Liveness probe for Docker / Cloud Run. Returns 200 if the app and
    its database are reachable. No auth required."""
    try:
        get_db().execute("SELECT 1")
        return {"status": "ok"}, 200
    except sqlite3.Error:
        return {"status": "error"}, 500


# Make sure the database exists as soon as the module is imported. This runs
# both under `flask run` / `python app.py` locally AND under gunicorn in the
# container, so there is never a "no such table" error on first request.
init_db()


if __name__ == "__main__":
    # Local development entry point. Cloud Run / gunicorn ignore this block
    # and import the `app` object directly.
    port = int(os.environ.get("PORT", 5000))
    # debug is on only when FLASK_DEBUG=1 to avoid leaking tracebacks in prod.
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="0.0.0.0", port=8080)
