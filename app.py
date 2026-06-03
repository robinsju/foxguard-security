"""
FoxGuard Security Portal
========================
A small Flask web application that acts as an internal security support
portal for FoxGuard Security. Analysts log in and manage security tickets.

The app uses Cloud SQL for MySQL through PyMySQL. Database credentials are
provided by environment variables so Cloud Run can inject them from Secret
Manager without hardcoding secrets in source control.
"""

import os
from datetime import datetime
from functools import wraps

import pymysql
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


BASE_DIR = os.path.abspath(os.path.dirname(__file__))

DB_HOST = os.environ.get("DB_HOST", "127.0.0.1")
DB_USER = os.environ.get("DB_USER", "foxguarduser")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")
DB_NAME = os.environ.get("DB_NAME", "foxguard")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-only-change-me")

TICKET_STATUSES = ["Open", "In Progress", "Resolved"]
TICKET_SEVERITIES = ["Low", "Medium", "High", "Critical"]


def get_db():
    """Return a per-request MySQL connection."""
    if "db" not in g:
        g.db = pymysql.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor,
            autocommit=False,
        )
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def fetch_one(sql, params=None):
    with get_db().cursor() as cursor:
        cursor.execute(sql, params or ())
        return cursor.fetchone()


def fetch_all(sql, params=None):
    with get_db().cursor() as cursor:
        cursor.execute(sql, params or ())
        return cursor.fetchall()


def execute_write(sql, params=None):
    db = get_db()
    with db.cursor() as cursor:
        cursor.execute(sql, params or ())
    db.commit()


def get_ticket_or_404(ticket_id):
    ticket = fetch_one("SELECT * FROM tickets WHERE id = %s", (ticket_id,))
    if ticket is None:
        abort(404)
    return ticket


def init_db():
    if not DB_PASSWORD:
        raise RuntimeError("DB_PASSWORD environment variable is required")

    db = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor,
    )
    try:
        with db.cursor() as cursor:
            with open(os.path.join(BASE_DIR, "schema.sql"), "r", encoding="utf-8") as f:
                for statement in f.read().split(";"):
                    statement = statement.strip()
                    if statement:
                        cursor.execute(statement)

            cursor.execute("SELECT id FROM users WHERE username = %s", ("analyst",))
            if cursor.fetchone() is None:
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (%s, %s)",
                    (
                        "analyst",
                        generate_password_hash(
                            "FoxGuard123!",
                            method="pbkdf2:sha256",
                        ),
                    ),
                )
        db.commit()
    finally:
        db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = fetch_one("SELECT * FROM users WHERE username = %s", (username,))
        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "danger")
            return render_template("login.html"), 401

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        flash(f"Welcome back, {user['username']}.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    tickets = fetch_all("SELECT * FROM tickets ORDER BY created_at DESC")
    return render_template("dashboard.html", tickets=tickets)


@app.route("/tickets/new", methods=["GET", "POST"])
@login_required
def create_ticket():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Low")
        status = request.form.get("status", "Open")

        errors = validate_ticket(title, severity, status)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_ticket_form("create_ticket.html"), 400

        execute_write(
            """INSERT INTO tickets
                   (title, description, severity, status, created_by, created_at)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                title,
                description,
                severity,
                status,
                session.get("username", "unknown"),
                datetime.utcnow().isoformat(timespec="seconds"),
            ),
        )
        flash("Ticket created.", "success")
        return redirect(url_for("dashboard"))

    return render_ticket_form("create_ticket.html")


@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = get_ticket_or_404(ticket_id)
    return render_template(
        "ticket_detail.html",
        ticket=ticket,
        statuses=TICKET_STATUSES,
    )


@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@login_required
def update_status(ticket_id):
    get_ticket_or_404(ticket_id)
    status = request.form.get("status", "")

    if status not in TICKET_STATUSES:
        flash("Invalid status.", "danger")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    execute_write(
        "UPDATE tickets SET status = %s, updated_at = %s WHERE id = %s",
        (status, datetime.utcnow().isoformat(timespec="seconds"), ticket_id),
    )
    flash(f"Ticket #{ticket_id} marked as {status}.", "success")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/edit", methods=["GET", "POST"])
@login_required
def edit_ticket(ticket_id):
    ticket = get_ticket_or_404(ticket_id)

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        severity = request.form.get("severity", "Low")
        status = request.form.get("status", "Open")

        errors = validate_ticket(title, severity, status)
        if errors:
            for message in errors:
                flash(message, "danger")
            return render_ticket_form("edit_ticket.html", ticket=ticket), 400

        execute_write(
            """UPDATE tickets
                  SET title = %s,
                      description = %s,
                      severity = %s,
                      status = %s,
                      updated_at = %s
                WHERE id = %s""",
            (
                title,
                description,
                severity,
                status,
                datetime.utcnow().isoformat(timespec="seconds"),
                ticket_id,
            ),
        )
        flash(f"Ticket #{ticket_id} updated.", "success")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))

    return render_ticket_form("edit_ticket.html", ticket=ticket)


@app.route("/tickets/<int:ticket_id>/delete", methods=["POST"])
@login_required
def delete_ticket(ticket_id):
    get_ticket_or_404(ticket_id)
    execute_write("DELETE FROM tickets WHERE id = %s", (ticket_id,))
    flash(f"Ticket #{ticket_id} deleted.", "info")
    return redirect(url_for("dashboard"))


@app.route("/healthz")
def healthz():
    try:
        fetch_one("SELECT 1 AS ok")
        return {"status": "ok"}, 200
    except pymysql.MySQLError:
        return {"status": "error"}, 500


def validate_ticket(title, severity, status):
    errors = []
    if not title:
        errors.append("Title is required.")
    if severity not in TICKET_SEVERITIES:
        errors.append("Invalid severity.")
    if status not in TICKET_STATUSES:
        errors.append("Invalid status.")
    return errors


def render_ticket_form(template, **kwargs):
    return render_template(
        template,
        severities=TICKET_SEVERITIES,
        statuses=TICKET_STATUSES,
        **kwargs,
    )


if os.environ.get("SKIP_DB_INIT") != "1":
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
