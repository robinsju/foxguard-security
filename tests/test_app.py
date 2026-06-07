"""Route, auth, and ticket-CRUD tests for the FoxGuard Security Portal."""

from conftest import DEMO_PASSWORD, DEMO_USER


# ── Health ───────────────────────────────────────────────────────────────────
def test_healthz_ok(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}


# ── Authentication ───────────────────────────────────────────────────────────
def test_login_page_loads(client):
    resp = client.get("/login")
    assert resp.status_code == 200
    assert b"Analyst Login" in resp.data


def test_login_success_redirects_to_dashboard(client):
    resp = client.post(
        "/login",
        data={"username": DEMO_USER, "password": DEMO_PASSWORD},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/dashboard")


def test_login_failure_returns_401(client):
    resp = client.post(
        "/login",
        data={"username": DEMO_USER, "password": "wrong-password"},
    )
    assert resp.status_code == 401
    assert b"Invalid username or password" in resp.data


def test_login_is_not_sql_injectable(client):
    # A classic auth-bypass payload must NOT authenticate (parameterized query).
    resp = client.post(
        "/login",
        data={"username": "analyst' OR '1'='1", "password": "x"},
    )
    assert resp.status_code == 401


def test_dashboard_requires_login(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_logout_clears_session(auth_client):
    # Logged in: dashboard is reachable.
    assert auth_client.get("/dashboard").status_code == 200
    auth_client.get("/logout")
    # Logged out: dashboard now redirects to login.
    assert auth_client.get("/dashboard").status_code == 302


# ── Ticket CRUD ──────────────────────────────────────────────────────────────
def _create_ticket(client, title="Phishing report", severity="High", status="Open"):
    return client.post(
        "/tickets/new",
        data={
            "title": title,
            "description": "Suspicious email reported by finance.",
            "severity": severity,
            "status": status,
        },
        follow_redirects=True,
    )


def test_create_ticket_appears_on_dashboard(auth_client):
    resp = _create_ticket(auth_client, title="Malware alert")
    assert resp.status_code == 200
    assert b"Malware alert" in resp.data


def test_create_ticket_validation_rejects_empty_title(auth_client):
    resp = auth_client.post(
        "/tickets/new",
        data={"title": "", "description": "x", "severity": "Low", "status": "Open"},
    )
    assert resp.status_code == 400
    assert b"Title is required" in resp.data


def test_create_ticket_validation_rejects_bad_severity(auth_client):
    resp = auth_client.post(
        "/tickets/new",
        data={"title": "x", "description": "y", "severity": "Bogus", "status": "Open"},
    )
    assert resp.status_code == 400
    assert b"Invalid severity" in resp.data


def test_ticket_detail_and_status_update(auth_client):
    _create_ticket(auth_client, title="Lateral movement")
    # First created ticket has id 1 (fresh autoincrement).
    detail = auth_client.get("/tickets/1")
    assert detail.status_code == 200
    assert b"Lateral movement" in detail.data

    resp = auth_client.post(
        "/tickets/1/status", data={"status": "Resolved"}, follow_redirects=True
    )
    assert resp.status_code == 200
    assert b"Resolved" in resp.data


def test_status_update_rejects_invalid_value(auth_client):
    _create_ticket(auth_client)
    resp = auth_client.post(
        "/tickets/1/status", data={"status": "NotAStatus"}, follow_redirects=True
    )
    assert b"Invalid status" in resp.data


def test_edit_ticket_updates_title(auth_client):
    _create_ticket(auth_client, title="Old title")
    resp = auth_client.post(
        "/tickets/1/edit",
        data={
            "title": "New title",
            "description": "updated",
            "severity": "Medium",
            "status": "In Progress",
        },
        follow_redirects=True,
    )
    assert resp.status_code == 200
    assert b"New title" in resp.data


def test_delete_ticket_removes_it(auth_client):
    _create_ticket(auth_client, title="Temporary ticket")
    auth_client.post("/tickets/1/delete", follow_redirects=True)
    dash = auth_client.get("/dashboard")
    assert b"Temporary ticket" not in dash.data


def test_unknown_ticket_returns_404(auth_client):
    assert auth_client.get("/tickets/9999").status_code == 404


def test_ticket_routes_require_login(client):
    for path in ("/dashboard", "/tickets/new", "/tickets/1", "/tickets/1/edit"):
        resp = client.get(path)
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
