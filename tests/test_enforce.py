from datetime import datetime, timedelta, timezone

import pytest

from backend import config, models
from backend.api import enforce
from backend.auth.auth import hash_password
from tests.conftest import TestingSessionLocal

H = {"x-forwarded-host": "email.test"}


@pytest.fixture(autouse=True)
def _setup(client, monkeypatch):
    monkeypatch.setattr(config, "ENFORCE_CACHE_SECONDS", 0)
    enforce.clear_cache()
    with TestingSessionLocal() as db:
        for name, host in (("Email", "email.test"), ("Admin Console", "admin.test")):
            db.query(models.Application).filter(models.Application.name == name).first().upstream_host = host
        org = db.query(models.Organization).first()
        db.add(models.User(organization_id=org.id, username="other", password_hash=hash_password("OtherPass12345"),
                           display_name="O", role="employee", email="o@x.com", is_active=True))
        db.commit()


def _login(client, u="developer01", p="CloudDemo123!"):
    return client.post("/api/auth/login", json={"username": u, "password": p}).json()["access_token"]


def _bearer(t):
    return {**H, "authorization": f"Bearer {t}"}


def test_unknown_host_denied(client):
    assert client.get("/api/enforce/verify", headers={"x-forwarded-host": "nope.test"}).status_code == 403
    assert client.get("/api/enforce/verify").status_code == 403


def test_no_auth_is_401(client):
    assert client.anon.get("/api/enforce/verify", headers=H).status_code == 401


def test_healthy_user_low_sensitivity_allowed(client):
    r = client.get("/api/enforce/verify", headers=_bearer(_login(client)))
    assert r.status_code == 200 and r.headers["x-cloudsentinel-user"] == "developer01"


def test_critical_resource_not_silently_allowed(client):
    h = {"x-forwarded-host": "admin.test", "authorization": f"Bearer {_login(client)}"}
    r = client.get("/api/enforce/verify", headers=h)
    assert r.status_code == 403 and r.headers["x-cloudsentinel-decision"] in {"MFA_REQUIRED", "DENY", "ISOLATE"}


def test_gateway_cookie_works_and_is_not_an_api_token(client):
    t = _login(client)
    r = client.post("/api/enforce/session", headers={"authorization": f"Bearer {t}"})
    assert r.status_code == 204 and "httponly" in r.headers["set-cookie"].lower()
    cookie = r.cookies.get("cs_session")
    client.cookies.clear()
    assert client.get("/api/enforce/verify", headers=H, cookies={"cs_session": cookie}).status_code == 200
    assert client.get("/api/auth/me", headers={"authorization": f"Bearer {cookie}"}).status_code == 401


def test_stale_or_revoked_device_blocked_when_required(client, monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_AGENT_DEVICE", True)
    h = _bearer(_login(client))
    assert client.get("/api/enforce/verify", headers=h).status_code == 200
    with TestingSessionLocal() as db:
        d = db.query(models.Device).first()
        d.last_seen = datetime.now(timezone.utc) - timedelta(hours=2)
        db.commit()
    assert client.get("/api/enforce/verify", headers=h).status_code == 403
    with TestingSessionLocal() as db:
        d = db.query(models.Device).first()
        d.last_seen, d.status = datetime.now(timezone.utc), "REVOKED"
        db.commit()
    assert client.get("/api/enforce/verify", headers=h).status_code == 403


def test_login_redirect_only_to_registered_hosts(client):
    ok = client.post("/api/enforce/login", data={"username": "developer01", "password": "CloudDemo123!", "next": "http://email.test/x"}, follow_redirects=False)
    assert ok.status_code == 303 and "cs_session" in ok.headers["set-cookie"]
    bad = client.post("/api/enforce/login", data={"username": "developer01", "password": "CloudDemo123!", "next": "https://evil.com"}, follow_redirects=False)
    assert bad.status_code == 400
    assert client.post("/api/enforce/login", data={"username": "developer01", "password": "x"}).status_code == 401


def test_cannot_query_other_users_access(client):
    t = _login(client)
    with TestingSessionLocal() as db:
        oid = db.query(models.User).filter(models.User.username == "other").first().id
        app_id = db.query(models.Application).first().id
    h = {"authorization": f"Bearer {t}"}
    assert client.get(f"/api/users/{oid}/access-matrix", headers=h).status_code == 403
    assert client.post("/api/access/check", headers=h, json={"user_id": oid, "application_id": app_id, "action": "READ"}).status_code == 403


def test_only_admin_can_map_hosts(client):
    assert client.put("/api/enforce/applications/1/host", headers={"authorization": f"Bearer {_login(client)}"}, json={"upstream_host": "a.test"}).status_code == 403
