import pytest

from backend import models
from backend.auth.auth import hash_password
from tests.conftest import TestingSessionLocal

PW = "CloudDemo123!"
LEGACY_GET = [
    "/api/users", "/api/users/1", "/api/users/1/posture", "/api/users/1/risk",
    "/api/users/1/risk-history", "/api/users/1/telemetry", "/api/users/1/events",
    "/api/events", "/api/applications", "/api/applications/1",
]


def _mk(db, org_id, username, role):
    u = models.User(organization_id=org_id, username=username, password_hash=hash_password(PW),
                    display_name=username, role=role, email=f"{username}@example.com", is_active=True)
    db.add(u)
    db.flush()
    return u


@pytest.fixture()
def world(client):
    with TestingSessionLocal() as db:
        org1 = db.query(models.User).filter_by(username="developer01").first().organization_id
        org2 = models.Organization(name="Other", slug="other-org", status="ACTIVE", environment="PROD")
        db.add(org2)
        db.flush()
        _mk(db, org1, "admin1", "ADMIN")
        peer = _mk(db, org1, "peer1", "developer")
        foreign = _mk(db, org2.id, "foreign1", "developer")
        foreign_admin = _mk(db, org2.id, "fadmin", "ADMIN")
        db.add(models.SecurityEvent(organization_id=org2.id, user_id=foreign.id, event_type="X_FOREIGN",
                                    severity="LOW", description="m"))
        db.commit()
        return {"peer": peer.id, "foreign": foreign.id, "org1": org1}


def _h(client, username):
    t = client.post("/api/auth/login", json={"username": username, "password": PW}).json()["access_token"]
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.parametrize("path", LEGACY_GET)
def test_legacy_get_requires_auth(client, path):
    assert client.anon.get(path).status_code == 401


def test_telemetry_post_requires_auth(client):
    assert client.anon.post("/api/telemetry", json={}).status_code == 401


def test_user_sees_only_self(client, world):
    me = client.get("/api/auth/me").json()["id"]
    assert [u["id"] for u in client.get("/api/users").json()] == [me]
    assert client.get(f"/api/users/{world['peer']}").status_code == 404
    assert client.get(f"/api/users/{world['peer']}/risk").status_code == 404
    assert client.get(f"/api/users/{world['peer']}/telemetry").status_code == 404


def test_admin_sees_own_org_only(client, world):
    h = _h(client, "admin1")
    ids = {u["id"] for u in client.get("/api/users", headers=h).json()}
    assert world["peer"] in ids and world["foreign"] not in ids
    assert client.get(f"/api/users/{world['peer']}", headers=h).status_code == 200
    for sub in ("", "/posture", "/risk-history", "/telemetry", "/events"):
        assert client.get(f"/api/users/{world['foreign']}{sub}", headers=h).status_code == 404


def test_events_are_org_scoped(client, world):
    types = {e["event_type"] for e in client.get("/api/events", headers=_h(client, "admin1")).json()}
    assert "X_FOREIGN" not in types
    types = {e["event_type"] for e in client.get("/api/events", headers=_h(client, "fadmin")).json()}
    assert "X_FOREIGN" in types


def test_telemetry_post_cross_user_and_cross_org_blocked(client, world):
    body = {"device_id": "DEV-DEV-001", "requests_per_minute": 1, "data_download_mb": 0, "failed_logins": 0,
            "unique_applications": 1, "access_frequency": 1, "login_hour": 10, "location": "Pune",
            "event_type": "T", "source": "TEST"}
    assert client.post("/api/telemetry", json={**body, "user_id": world["peer"]}).status_code == 404
    assert client.post("/api/telemetry", json={**body, "user_id": world["foreign"]},
                       headers=_h(client, "admin1")).status_code == 404
