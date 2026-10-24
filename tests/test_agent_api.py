from datetime import datetime, timedelta, timezone

import pytest

from backend import models
from backend.auth.auth import hash_password
from tests.conftest import TestingSessionLocal


@pytest.fixture()
def admin_headers(client):
    with TestingSessionLocal() as db:
        org = db.query(models.Organization).first()
        db.add(
            models.User(
                organization_id=org.id, username="admin_t", password_hash=hash_password("AdminPass12345"),
                display_name="Admin T", role="admin", email="admin_t@example.com", is_active=True,
            )
        )
        db.commit()
    token = client.post("/api/auth/login", json={"username": "admin_t", "password": "AdminPass12345"}).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _enroll(client, admin_headers, host="LAPTOP-1"):
    tok = client.post("/api/agent/enrollment-tokens", json={}, headers=admin_headers).json()["token"]
    body = {"token": tok, "device_name": host, "hostname": host, "platform": "Windows", "platform_version": "Win11", "agent_version": "0.1.0"}
    return tok, body, client.post("/api/agent/enroll", json=body)


def test_non_admin_cannot_create_token(client):
    t = client.post("/api/auth/login", json={"username": "developer01", "password": "CloudDemo123!"}).json()["access_token"]
    assert client.post("/api/agent/enrollment-tokens", json={}, headers={"Authorization": f"Bearer {t}"}).status_code == 403


def test_enroll_heartbeat_posture_flow(client, admin_headers):
    _, _, r = _enroll(client, admin_headers)
    assert r.status_code == 201
    dev = {"Authorization": f"Bearer {r.json()['device_secret']}"}
    assert client.post("/api/agent/heartbeat", json={"agent_version": "0.1.0"}, headers=dev).status_code == 200
    ok = client.post("/api/agent/posture", headers=dev, json={
        "os": "Windows", "os_version": "11", "firewall_enabled": True, "encryption_enabled": True,
        "security_product_active": True, "patch_state": "UP_TO_DATE"})
    assert ok.json()["posture_status"] == "HEALTHY"
    bad = client.post("/api/agent/posture", headers=dev, json={
        "os": "Windows", "os_version": "11", "firewall_enabled": False, "patch_state": "UP_TO_DATE"})
    assert bad.json()["posture_status"] == "WARNING"


def test_enrollment_token_is_single_use(client, admin_headers):
    _, body, first = _enroll(client, admin_headers)
    assert first.status_code == 201
    assert client.post("/api/agent/enroll", json=body).status_code == 401


def test_expired_token_rejected(client, admin_headers):
    tok, body, _ = _enroll(client, admin_headers, "H2")
    tok2 = client.post("/api/agent/enrollment-tokens", json={}, headers=admin_headers).json()["token"]
    with TestingSessionLocal() as db:
        for row in db.query(models.EnrollmentToken).all():
            row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    assert client.post("/api/agent/enroll", json={**body, "token": tok2}).status_code == 401


def test_invalid_credentials_rejected(client, admin_headers):
    assert client.post("/api/agent/heartbeat", json={}).status_code == 401
    assert client.post("/api/agent/heartbeat", json={}, headers={"Authorization": "Bearer csd_nope"}).status_code == 401
    assert client.post("/api/agent/heartbeat", json={}, headers=admin_headers).status_code == 401


def test_revoked_device_loses_access(client, admin_headers):
    _, _, r = _enroll(client, admin_headers)
    dev = {"Authorization": f"Bearer {r.json()['device_secret']}"}
    assert client.post(f"/api/agent/devices/{r.json()['device_id']}/revoke", headers=admin_headers).status_code == 204
    assert client.post("/api/agent/heartbeat", json={}, headers=dev).status_code == 401


def test_reenroll_rotates_secret_same_device(client, admin_headers):
    _, _, a = _enroll(client, admin_headers)
    _, _, b = _enroll(client, admin_headers)
    assert a.json()["device_id"] == b.json()["device_id"]
    assert client.post("/api/agent/heartbeat", json={}, headers={"Authorization": f"Bearer {a.json()['device_secret']}"}).status_code == 401
