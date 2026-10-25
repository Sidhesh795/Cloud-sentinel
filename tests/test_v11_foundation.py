from backend import models
from backend.auth.auth import hash_password
from tests.conftest import TestingSessionLocal


DEMO_PASSWORD = "CloudDemo123!"


def login(client, username="developer01"):
    return client.post("/api/auth/login", json={"username": username, "password": DEMO_PASSWORD}).json()


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


def ensure_admin():
    db = TestingSessionLocal()
    try:
        org = db.query(models.Organization).filter_by(slug="cloudsentinel-demo").first()
        admin = db.query(models.User).filter_by(username="admin01").first()
        if admin is None:
            admin = models.User(
                organization_id=org.id,
                username="admin01",
                password_hash=hash_password(DEMO_PASSWORD),
                display_name="Avery Shah",
                role="admin",
                email="avery.shah@cloudsentinel.demo",
                status="ACTIVE",
                is_active=True,
            )
            db.add(admin)
            db.flush()
        else:
            admin.organization_id = org.id
            admin.role = "admin"
            admin.status = "ACTIVE"
            admin.is_active = True
        db.commit()
    finally:
        db.close()


def test_organization_context_and_mongodb_health(client):
    token = login(client)["access_token"]
    org = client.get("/api/organization", headers=auth_headers(token))
    assert org.status_code == 200
    assert org.json()["name"] == "CloudSentinel Demo"

    mongo = client.get("/api/health/mongodb")
    assert mongo.status_code == 200
    assert mongo.json()["database"] == "cloudsentinel"


def test_admin_user_lifecycle_and_role_authorization(client):
    ensure_admin()
    developer = login(client)
    forbidden = client.post(
        "/api/admin/users",
        headers=auth_headers(developer["access_token"]),
        json={
            "username": "blocked-admin",
            "password": DEMO_PASSWORD,
            "email": "blocked@cloudsentinel.demo",
            "display_name": "Blocked Admin",
            "role": "ADMIN",
        },
    )
    assert forbidden.status_code == 403

    admin = login(client, "admin01")
    create = client.post(
        "/api/admin/users",
        headers=auth_headers(admin["access_token"]),
        json={
            "username": "newuser01",
            "password": DEMO_PASSWORD,
            "email": "newuser01@cloudsentinel.demo",
            "display_name": "New User",
            "role": "DEVELOPER",
        },
    )
    assert create.status_code == 201
    user_id = create.json()["id"]
    assert "password_hash" not in create.json()

    update = client.patch(
        f"/api/admin/users/{user_id}",
        headers=auth_headers(admin["access_token"]),
        json={"status": "SUSPENDED", "role": "EMPLOYEE"},
    )
    assert update.status_code == 200
    assert update.json()["status"] == "SUSPENDED"

    disabled = client.delete(f"/api/admin/users/{user_id}", headers=auth_headers(admin["access_token"]))
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "DISABLED"


def test_device_registration_heartbeat_posture_and_storage(client):
    ensure_admin()
    admin = login(client, "admin01")
    headers = auth_headers(admin["access_token"])
    user_id = client.get("/api/admin/users", headers=headers).json()[0]["id"]

    registered = client.post(
        "/api/devices/register",
        headers=headers,
        json={
            "user_id": user_id,
            "device_name": "John's Laptop",
            "hostname": "john-win11",
            "platform": "Windows",
            "platform_version": "Windows 11",
            "agent_version": "0.1.0",
        },
    )
    assert registered.status_code == 201
    device_id = registered.json()["device_id"]
    assert registered.json()["agent_registration_token"]

    heartbeat = client.post(
        f"/api/devices/{device_id}/heartbeat",
        headers=headers,
        json={"agent_version": "0.1.1"},
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "ONLINE"
    assert heartbeat.json()["next_heartbeat_seconds"] == 30

    posture = client.post(
        f"/api/devices/{device_id}/posture",
        headers=headers,
        json={
            "os": "Windows",
            "os_version": "Windows 11",
            "firewall_enabled": True,
            "encryption_enabled": True,
            "security_product_active": True,
            "patch_state": "CURRENT",
        },
    )
    assert posture.status_code == 200
    assert posture.json()["posture_status"] == "HEALTHY"

    devices = client.get("/api/devices", headers=headers)
    assert devices.status_code == 200
    assert device_id in {item["device_id"] for item in devices.json()}

    events = client.get("/api/events", headers=headers)
    event_types = {item["event_type"] for item in events.json()}
    assert "DEVICE_REGISTERED" in event_types
    assert "DEVICE_ONLINE" in event_types

    telemetry = client.get(f"/api/users/{user_id}/telemetry", headers=headers)
    assert telemetry.status_code == 200
    assert telemetry.json()[0]["source"] in {"AGENT", "SIMULATION"}
