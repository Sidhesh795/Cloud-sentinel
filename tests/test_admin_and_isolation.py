from backend import models
from backend.auth.auth import hash_password
from tests.conftest import TestingSessionLocal


DEMO_PASSWORD = "CloudDemo123!"


USERS = [
    ("admin01", "Avery Shah", "admin", "avery.shah@cloudsentinel.demo", "DEV-ADMIN-001"),
    ("employee01", "Marcus Lee", "employee", "marcus.lee@cloudsentinel.demo", "DEV-EMP-001"),
    ("analyst01", "Sara Iyer", "analyst", "sara.iyer@cloudsentinel.demo", "DEV-ANALYST-001"),
]


def login_as(client, username):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": DEMO_PASSWORD},
    ).json()


def headers(token):
    return {"Authorization": f"Bearer {token}"}


def ensure_demo_users():
    db = TestingSessionLocal()
    try:
        for username, display_name, role, email, device_id in USERS:
            existing = db.query(models.User).filter_by(username=username).first()
            if existing:
                continue
            user = models.User(
                username=username,
                password_hash=hash_password(DEMO_PASSWORD),
                display_name=display_name,
                role=role,
                email=email,
                device_id=device_id,
                is_active=True,
            )
            db.add(user)
            db.flush()
            device = models.Device(
                device_id=device_id,
                user_id=user.id,
                os="Windows",
                os_version="Windows 11 Enterprise 23H2",
                trusted_device=True,
                os_compliant=True,
                av_active=True,
                location="Pune",
            )
            db.add(device)
            db.flush()
            db.add(
                models.Telemetry(
                    user_id=user.id,
                    device_id=device.id,
                    requests_per_minute=20,
                    data_download_mb=50,
                    failed_logins=0,
                    unique_applications=2,
                    access_frequency=5,
                    login_hour=10,
                    location="Pune",
                )
            )
            db.add(models.SimulationState(user_id=user.id, simulation_active=False, state="NORMAL"))
        db.commit()
    finally:
        db.close()


def access_matrix(client, token, user_id):
    response = client.get(f"/api/users/{user_id}/access-matrix", headers=headers(token))
    assert response.status_code == 200
    return {item["application"]: item["decision"] for item in response.json()}


def reset_user(client, token, user_id):
    response = client.post("/api/simulation/reset", headers=headers(token), json={"user_id": user_id})
    assert response.status_code == 200
    return response.json()


def attack_user(client, token, user_id):
    response = client.post("/api/simulation/attack", headers=headers(token), json={"user_id": user_id})
    assert response.status_code == 200
    return response.json()


def test_admin_normal_access_across_all_clouds(client):
    ensure_demo_users()
    admin = login_as(client, "admin01")
    token = admin["access_token"]
    user_id = admin["user"]["id"]
    reset = reset_user(client, token, user_id)
    assert reset["risk_level"] == "LOW"
    matrix = {item["application"]: item["decision"] for item in reset["access_matrix"]}
    assert matrix == {
        "Customer Database": "ALLOW",
        "Admin Console": "ALLOW",
        "Email": "ALLOW",
        "HR Portal": "ALLOW",
        "Analytics Service": "ALLOW",
        "Cloud Storage": "ALLOW",
    }


def test_admin_compromised_retains_privileged_authorization_with_step_up(client):
    ensure_demo_users()
    admin = login_as(client, "admin01")
    token = admin["access_token"]
    user_id = admin["user"]["id"]
    reset_user(client, token, user_id)
    attack = attack_user(client, token, user_id)
    assert attack["risk_level"] in {"HIGH", "CRITICAL"}
    matrix = {item["application"]: item["decision"] for item in attack["access_matrix"]}
    assert matrix["Customer Database"] == "MFA_REQUIRED"
    assert matrix["Admin Console"] == "MFA_REQUIRED"
    assert matrix["Cloud Storage"] == "MFA_REQUIRED"
    assert matrix["Analytics Service"] == "MFA_REQUIRED"
    assert matrix["Email"] == "ALLOW"
    assert matrix["HR Portal"] == "ALLOW"
    assert "DENY" not in set(matrix.values())


def test_non_admin_compromised_behavior_unchanged(client):
    ensure_demo_users()
    for username in ["developer01", "employee01", "analyst01"]:
        account = login_as(client, username)
        token = account["access_token"]
        user_id = account["user"]["id"]
        reset_user(client, token, user_id)
        attack = attack_user(client, token, user_id)
        matrix = {item["application"]: item["decision"] for item in attack["access_matrix"]}
        assert attack["risk_level"] in {"HIGH", "CRITICAL"}
        assert matrix["Customer Database"] == "DENY"
        assert matrix["Admin Console"] == "DENY"
        assert matrix["Cloud Storage"] in {"READ_ONLY", "DENY"}
        reset = reset_user(client, token, user_id)
        assert reset["risk_level"] == "LOW"


def test_simulation_is_self_only_and_user_isolated(client):
    ensure_demo_users()
    admin = login_as(client, "admin01")
    developer = login_as(client, "developer01")
    employee = login_as(client, "employee01")
    analyst = login_as(client, "analyst01")

    forbidden = client.post(
        "/api/simulation/attack",
        headers=headers(developer["access_token"]),
        json={"user_id": admin["user"]["id"]},
    )
    assert forbidden.status_code == 403

    for account in [developer, employee, analyst, admin]:
        reset_user(client, account["access_token"], account["user"]["id"])

    attack = attack_user(client, admin["access_token"], admin["user"]["id"])
    assert attack["state"] == "COMPROMISED"

    for account in [developer, employee, analyst]:
        status = client.get(
            f"/api/simulation/status/{account['user']['id']}",
            headers=headers(account["access_token"]),
        )
        assert status.status_code == 200
        assert status.json()["state"] == "NORMAL"
        risk = client.get(f"/api/users/{account['user']['id']}/risk").json()
        assert risk["risk_level"] == "LOW"

    reset = reset_user(client, admin["access_token"], admin["user"]["id"])
    assert reset["state"] == "NORMAL"
    assert reset["risk_level"] == "LOW"
