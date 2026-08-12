def login(client, password="CloudDemo123!"):
    return client.post(
        "/api/auth/login",
        json={"username": "developer01", "password": password},
    )


def auth_headers(client):
    token = login(client).json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "healthy",
        "service": "cloudsentinel-backend",
    }


def test_login_valid_credentials(client):
    response = login(client)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["user"]["username"] == "developer01"


def test_login_invalid_credentials(client):
    response = login(client, password="wrong")
    assert response.status_code == 401


def test_me_without_token(client):
    response = client.get("/api/auth/me")
    assert response.status_code == 401


def test_me_with_valid_token(client):
    token = login(client).json()["access_token"]
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["username"] == "developer01"


def test_list_users(client):
    response = client.get("/api/users")
    assert response.status_code == 200
    assert response.json()[0]["username"] == "developer01"
    assert "password_hash" not in response.json()[0]


def test_get_valid_user(client):
    user_id = client.get("/api/users").json()[0]["id"]
    response = client.get(f"/api/users/{user_id}")
    assert response.status_code == 200
    assert response.json()["id"] == user_id


def test_get_invalid_user(client):
    response = client.get("/api/users/9999")
    assert response.status_code == 404


def test_list_applications(client):
    response = client.get("/api/applications")
    assert response.status_code == 200
    assert "Email" in {item["name"] for item in response.json()}


def test_user_posture(client):
    user_id = client.get("/api/users").json()[0]["id"]
    response = client.get(f"/api/users/{user_id}/posture")
    assert response.status_code == 200
    body = response.json()
    assert body["user"]["username"] == "developer01"
    assert body["devices"][0]["device_id"] == "DEV-DEV-001"
    assert {tag["tag"] for tag in body["security_tags"]} >= {"TRUSTED_DEVICE", "MFA_VERIFIED"}
    assert body["posture_status"] in {"HEALTHY", "MEDIUM", "HIGH", "CRITICAL"}


def test_telemetry_ingestion_valid(client):
    user_id = client.get("/api/users").json()[0]["id"]
    response = client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 20,
            "data_download_mb": 50,
            "failed_logins": 0,
            "unique_applications": 2,
            "access_frequency": 5,
            "login_hour": 10,
            "location": "Pune",
        },
    )
    assert response.status_code == 201
    assert response.json()["requests_per_minute"] == 20
    telemetry = client.get(f"/api/users/{user_id}/telemetry")
    assert telemetry.status_code == 200
    assert telemetry.json()[0]["location"] == "Pune"


def test_telemetry_ingestion_invalid(client):
    user_id = client.get("/api/users").json()[0]["id"]
    response = client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": -1,
            "data_download_mb": 50,
            "failed_logins": 0,
            "unique_applications": 2,
            "access_frequency": 5,
            "login_hour": 10,
            "location": "Pune",
        },
    )
    assert response.status_code == 422


def test_normal_risk_is_low(client):
    user_id = client.get("/api/users").json()[0]["id"]
    client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 20,
            "data_download_mb": 50,
            "failed_logins": 0,
            "unique_applications": 2,
            "access_frequency": 5,
            "login_hour": 10,
            "location": "Pune",
        },
    )
    response = client.get(f"/api/users/{user_id}/risk")
    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] == "LOW"
    assert 0 <= body["risk_score"] <= 100
    assert set(body["components"]) == {"identity", "posture", "behavior", "context"}


def test_attack_like_risk_is_high_or_critical(client):
    user_id = client.get("/api/users").json()[0]["id"]
    client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 180,
            "data_download_mb": 850,
            "failed_logins": 4,
            "unique_applications": 5,
            "access_frequency": 30,
            "login_hour": 2,
            "location": "Singapore",
        },
    )
    response = client.get(f"/api/users/{user_id}/risk")
    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] in {"HIGH", "CRITICAL"}
    assert body["risk_score"] >= 60
    assert body["anomaly"]["is_anomaly"] is True
    assert {"DATA_EXFILTRATION", "NEW_LOCATION"} <= {tag["tag"] for tag in body["tags"]}
    assert body["reasons"]


def test_posture_tags_change_with_attack_like_telemetry(client):
    user_id = client.get("/api/users").json()[0]["id"]
    client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 180,
            "data_download_mb": 850,
            "failed_logins": 4,
            "unique_applications": 5,
            "access_frequency": 30,
            "login_hour": 2,
            "location": "Singapore",
        },
    )
    response = client.get(f"/api/users/{user_id}/posture")
    assert response.status_code == 200
    tags = {tag["tag"] for tag in response.json()["security_tags"]}
    assert {"NEW_LOCATION", "AUTH_ANOMALY", "DATA_EXFILTRATION", "UNUSUAL_ACTIVITY"} <= tags


def _submit_normal_telemetry(client, user_id):
    return client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 20,
            "data_download_mb": 50,
            "failed_logins": 0,
            "unique_applications": 2,
            "access_frequency": 5,
            "login_hour": 10,
            "location": "Pune",
        },
    )


def _submit_attack_telemetry(client, user_id):
    return client.post(
        "/api/telemetry",
        json={
            "user_id": user_id,
            "device_id": "DEV-DEV-001",
            "requests_per_minute": 180,
            "data_download_mb": 850,
            "failed_logins": 4,
            "unique_applications": 5,
            "access_frequency": 30,
            "login_hour": 2,
            "location": "Singapore",
        },
    )


def _app_id_by_name(client, name):
    apps = client.get("/api/applications").json()
    return next(app["id"] for app in apps if app["name"] == name)


def test_access_check_requires_authentication(client):
    user_id = client.get("/api/users").json()[0]["id"]
    _submit_normal_telemetry(client, user_id)
    response = client.post(
        "/api/access/check",
        json={"user_id": user_id, "application_id": _app_id_by_name(client, "Email"), "action": "READ"},
    )
    assert response.status_code == 401


def test_access_check_persists_request_and_audit_event(client):
    user_id = client.get("/api/users").json()[0]["id"]
    _submit_normal_telemetry(client, user_id)
    response = client.post(
        "/api/access/check",
        headers=auth_headers(client),
        json={
            "user_id": user_id,
            "application_id": _app_id_by_name(client, "Customer Database"),
            "action": "READ",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "MFA_REQUIRED"
    assert body["policy_rule"] == "LOW_RISK_CRITICAL_RESOURCE"
    events = client.get("/api/events").json()
    assert events[0]["event_type"] == "MFA_REQUIRED"
    assert events[0]["metadata"]["application"] == "Customer Database"


def test_access_matrix_normal_user_preserves_blast_radius(client):
    user_id = client.get("/api/users").json()[0]["id"]
    _submit_normal_telemetry(client, user_id)
    response = client.get(f"/api/users/{user_id}/access-matrix", headers=auth_headers(client))
    assert response.status_code == 200
    decisions = {item["application"]: item["decision"] for item in response.json()}
    assert decisions["Email"] == "ALLOW"
    assert decisions["HR Portal"] == "ALLOW"
    assert decisions["Cloud Storage"] == "ALLOW"
    assert decisions["Customer Database"] == "MFA_REQUIRED"
    assert decisions["Admin Console"] == "MFA_REQUIRED"


def test_access_matrix_attack_like_user_restricts_sensitive_resources_only(client):
    user_id = client.get("/api/users").json()[0]["id"]
    _submit_attack_telemetry(client, user_id)
    response = client.get(f"/api/users/{user_id}/access-matrix", headers=auth_headers(client))
    assert response.status_code == 200
    decisions = {item["application"]: item["decision"] for item in response.json()}
    assert decisions["Email"] == "MFA_REQUIRED"
    assert decisions["HR Portal"] == "MFA_REQUIRED"
    assert decisions["Cloud Storage"] in {"READ_ONLY", "DENY"}
    assert decisions["Customer Database"] == "DENY"
    assert decisions["Admin Console"] == "DENY"
    assert "ALLOW" in set(decisions.values()) or "MFA_REQUIRED" in set(decisions.values())


def test_access_check_dangerous_action_denied_for_high_risk_storage(client):
    user_id = client.get("/api/users").json()[0]["id"]
    _submit_attack_telemetry(client, user_id)
    response = client.post(
        "/api/access/check",
        headers=auth_headers(client),
        json={
            "user_id": user_id,
            "application_id": _app_id_by_name(client, "Cloud Storage"),
            "action": "DELETE",
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"


def test_simulation_attack_status_and_reset_flow(client):
    user_id = client.get("/api/users").json()[0]["id"]
    headers = auth_headers(client)
    _submit_normal_telemetry(client, user_id)

    normal_risk = client.get(f"/api/users/{user_id}/risk").json()
    normal_matrix = client.get(f"/api/users/{user_id}/access-matrix", headers=headers).json()
    normal_decisions = {item["application"]: item["decision"] for item in normal_matrix}
    assert normal_risk["risk_level"] == "LOW"
    assert normal_decisions["Email"] == "ALLOW"
    assert normal_decisions["Admin Console"] == "MFA_REQUIRED"

    attack = client.post("/api/simulation/attack", headers=headers, json={"user_id": user_id})
    assert attack.status_code == 200
    attack_body = attack.json()
    assert attack_body["simulation_active"] is True
    assert attack_body["state"] == "COMPROMISED"
    assert attack_body["risk_level"] in {"HIGH", "CRITICAL"}
    attack_decisions = {item["application"]: item["decision"] for item in attack_body["access_matrix"]}
    assert attack_decisions["Email"] in {"ALLOW", "MFA_REQUIRED"}
    assert attack_decisions["HR Portal"] == "MFA_REQUIRED"
    assert attack_decisions["Cloud Storage"] in {"READ_ONLY", "DENY"}
    assert attack_decisions["Customer Database"] == "DENY"
    assert attack_decisions["Admin Console"] == "DENY"

    status = client.get(f"/api/simulation/status/{user_id}", headers=headers)
    assert status.status_code == 200
    assert status.json()["state"] == "COMPROMISED"

    repeat = client.post("/api/simulation/attack", headers=headers, json={"user_id": user_id})
    assert repeat.status_code == 200
    assert repeat.json()["state"] == "COMPROMISED"

    posture = client.get(f"/api/users/{user_id}/posture").json()
    tags = {tag["tag"] for tag in posture["security_tags"]}
    assert {"NEW_DEVICE", "NEW_LOCATION", "DATA_EXFILTRATION", "THREAT_DETECTED"} <= tags

    events = client.get("/api/events").json()
    event_types = {event["event_type"] for event in events}
    assert "ACCOUNT_COMPROMISE_SIMULATED" in event_types
    assert "DATA_EXFILTRATION_DETECTED" in event_types
    assert "POLICY_REEVALUATED" in event_types

    reset = client.post("/api/simulation/reset", headers=headers, json={"user_id": user_id})
    assert reset.status_code == 200
    reset_body = reset.json()
    assert reset_body["simulation_active"] is False
    assert reset_body["state"] == "NORMAL"
    assert reset_body["risk_level"] == "LOW"
    reset_decisions = {item["application"]: item["decision"] for item in reset_body["access_matrix"]}
    assert reset_decisions["Email"] == "ALLOW"
    assert reset_decisions["Cloud Storage"] == "ALLOW"
    assert reset_decisions["Admin Console"] == "MFA_REQUIRED"

    reset_status = client.get(f"/api/simulation/status/{user_id}", headers=headers)
    assert reset_status.json()["state"] == "NORMAL"
