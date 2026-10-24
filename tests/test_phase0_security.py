import importlib

import pytest

from backend import config


def test_demo_login_blocked_when_demo_mode_off(client, monkeypatch):
    from backend.auth import auth

    monkeypatch.setattr(auth, "DEMO_MODE", False)
    r = client.post("/api/auth/login", json={"username": "admin01", "password": "CloudDemo123!"})
    assert r.status_code == 401


def test_wrong_password_rejected_for_existing_demo_user(client):
    r = client.post("/api/auth/login", json={"username": "developer01", "password": "wrong"})
    assert r.status_code == 401


def test_seed_endpoint_requires_admin(client):
    assert client.post("/api/seed").status_code in (401, 403, 404)


def test_production_requires_strong_jwt_secret(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("CLOUDSENTINEL_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError):
        importlib.reload(config)
    monkeypatch.setenv("APP_ENV", "development")
    importlib.reload(config)
