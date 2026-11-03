import pytest

from backend import config
from backend.security.ratelimit import client_ip, limiter


def _login(c, user="developer01", pw="wrong"):
    return c.post("/api/auth/login", json={"username": user, "password": pw})


def test_login_ip_limit(client, monkeypatch):
    monkeypatch.setattr(config, "RL_LOGIN_PER_MIN", 3)
    limiter.reset()
    monkeypatch.setattr(config, "LOGIN_USER_FAILS", 1000)
    codes = [_login(client.anon, f"nobody{i}").status_code for i in range(5)]
    assert codes[:3] == [401, 401, 401]
    r = _login(client.anon, "nobody9")
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0


def test_login_username_lockout_only_on_failures(client, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_USER_FAILS", 3)
    for _ in range(3):
        assert _login(client.anon).status_code == 401
    assert _login(client.anon).status_code == 429
    assert _login(client.anon, "developer01", "CloudDemo123!").status_code == 429
    assert _login(client.anon, "other", "x").status_code == 401


def test_successful_logins_do_not_lock_user(client, monkeypatch):
    monkeypatch.setattr(config, "LOGIN_USER_FAILS", 2)
    for _ in range(5):
        assert _login(client.anon, "developer01", "CloudDemo123!").status_code == 200


def test_mfa_verify_ip_limit(client, monkeypatch):
    monkeypatch.setattr(config, "RL_MFA_PER_MIN", 2)
    body = {"mfa_token": "x", "code": "123456"}
    assert client.anon.post("/api/auth/mfa/verify", json=body).status_code == 401
    assert client.anon.post("/api/auth/mfa/verify", json=body).status_code == 401
    assert client.anon.post("/api/auth/mfa/verify", json=body).status_code == 429


def test_enroll_ip_limit(client, monkeypatch):
    monkeypatch.setattr(config, "RL_ENROLL_PER_MIN", 2)
    body = {"token": "bad-token-123", "hostname": "h", "platform": "Windows", "platform_version": "11", "device_name": "d", "agent_version": "1"}
    codes = [client.anon.post("/api/agent/enroll", json=body).status_code for _ in range(3)]
    assert codes[-1] == 429 and 429 not in codes[:2]


def test_enforce_form_login_limit(client, monkeypatch):
    monkeypatch.setattr(config, "RL_LOGIN_PER_MIN", 2)
    limiter.reset()
    codes = [client.anon.post("/api/enforce/login", data={"username": f"u{i}", "password": "x"}).status_code for i in range(3)]
    assert codes == [401, 401, 429]


def test_disabled_flag(client, monkeypatch):
    monkeypatch.setattr(config, "RATE_LIMIT_ENABLED", False)
    monkeypatch.setattr(config, "RL_LOGIN_PER_MIN", 1)
    assert all(_login(client.anon, f"n{i}").status_code == 401 for i in range(5))


def test_window_expires(monkeypatch):
    import backend.security.ratelimit as rl
    t = [1000.0]
    monkeypatch.setattr(rl.time, "monotonic", lambda: t[0])
    limiter.reset()
    limiter.check("k", 1, 10)
    with pytest.raises(Exception):
        limiter.check("k", 1, 10)
    t[0] += 11
    limiter.check("k", 1, 10)


def test_client_ip_trusted_hops(monkeypatch):
    class R:
        headers = {"x-forwarded-for": "6.6.6.6, 1.2.3.4"}
        client = type("C", (), {"host": "10.0.0.1"})()
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 0)
    assert client_ip(R) == "10.0.0.1"
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 1)
    assert client_ip(R) == "1.2.3.4"
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 2)
    assert client_ip(R) == "6.6.6.6"
    monkeypatch.setattr(config, "TRUSTED_PROXY_HOPS", 3)
    assert client_ip(R) == "10.0.0.1"
