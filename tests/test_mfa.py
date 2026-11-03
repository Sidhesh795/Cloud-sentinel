import time

import pytest

from backend import models
from backend.api import enforce
from backend.auth.auth import create_access_token, create_mfa_pending_token
from backend.security import mfa
from tests.conftest import TestingSessionLocal

KEY = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


def test_rfc6238_vectors():
    for t, code in [(59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (2000000000, "279037")]:
        assert mfa.match_step(KEY, code, at=t, window=0) == t // 30
    assert mfa.match_step(KEY, "000000", at=59, window=0) is None


def _code(secret, offset=0):
    return mfa._hotp(secret, int(time.time() // 30) + offset)


@pytest.fixture()
def enrolled(client):
    """developer01 with MFA enabled; returns (secret, recovery_codes)."""
    secret = client.post("/api/mfa/setup").json()["secret"]
    codes = client.post("/api/mfa/enable", json={"code": _code(secret)}).json()["recovery_codes"]
    return secret, codes


def _login(client, secret=None):
    r = client.anon.post("/api/auth/login", json={"username": "developer01", "password": "CloudDemo123!"})
    return r.json()


def test_setup_enable_and_status(client):
    setup = client.post("/api/mfa/setup").json()
    assert setup["otpauth_uri"].startswith("otpauth://totp/CloudSentinel:") and setup["secret"] in setup["otpauth_uri"]
    assert client.get("/api/mfa/status").json()["enabled"] is False
    assert client.post("/api/mfa/enable", json={"code": "000000"}).status_code == 400
    r = client.post("/api/mfa/enable", json={"code": _code(setup["secret"])})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 8
    assert client.get("/api/mfa/status").json() == {"enabled": True, "recovery_codes_remaining": 8}
    assert client.post("/api/mfa/setup").status_code == 409


def test_secret_encrypted_at_rest(client):
    secret = client.post("/api/mfa/setup").json()["secret"]
    with TestingSessionLocal() as db:
        raw = db.query(models.User).filter_by(username="developer01").first().mfa_secret_enc
    assert raw and secret not in raw


def test_login_requires_second_factor(client, enrolled):
    secret, _ = enrolled
    first = _login(client)
    assert first["mfa_required"] is True and first["access_token"] is None and first["mfa_token"]
    pending = {"Authorization": f"Bearer {first['mfa_token']}"}
    assert client.anon.get("/api/auth/me", headers=pending).status_code == 401  # pending token is not an API token
    bad = client.anon.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": "000000"})
    assert bad.status_code == 401
    ok = client.anon.post("/api/auth/mfa/verify", json={"mfa_token": first["mfa_token"], "code": _code(secret, 1)})
    assert ok.status_code == 200 and ok.json()["access_token"]
    me = client.anon.get("/api/auth/me", headers={"Authorization": f"Bearer {ok.json()['access_token']}"})
    assert me.status_code == 200


def test_totp_code_cannot_be_replayed(client, enrolled):
    secret, _ = enrolled
    tok = _login(client)["mfa_token"]
    code = _code(secret, 1)
    assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": code}).status_code == 200
    assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": code}).status_code == 401


def test_recovery_code_is_single_use(client, enrolled):
    _, codes = enrolled
    tok = _login(client)["mfa_token"]
    assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": codes[0].lower()}).status_code == 200
    assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": codes[0]}).status_code == 401
    assert client.get("/api/mfa/status").json()["recovery_codes_remaining"] == 7


def test_lockout_after_repeated_failures(client, enrolled):
    secret, _ = enrolled
    tok = _login(client)["mfa_token"]
    for _ in range(5):
        assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": "111111"}).status_code == 401
    locked = client.anon.post("/api/auth/mfa/verify", json={"mfa_token": tok, "code": _code(secret, 1)})
    assert locked.status_code == 429


def test_wrong_password_never_yields_mfa_token(client, enrolled):
    r = client.anon.post("/api/auth/login", json={"username": "developer01", "password": "nope-nope-nope"})
    assert r.status_code == 401 and "mfa_token" not in r.text


def test_expired_pending_token_rejected(client, enrolled):
    secret, _ = enrolled
    assert client.anon.post("/api/auth/mfa/verify", json={"mfa_token": "garbage", "code": _code(secret)}).status_code == 401


def test_stepup_token_carries_mfa_claim(client, enrolled):
    secret, _ = enrolled
    r = client.post("/api/mfa/stepup", json={"code": _code(secret, 1)})
    assert r.status_code == 200
    from backend.auth.auth import mfa_at_from_token
    assert mfa_at_from_token(r.json()["access_token"])
    assert mfa_at_from_token(create_access_token("developer01")) is None
    assert mfa_at_from_token(create_access_token("developer01", mfa_at=int(time.time()) - 7200)) is None


def test_disable_requires_password_and_code(client, enrolled):
    secret, _ = enrolled
    assert client.post("/api/mfa/disable", json={"password": "wrong-password", "code": _code(secret, 1)}).status_code == 400
    assert client.post("/api/mfa/disable", json={"password": "CloudDemo123!", "code": _code(secret, 1)}).status_code == 204
    assert client.get("/api/mfa/status").json()["enabled"] is False
    assert "mfa_required" in _login(client) and _login(client)["mfa_required"] is False


def test_enforce_mfa_required_is_satisfied_by_stepup(client, enrolled, monkeypatch):
    from backend.security.zero_trust_gateway import evaluate_access as real
    secret, _ = enrolled
    with TestingSessionLocal() as db:
        app = db.query(models.Application).first()
        app.upstream_host = "mfa.test"
        db.commit()

    class P:  # force an MFA_REQUIRED policy decision
        decision, reason, risk_score = "MFA_REQUIRED", "WRITE_ELEVATED_AUTH", 40

    class R:
        reasons: list = []

    class G:
        policy, risk = P(), R()

    monkeypatch.setattr(enforce, "evaluate_access", lambda *a, **k: G())
    monkeypatch.setattr(enforce.config, "REQUIRE_AGENT_DEVICE", False)
    enforce.clear_cache()
    H = {"X-Forwarded-Host": "mfa.test"}
    plain = {**H, "Authorization": "Bearer " + create_access_token("developer01")}
    blocked = client.anon.get("/api/enforce/verify", headers=plain)
    assert blocked.status_code == 403 and blocked.headers["x-cloudsentinel-decision"] == "MFA_REQUIRED"
    stepped = {**H, "Authorization": "Bearer " + create_access_token("developer01", mfa_at=int(time.time()))}
    assert client.anon.get("/api/enforce/verify", headers=stepped).status_code == 200
    # a stale/absent claim does not satisfy it, and non-MFA decisions are never upgraded
    stale = {**H, "Authorization": "Bearer " + create_access_token("developer01", mfa_at=int(time.time()) - 7200)}
    assert client.anon.get("/api/enforce/verify", headers=stale).status_code == 403
    P.decision = "DENY"
    enforce.clear_cache()
    assert client.anon.get("/api/enforce/verify", headers=stepped).status_code == 403


def test_enforce_login_form_flow(client, enrolled):
    secret, _ = enrolled
    page = client.anon.post("/api/enforce/login", data={"username": "developer01", "password": "CloudDemo123!", "next": ""})
    assert "Verification code" in page.text and "cs_session" not in page.headers.get("set-cookie", "")
    tok = page.text.split('name=mfa_token value="')[1].split('"')[0]
    bad = client.anon.post("/api/enforce/login/mfa", data={"mfa_token": tok, "code": "000000", "next": ""})
    assert bad.status_code == 401
    good = client.anon.post("/api/enforce/login/mfa", data={"mfa_token": tok, "code": _code(secret, 1), "next": ""})
    assert good.status_code == 200 and "cs_session" in good.headers["set-cookie"]

