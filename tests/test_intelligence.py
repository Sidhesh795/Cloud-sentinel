from datetime import datetime, timedelta, timezone

import pytest

from backend import config, models
from backend.api import enforce
from backend.auth.auth import hash_password
from backend.security import behavior
from tests.conftest import TestingSessionLocal

NOW = lambda: datetime.now(timezone.utc)  # noqa: E731


def _row(db, user, rpm=5, hour=10, flag=False, minutes=1, failed=0):
    t = models.Telemetry(
        organization_id=user.organization_id, user_id=user.id, requests_per_minute=rpm, data_download_mb=0.0,
        failed_logins=failed, unique_applications=2, access_frequency=rpm * 2, login_hour=hour, location="X",
        event_type="LIVE_SNAPSHOT", source="LIVE", anomaly_flag=flag, timestamp=NOW() - timedelta(minutes=minutes),
        metadata_json={"behavior_risk": 70 if flag else 5, "explanations": ["requests/min 60 vs usual 5"] if flag else []},
    )
    db.add(t)
    db.flush()
    return t


def _dev(db):
    return db.query(models.User).filter(models.User.username == "developer01").first()


def _seed_baseline(db, user, n=40):
    for i in range(n):
        _row(db, user, rpm=4 + i % 3, hour=9 + i % 3, minutes=10 + i)
    db.commit()


NORMAL = [5.0, 0.0, 0.0, 2.0, 10.0, 10.0]


def test_cold_start_uses_default_thresholds():
    a = behavior.assess_live(NORMAL, [])
    assert "Learning baseline (0/30" in a.reason and not a.is_anomaly


def test_baseline_flags_deviation_with_explanation(client):
    with TestingSessionLocal() as db:
        _seed_baseline(db, _dev(db))
        rows = behavior.baseline_rows(db, _dev(db).id, NOW())
    normal = behavior.assess_live(NORMAL, rows)
    assert normal.behavior_risk < 30 and "consistent" in normal.reason
    spike = behavior.assess_live([60.0, 0.0, 0.0, 2.0, 10.0, 10.0], rows)
    assert spike.is_anomaly and any("requests/min 60 vs usual" in e for e in spike.explanations)
    night = behavior.assess_live([5.0, 0.0, 0.0, 2.0, 10.0, 3.0], rows)
    assert any("outside usual hours" in e for e in night.explanations)


def test_per_user_baseline_differs(client):
    with TestingSessionLocal() as db:
        u = _dev(db)
        for i in range(40):
            _row(db, u, rpm=80 + i % 5, minutes=10 + i)
        db.commit()
        rows = behavior.baseline_rows(db, u.id, NOW())
    assert not behavior.assess_live([85.0, 0.0, 0.0, 2.0, 10.0, 10.0], rows).is_anomaly


def test_flagged_and_confirmed_rows_do_not_poison_baseline_and_fp_feedback_restores(client):
    with TestingSessionLocal() as db:
        u = _dev(db)
        _seed_baseline(db, u, 30)
        flagged = _row(db, u, rpm=60, flag=True)
        db.commit()
        assert len(behavior.baseline_rows(db, u.id, NOW())) == 30
        db.add(models.AnomalyFeedback(organization_id=u.organization_id, telemetry_id=flagged.id, verdict="FALSE_POSITIVE", created_by_id=u.id))
        db.commit()
        assert len(behavior.baseline_rows(db, u.id, NOW())) == 31
        fb = db.query(models.AnomalyFeedback).first()
        fb.verdict = "CONFIRMED"
        db.commit()
        assert len(behavior.baseline_rows(db, u.id, NOW())) == 30


@pytest.fixture()
def admin(client):
    with TestingSessionLocal() as db:
        org = db.query(models.Organization).first()
        db.add(models.User(organization_id=org.id, username="ia", password_hash=hash_password("AdminPass12345"), display_name="IA", role="admin", email="ia@x.com", is_active=True))
        other = models.Organization(name="Other", slug="other", status="ACTIVE", environment="DEMO")
        db.add(other)
        db.flush()
        db.add(models.User(organization_id=other.id, username="oa", password_hash=hash_password("AdminPass12345"), display_name="OA", role="admin", email="oa@x.com", is_active=True))
        db.commit()

    def h(u):
        return {"authorization": "Bearer " + client.post("/api/auth/login", json={"username": u, "password": "AdminPass12345"}).json()["access_token"]}

    return h


def test_intelligence_api_feedback_loop_and_metrics(client, admin):
    with TestingSessionLocal() as db:
        u = _dev(db)
        uid = u.id
        _seed_baseline(db, u, 30)
        sid = _row(db, u, rpm=60, flag=True).id
        db.commit()
    h = admin("ia")
    b = client.get(f"/api/intelligence/users/{uid}/baseline", headers=h).json()
    assert b["ready"] and b["samples"] == 30
    snaps = client.get(f"/api/intelligence/users/{uid}/snapshots?flagged=true", headers=h).json()
    assert [s["id"] for s in snaps] == [sid] and snaps[0]["explanations"]
    assert client.post(f"/api/intelligence/snapshots/{sid}/feedback", headers=h, json={"verdict": "FALSE_POSITIVE"}).status_code == 204
    assert client.get(f"/api/intelligence/users/{uid}/baseline", headers=h).json()["samples"] == 31
    m = client.get("/api/intelligence/metrics", headers=h).json()
    assert m["flagged"] == 1 and m["false_positives"] == 1 and m["false_positive_rate"] == 1.0
    assert client.post(f"/api/intelligence/snapshots/{sid}/feedback", headers=h, json={"verdict": "BAD"}).status_code == 422


def test_intelligence_is_tenant_isolated_and_admin_only(client, admin):
    with TestingSessionLocal() as db:
        uid = _dev(db).id
    assert client.get(f"/api/intelligence/users/{uid}/baseline", headers=admin("oa")).status_code == 404
    t = client.post("/api/auth/login", json={"username": "developer01", "password": "CloudDemo123!"}).json()["access_token"]
    assert client.get(f"/api/intelligence/users/{uid}/baseline", headers={"authorization": f"Bearer {t}"}).status_code == 403


def test_failed_logins_recorded_and_counted(client):
    for _ in range(4):
        client.post("/api/auth/login", json={"username": "developer01", "password": "wrong"})
    with TestingSessionLocal() as db:
        assert db.query(models.LoginAttempt).filter_by(success=False).count() == 4
        assert behavior.live_features(db, _dev(db), NOW())[2] == 4.0


def test_live_enforcement_stores_throttled_snapshots(client, monkeypatch):
    monkeypatch.setattr(config, "LIVE_BEHAVIOR", True)
    monkeypatch.setattr(config, "ENFORCE_CACHE_SECONDS", 0)
    enforce.clear_cache()
    behavior.reset_hits()
    with TestingSessionLocal() as db:
        db.query(models.Application).filter_by(name="Email").first().upstream_host = "email.test"
        db.commit()
    t = client.post("/api/auth/login", json={"username": "developer01", "password": "CloudDemo123!"}).json()["access_token"]
    h = {"x-forwarded-host": "email.test", "authorization": f"Bearer {t}"}
    for _ in range(3):
        assert client.get("/api/enforce/verify", headers=h).status_code == 200
    with TestingSessionLocal() as db:
        rows = db.query(models.Telemetry).filter_by(source="LIVE").all()
        assert len(rows) == 1 and rows[0].requests_per_minute == 1


def test_live_source_cannot_be_injected_via_telemetry_api(client):
    r = client.post("/api/telemetry", json={"user_id": 1, "device_id": "x", "requests_per_minute": 1, "data_download_mb": 0, "failed_logins": 0,
                                            "unique_applications": 1, "access_frequency": 1, "login_hour": 10, "location": "X", "source": "LIVE"})
    assert r.status_code in (404, 422)


def test_live_spike_is_blocked_with_explanation(client, monkeypatch):
    monkeypatch.setattr(config, "LIVE_BEHAVIOR", True)
    monkeypatch.setattr(config, "ENFORCE_CACHE_SECONDS", 0)
    enforce.clear_cache()
    behavior.reset_hits()
    with TestingSessionLocal() as db:
        db.query(models.Application).filter_by(name="Email").first().upstream_host = "email.test"
        _seed_baseline(db, _dev(db))
    t = client.post("/api/auth/login", json={"username": "developer01", "password": "CloudDemo123!"}).json()["access_token"]
    h = {"x-forwarded-host": "email.test", "authorization": f"Bearer {t}"}
    assert client.get("/api/enforce/verify", headers=h).status_code == 200
    for _ in range(45):
        r = client.get("/api/enforce/verify", headers=h)
    assert r.status_code == 403 and "usual" in r.headers["x-cloudsentinel-reason"]
    with TestingSessionLocal() as db:
        ev = db.query(models.SecurityEvent).filter(models.SecurityEvent.event_type != "ACCESS_ALLOWED").order_by(models.SecurityEvent.id.desc()).first()
        assert ev and ev.metadata_json["reasons"]
