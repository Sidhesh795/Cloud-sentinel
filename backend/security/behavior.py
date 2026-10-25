import statistics
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from backend import models
from backend.security.anomaly import AnomalyAssessment, heuristic_behavior_risk, telemetry_to_features

MIN_SAMPLES = 30
WINDOW_DAYS = 14
SNAPSHOT_INTERVAL = timedelta(minutes=5)
FLAGGED_INTERVAL = timedelta(seconds=60)
# (index in FEATURES, label, minimum scale so tiny variance cannot cause hair-trigger alerts)
COUNT_FEATURES = [(0, "requests/min", 5), (1, "download MB", 25), (2, "failed logins", 1), (3, "distinct apps/hour", 1), (4, "requests/hour", 3)]
_hits: dict[int, deque] = defaultdict(lambda: deque(maxlen=5000))


def record_hit(user_id: int, app_id: int) -> None:
    _hits[user_id].append((time.time(), app_id))


def reset_hits() -> None:
    _hits.clear()


def record_login(db: Session, username: str, user: models.User | None, ip: str | None) -> None:
    db.add(models.LoginAttempt(user_id=user.id if user else None, username=username[:150], success=user is not None, ip=ip))
    db.commit()


def live_features(db: Session, user: models.User, now: datetime) -> list[float]:
    t = now.timestamp()
    hits = [h for h in _hits.get(user.id, ()) if t - h[0] <= 3600]
    failed = (
        db.query(func.count(models.LoginAttempt.id))
        .filter(models.LoginAttempt.user_id.is_(None) | (models.LoginAttempt.user_id == user.id))
        .filter(models.LoginAttempt.username == user.username, models.LoginAttempt.success.is_(False))
        .filter(models.LoginAttempt.timestamp >= now - timedelta(minutes=15))
        .scalar()
        or 0
    )
    return [
        float(sum(1 for h in hits if t - h[0] <= 60)),
        0.0,
        float(failed),
        float(len({h[1] for h in hits})),
        float(len(hits)),
        float(now.hour),
    ]


def baseline_rows(db: Session, user_id: int, now: datetime) -> list[models.Telemetry]:
    fp = db.query(models.AnomalyFeedback.telemetry_id).filter(models.AnomalyFeedback.verdict == "FALSE_POSITIVE")
    bad = db.query(models.AnomalyFeedback.telemetry_id).filter(models.AnomalyFeedback.verdict == "CONFIRMED")
    return (
        db.query(models.Telemetry)
        .filter(models.Telemetry.user_id == user_id, models.Telemetry.source == "LIVE")
        .filter(models.Telemetry.timestamp >= now - timedelta(days=WINDOW_DAYS))
        .filter(or_(models.Telemetry.anomaly_flag.is_(False), models.Telemetry.id.in_(fp)))
        .filter(~models.Telemetry.id.in_(bad))
        .order_by(models.Telemetry.timestamp.desc())
        .limit(500)
        .all()
    )


def baseline_stats(rows: list) -> dict:
    cols = list(zip(*[telemetry_to_features(r) for r in rows])) if rows else []
    out = {}
    for idx, label, floor in COUNT_FEATURES:
        if cols:
            med = statistics.median(cols[idx])
            mad = statistics.median([abs(v - med) for v in cols[idx]])
            out[label] = {"median": round(med, 2), "scale": round(max(1.4826 * mad, floor), 2)}
    if cols:
        out["login hours"] = sorted({int(h) for h in cols[5]})
    return out


def _hour_gap(hour: int, usual: list[int]) -> int:
    return min(min(abs(hour - u), 24 - abs(hour - u)) for u in usual)


def assess_live(features: list[float], rows: list) -> AnomalyAssessment:
    n = len(rows)
    if n < MIN_SAMPLES:
        risk = heuristic_behavior_risk(features)
        return AnomalyAssessment(risk >= 60, round(risk / 100, 2), risk, f"Learning baseline ({n}/{MIN_SAMPLES} samples); default thresholds applied")
    stats = baseline_stats(rows)
    risk, notes = 5.0, []
    for idx, label, _ in COUNT_FEATURES:
        s = stats[label]
        z = (features[idx] - s["median"]) / s["scale"]
        if z >= 3:
            risk += min(60.0, 10 + (z - 3) * 10)
            notes.append((z, f"{label} {features[idx]:g} vs usual {s['median']:g}"))
    gap = _hour_gap(int(features[5]), stats["login hours"])
    if gap >= 4:
        risk += 10 + (5 if gap >= 8 else 0)
        notes.append((gap / 2, f"activity at {int(features[5])}:00 UTC, outside usual hours"))
    risk = int(min(100, risk))
    top = tuple(text for _, text in sorted(notes, reverse=True)[:3])
    if risk >= 60:
        reason = "Behavior deviates from this user's baseline: " + "; ".join(top)
    elif risk >= 30:
        reason = "Behavior is unusual for this user: " + "; ".join(top)
    else:
        reason = "Behavior is consistent with this user's baseline"
    return AnomalyAssessment(risk >= 60, round(risk / 100, 2), risk, reason, top)


def _maybe_store(db: Session, user_id: int, tel: models.Telemetry, flagged: bool, now: datetime) -> None:
    q = db.query(func.max(models.Telemetry.timestamp)).filter(models.Telemetry.user_id == user_id, models.Telemetry.source == "LIVE")

    def _age(last):
        if last is None:
            return None
        return now - (last if last.tzinfo else last.replace(tzinfo=timezone.utc))

    age = _age(q.scalar())
    due = age is None or age >= SNAPSHOT_INTERVAL
    if not due and flagged:
        flagged_age = _age(q.filter(models.Telemetry.anomaly_flag.is_(True)).scalar())
        due = flagged_age is None or flagged_age >= FLAGGED_INTERVAL
    if due:
        db.add(tel)


def live_context(db: Session, user: models.User, device: models.Device | None):
    now = datetime.now(timezone.utc)
    features = live_features(db, user, now)
    anomaly = assess_live(features, baseline_rows(db, user.id, now))
    tel = models.Telemetry(
        organization_id=user.organization_id, user_id=user.id, device_id=device.id if device else None,
        requests_per_minute=int(features[0]), data_download_mb=features[1], failed_logins=int(features[2]),
        unique_applications=int(features[3]), access_frequency=int(features[4]), login_hour=int(features[5]),
        location=(device.location if device and device.location else "Unknown"), event_type="LIVE_SNAPSHOT",
        source="LIVE", anomaly_flag=anomaly.is_anomaly, timestamp=now,
        metadata_json={"behavior_risk": anomaly.behavior_risk, "explanations": list(anomaly.explanations)},
    )
    _maybe_store(db, user.id, tel, anomaly.is_anomaly, now)
    return tel, anomaly
