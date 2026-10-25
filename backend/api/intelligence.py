from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend import models
from backend.auth.auth import require_admin_or_security
from backend.database import get_db
from backend.security.behavior import MIN_SAMPLES, baseline_rows, baseline_stats

router = APIRouter(prefix="/intelligence", tags=["intelligence"])


def _user(db: Session, admin: models.User, user_id: int) -> models.User:
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user is None or user.organization_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    return user


@router.get("/users/{user_id}/baseline")
def get_baseline(user_id: int, db: Session = Depends(get_db), admin: models.User = Depends(require_admin_or_security)) -> dict:
    user = _user(db, admin, user_id)
    rows = baseline_rows(db, user.id, datetime.now(timezone.utc))
    return {"user_id": user.id, "samples": len(rows), "required": MIN_SAMPLES, "ready": len(rows) >= MIN_SAMPLES, "features": baseline_stats(rows)}


@router.get("/users/{user_id}/snapshots")
def list_snapshots(
    user_id: int, flagged: bool = False, limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db), admin: models.User = Depends(require_admin_or_security),
) -> list[dict]:
    user = _user(db, admin, user_id)
    q = db.query(models.Telemetry, models.AnomalyFeedback.verdict).outerjoin(
        models.AnomalyFeedback, models.AnomalyFeedback.telemetry_id == models.Telemetry.id
    ).filter(models.Telemetry.user_id == user.id, models.Telemetry.source == "LIVE")
    if flagged:
        q = q.filter(models.Telemetry.anomaly_flag.is_(True))
    return [
        {
            "id": t.id, "timestamp": t.timestamp, "behavior_risk": (t.metadata_json or {}).get("behavior_risk"),
            "explanations": (t.metadata_json or {}).get("explanations", []), "verdict": verdict,
            "requests_per_minute": t.requests_per_minute, "failed_logins": t.failed_logins,
            "unique_applications": t.unique_applications, "access_frequency": t.access_frequency, "login_hour": t.login_hour,
        }
        for t, verdict in q.order_by(models.Telemetry.timestamp.desc()).limit(limit).all()
    ]


class FeedbackBody(BaseModel):
    verdict: str = Field(pattern="^(FALSE_POSITIVE|CONFIRMED)$")


@router.post("/snapshots/{snapshot_id}/feedback", status_code=status.HTTP_204_NO_CONTENT)
def give_feedback(snapshot_id: int, body: FeedbackBody, db: Session = Depends(get_db), admin: models.User = Depends(require_admin_or_security)) -> None:
    tel = db.query(models.Telemetry).filter(models.Telemetry.id == snapshot_id, models.Telemetry.source == "LIVE").first()
    if tel is None or tel.organization_id != admin.organization_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Snapshot not found")
    fb = db.query(models.AnomalyFeedback).filter(models.AnomalyFeedback.telemetry_id == tel.id).first()
    if fb is None:
        db.add(models.AnomalyFeedback(organization_id=tel.organization_id, telemetry_id=tel.id, verdict=body.verdict, created_by_id=admin.id))
    else:
        fb.verdict, fb.created_by_id = body.verdict, admin.id
    db.commit()


@router.get("/metrics")
def metrics(days: int = Query(30, ge=1, le=365), db: Session = Depends(get_db), admin: models.User = Depends(require_admin_or_security)) -> dict:
    since = datetime.now(timezone.utc) - timedelta(days=days)
    org = admin.organization_id
    flagged = db.query(func.count(models.Telemetry.id)).filter(
        models.Telemetry.organization_id == org, models.Telemetry.source == "LIVE",
        models.Telemetry.anomaly_flag.is_(True), models.Telemetry.timestamp >= since).scalar() or 0
    counts = dict(db.query(models.AnomalyFeedback.verdict, func.count(models.AnomalyFeedback.id)).filter(
        models.AnomalyFeedback.organization_id == org, models.AnomalyFeedback.created_at >= since).group_by(models.AnomalyFeedback.verdict).all())
    fp, tp = counts.get("FALSE_POSITIVE", 0), counts.get("CONFIRMED", 0)
    return {
        "days": days, "flagged": flagged, "reviewed": fp + tp, "false_positives": fp, "confirmed": tp,
        "precision": round(tp / (tp + fp), 3) if tp + fp else None,
        "false_positive_rate": round(fp / (tp + fp), 3) if tp + fp else None,
    }
