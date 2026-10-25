import html
import logging
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend import config, models
from backend.auth.auth import (
    authenticate_user,
    create_gateway_token,
    require_admin_or_security,
    username_from_token,
)
from backend.database import get_db
from backend.security.behavior import record_hit, record_login
from backend.security.zero_trust_gateway import evaluate_access, primary_device

router = APIRouter(prefix="/enforce", tags=["enforcement"])
logger = logging.getLogger("uvicorn.error")
COOKIE = "cs_session"
_cache: dict[tuple, tuple[float, int, dict]] = {}


def clear_cache() -> None:
    _cache.clear()


def _host(request: Request) -> str:
    raw = request.headers.get("x-forwarded-host") or request.headers.get("x-original-host") or ""
    host = raw.split(",")[0].strip().lower()
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _action(request: Request) -> str:
    method = (request.headers.get("x-original-method") or request.method).upper()
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "READ"
    return "DELETE" if method == "DELETE" else "WRITE"


def _token(request: Request) -> str | None:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return request.cookies.get(COOKIE)


def _reply(code: int, decision: str, reason: str, **extra: str) -> Response:
    safe = reason.encode("ascii", "ignore").decode().replace("\n", " ")[:200]
    headers = {"X-CloudSentinel-Decision": decision, "X-CloudSentinel-Reason": safe, **extra}
    return Response(status_code=code, headers=headers)


def _device_gate(user: models.User) -> str | None:
    device = primary_device(user)
    if device is None:
        return "No enrolled device"
    seen = device.last_seen if device.last_seen.tzinfo else device.last_seen.replace(tzinfo=timezone.utc)
    if (datetime.now(timezone.utc) - seen).total_seconds() > config.DEVICE_STALE_SECONDS:
        return "Device agent is offline"
    if device.posture_status == "UNKNOWN":
        return "Device posture not reported"
    return None


@router.api_route("/verify", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
def verify(request: Request, db: Session = Depends(get_db)) -> Response:
    """Forward-auth endpoint for Nginx auth_request / Traefik / Caddy. Fails closed."""
    host = _host(request)
    app = db.query(models.Application).filter(models.Application.upstream_host == host, models.Application.is_active.is_(True)).first() if host else None
    if app is None:
        return _reply(403, "DENY", "Unknown protected resource")
    token = _token(request)
    username = username_from_token(token) if token else None
    user = db.query(models.User).filter(models.User.username == username).first() if username else None
    if user is None or not user.is_active or getattr(user, "status", "ACTIVE") != "ACTIVE":
        return _reply(401, "AUTH_REQUIRED", "Authentication required")
    if app.organization_id is not None and user.organization_id != app.organization_id:
        return _reply(403, "DENY", "Resource belongs to another organization")
    if config.REQUIRE_AGENT_DEVICE:
        problem = _device_gate(user)
        if problem:
            return _reply(403, "DENY", problem)

    action = _action(request)
    record_hit(user.id, app.id)
    key = (user.id, app.id, action)
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < config.ENFORCE_CACHE_SECONDS:
        return Response(status_code=hit[1], headers=hit[2])
    try:
        gd = evaluate_access(db, user_id=user.id, application_id=app.id, action=action, persist=True, live=config.LIVE_BEHAVIOR)
        d = gd.policy
    except HTTPException as exc:
        logger.warning("enforce evaluation failed: %s", exc.detail)
        return _reply(403, "DENY", "Access could not be evaluated")
    except Exception:
        logger.exception("enforce unexpected error")
        return _reply(403, "DENY", "Access could not be evaluated")

    allowed = d.decision == "ALLOW" or (d.decision == "READ_ONLY" and action == "READ")
    response = _reply(
        200 if allowed else 403,
        d.decision,
        d.reason + ((" | " + "; ".join(gd.risk.reasons[:3])) if not allowed and gd.risk.reasons else ""),
        **({"X-CloudSentinel-User": user.username, "X-CloudSentinel-Risk": str(d.risk_score)} if allowed else {}),
    )
    _cache[key] = (time.monotonic(), response.status_code, dict(response.headers))
    return response


class HostBody(BaseModel):
    upstream_host: str | None = Field(default=None, max_length=255, pattern=r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")


@router.put("/applications/{application_id}/host", status_code=status.HTTP_204_NO_CONTENT)
def set_upstream_host(
    application_id: int,
    body: HostBody,
    db: Session = Depends(get_db),
    admin: models.User = Depends(require_admin_or_security),
) -> None:
    query = db.query(models.Application).filter(models.Application.id == application_id)
    app = query.first()
    if app is None or (app.organization_id is not None and app.organization_id != admin.organization_id):
        raise HTTPException(status_code=404, detail="Application not found")
    if body.upstream_host and db.query(models.Application).filter(models.Application.upstream_host == body.upstream_host, models.Application.id != app.id).first():
        raise HTTPException(status_code=409, detail="Host already mapped")
    app.upstream_host = body.upstream_host
    db.commit()
    clear_cache()


def _set_cookie(response: Response, username: str) -> None:
    response.set_cookie(
        COOKIE, create_gateway_token(username), max_age=config.SESSION_MINUTES * 60,
        httponly=True, secure=config.IS_PRODUCTION, samesite="lax", domain=config.COOKIE_DOMAIN,
    )


@router.post("/session", status_code=status.HTTP_204_NO_CONTENT)
def create_session(request: Request, response: Response, db: Session = Depends(get_db)) -> None:
    username = username_from_token(_token(request) or "")
    if not username:
        raise HTTPException(status_code=401, detail="Not authenticated")
    _set_cookie(response, username)


def _safe_next(db: Session, target: str) -> str | None:
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    ok = db.query(models.Application).filter(models.Application.upstream_host == parsed.hostname.lower()).first()
    return target if ok else None


_FORM = """<!doctype html><meta charset=utf-8><title>CloudSentinel</title>
<body style="font-family:system-ui;max-width:340px;margin:12vh auto"><h2>CloudSentinel sign-in</h2>{msg}
<form method=post><input type=hidden name=next value="{nxt}">
<p><input name=username placeholder=Username autofocus style="width:100%;padding:8px"></p>
<p><input name=password type=password placeholder=Password style="width:100%;padding:8px"></p>
<button style="padding:8px 16px">Sign in</button></form></body>"""


@router.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(next: str = "") -> HTMLResponse:
    return HTMLResponse(_FORM.format(msg="", nxt=html.escape(next, quote=True)))


@router.post("/login", include_in_schema=False)
def login_submit(request: Request, username: str = Form(...), password: str = Form(...), next: str = Form(""), db: Session = Depends(get_db)):
    user = authenticate_user(db, username, password)
    record_login(db, username, user, request.client.host if request.client else None)
    if user is None:
        return HTMLResponse(_FORM.format(msg="<p style=color:#b00>Invalid credentials</p>", nxt=html.escape(next, quote=True)), status_code=401)
    destination = _safe_next(db, next) if next else None
    if next and destination is None:
        raise HTTPException(status_code=400, detail="Invalid redirect target")
    response = RedirectResponse(destination, status_code=303) if destination else HTMLResponse("Signed in. You can close this tab.")
    _set_cookie(response, user.username)
    return response
