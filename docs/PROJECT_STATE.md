# CloudSentinel project state (for new contributors / new chats)

Adaptive Zero Trust access engine: device posture + behavior -> risk score -> policy decision (ALLOW / MFA_REQUIRED / READ_ONLY / DENY / ISOLATE), enforced at a reverse proxy.
Stack: FastAPI + SQLAlchemy + Alembic (Postgres in prod, SQLite in dev), React/Vite frontend, Python endpoint agent.

## Done
- Phase 0: `APP_ENV`/`DEMO_MODE` gating, required `JWT_SECRET` in prod, Alembic, CI, Render+Postgres config, `python -m backend.cli create-admin`.
- Phase 1: `agent/` (enroll, collect posture, heartbeat), `/api/agent/*` with per-device credentials, enrollment tokens, revoke.
- Phase 2: `/api/enforce/verify` forward-auth (nginx auth_request), session cookie + login page, host->app mapping, device gate, tenant checks, `deploy/` nginx+compose.
- Phase 3: per-user robust baselines from LIVE snapshots (`backend/security/behavior.py`), explainable deviations, false-positive/confirmed feedback, metrics (`/api/intelligence/*`), login-attempt tracking. Active when `LIVE_BEHAVIOR=true` (default off in demo mode).

## Key env vars
APP_ENV, DEMO_MODE, JWT_SECRET, DATABASE_URL, ALLOWED_ORIGINS, COOKIE_DOMAIN, REQUIRE_AGENT_DEVICE, DEVICE_STALE_SECONDS, ENFORCE_CACHE_SECONDS, LIVE_BEHAVIOR, SENTRY_DSN.

## Known gaps (priority order)
1. Many legacy endpoints are unauthenticated (`/api/users/*`, `POST /api/telemetry`, devices list...). Authenticate + tenant-scope them, then fix tests/frontend.
2. MFA is not implemented: `MFA_REQUIRED` is treated as blocked. Add TOTP/WebAuthn step-up.
3. No rate limiting (login, enroll, verify).
4. Live behavior state (request hits) is in-process memory; use Redis for multi-worker. Data-volume feature is always 0 (proxy doesn't measure bytes).
5. MongoDB path is deprecated but still wired in; remove.
6. Browser sessions are not bound to a specific device (verify uses user's most recent device).
7. `ml/model.pkl` is loaded with pickle; ship it from a trusted build only or replace.
8. Agent: Windows service + signed .exe, DPAPI credential store; Defender-only AV detection.
9. Frontend pages for enrollment, baselines/feedback, host mapping.

## Dev
`python -m pytest` (83 tests) | `python -m alembic upgrade head` | `python -m uvicorn backend.main:app` | agent: `python -m agent enroll|once|run`
Windows PowerShell 5: no `&&`; use `python -m <tool>`.
