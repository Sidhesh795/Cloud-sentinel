# CloudSentinel

AI-Powered Adaptive Zero Trust for Multi-Cloud Applications.

CloudSentinel is a hackathon-ready prototype that demonstrates continuous, context-aware, application-level Zero Trust enforcement. It evaluates identity, endpoint posture, behavioral telemetry, security tags, current risk, requested action, and resource sensitivity before returning an access decision.

The core demo story:

```text
NORMAL USER
-> account-compromise simulation
-> telemetry and posture change
-> behavioral anomaly detected
-> risk increases
-> Zero Trust policy re-evaluates every application
-> sensitive resources are denied/restricted
-> lower-risk resources remain available
-> events are audited
-> reset returns to healthy baseline
```

## Status

Final engineering phase complete.

- FastAPI backend, SQLite database, JWT authentication
- Telemetry, posture tags, Isolation Forest behavioral anomaly detection
- Transparent risk engine
- Zero Trust Gateway and Adaptive Policy Engine
- Resource-level access matrix and decision explanations
- React/Vite/Tailwind enterprise dashboard
- Deterministic attack simulation, reset, containment summary, and blast-radius visualization

This is a controlled demo simulation. It does not execute malware, scan the host, collect personal data, perform real cloud enforcement, or integrate with real MFA.

## Technology Stack

- Backend: Python, FastAPI, Pydantic, SQLAlchemy, SQLite
- Auth: JWT, bcrypt password hashing
- AI/ML: scikit-learn Isolation Forest
- Frontend: React, Vite, Tailwind CSS, Recharts, Lucide React, Axios
- Tests: pytest, Playwright/Chrome smoke verification

## Folder Structure

```text
backend/              FastAPI app, database, models, schemas, API routers
backend/security/     posture, tags, anomaly, risk, policy, gateway, simulation
backend/data/         deterministic seed script
frontend/             React dashboard
frontend/src/         pages, components, hooks, services
ml/                   Isolation Forest training script and model
tests/                backend test suite
scripts/              smoke verification scripts
docs/                 architecture and live demo guide
```

## Backend Setup

```bash
cd C:\Users\Nihal\Desktop\AZTMM\cloudsentinel
python -m pip install -r requirements.txt
python -m backend.data.seed
python -m ml.train
python -m uvicorn backend.main:app --reload
```

Backend URLs:

- `http://127.0.0.1:8000/api/health`
- `http://127.0.0.1:8000/docs`
- `http://127.0.0.1:8000/openapi.json`

## Frontend Setup

```bash
cd C:\Users\Nihal\Desktop\AZTMM\cloudsentinel\frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Demo Login

```text
username: developer01
password: CloudDemo123!
```

The demo password is only for seeded local accounts. Passwords are stored hashed in SQLite.

## Demo Flow

1. Log in as `developer01`.
2. Confirm the normal dashboard: LOW risk, healthy tags, low/high resources available, critical resources MFA-protected.
3. Click `SIMULATE ACCOUNT COMPROMISE`.
4. Watch the staged incident sequence.
5. Show new/warning/critical posture tags.
6. Show risk escalation.
7. Show access matrix changes: low-risk resources remain available or MFA-protected while sensitive resources are restricted/denied.
8. Show live security events and containment/blast-radius summary.
9. Click `RESET DEMO`.
10. Confirm the dashboard returns to LOW risk and healthy posture.

Full presenter script: [docs/DEMO.md](docs/DEMO.md).

## Useful API Endpoints

- `POST /api/auth/login`
- `GET /api/auth/me`
- `GET /api/users`
- `GET /api/users/{user_id}/posture`
- `GET /api/users/{user_id}/risk`
- `GET /api/users/{user_id}/risk-history`
- `GET /api/users/{user_id}/access-matrix`
- `POST /api/access/check`
- `GET /api/events`
- `POST /api/simulation/attack`
- `POST /api/simulation/reset`
- `GET /api/simulation/status/{user_id}`

## Resetting Demo Data

To restore the local database to a healthy baseline:

```bash
python -m backend.data.seed
```

The seed script is idempotent and restores simulation state to `NORMAL`.

## Verification

```bash
python -m pytest
npm --prefix frontend run build
python scripts\verify_phase5.py
python scripts\verify_phase5_browser.py
```

Expected:

- backend tests pass
- frontend build succeeds
- API smoke succeeds
- browser simulation smoke succeeds with no console errors

## Prototype Limitations

- Cloud resources are simulated metadata, not real AWS/Azure/GCP integrations.
- Endpoint threat signals are simulated through database state and telemetry.
- MFA and isolation are returned as policy decisions, not real enforcement integrations.
- Isolation Forest uses deterministic demo telemetry.
- There is no real EDR, malware detection, endpoint scanning, host telemetry collection, or cloud IAM enforcement.
