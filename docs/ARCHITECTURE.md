# CloudSentinel Architecture

## Repository Status

Phase 1 inspection found an empty workspace at:

```text
C:\Users\Nihal\Desktop\AZTMM
```

Phase 2 added the backend and database foundation. Phase 3 added telemetry ingestion, dynamic posture/tag evaluation, Isolation Forest behavioral anomaly detection, and transparent risk scoring. Phase 4 added the Adaptive Zero Trust policy engine, gateway orchestration, access decision persistence, audit events, and resource-level access APIs. Phase 5 added the React/Vite/Tailwind dashboard that displays backend-authored risk, posture, access, and audit data. Phase 6 added a deterministic account-compromise simulation, reset/status APIs, staged frontend demo flow, containment summary, and blast-radius visualization.

## Target Project Layout

The implementation should use this structure:

```text
cloudsentinel/
  backend/
    main.py
    database.py
    models.py
    schemas.py
    auth/
      auth.py
    security/
      posture.py
      tags.py
      anomaly.py
      risk_engine.py
      policy_engine.py
    api/
      auth.py
      users.py
      applications.py
      telemetry.py
      risk.py
      access.py
      events.py
      health.py
      simulation.py
    data/
      seed.py
  ml/
    train.py
    model.pkl
  frontend/
    src/
      components/
      pages/
      services/
      hooks/
      App.jsx
  docs/
    ARCHITECTURE.md
    DEMO.md
  requirements.txt
  README.md
  AGENTS.md
```

## Logical System Flow

CloudSentinel demonstrates the complete Zero Trust decision lifecycle:

```text
User
-> Identity / MFA
-> Zero Trust Gateway
-> Endpoint Posture + Behavior + Resource Context
-> Security Posture Tags
-> AI / Behavioral Risk Analysis
-> Risk Score 0-100
-> Adaptive Policy Engine
-> Application-Level Access Decision
-> Allow / MFA / Read Only / Deny / Isolate
-> Audit + Continuous Monitoring
```

The system must not reduce access control to a single compromised/not-compromised switch. Decisions are resource-specific and include resource sensitivity, current posture, behavior, identity, and context.

## Backend Architecture

### FastAPI Application

`backend/main.py` should create the FastAPI app, configure CORS for the Vite frontend, initialize route modules, and expose a health endpoint.

Implemented routers:

- `api/auth.py`: login and JWT issuing
- `api/users.py`: user list, user profile, stored posture summary
- `api/applications.py`: application inventory
- `api/events.py`: security timeline
- `api/health.py`: service health
- `api/telemetry.py`: telemetry ingestion and recent telemetry retrieval
- `api/risk.py`: dynamic posture, anomaly, tag, and risk assessment
- `api/access.py`: authenticated access checks and per-user access matrix
- `api/simulation.py`: deterministic attack, reset, and simulation status controls

### Database

SQLite is accessed through SQLAlchemy. The implemented tables are:

- `users`
- `devices`
- `applications`
- `security_tags`
- `telemetry`
- `risk_scores`
- `access_requests`
- `security_events`
- `simulation_states`

Seed data includes:

- Users: `admin01`, `developer01`, `employee01`, `analyst01`
- Applications: Email, HR Portal, Cloud Storage, Customer Database, Admin Console, Analytics Service
- Clouds: AWS, Azure, GCP

### Security Modules

Implemented security modules:

`security/tags.py`

- Converts endpoint, identity, and behavior signals into posture tags.
- Owns tag definitions and severity categories.
- Persists active posture tags and deactivates obsolete generated tags.

`security/posture.py`

- Evaluates device state, MFA state, OS compliance, AV status, location, process list, and vulnerability posture.
- Produces current posture status, posture risk, generated tags, and reasons.

`security/anomaly.py`

- Loads or trains an Isolation Forest model.
- Scores behavior telemetry features:
  - requests per minute
  - data download MB
  - failed logins
  - unique applications
  - access frequency
- Maps model and threshold output into a human-facing anomaly state and 0-100 behavior risk.

`security/risk_engine.py`

- Produces transparent 0-100 risk scores.
- Combines identity, posture, behavior, and context components.
- Returns score, level, component breakdown, and explanatory factors.

`security/policy_engine.py`

- Authoritative source for final decisions.
- Inputs:
  - user
  - application
  - action
  - risk score
  - security tags
  - resource sensitivity
- Outputs:
  - `ALLOW`
  - `MFA_REQUIRED`
  - `READ_ONLY`
  - `DENY`
  - `ISOLATE`
- Also returns human-readable reasons and machine-readable factors for the UI.

`security/zero_trust_gateway.py`

- Orchestrates identity, current telemetry, posture, tags, risk, resource lookup, policy evaluation, access request persistence, and audit events.
- Keeps API route handlers thin and keeps policy logic out of FastAPI.

`security/simulation.py`

- Creates controlled demo telemetry and device-state changes.
- Reuses posture, tags, anomaly, risk, gateway, and policy services for final outcomes.
- Provides reset to healthy baseline without deleting the whole database.

## API Contracts

The implemented API surface is:

```text
GET /api/health
POST /api/auth/login
GET /api/auth/me
GET /api/users
GET /api/users/{user_id}
GET /api/users/{user_id}/posture
GET /api/users/{user_id}/risk
GET /api/users/{user_id}/telemetry
GET /api/users/{user_id}/access-matrix
GET /api/applications
GET /api/applications/{application_id}
GET /api/events
GET /api/users/{user_id}/events
POST /api/telemetry
POST /api/access/check
POST /api/simulation/attack
POST /api/simulation/reset
GET /api/simulation/status/{user_id}
```

The frontend must call `POST /api/access/check` or `GET /api/users/{user_id}/access-matrix` to obtain access decisions. It must not calculate final authorization locally.

Example response:

```json
{
  "decision": "DENY",
  "risk_score": 87,
  "risk_level": "CRITICAL",
  "reason": "Critical resource requested by high-risk endpoint.",
  "factors": [
    "MALICIOUS_PROCESS",
    "DATA_EXFILTRATION",
    "NEW_DEVICE"
  ]
}
```

## Frontend Architecture

The React frontend is a dashboard, not a static mockup. It fetches backend state through Axios services and renders policy results returned by the backend.

Implemented pages:

- `Dashboard`: overview cards, user risk monitor, access summary, live events, risk trend
- `Users`: user list and risk ranking
- `UserProfile`: selected user's posture, behavior, AI assessment, access matrix
- `Resources`: multi-cloud resource inventory and sensitivity
- `Incidents`: active attack simulation and containment state
- `AuditLogs`: policy decisions and events

Implemented component groups include:

- `Sidebar`
- `Header`
- `RiskGauge`
- `PostureTags`
- `AccessMatrix`
- `DecisionModal`
- `SimulationPanel`
- loading/error/empty state components

## Demo State Model

The demo should center on `developer01`.

Healthy baseline:

```text
Risk: 7 LOW in the current seeded implementation
Requests/min: 20
Data transfer: 50 MB
Failed logins: 0
Applications: 2
Tags: TRUSTED_DEVICE, MFA_VERIFIED, OS_COMPLIANT, AV_ACTIVE, NORMAL_BEHAVIOR, NORMAL_LOCATION
```

Attack stages:

```text
NEW_DEVICE
NEW_LOCATION
ABNORMAL_REQUEST_RATE
DATA_EXFILTRATION
BEHAVIORAL_ANOMALY
POLICY_REEVALUATION
```

Final decisions after compromise:

```text
Email: ALLOW
HR Portal: MFA_REQUIRED
Cloud Storage: READ_ONLY
Customer Database: DENY
Admin Console: DENY
```

## Verification Plan

Each implementation phase should be verified before continuing:

- Backend imports cleanly.
- Database creates and seeds deterministically.
- API routes return valid Pydantic schemas.
- Policy decisions are generated by backend code.
- Frontend consumes API state rather than hardcoded decisions.
- Attack simulation and reset are repeatable.
- Dashboard remains usable at 1280x720, 1366x768, and 1440x900.

## Phase 5 Entry Criteria

Phase 5 implemented:

- React/Vite frontend shell
- enterprise security dashboard layout
- user profile and access matrix views backed by existing APIs
- decision explanation panel using backend policy responses

## Current End-To-End Demo

The implemented demo flow is:

```text
Normal user
-> simulate account compromise
-> attack telemetry is stored
-> posture/tags/anomaly/risk are recalculated
-> Zero Trust policies are re-evaluated
-> sensitive resources are restricted
-> audit events are created
-> reset demo restores healthy baseline
```

## Prototype Boundaries

- AWS, Azure, and GCP resources are simulated application metadata.
- Endpoint posture and threat signals are simulated through deterministic database state.
- MFA, read-only mode, denial, and isolation are enforcement decisions, not real provider integrations.
- No real malware detection, endpoint scanning, host telemetry collection, cloud IAM enforcement, or network isolation is performed.
- Isolation Forest uses demo telemetry to contribute behavioral anomaly risk.
