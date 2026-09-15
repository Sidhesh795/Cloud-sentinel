# CloudSentinel Real-World Roadmap

## Current

CloudSentinel is a hackathon prototype of an Adaptive Zero Trust control plane. It uses deterministic SQLite demo data, simulated applications, simulated telemetry, explainable risk scoring, and backend-authored policy decisions.

Implemented:

- FastAPI, SQLite, SQLAlchemy, JWT, bcrypt password hashing
- Telemetry, posture tags, Isolation Forest behavior input, risk engine, policy engine
- Access matrix, audit events, simulation attack/reset, React/Vite/Tailwind dashboard

Not implemented:

- Real endpoint monitoring, malware detection, packet interception, VPN, MFA infrastructure, or real AWS/Azure/GCP enforcement

## V1.1

Real control-plane foundation.

Implemented:

- Organization model with tenant-aware IDs
- Admin user management APIs and UI
- Device registration, heartbeat, posture ingestion, and device dashboard
- Optional MongoDB Atlas cloud persistence layer using PyMongo
- MongoDB health endpoint and clean MongoDB demo seed process
- Source distinction for telemetry and events: `SIMULATION`, `AGENT`, and `CONTROL_PLANE`

Planned after V1.1:

- Full migration of every read/write workflow to MongoDB-native repositories
- Production-grade migrations and external secret management

## V1.2

Planned Windows Endpoint Agent.

- Windows service packaging
- Agent enrollment against `/api/devices/register`
- Periodic heartbeat
- Basic posture signal collection

## V1.3

Planned real behavioral telemetry.

- Security-relevant metadata ingestion from endpoint and identity providers
- Strong data minimization controls
- Expanded anomaly and risk features

## V1.4

Planned application enforcement gateway.

- Provider-agnostic enforcement adapter contracts
- Real policy decision relay
- Step-up and read-only control integrations where providers support them

## V1.5

Planned cloud IAM integration.

- AWS, Azure, and GCP IAM/resource inventory connectors
- Organization-scoped cloud account onboarding
- Audited policy mapping

## V2

Planned enterprise deployment.

- External database and secrets
- Production authentication/MFA integration
- Observability, rate limiting, operational hardening, and deployment automation
