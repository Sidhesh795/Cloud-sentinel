# CloudSentinel Engineering Guide

## Product Intent

CloudSentinel is a hackathon prototype of an AI-powered Adaptive Zero Trust control plane. The central demo story is resource-specific access control:

```text
same user + same moment + different resource sensitivity = different access decision
```

The frontend must present decisions produced by the backend policy engine. It must not calculate final authorization outcomes locally.

## Implementation Principles

- Keep the architecture modular: telemetry, posture tags, anomaly detection, risk scoring, policy decisions, API, and UI each belong in separate modules.
- Prefer deterministic demo data over random behavior so the presentation is repeatable.
- Treat the Isolation Forest as one input into behavioral risk, not as the entire security model.
- Keep provider-specific resource data simulated and provider-independent.
- Keep the MVP stable and visually convincing before adding breadth.

## Phase Boundaries

Phase 1:

- Inspect repository.
- Document architecture.
- Do not implement runtime application code.

Phase 2:

- Build backend skeleton.
- Add database models and SQLite setup.
- Add seed data.
- Add basic route wiring and health checks.

Phase 3 and later:

- Add telemetry, posture tags, risk engine, policy engine, frontend, simulation, and polish in order.

## Demo Invariants

- `developer01` starts healthy with risk near 12.
- Attack simulation raises risk through visible stages: 12 -> 35 -> 58 -> 74 -> 91.
- After compromise, low-risk resources remain reachable while sensitive resources are restricted.
- Reset returns the demo to a healthy baseline without code changes.
