# CloudGuardAI — System Architecture

## 1. Architecture Overview

CloudGuardAI uses a modular SaaS architecture.

The backend is implemented with FastAPI and is organized into API routes, services, models, schemas, middleware, utilities, database connectivity, AI integration, and monitoring components.

The system is designed to support organization-based cloud security operations and asynchronous AWS security scanning.

---

## 2. High-Level Architecture

```text
                    ┌──────────────────────┐
                    │     React Frontend   │
                    │   CloudGuardAI UI    │
                    └──────────┬───────────┘
                               │
                               │ HTTP / REST API
                               ▼
                    ┌──────────────────────┐
                    │    FastAPI Backend   │
                    │      Uvicorn         │
                    └──────────┬───────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
          ▼                    ▼                    ▼
   ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
   │ API Layer   │      │ Middleware  │      │ AI Layer    │
   │             │      │             │      │             │
   │ Auth        │      │ JWT         │      │ Gemini      │
   │ AWS         │      │ Rate Limit  │      │ AI Chat     │
   │ Findings    │      │ Security    │      │ AI Explain  │
   │ Dashboard   │      │             │      │             │
   │ Scan Jobs   │      │             │      │             │
   │ Billing     │      │             │      │             │
   └──────┬──────┘      └─────────────┘      └─────────────┘
          │
          ▼
   ┌───────────────────────────────┐
   │        Service Layer          │
   │                               │
   │ AWS Connection / Scanning     │
   │ Security Checkers             │
   │ Scan Job Service              │
   │ Organization Services         │
   │ Compliance Engine             │
   │ Billing Services              │
   │ Audit Services                │
   │ Monitoring Services           │
   │ Scan Remediation Reconciler   │
   └───────────────┬───────────────┘
                   │
          ┌────────┴────────┐
          ▼                 ▼
   ┌─────────────┐   ┌─────────────┐
   │ MongoDB     │   │ AWS Cloud   │
   │ Atlas       │   │ Resources   │
   └─────────────┘   └─────────────┘

                   ┌──────────────────┐
                   │ Standalone Scan  │
                   │ Worker           │
                   └────────┬─────────┘
                            │
                            ▼
                    Scan Job Processing
```

---

## 3. Remediation & Authoritative Finding Resolution (Phase 8)

CloudGuardAI strictly enforces **Authoritative Verification**:

1. **Proposal & Approval**: Remediations enter a Human-in-the-Loop proposal lifecycle (`PROPOSED` -> `APPROVED`).
2. **Execution & Read-Back**: Authorized execution assumes the target AWS role and runs the remediation adapter (EC2, S3, IAM, VPC, RDS, CloudTrail). An immediate AWS read-back check verifies the mutation succeeded, and the proposal transitions to `COMPLETED`.
3. **No Premature Resolution**: Successful execution does **not** mark findings as `RESOLVED`. Findings remain `OPEN` or `IN_PROGRESS` until a qualifying scan occurs.
4. **Scan Reconciliation (`scan_remediation_reconciler.py`)**:
   - Following a complete and successful scan (`status == "completed"`), the reconciler checks candidate findings.
   - Requires `executed_at <= scan_started_at` to prevent stale scan degradation.
   - Evaluates service coverage and verifies the finding is absent from fresh scan detections.
   - Atomically transitions findings to `RESOLVED` with `verifying_scan_id`.
   - Records verification metadata on the remediation proposal and emits an immutable audit event (`EVENT_FINDING_RESOLVED`).