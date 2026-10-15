# CloudGuardAI — Deployment & DevSecOps Production Guide
**Version:** 1.0.0 (Phase 6 Deployment Readiness)
**Target Environments:** Staging / Production
**Architecture:** Distributed Multi-Tenant SaaS (FastAPI + React Vite + MongoDB Atlas + AWS STS / Boto3)

---

## 1. Overview & Architecture

CloudGuardAI2 operates as a secure, containerized multi-tenant cloud security posture management (CSPM) and remediation platform:
1. **Frontend**: Single Page Application (SPA) built with React 19 and Vite 8, served in production via hardened Nginx Alpine with SPA routing and HTTP security headers.
2. **Backend API**: FastAPI application served via Uvicorn, operating with non-root security boundaries (`cloudguard` uid 10001), structured security logging, CORS controls, rate limiting, and automated tenant isolation.
3. **Background Worker**: Standalone Python process (`worker.py`) executing queued security scan jobs and retries independently from the HTTP API.
4. **Database**: MongoDB Atlas M10+ replica set with TLS 1.3 encryption in transit, IP access lists, and majority write concerns.
5. **Cloud Integrations**: Cross-account AWS IAM AssumeRole via STS (zero static long-lived credentials stored), Google Gemini 2.0 API, and Razorpay subscription billing.

---

## 2. CI/CD Pipeline & Automated DevSecOps Gate

The GitHub Actions workflow (`.github/workflows/ci.yml`) enforces automated quality, security, and regression gates prior to merging or deploying.

### Trigger Matrix
- **Pushes**: `main`, `develop`, and feature branches (`feat/**`).
- **Pull Requests**: Targeting `main` and `develop`.
- **Concurrency**: `cancel-in-progress: true` prevents wasted runner hours on rapid commits.

### Jobs & Automated Checks
1. **Backend CI (`backend-ci`)**:
   - Runtime: Python 3.12 on `ubuntu-latest`.
   - Dependency verification: `python -m pip check` verifies zero broken package dependencies.
   - Test Isolation: Runs with `APP_ENV=test`, `DATABASE_NAME=cloudguardai_test`, mocked AWS STS, Gemini, and Razorpay APIs.
   - Health Probe Suite: Runs `backend/test_health_endpoints.py` to ensure `/health` and `/health/ready` operate fail-closed.
   - Comprehensive Regression: Executes all 420+ backend unit, tenant-isolation, RBAC, and remediation test suites.
2. **Frontend CI (`frontend-ci`)**:
   - Runtime: Node.js 20 LTS on `ubuntu-latest`.
   - Deterministic Install: `npm ci --prefix frontend` from `package-lock.json`.
   - Code Quality: `npm run lint --prefix frontend` (ESLint with zero warnings/errors).
   - Production Build: `npm run build --prefix frontend` verifying zero asset bundling failures.
3. **DevSecOps Security Audit (`devsecops-audit`)**:
   - Git Secrets Guard: Prohibits active `.env` or credential files from being tracked in Git.
   - Token Pattern Scanner: Scans source tree with regex patterns for leaked AWS access keys (`AKIA...`), temporary session keys (`ASIA...`), Google API tokens (`AIza...`), or GitHub PATs (`ghp_...`).
   - Dependency Vulnerability Scan: Audits package graphs via `npm audit --prefix frontend --audit-level=critical`.

---

## 3. Container Images & Runtime Configuration

### 3.1 Backend Dockerfile (`backend/Dockerfile`)
- **Base Image**: Minimal `python:3.12-slim`.
- **Security Boundary**: Runs as non-root user `cloudguard` (UID 10001, GID 10001) with `/sbin/nologin`.
- **Clean Layers**: Cached dependency installation before source code copy.
- **Excluded Files (`backend/.dockerignore`)**: `.env`, `.git`, `venv/`, `__pycache__`, `reports/`, test files, and local logs are strictly prevented from entering images.
- **Liveness Healthcheck**: Native standard-library Python probe executing against `http://127.0.0.1:8000/health` (no curl dependency required).

### 3.2 Frontend Dockerfile (`frontend/Dockerfile`)
- **Stage 1 (Builder)**: `node:20-alpine` builds minified assets (`npm run build`).
- **Stage 2 (Runtime)**: Minimal `nginx:1.27-alpine` serving static bundle from `/usr/share/nginx/html`.
- **Nginx Configuration (`frontend/nginx.conf`)**:
  - Gzip compression for CSS, JS, SVG, and JSON.
  - Client-side SPA routing fallback (`try_files $uri $uri/ /index.html`).
  - Hardened headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`.
  - Blocked hidden files (`location ~ /\. { deny all; }`).

### 3.3 Docker Compose (`docker-compose.yml`)
Declarative local / staging topology:
```yaml
services:
  backend:
    build: ./backend
    container_name: cloudguardai-backend
    ports: ["8000:8000"]
    env_file: ./backend/.env
    restart: unless-stopped

  worker:
    build: ./backend
    container_name: cloudguardai-worker
    command: ["python", "worker.py"]
    env_file: ./backend/.env
    restart: unless-stopped

  frontend:
    build: ./frontend
    container_name: cloudguardai-frontend
    ports: ["3000:80"]
    depends_on: [backend]
    restart: unless-stopped
```

---

## 4. Production Configuration & Environment Variable Schema

> [!IMPORTANT]
> Never store credential values in source control, pull request comments, or public build artifacts.

### 4.1 Backend Required Variable Names
| Variable Name | Purpose | Example Format / Constraint |
| :--- | :--- | :--- |
| `APP_ENV` | Application environment state | `staging` or `production` |
| `MONGODB_URL` | MongoDB Atlas primary SRV URI | `mongodb+srv://<user>:<pwd>@<cluster>.mongodb.net/` |
| `DATABASE_NAME` | Primary database name | `cloudguardai` |
| `JWT_SECRET_KEY` | Cryptographic secret for signing JWTs | High-entropy random 256-bit string |
| `JWT_ALGORITHM` | JWT signing algorithm | `HS256` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | Session token lifespan | e.g. `60` |
| `FRONTEND_URL` | Allowed CORS origins (comma-separated for multi-domain) | `https://app.cloudguardai.com,https://dashboard.cloudguardai.com` |
| `DEFAULT_AWS_REGION` | Scanner STS default region | e.g. `us-east-1` or `ap-south-1` |
| `GEMINI_API_KEY` | Google Gemini API key for AI remediations | Masked secret |
| `RAZORPAY_KEY_ID` | Razorpay Merchant Key ID | Masked key identifier |
| `RAZORPAY_KEY_SECRET` | Razorpay API Secret | Masked secret |
| `RAZORPAY_WEBHOOK_SECRET` | Webhook signature verification secret | High-entropy HMAC key |

### 4.2 Frontend Variable Names
| Variable Name | Purpose | Example Format / Constraint |
| :--- | :--- | :--- |
| `VITE_API_URL` | Backend API base URL consumed by React client | `https://api.cloudguardai.com` |

---

## 5. Health Probes & Monitoring

The backend exposes dedicated zero-disclosure health endpoints:

### Liveness Probe (`GET /health`)
- **HTTP Status**: `200 OK`
- **Output**:
  ```json
  {
    "status": "healthy",
    "service": "cloudguardai-api",
    "version": "1.0.0",
    "timestamp": "2026-10-15T14:30:00.000000+00:00"
  }
  ```
- **Usage**: Configured on AWS ALB target groups and container orchestrators. Fails only if the Python HTTP process hangs.

### Readiness Probe (`GET /health/ready`)
- **HTTP Status**: `200 OK` on active DB ping; `503 Service Unavailable` on database disconnection.
- **Fail-Closed Security**: Throws generic `"Service dependencies unavailable"` upon failure—**never discloses connection strings, hostnames, or database exception tracebacks**.
- **Usage**: Used by ingress controllers to determine if traffic should route to the task.

---

## 6. Cloud Deployment Architecture Options & Cost Analysis

### Option A: AWS ECS Fargate + AWS S3 / CloudFront (Recommended Enterprise CSPM)
- **Frontend**: Uploaded to private Amazon S3 bucket fronted by Amazon CloudFront CDN with TLS 1.3 ACM Certificate and Origin Access Control (OAC).
- **Backend & Worker**: AWS ECS Fargate cluster running 2 tasks for API (behind Application Load Balancer) and 1 task for the background worker.
- **Database**: MongoDB Atlas M10 (Dedicated 3-node replica set in same AWS region via VPC Peering).
- **Secrets**: AWS Secrets Manager + AWS Systems Manager Parameter Store.
- **Estimated Cost**:
  - CloudFront + S3 (Frontend): ~$2–$5/month
  - ECS Fargate (2x 0.5 vCPU, 1 GB RAM tasks for API + 1 worker task): ~$35–$45/month
  - Application Load Balancer (ALB): ~$18–$22/month
  - MongoDB Atlas M10 (Dedicated): ~$57/month
  - **Total Estimated Cost**: ~$115–$130/month

### Option B: AWS App Runner + Static Host (Fastest Time-to-Market / Lower Overhead)
- **Frontend**: Cloudflare Pages / Vercel Enterprise / S3 static hosting.
- **Backend API**: AWS App Runner connected directly to ECR image. Automatic TLS, auto-scaling, and health monitoring included.
- **Worker**: Lightweight ECS Fargate task or EC2 t4g.small instance running `python worker.py`.
- **Estimated Cost**:
  - Frontend: Free tier to ~$10/month
  - App Runner (1 vCPU, 2 GB RAM): ~$25–$40/month (scales down during low traffic)
  - Worker Task: ~$12–$18/month
  - MongoDB Atlas M10: ~$57/month
  - **Total Estimated Cost**: ~$95–$120/month

---

## 7. Release Management & Zero-Downtime Rollback Strategy

### 7.1 Pre-Release Validation Checklist
- [ ] All GitHub Actions CI checks green on target commit.
- [ ] Staging environment deploy passes automated smoke tests (`/health`, `/health/ready`, token auth, finding queries).
- [ ] No unconfirmed migration or breaking API changes.
- [ ] Human release approval recorded by Technical Lead / Security Officer.

### 7.2 Release Promotion Steps
1. **Build & Tag Artifacts**:
   - `cloudguardai-backend:v1.0.0`
   - `cloudguardai-frontend:v1.0.0`
2. **Deploy to Staging**:
   - Deploy backend to staging cluster with `APP_ENV=staging`.
   - Verify `/health` and `/health/ready` return 200.
   - Run end-to-end integration smoke tests.
3. **Production Blue/Green Deployment**:
   - Deploy new task definition revision on ECS / App Runner.
   - Route 10% canary traffic to new task.
   - Monitor error rate metrics (`REQUEST_FAILED`, HTTP 5xx) on CloudWatch for 15 minutes.
   - Shift 100% traffic once error rate remains < 0.01%.

### 7.3 Instant Rollback Runbook
If critical defects or error spikes occur:
1. **Application Rollback**:
   - Revert ALB target group or ECS service to previous task definition revision:
     ```bash
     aws ecs update-service --cluster cloudguardai-prod --service api-service --task-definition cloudguardai-backend:<PREVIOUS_REVISION>
     ```
   - Rollback completes in < 60 seconds with zero data destruction.
2. **Database Precautions**:
   - CloudGuardAI adheres to additive schema evolution (no destructive field drops).
   - Point-In-Time Restore (PITR) enabled on MongoDB Atlas for emergency state restoration.

---

## 8. Security Guardrails & Troubleshooting

1. **Zero Auto-Remediation on Deploy**:
   - CloudGuardAI strictly prohibits automated execution of cloud mutations during deployment or application startup.
   - All remediation actions require explicit multi-user human approval (`analyst` proposes, `admin`/`owner` approves, confirmed execution).
2. **Credential Rotation**:
   - JWT secret keys and webhook secrets should be rotated every 90 days via AWS Secrets Manager with zero-downtime dual-key acceptance during rotation windows.
3. **Common Incident Runbooks**:
   - *503 on `/health/ready`*: Check MongoDB Atlas network access list and replica set primary election status.
   - *401 on API endpoints*: Verify clock drift on client / server and validate JWT expiry timestamps.
   - *AWS Scan Failures*: Confirm customer's IAM Role ARN trust policy still permits `sts:AssumeRole` from CloudGuardAI's AWS Account ID and External ID.