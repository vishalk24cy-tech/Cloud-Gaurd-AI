# CloudGuardAI - Project Overview

## 1. Project Name

CloudGuardAI

## 2. Project Description

CloudGuardAI is a SaaS-based cloud security platform designed to help organizations monitor and analyze the security posture of their AWS cloud environments.

The platform provides organization-based multi-tenancy, authentication, role-based access control, AWS account management, cloud security scanning, findings management, scan history, AI-assisted security analysis, compliance capabilities, monitoring, billing, and asynchronous scan-job processing.

## 3. Core Architecture

CloudGuardAI follows a modular SaaS architecture consisting of:

- React frontend
- FastAPI backend
- MongoDB Atlas database
- AWS integration
- Gemini AI integration
- Razorpay billing integration
- Dedicated background scan worker
- Monitoring scheduler
- Docker-based backend deployment

## 4. Backend

The backend is implemented using:

- Python
- FastAPI
- Uvicorn
- PyMongo
- MongoDB Atlas
- Boto3
- JWT authentication
- bcrypt/password hashing
- Google Gemini
- Razorpay
- APScheduler

## 5. Frontend

The frontend is implemented using React and provides the SaaS user interface for:

- Authentication
- Dashboard
- AWS account management
- Security scans
- Findings
- Scan progress
- Organizations
- Team management
- Notifications
- Compliance
- Security analysis
- Billing and subscription workflows

## 6. Security Architecture

CloudGuardAI includes:

- JWT-based authentication
- Role-based access control
- Organization-level tenant isolation
- Rate limiting
- Request correlation using X-Request-ID
- Structured security logging
- Sensitive-value redaction
- Security response headers
- Content Security Policy
- CORS configuration
- Audit logging
- Duplicate scan protection
- Race-condition-safe scan protection
- Automatic scan retries
- Stale-job recovery

## 7. Scan Architecture

AWS scans are processed asynchronously using scan jobs.

The scan lifecycle includes:

queued -> running -> completed

with retry and failure handling.

Active duplicate scans are prevented using organization/account-specific active job protection.

The production architecture separates the API process from the standalone scan worker.

## 8. Monitoring

The backend provides structured JSON logging with:

- Application startup events
- Request completion events
- Request IDs
- Request duration
- HTTP status codes
- Exception events
- Sensitive-data sanitization

The monitoring scheduler also handles scheduled monitoring tasks and trial-expiry processing.

## 9. Docker Deployment

The backend is containerized using Docker.

The backend image is:

cloudguardai-backend:latest

The FastAPI service is exposed on:

http://localhost:8000

The Docker container connects successfully to MongoDB Atlas and starts the monitoring scheduler.

## 10. Testing Completed

The project has been tested for:

- Authentication
- AWS account management
- AWS scanning
- Findings
- Scan jobs
- Duplicate scan protection
- Retry handling
- Stale-job recovery
- Background worker processing
- API health
- Docker deployment
- MongoDB connectivity
- Gemini configuration
- Basic load testing
- Security headers
- Structured request logging

A basic Docker API load test produced 50 successful HTTP 200 responses.

## 11. Current Project Status

Major implementation phases completed:

1. Authentication & JWT
2. Organizations / Multi-tenancy
3. Team Members / Invitations
4. RBAC
5. AWS Account Management
6. AWS Scanning
7. Findings & Scan History
8. Dashboard & Usage
9. Subscription / Trial
10. Razorpay Billing Foundation
11. SaaS Onboarding
12. Tenant Isolation
13. Scan Job Model / Service
14. Queue / Running / Completed / Failed lifecycle
15. Automatic Retries
16. Stale-Job Recovery
17. Background Worker
18. Scan Job Status API
19. Duplicate Scan Protection
20. Race-condition-safe Duplicate Protection
21. Production Worker Isolation
22. Production Scheduler Architecture
23. Frontend Async Scan / Job Progress
24. Docker / Production Deployment
25. Monitoring & Error Tracking
26. Load & Security Testing

## 12. Documentation Status

Final documentation is being organized under:

docs/

- architecture/
- deployment/
- testing/
- api/
- project/