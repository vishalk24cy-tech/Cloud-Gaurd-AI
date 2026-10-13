# CloudGuardAI - Deployment Guide

## 1. Overview

CloudGuardAI uses a Docker-based deployment architecture for the FastAPI backend.

The backend runs as a Docker container and connects to MongoDB Atlas and the configured external services.

---

## 2. Backend Docker Image

The backend Docker image is:

cloudguardai-backend:latest

The Dockerfile is located at:

backend/Dockerfile

---

## 3. Build the Backend Image

From the project root, run:

docker build -t cloudguardai-backend ./backend

A successful build creates the image:

cloudguardai-backend:latest

---

## 4. Environment Configuration

The backend uses environment variables for configuration.

The environment file is:

backend/.env

Sensitive credentials should not be committed to source control.

Important configuration areas include:

- MongoDB connection
- JWT configuration
- AWS configuration
- Gemini API configuration
- Razorpay configuration
- Application configuration

---

## 5. Start the Backend Container

Run:

docker run -d --name cloudguardai-backend --env-file .\backend\.env -p 8000:8000 cloudguardai-backend:latest

The backend is exposed on:

http://localhost:8000

---

## 6. Verify the Container

Check the running Docker containers:

docker ps

The CloudGuardAI backend container should show port:

0.0.0.0:8000->8000/tcp

The container name is:

cloudguardai-backend

---

## 7. Verify the API

Open or request:

http://localhost:8000/

A successful response should contain:

{"status":"success","message":"Welcome to CloudGuardAI Backend"}

The API health check should return HTTP 200.

---

## 8. View Container Logs

To view the backend logs:

docker logs cloudguardai-backend

To follow the logs continuously:

docker logs -f cloudguardai-backend

Logs can be used to verify:

- Application startup
- MongoDB connection
- Scheduler startup
- API requests
- Errors
- Exceptions

---

## 9. Monitor Container Resources

Use:

docker stats --no-stream cloudguardai-backend

This displays:

- CPU usage
- Memory usage
- Network usage
- Process count

---

## 10. Restart the Backend

To restart the existing backend container:

docker restart cloudguardai-backend

---

## 11. Scan Worker Architecture

CloudGuardAI separates the API process from the background scan worker.

The standalone worker is located at:

backend/worker.py

The worker processes queued and retrying scan jobs.

The API process does not run the standalone scan worker internally.

---

## 12. Monitoring Scheduler

The monitoring scheduler runs inside the configured backend application process.

Scheduled tasks include:

- Cloud monitoring
- Trial expiration processing

The scheduler uses controlled execution settings to prevent overlapping executions.

---

## 13. MongoDB Atlas

CloudGuardAI uses MongoDB Atlas as its database.

The backend establishes the MongoDB connection using the configured environment variables.

MongoDB connectivity should be verified before performing production scans.

---

## 14. Security Considerations

Production deployment should protect all sensitive environment variables.

Do not commit:

.env

to Git.

Security controls implemented in the application include:

- JWT authentication
- Role-based access control
- Tenant isolation
- Rate limiting
- Security headers
- Content Security Policy
- Structured security logging
- Sensitive-value redaction
- Audit logging

---

## 15. Deployment Verification Checklist

Before considering the backend deployment ready, verify:

- [ ] Docker image builds successfully
- [ ] Backend container starts successfully
- [ ] Port 8000 is accessible
- [ ] MongoDB connection succeeds
- [ ] API health endpoint returns HTTP 200
- [ ] Backend logs are available
- [ ] Security headers are present
- [ ] Scan worker architecture is configured
- [ ] Scheduler starts correctly
- [ ] Sensitive environment variables are protected

---

## 16. Current Verified Deployment

The CloudGuardAI backend has been tested in Docker with:

Image:

cloudguardai-backend:latest

Container:

cloudguardai-backend

Port:

8000

API:

http://localhost:8000/

The API health endpoint returned HTTP 200 during deployment testing.

A basic request test also produced 50 successful HTTP 200 responses.