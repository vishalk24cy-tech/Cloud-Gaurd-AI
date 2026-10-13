# CloudGuardAI - API Reference

## Scan Jobs API

Base path:

/scan-jobs

Authentication is required for all Scan Jobs API endpoints.

The Scan Jobs API provides asynchronous AWS scan job creation, status tracking, and job listing.

---

## 1. Create Scan Job

### Endpoint

POST /scan-jobs?account_id={account_id}

### Purpose

Creates a new asynchronous AWS security scan job for the specified AWS account.

### Authentication

JWT token required.

### Query Parameter

| Parameter | Type | Required | Description |
|---|---|---|---|
| account_id | string | Yes | AWS account ID to scan |

### Success Response

    {
      "status": "success",
      "message": "Scan job created.",
      "job": {}
    }

### Possible Errors

- 400 - Invalid request or an active scan already exists.
- 401 - Authentication required.
- 403 - Organization information missing.
- 500 - Internal server error.

---

## 2. List Scan Jobs

### Endpoint

GET /scan-jobs

### Purpose

Returns scan jobs belonging to the authenticated user's organization.

### Query Parameters

| Parameter | Type | Required | Description |
|---|---|---|---|
| status | string | No | Filter by job status |
| limit | integer | No | Number of jobs to return |

### Supported Status Values

- queued
- running
- retrying
- completed
- failed

### Success Response

    {
      "status": "success",
      "count": 1,
      "jobs": []
    }

### Authentication

JWT token required.

---

## 3. Get Scan Job Status

### Endpoint

GET /scan-jobs/{job_id}

### Purpose

Returns the current status and details of a specific scan job.

### Path Parameter

| Parameter | Type | Required | Description |
|---|---|---|---|
| job_id | string | Yes | ID of the scan job |

### Authentication

JWT token required.

### Success Response

    {
      "status": "success",
      "job": {}
    }

### Possible Errors

- 401 - Authentication required.
- 404 - Scan job not found.
- 500 - Internal server error.

---

## Scan Job Lifecycle

A scan job normally follows this lifecycle:

queued
  |
  v
running
  |
  v
completed

If a scan fails temporarily:

running
  |
  v
retrying
  |
  v
running

If the scan cannot be completed:

running
  |
  v
failed

---

## Authentication

All Scan Jobs API endpoints require a valid JWT authentication token.

## Tenant Isolation

Scan jobs are restricted to the authenticated user's organization.

A user cannot access scan jobs belonging to another organization.