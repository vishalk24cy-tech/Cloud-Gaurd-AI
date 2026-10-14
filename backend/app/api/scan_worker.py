# ============================================================
# CloudGuardAI - Scan Worker API
# Production Background Scan Execution
# ============================================================

import hmac
import os
from typing import Any, Dict, Optional

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.database.connection import db
from app.services.scan_worker import process_scan_job
from app.services.tenant_context import (
    resolve_tenant_context,
)
from app.middleware.auth_middleware import verify_token


router = APIRouter(
    prefix="/scan-worker",
    tags=["Scan Worker"],
)

# Configuration requirement for internal worker authentication:
# To enable internal service-to-service worker execution without human user JWT,
# set the environment variable SCAN_WORKER_SECRET (e.g., in secure deployment configs).
# If unset or empty, internal worker secret authentication is disabled.
SCAN_WORKER_SECRET_ENV_VAR = "SCAN_WORKER_SECRET"

_bearer_optional = HTTPBearer(auto_error=False)


def _extract_worker_secret(
    x_internal_worker_key: Optional[str] = Header(None, alias="X-Internal-Worker-Key"),
    x_worker_key: Optional[str] = Header(None, alias="X-Worker-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Optional[str]:
    """Extract candidate internal worker secret from request headers."""
    if x_internal_worker_key and x_internal_worker_key.strip():
        return x_internal_worker_key.strip()
    if x_worker_key and x_worker_key.strip():
        return x_worker_key.strip()
    if authorization and authorization.lower().startswith("worker "):
        return authorization[7:].strip()
    return None


def optional_verify_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer_optional),
) -> Optional[Dict[str, Any]]:
    """
    Extract and verify bearer JWT token if present.
    Returns None if no Authorization header was provided.
    """
    if not credentials or not credentials.credentials:
        return None
    return verify_token(request=request, credentials=credentials)


@router.post("/{job_id}/process")
def process_job(
    job_id: str,
    request: Request,
    worker_key: Optional[str] = Depends(_extract_worker_secret),
    current_user: Optional[Dict[str, Any]] = Depends(optional_verify_token),
):
    """
    Execute background scan worker processing for a specific scan job.

    Security & Authorization Model:
    1. Internal Worker Authentication:
       - Authenticated if candidate key matches SCAN_WORKER_SECRET via constant-time comparison.
       - Even with valid worker credentials, the job must be verified against its trusted
         database organization; client cannot select an arbitrary organization or bypass checks.
    2. Human Administrator Authorization:
       - If no valid worker secret is provided, requires authenticated administrator JWT
         (owner or admin) with active membership in the job's organization.
       - Ordinary members (analyst, viewer) are denied (403 Forbidden).
    3. Fails closed with 401 Unauthorized if neither credential is valid.
    """
    # ------------------------------------------------------------
    # 1. Parse and validate job ID
    # ------------------------------------------------------------
    try:
        object_id = ObjectId(str(job_id))
    except (InvalidId, TypeError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found.",
        )

    job = db.scan_jobs.find_one({"_id": object_id})
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan job not found.",
        )

    trusted_org_id = str(job.get("organization_id") or "").strip()
    if not trusted_org_id:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Scan job missing organization context.",
        )

    # ------------------------------------------------------------
    # 2. Authenticate Channel A: Internal Worker Credential
    # ------------------------------------------------------------
    expected_secret = os.getenv(SCAN_WORKER_SECRET_ENV_VAR, "").strip()
    is_worker_auth = False

    if expected_secret and worker_key:
        if hmac.compare_digest(worker_key, expected_secret):
            is_worker_auth = True

    if is_worker_auth:
        # Internal service is authenticated.
        # Enforce that the job belongs to trusted_org_id.
        # If caller specified target organization header, it MUST match the job's organization.
        req_org_id = request.headers.get("x-organization-id")
        if req_org_id and req_org_id.strip() != trusted_org_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Target organization does not match scan job organization.",
            )

        target_organization_id = trusted_org_id

    else:
        # --------------------------------------------------------
        # 3. Authenticate Channel B: Human Administrator Authorization
        # --------------------------------------------------------
        # If worker key was sent but invalid, fail closed immediately
        if worker_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid internal worker credentials.",
            )

        # Must have valid JWT credentials
        if not current_user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Provide valid worker credentials or administrator token.",
            )

        # Resolve tenant context for the job's organization
        context = resolve_tenant_context(
            target_organization_id=trusted_org_id,
            current_user=current_user,
            request=request,
        )

        # Enforce administrative permissions (only owner or admin can manually trigger processing)
        if not context.has_role(["owner", "admin"]):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied. Requires one of roles: admin, owner.",
            )

        target_organization_id = context.organization_id

    # ------------------------------------------------------------
    # 4. Execute scan job processing
    # ------------------------------------------------------------
    try:
        result = process_scan_job(
            job_id=str(job["_id"]),
            organization_id=target_organization_id,
        )
        return result
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to process scan job.",
        )