# ============================================================
# CloudGuardAI - Scan Jobs API
# Production / Commercial SaaS
# ============================================================

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from app.models.aws_account import get_account
from app.services.scan_job_service import (
    create_scan_job,
    get_scan_job,
    get_scan_jobs,
)
from app.services.tenant_context import (
    TenantContext,
    get_tenant_context,
    require_analyst_or_above,
)


router = APIRouter(
    prefix="/scan-jobs",
    tags=["Scan Jobs"],
)


# ============================================================
# CREATE SCAN JOB
# ============================================================

@router.post("")
def create_job(
    account_id: str = Query(
        ...,
        min_length=1,
        description="Connected AWS account ID",
    ),
    context: TenantContext = Depends(
        require_analyst_or_above
    ),
):
    """
    Create a new queued AWS security scan job.

    Authorization:
    - Requires authenticated active tenant membership with role
      owner, admin, or analyst. Viewers are denied (403 Forbidden).
    - Validates that the requested AWS account belongs to the
      authenticated tenant and is in 'connected' status.
    """
    account = get_account(
        account_id=account_id,
        organization_id=context.organization_id,
    )

    if not account:
        raise HTTPException(
            status_code=404,
            detail="Connected AWS account not found in organization.",
        )

    if account.get("status") != "connected":
        raise HTTPException(
            status_code=400,
            detail=f"AWS account is not connected (status: {account.get('status', 'unknown')}).",
        )

    try:
        job = create_scan_job(
            organization_id=context.organization_id,
            user_id=context.user_id,
            account_id=str(account["_id"]),
            aws_account_id=account.get("aws_account_id"),
        )

        return {
            "status": "success",
            "message": "Scan job created.",
            "job": job,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to create scan job.",
        )


# ============================================================
# LIST SCAN JOBS
# ============================================================

@router.get("")
def list_jobs(
    status: Optional[str] = Query(
        default=None,
        description=(
            "Optional job status filter: "
            "queued, running, retrying, "
            "completed, failed"
        ),
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    context: TenantContext = Depends(
        get_tenant_context
    ),
):
    """
    Return scan jobs for the authenticated organization only.
    """
    try:
        jobs = get_scan_jobs(
            organization_id=context.organization_id,
            limit=limit,
            status=status,
        )

        return {
            "status": "success",
            "count": len(jobs),
            "jobs": jobs,
        }

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except HTTPException:
        raise

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve scan jobs.",
        )


# ============================================================
# GET SINGLE SCAN JOB
# ============================================================

@router.get("/{job_id}")
def get_job(
    job_id: str,
    context: TenantContext = Depends(
        get_tenant_context
    ),
):
    """
    Get a single scan job belonging to the authenticated organization.

    Cross-tenant isolation:
    Returns 404 Not Found if the job does not exist in the tenant,
    never disclosing whether it exists in another organization.
    """
    try:
        job = get_scan_job(
            job_id=job_id,
            organization_id=context.organization_id,
        )

        if not job:
            raise HTTPException(
                status_code=404,
                detail="Scan job not found.",
            )

        return {
            "status": "success",
            "job": job,
        }

    except HTTPException:
        raise

    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve scan job.",
        )