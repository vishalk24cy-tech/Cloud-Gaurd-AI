from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Optional

from app.services.scan_job_service import (
    create_scan_job,
    get_scan_job,
    get_scan_jobs,
)

from app.middleware.auth_middleware import verify_token


router = APIRouter(
    prefix="/scan-jobs",
    tags=["Scan Jobs"],
)


# ============================================================
# HELPERS
# ============================================================

def _get_user_id(
    current_user: dict
) -> str:

    user_id = (
        current_user.get("_id")
        or current_user.get("user_id")
        or current_user.get("id")
    )

    if not user_id:

        raise HTTPException(
            status_code=401,
            detail="Authenticated user ID is missing.",
        )

    return str(user_id)


def _get_organization_id(
    current_user: dict
) -> str:

    organization_id = current_user.get(
        "organization"
    )

    if not organization_id:

        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    return str(organization_id)


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

    current_user: dict = Depends(
        verify_token
    ),
):

    user_id = _get_user_id(
        current_user
    )

    organization_id = _get_organization_id(
        current_user
    )

    try:

        job = create_scan_job(
            organization_id=organization_id,
            user_id=user_id,
            account_id=account_id,
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

    current_user: dict = Depends(
        verify_token
    ),
):

    organization_id = _get_organization_id(
        current_user
    )

    try:

        jobs = get_scan_jobs(
            organization_id=organization_id,
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

    current_user: dict = Depends(
        verify_token
    ),
):

    organization_id = _get_organization_id(
        current_user
    )

    try:

        job = get_scan_job(
            job_id=job_id,
            organization_id=organization_id,
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