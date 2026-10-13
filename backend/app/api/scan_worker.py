from fastapi import APIRouter, Depends, HTTPException

from app.middleware.auth_middleware import verify_token
from app.services.scan_worker import process_scan_job


router = APIRouter(
    prefix="/scan-worker",
    tags=["Scan Worker"],
)


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


@router.post("/{job_id}/process")
def process_job(
    job_id: str,
    current_user: dict = Depends(
        verify_token
    ),
):

    organization_id = _get_organization_id(
        current_user
    )

    try:

        result = process_scan_job(
            job_id=job_id,
            organization_id=organization_id,
        )

        return result

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to process scan job.",
        )