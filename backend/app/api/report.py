# ============================================================
# CloudGuardAI - Security Reports API
# Production / Commercial SaaS Version
# ============================================================

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse

from app.middleware.auth_middleware import verify_token

from app.services.scan_service import (
    get_all_scans,
)

from app.services.pdf_service import (
    generate_pdf,
)

from app.services.quota_service import (
    reserve_quota,
)

from app.services.organization_usage_service import (
    release_usage,
)


router = APIRouter()


# ============================================================
# HELPERS
# ============================================================

def _get_user_id(current_user):
    """
    Extract the authenticated CloudGuardAI user ID.
    """

    if (
        not current_user
        or not current_user.get("_id")
    ):
        raise HTTPException(
            status_code=401,
            detail="Authentication required."
        )

    return str(
        current_user["_id"]
    )


def _validate_pdf_path(pdf_path):
    """
    Validate that the generated PDF exists and is a file.

    This prevents returning an invalid FileResponse path.
    """

    if not pdf_path:
        raise HTTPException(
            status_code=500,
            detail="Security report generation failed."
        )

    path = Path(
        str(pdf_path)
    )

    if not path.exists():
        raise HTTPException(
            status_code=500,
            detail="Generated security report was not found."
        )

    if not path.is_file():
        raise HTTPException(
            status_code=500,
            detail="Generated security report is invalid."
        )

    return path


# ============================================================
# DOWNLOAD LATEST SECURITY REPORT
# ============================================================

@router.get("/pdf")
def download_pdf(
    current_user=Depends(
        verify_token
    )
):
    """
    Generate and download the latest security report
    belonging to the authenticated CloudGuardAI user.

    Tenant isolation:
        user_id -> scan history -> latest scan -> PDF

    SaaS quota:
        organization -> reports quota -> reserve 1 report

    The endpoint never reads scans belonging to another user.
    """

    user_id = _get_user_id(
        current_user
    )

    # ========================================================
    # SAAS ORGANIZATION CONTEXT
    # ========================================================

    organization_id = str(
        current_user.get("organization") or ""
    ).strip()

    if not organization_id:

        raise HTTPException(
            status_code=403,
            detail=(
                "Organization context is required "
                "for report generation."
            )
        )

    # ========================================================
    # SAAS QUOTA: REPORT RESERVATION STATE
    # ========================================================

    report_quota_reserved = False

    # ========================================================
    # LOAD USER SCAN HISTORY
    # ========================================================

    scans = get_all_scans(
        user_id
    )

    if not scans:

        raise HTTPException(
            status_code=404,
            detail=(
                "No scan history found. "
                "Run an AWS security scan before "
                "generating a report."
            )
        )

    # ========================================================
    # FIND LATEST COMPLETED SCAN
    # ========================================================

    latest_scan = None

    for scan in scans:

        status = str(
            scan.get(
                "status",
                ""
            )
        ).strip().lower()

        if status == "completed":

            latest_scan = scan
            break

    # ========================================================
    # NO COMPLETED SCAN
    # ========================================================

    if latest_scan is None:

        raise HTTPException(
            status_code=409,
            detail=(
                "No completed security scan is available "
                "for report generation."
            )
        )

    # ========================================================
    # SAAS QUOTA: RESERVE REPORT
    #
    # Reserve only after confirming that a completed scan
    # exists. This prevents consuming quota when there is
    # nothing available to generate.
    # ========================================================

    try:

        reserve_quota(
            organization_id=organization_id,
            quota_type="reports",
            amount=1
        )

        report_quota_reserved = True

    except ValueError as quota_error:

        raise HTTPException(
            status_code=403,
            detail=str(quota_error)
        ) from quota_error

    # ========================================================
    # GENERATE PDF
    # ========================================================

    try:

        pdf_path = generate_pdf(
            latest_scan
        )

    except Exception as error:

        # Do not expose internal filesystem or library
        # details to the customer.

        print(
            "[REPORT] PDF generation failed:",
            error
        )

        # ====================================================
        # SAAS QUOTA: RELEASE RESERVED REPORT
        #
        # PDF generation failed, so the report quota should
        # not be consumed.
        # ====================================================

        if report_quota_reserved:

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="reports_used",
                    amount=1
                )

            except Exception as release_error:

                print(
                    "[REPORT] Failed to release report quota:",
                    release_error
                )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to generate the security report."
            )
        )

    # ========================================================
    # VALIDATE GENERATED FILE
    # ========================================================

    try:

        path = _validate_pdf_path(
            pdf_path
        )

    except Exception:

        # ====================================================
        # SAAS QUOTA: RELEASE RESERVED REPORT
        #
        # PDF path validation failed, therefore the report
        # was not successfully generated for the customer.
        # ====================================================

        if report_quota_reserved:

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="reports_used",
                    amount=1
                )

            except Exception as release_error:

                print(
                    "[REPORT] Failed to release report quota:",
                    release_error
                )

        raise

    # ========================================================
    # SAAS QUOTA: REPORT CONSUMED
    #
    # The PDF has now been successfully generated and
    # validated. The reserved quota is therefore consumed.
    #
    # Any later non-critical operation must NOT release it.
    # ========================================================

    report_quota_reserved = False

    # ========================================================
    # ACCOUNT-AWARE FILENAME
    # ========================================================

    aws_account_id = str(
        latest_scan.get(
            "aws_account_id",
            ""
        )
    ).strip()

    if aws_account_id:

        filename = (
            f"CloudGuardAI_Security_Report_"
            f"{aws_account_id}.pdf"
        )

    else:

        filename = (
            "CloudGuardAI_Security_Report.pdf"
        )

    # ========================================================
    # RESPONSE
    # ========================================================

    return FileResponse(
        path=str(path),
        filename=filename,
        media_type="application/pdf",
        headers={
            "Cache-Control": (
                "private, no-store, max-age=0"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )