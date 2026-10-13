# ============================================================
# CloudGuardAI - Scan Worker
# Production Background Scan Execution
# ============================================================

import logging
import uuid

from app.services.scan_job_service import (
    get_scan_job,
    claim_scan_job,
    complete_scan_job,
    fail_scan_job,
)

from app.api.cloud import scan_aws


logger = logging.getLogger("cloudguardai.scan_worker")


# ============================================================
# PROCESS ONE SCAN JOB
# ============================================================

def process_scan_job(
    job_id: str,
    organization_id: str,
):
    """
    Process one queued/retryable scan job.

    The worker:
        1. Loads the tenant-scoped job.
        2. Atomically claims it.
        3. Executes the existing AWS scan engine.
        4. Marks the job completed with scan_id.
        5. Marks the job retrying/failed on error.

    The existing scan engine remains the source of truth
    for AWS scanning, quota handling, findings, audit logs,
    notifications, and scan persistence.
    """

    worker_id = (
        f"worker-"
        f"{uuid.uuid4().hex[:12]}"
    )

    # ========================================================
    # LOAD JOB
    # ========================================================

    job = get_scan_job(
        job_id=job_id,
        organization_id=organization_id,
    )

    if not job:

        logger.warning(
            "SCAN_JOB_NOT_FOUND job_id=%s organization_id=%s",
            job_id,
            organization_id,
        )

        return {
            "status": "not_found",
            "job_id": job_id,
        }

    # ========================================================
    # CLAIM JOB
    # ========================================================

    claimed_job = claim_scan_job(
        job_id=job_id,
        organization_id=organization_id,
        worker_id=worker_id,
    )

    if not claimed_job:

        logger.info(
            "SCAN_JOB_NOT_CLAIMED job_id=%s organization_id=%s",
            job_id,
            organization_id,
        )

        return {
            "status": "not_claimed",
            "job_id": job_id,
        }

    logger.info(
        "SCAN_JOB_STARTED job_id=%s worker_id=%s "
        "organization_id=%s account_id=%s attempt=%s",
        job_id,
        worker_id,
        organization_id,
        claimed_job.get("account_id"),
        claimed_job.get("attempts"),
    )

    # ========================================================
    # EXECUTE EXISTING AWS SCAN ENGINE
    # ========================================================

    try:

        account_id = str(
            claimed_job.get("account_id")
        )

        user_id = str(
            claimed_job.get("user_id")
        )

        # ----------------------------------------------------
        # scan_aws() expects the same authenticated-user
        # structure that verify_token normally returns.
        #
        # We construct only the fields required by the
        # existing scan engine.
        # ----------------------------------------------------

        worker_user = {
            "_id": user_id,
            "organization": organization_id,
        }

        result = scan_aws(
            account_id=account_id,
            current_user=worker_user,
        )

        # ====================================================
        # EXTRACT SCAN ID
        # ====================================================

        scan = {}

        if isinstance(result, dict):

            scan = result.get(
                "scan",
                {}
            )

        scan_id = None

        if isinstance(scan, dict):

            scan_id = scan.get(
                "_id"
            )

        # ====================================================
        # COMPLETE JOB
        # ====================================================

        completed_job = complete_scan_job(
            job_id=job_id,
            organization_id=organization_id,
            scan_id=(
                str(scan_id)
                if scan_id
                else None
            ),
        )

        logger.info(
            "SCAN_JOB_COMPLETED job_id=%s worker_id=%s "
            "organization_id=%s scan_id=%s",
            job_id,
            worker_id,
            organization_id,
            scan_id,
        )

        return {
            "status": "completed",
            "job": completed_job,
            "scan": scan,
        }

    except Exception as exc:

        logger.exception(
            "SCAN_JOB_FAILED job_id=%s worker_id=%s "
            "organization_id=%s error=%s",
            job_id,
            worker_id,
            organization_id,
            exc,
        )

        # ====================================================
        # RETRY / FAIL
        # ====================================================

        failed_job = fail_scan_job(
            job_id=job_id,
            organization_id=organization_id,
            error_message=(
                f"{type(exc).__name__}: "
                f"{str(exc)}"
            ),
        )

        return {
            "status": "failed",
            "job": failed_job,
        }
# ============================================================
# STANDALONE WORKER LOOP
# ============================================================

import time
from app.database.connection import db


def run_background_worker():
    """
    Continuously process queued/retryable scan jobs.

    This function is intended to run in a separate
    worker process from the FastAPI API server.
    """

    print("[SCAN-WORKER] Standalone worker started.")

    while True:

        try:

            job = db.scan_jobs.find_one(
                {
                    "status": {
                        "$in": [
                            "queued",
                            "retrying",
                        ]
                    }
                },
                sort=[
                    ("created_at", 1)
                ],
            )

            if not job:

                time.sleep(2)
                continue

            job_id = str(
                job["_id"]
            )

            organization_id = str(
                job["organization_id"]
            )

            print(
                f"[SCAN-WORKER] Processing job "
                f"{job_id}"
            )

            process_scan_job(
                job_id=job_id,
                organization_id=organization_id,
            )

        except KeyboardInterrupt:

            print(
                "[SCAN-WORKER] Worker stopped."
            )

            break

        except Exception as exc:

            logger.exception(
                "SCAN_WORKER_LOOP_ERROR error=%s",
                exc,
            )

            time.sleep(5)