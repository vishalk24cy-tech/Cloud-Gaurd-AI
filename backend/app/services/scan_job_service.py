from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.database.connection import db


# ============================================================
# COLLECTION
# ============================================================

COLLECTION = db.scan_jobs


# ============================================================
# CONSTANTS
# ============================================================

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_RETRYING = "retrying"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"


VALID_STATUSES = {
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_RETRYING,
    STATUS_COMPLETED,
    STATUS_FAILED,
}


ACTIVE_STATUSES = {
    STATUS_QUEUED,
    STATUS_RUNNING,
    STATUS_RETRYING,
}


# ============================================================
# HELPERS
# ============================================================

def _now():
    return datetime.now(timezone.utc)


def _safe_string(value):
    if value is None:
        return ""

    return str(value).strip()


def _build_active_job_key(
    organization_id: str,
    account_id: str,
):
    organization_id = _safe_string(
        organization_id
    )

    account_id = _safe_string(
        account_id
    )

    return (
        f"{organization_id}:"
        f"{account_id}"
    )


def _serialize_job(job):
    if not job:
        return None

    job = dict(job)

    if "_id" in job:
        job["_id"] = str(job["_id"])

    return job


def _object_id(job_id):
    try:
        return ObjectId(
            str(job_id)
        )
    except Exception:
        return None


# ============================================================
# RECOVER STALE JOBS
# ============================================================

def recover_stale_scan_jobs(
    stale_after_seconds: int = 600
):
    """
    Recover scan jobs left in RUNNING after a worker/process
    interruption.

    A running job is considered stale when its started_at
    timestamp is older than stale_after_seconds.

    Recovery behavior:
        - If attempts remain:
              RUNNING -> RETRYING
        - If max attempts are exhausted:
              RUNNING -> FAILED

    The update is atomic so multiple worker processes cannot
    recover the same job simultaneously.
    """

    try:
        stale_after_seconds = int(
            stale_after_seconds
        )
    except Exception:
        stale_after_seconds = 600

    stale_after_seconds = max(
        60,
        stale_after_seconds
    )

    now = _now()

    from datetime import timedelta

    stale_before = (
        now
        - timedelta(
            seconds=stale_after_seconds
        )
    )

    recovered = 0
    failed = 0

    while True:

        job = COLLECTION.find_one(
            {
                "status": STATUS_RUNNING,
                "started_at": {
                    "$lte": stale_before
                },
            },
            sort=[
                (
                    "started_at",
                    1
                )
            ]
        )

        if not job:
            break

        job_id = job.get(
            "_id"
        )

        organization_id = _safe_string(
            job.get(
                "organization_id"
            )
        )

        if not job_id or not organization_id:
            break

        attempts = int(
            job.get(
                "attempts",
                0
            )
        )

        max_attempts = int(
            job.get(
                "max_attempts",
                3
            )
        )

        stale_error = (
            "Scan worker interruption detected. "
            "The running job was recovered automatically."
        )

        if attempts < max_attempts:

            result = COLLECTION.find_one_and_update(
                {
                    "_id": job_id,
                    "organization_id": organization_id,
                    "status": STATUS_RUNNING,
                    "started_at": {
                        "$lte": stale_before
                    },
                },
                {
                    "$set": {
                        "status": STATUS_RETRYING,
                        "error_message": stale_error,
                        "next_retry_at": now,
                        "updated_at": now,
                        "worker_id": None,
                    }
                },
                return_document=True,
            )

            if result:
                recovered += 1
            else:
                continue

        else:

            result = COLLECTION.find_one_and_update(
                {
                    "_id": job_id,
                    "organization_id": organization_id,
                    "status": STATUS_RUNNING,
                    "started_at": {
                        "$lte": stale_before
                    },
                },
                {
                    "$set": {
                        "status": STATUS_FAILED,
                        "error_message": stale_error,
                        "failed_at": now,
                        "updated_at": now,
                        "next_retry_at": None,
                        "worker_id": None,
                        "active_job_key": None,
                    }
                },
                return_document=True,
            )

            if result:
                failed += 1
            else:
                continue

    return {
        "recovered": recovered,
        "failed": failed,
        "stale_after_seconds": stale_after_seconds,
    }


# ============================================================
# INDEX INITIALIZATION
# ============================================================

def initialize_scan_job_indexes():
    """
    Create production indexes for the scan_jobs collection.

    Important indexes:
        organization_id + created_at
        organization_id + status
        organization_id + account_id + status
        status + next_retry_at
        user_id + created_at

    Duplicate protection:
        unique active_job_key index with a partial filter.

    The unique index only applies to jobs whose status is:
        queued
        running
        retrying
    """

    COLLECTION.create_index(
        [
            ("organization_id", 1),
            ("created_at", -1),
        ],
        name="scan_job_org_created_idx",
    )

    COLLECTION.create_index(
        [
            ("organization_id", 1),
            ("status", 1),
        ],
        name="scan_job_org_status_idx",
    )

    COLLECTION.create_index(
        [
            ("organization_id", 1),
            ("account_id", 1),
            ("status", 1),
        ],
        name="scan_job_org_account_status_idx",
    )

    COLLECTION.create_index(
        [
            ("status", 1),
            ("next_retry_at", 1),
        ],
        name="scan_job_status_retry_idx",
    )

    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("created_at", -1),
        ],
        name="scan_job_user_created_idx",
    )

    # ========================================================
    # ATOMIC DUPLICATE-SCAN PROTECTION
    # ========================================================

    COLLECTION.create_index(
        [
            ("active_job_key", 1),
        ],
        unique=True,
        partialFilterExpression={
            "status": {
                "$in": [
                    STATUS_QUEUED,
                    STATUS_RUNNING,
                    STATUS_RETRYING,
                ]
            }
        },
        name="scan_job_active_unique_idx",
    )


# ============================================================
# CREATE JOB
# ============================================================

def create_scan_job(
    organization_id: str,
    user_id: str,
    account_id: str,
    aws_account_id: Optional[str] = None,
    max_attempts: int = 3,
):
    """
    Create a new queued AWS scan job.

    Duplicate protection:
        Only one active scan job is allowed for the same
        organization + AWS account.

    MongoDB unique partial index provides atomic protection
    against concurrent requests.

    Active statuses:
        queued
        running
        retrying

    Completed and failed jobs do not block a new scan.

    Tenant isolation:
        organization_id is always stored with the job.
    """

    organization_id = _safe_string(
        organization_id
    )

    user_id = _safe_string(
        user_id
    )

    account_id = _safe_string(
        account_id
    )

    # ========================================================
    # VALIDATION
    # ========================================================

    if not organization_id:
        raise ValueError(
            "organization_id is required"
        )

    if not user_id:
        raise ValueError(
            "user_id is required"
        )

    if not account_id:
        raise ValueError(
            "account_id is required"
        )

    if max_attempts < 1:
        raise ValueError(
            "max_attempts must be at least 1"
        )

    # ========================================================
    # ACTIVE JOB KEY
    # ========================================================

    active_job_key = _build_active_job_key(
        organization_id,
        account_id,
    )

    # ========================================================
    # OPTIONAL FRIENDLY DUPLICATE CHECK
    # ========================================================
    #
    # This provides a fast and clear error for normal
    # duplicate requests.
    #
    # The unique MongoDB index below is still the real
    # protection against race conditions.
    # ========================================================

    active_job = COLLECTION.find_one(
        {
            "organization_id": organization_id,
            "account_id": account_id,
            "status": {
                "$in": [
                    STATUS_QUEUED,
                    STATUS_RUNNING,
                    STATUS_RETRYING,
                ]
            },
        },
        sort=[
            (
                "created_at",
                -1
            )
        ],
    )

    if active_job:

        raise ValueError(
            "A scan is already active for this AWS account."
        )

    # ========================================================
    # CREATE JOB DOCUMENT
    # ========================================================

    now = _now()

    document = {
        "organization_id": organization_id,
        "user_id": user_id,

        "account_id": account_id,

        "aws_account_id": _safe_string(
            aws_account_id
        ) or None,

        "active_job_key": active_job_key,

        "status": STATUS_QUEUED,

        "attempts": 0,
        "max_attempts": max_attempts,

        "scan_id": None,

        "error_message": None,

        "queued_at": now,
        "started_at": None,
        "completed_at": None,
        "failed_at": None,

        "worker_id": None,

        "next_retry_at": None,

        "created_at": now,
        "updated_at": now,
    }

    # ========================================================
    # ATOMIC INSERT
    # ========================================================

    try:

        result = COLLECTION.insert_one(
            document
        )

    except DuplicateKeyError:

        raise ValueError(
            "A scan is already active for this AWS account."
        )

    # ========================================================
    # RETURN JOB
    # ========================================================

    document["_id"] = (
        result.inserted_id
    )

    return _serialize_job(
        document
    )


# ============================================================
# GET JOB
# ============================================================

def get_scan_job(
    job_id: str,
    organization_id: str,
):
    """
    Get a scan job belonging to the authenticated organization.
    """

    object_id = _object_id(
        job_id
    )

    organization_id = _safe_string(
        organization_id
    )

    if object_id is None:
        return None

    if not organization_id:
        return None

    job = COLLECTION.find_one(
        {
            "_id": object_id,
            "organization_id": organization_id,
        }
    )

    return _serialize_job(
        job
    )


# ============================================================
# LIST ORGANIZATION JOBS
# ============================================================

def get_scan_jobs(
    organization_id: str,
    limit: int = 50,
    status: Optional[str] = None,
):
    """
    Return scan jobs for one organization only.
    """

    organization_id = _safe_string(
        organization_id
    )

    if not organization_id:
        return []

    try:
        limit = int(
            limit
        )
    except Exception:
        limit = 50

    limit = max(
        1,
        min(
            limit,
            100
        )
    )

    query = {
        "organization_id": organization_id,
    }

    if status:

        status = _safe_string(
            status
        )

        if status not in VALID_STATUSES:

            raise ValueError(
                f"Invalid scan job status: {status}"
            )

        query["status"] = status

    jobs = (
        COLLECTION
        .find(query)
        .sort(
            "created_at",
            -1
        )
        .limit(limit)
    )

    return [
        _serialize_job(job)
        for job in jobs
    ]


# ============================================================
# CLAIM JOB
# ============================================================

def claim_scan_job(
    job_id: str,
    organization_id: str,
    worker_id: str,
):
    """
    Atomically claim a queued/retrying job.

    Only one worker should successfully transition
    a job into RUNNING.
    """

    object_id = _object_id(
        job_id
    )

    organization_id = _safe_string(
        organization_id
    )

    worker_id = _safe_string(
        worker_id
    )

    if object_id is None:
        return None

    if not organization_id:
        return None

    if not worker_id:
        return None

    now = _now()

    query = {
        "_id": object_id,

        "organization_id": organization_id,

        "$or": [
            {
                "status": STATUS_QUEUED,
            },
            {
                "status": STATUS_RETRYING,
                "$or": [
                    {
                        "next_retry_at": None,
                    },
                    {
                        "next_retry_at": {
                            "$lte": now,
                        }
                    },
                ],
            },
        ],
    }

    update = {
        "$set": {
            "status": STATUS_RUNNING,
            "started_at": now,
            "updated_at": now,
            "worker_id": worker_id,
            "error_message": None,
            "next_retry_at": None,
        },

        "$inc": {
            "attempts": 1,
        },
    }

    job = COLLECTION.find_one_and_update(
        query,
        update,
        return_document=True,
    )

    return _serialize_job(
        job
    )


# ============================================================
# COMPLETE JOB
# ============================================================

def complete_scan_job(
    job_id: str,
    organization_id: str,
    scan_id: str,
):
    """
    Mark a running scan job as successfully completed.

    The active_job_key is cleared so a new scan can be
    created for the same AWS account.
    """

    object_id = _object_id(
        job_id
    )

    organization_id = _safe_string(
        organization_id
    )

    scan_id = _safe_string(
        scan_id
    )

    if object_id is None:
        return None

    if not organization_id:
        return None

    if not scan_id:
        return None

    now = _now()

    result = COLLECTION.find_one_and_update(
        {
            "_id": object_id,
            "organization_id": organization_id,
            "status": STATUS_RUNNING,
        },
        {
            "$set": {
                "status": STATUS_COMPLETED,
                "scan_id": scan_id,
                "completed_at": now,
                "updated_at": now,
                "error_message": None,
                "next_retry_at": None,
                "active_job_key": None,
            }
        },
        return_document=True,
    )

    return _serialize_job(
        result
    )


# ============================================================
# FAIL JOB
# ============================================================

def fail_scan_job(
    job_id: str,
    organization_id: str,
    error_message: str,
):
    """
    Mark a running job as failed.

    If retry attempts remain:
        running -> retrying

    Otherwise:
        running -> failed

    The active_job_key remains while retrying so another
    scan cannot start during the retry window.

    Once permanently failed, the key is cleared.
    """

    object_id = _object_id(
        job_id
    )

    organization_id = _safe_string(
        organization_id
    )

    error_message = _safe_string(
        error_message
    )

    if object_id is None:
        return None

    if not organization_id:
        return None

    job = COLLECTION.find_one(
        {
            "_id": object_id,
            "organization_id": organization_id,
            "status": STATUS_RUNNING,
        }
    )

    if not job:
        return None

    attempts = int(
        job.get(
            "attempts",
            0
        )
    )

    max_attempts = int(
        job.get(
            "max_attempts",
            3
        )
    )

    now = _now()

    if attempts < max_attempts:

        retry_delay_seconds = min(
            300,
            30 * max(
                1,
                attempts
            )
        )

        from datetime import timedelta

        next_retry_at = (
            now
            + timedelta(
                seconds=retry_delay_seconds
            )
        )

        update = {
            "$set": {
                "status": STATUS_RETRYING,

                "error_message": (
                    error_message[:2000]
                    if error_message
                    else "Scan failed"
                ),

                "next_retry_at": next_retry_at,

                "updated_at": now,
            }
        }

    else:

        update = {
            "$set": {
                "status": STATUS_FAILED,

                "error_message": (
                    error_message[:2000]
                    if error_message
                    else "Scan failed"
                ),

                "failed_at": now,

                "updated_at": now,

                "next_retry_at": None,

                "active_job_key": None,
            }
        }

    result = COLLECTION.find_one_and_update(
        {
            "_id": object_id,
            "organization_id": organization_id,
            "status": STATUS_RUNNING,
        },
        update,
        return_document=True,
    )

    return _serialize_job(
        result
    )


# ============================================================
# CANCEL QUEUED JOB
# ============================================================

def cancel_scan_job(
    job_id: str,
    organization_id: str,
):
    """
    Cancel a job that has not started yet.

    We represent cancellation as failed with a clear reason.
    """

    object_id = _object_id(
        job_id
    )

    organization_id = _safe_string(
        organization_id
    )

    if object_id is None:
        return None

    if not organization_id:
        return None

    now = _now()

    result = COLLECTION.find_one_and_update(
        {
            "_id": object_id,
            "organization_id": organization_id,
            "status": {
                "$in": [
                    STATUS_QUEUED,
                    STATUS_RETRYING,
                ]
            },
        },
        {
            "$set": {
                "status": STATUS_FAILED,
                "error_message": "Scan job cancelled",
                "failed_at": now,
                "updated_at": now,
                "next_retry_at": None,
                "active_job_key": None,
            }
        },
        return_document=True,
    )

    return _serialize_job(
        result
    )