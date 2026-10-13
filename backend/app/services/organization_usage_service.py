from datetime import datetime, timezone
from calendar import monthrange

from bson import ObjectId

from app.database.connection import db


USAGE = db.organization_usage


# ============================================================
# HELPERS
# ============================================================

def _get_month_period(reference_time=None):
    """
    Return the UTC start and end of the month containing
    reference_time.
    """

    now = reference_time or datetime.now(timezone.utc)

    period_start = datetime(
        now.year,
        now.month,
        1,
        tzinfo=timezone.utc
    )

    if now.month == 12:
        next_month = datetime(
            now.year + 1,
            1,
            1,
            tzinfo=timezone.utc
        )
    else:
        next_month = datetime(
            now.year,
            now.month + 1,
            1,
            tzinfo=timezone.utc
        )

    return period_start, next_month


def _normalize_organization_id(
    organization_id: str
):
    """
    Normalize and validate organization ID.
    """

    if not organization_id:
        raise ValueError(
            "Organization ID is required"
        )

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required"
        )

    try:
        ObjectId(organization_id)
    except Exception:
        raise ValueError(
            "Invalid organization ID"
        )

    return organization_id


# ============================================================
# INDEX INITIALIZATION
# ============================================================

def initialize_usage_indexes():
    """
    Initialize indexes required for efficient SaaS usage access.
    """

    USAGE.create_index(
        [
            ("organization_id", 1),
            ("period_start", 1)
        ],
        unique=True,
        name="organization_usage_period_unique_idx"
    )

    USAGE.create_index(
        "organization_id",
        name="organization_usage_org_idx"
    )


# ============================================================
# GET CURRENT USAGE
# ============================================================

def get_current_usage(
    organization_id: str
):
    """
    Return the current month's usage for an organization.

    If no usage record exists yet, return zero usage
    without creating a database document.
    """

    organization_id = _normalize_organization_id(
        organization_id
    )

    period_start, period_end = _get_month_period()

    usage = USAGE.find_one(
        {
            "organization_id": organization_id,
            "period_start": period_start
        }
    )

    if not usage:
        return {
            "organization_id": organization_id,
            "period_start": period_start,
            "period_end": period_end,
            "aws_accounts_used": 0,
            "team_members_used": 0,
            "scans_used": 0,
            "reports_used": 0,
            "storage_mb_used": 0
        }

    usage["id"] = str(
        usage["_id"]
    )

    usage.pop(
        "_id",
        None
    )

    return usage


# ============================================================
# ENSURE CURRENT USAGE RECORD
# ============================================================

def ensure_current_usage(
    organization_id: str
):
    """
    Create the current month's usage record if it does not exist.

    Uses atomic upsert so concurrent requests cannot create
    duplicate monthly usage documents.
    """

    organization_id = _normalize_organization_id(
        organization_id
    )

    period_start, period_end = _get_month_period()

    now = datetime.now(
        timezone.utc
    )

    result = USAGE.find_one_and_update(
        {
            "organization_id": organization_id,
            "period_start": period_start
        },
        {
            "$setOnInsert": {
                "organization_id": organization_id,
                "period_start": period_start,
                "period_end": period_end,
                "aws_accounts_used": 0,
                "team_members_used": 0,
                "scans_used": 0,
                "reports_used": 0,
                "storage_mb_used": 0,
                "created_at": now,
                "updated_at": now
            }
        },
        upsert=True,
        return_document=True
    )

    result["id"] = str(
        result["_id"]
    )

    result.pop(
        "_id",
        None
    )

    return result


# ============================================================
# INCREMENT USAGE
# ============================================================

def increment_usage(
    organization_id: str,
    usage_field: str,
    amount: int = 1
):
    """
    Atomically increment a usage counter.

    Supported fields:
        aws_accounts_used
        team_members_used
        scans_used
        reports_used
        storage_mb_used
    """

    organization_id = _normalize_organization_id(
        organization_id
    )

    allowed_fields = {
        "aws_accounts_used",
        "team_members_used",
        "scans_used",
        "reports_used",
        "storage_mb_used"
    }

    if usage_field not in allowed_fields:
        raise ValueError(
            "Invalid usage field"
        )

    try:
        amount = int(amount)
    except (
        ValueError,
        TypeError
    ):
        raise ValueError(
            "Usage amount must be an integer"
        )

    if amount <= 0:
        raise ValueError(
            "Usage amount must be greater than zero"
        )

    period_start, period_end = _get_month_period()

    now = datetime.now(
        timezone.utc
    )

    result = USAGE.find_one_and_update(
        {
            "organization_id": organization_id,
            "period_start": period_start
        },
        {
            "$setOnInsert": {
                "organization_id": organization_id,
                "period_start": period_start,
                "period_end": period_end,
                "aws_accounts_used": 0,
                "team_members_used": 0,
                "scans_used": 0,
                "reports_used": 0,
                "storage_mb_used": 0,
                "created_at": now
            },
            "$inc": {
                usage_field: amount
            },
            "$set": {
                "updated_at": now
            }
        },
        upsert=True,
        return_document=True
    )

    result["id"] = str(
        result["_id"]
    )

    result.pop(
        "_id",
        None
    )

    return result


# ============================================================
# DECREMENT USAGE
# ============================================================

def decrement_usage(
    organization_id: str,
    usage_field: str,
    amount: int = 1
):
    """
    Atomically decrement a usage counter.

    Counters are never allowed to become negative.
    """

    organization_id = _normalize_organization_id(
        organization_id
    )

    allowed_fields = {
        "aws_accounts_used",
        "team_members_used",
        "scans_used",
        "reports_used",
        "storage_mb_used"
    }

    if usage_field not in allowed_fields:
        raise ValueError(
            "Invalid usage field"
        )

    try:
        amount = int(amount)
    except (
        ValueError,
        TypeError
    ):
        raise ValueError(
            "Usage amount must be an integer"
        )

    if amount <= 0:
        raise ValueError(
            "Usage amount must be greater than zero"
        )

    period_start, _ = _get_month_period()

    now = datetime.now(
        timezone.utc
    )

    result = USAGE.find_one_and_update(
        {
            "organization_id": organization_id,
            "period_start": period_start,
            usage_field: {
                "$gte": amount
            }
        },
        {
            "$inc": {
                usage_field: -amount
            },
            "$set": {
                "updated_at": now
            }
        },
        return_document=True
    )

    if not result:
        raise ValueError(
            "Usage cannot be reduced below zero"
        )

    result["id"] = str(
        result["_id"]
    )

    result.pop(
        "_id",
        None
    )

    return result


# ============================================================
# ATOMIC USAGE RESERVATION
# ============================================================

def reserve_usage(
    organization_id: str,
    usage_field: str,
    limit: int,
    amount: int = 1
):
    """
    Atomically reserve usage against a quota limit.

    Reservation succeeds only when:

        current_usage + amount <= limit

    The usage document is ensured before the conditional
    update. This avoids MongoDB conflicts between $inc and
    $setOnInsert on the same usage field.
    """

    organization_id = _normalize_organization_id(
        organization_id
    )

    allowed_fields = {
        "aws_accounts_used",
        "team_members_used",
        "scans_used",
        "reports_used",
        "storage_mb_used"
    }

    if usage_field not in allowed_fields:
        raise ValueError(
            "Invalid usage field"
        )

    try:
        amount = int(amount)
    except (
        ValueError,
        TypeError
    ):
        raise ValueError(
            "Usage amount must be an integer"
        )

    if amount <= 0:
        raise ValueError(
            "Usage amount must be greater than zero"
        )

    try:
        limit = int(limit)
    except (
        ValueError,
        TypeError
    ):
        raise ValueError(
            "Quota limit must be an integer"
        )

    if limit < -1:
        raise ValueError(
            "Quota limit cannot be less than -1"
        )

    # --------------------------------------------------------
    # Unlimited quota
    # --------------------------------------------------------

    if limit == -1:

        ensure_current_usage(
            organization_id
        )

        period_start, _ = _get_month_period()

        now = datetime.now(
            timezone.utc
        )

        result = USAGE.find_one_and_update(
            {
                "organization_id": organization_id,
                "period_start": period_start
            },
            {
                "$inc": {
                    usage_field: amount
                },
                "$set": {
                    "updated_at": now
                }
            },
            return_document=True
        )

        if not result:
            raise ValueError(
                "Unable to reserve usage"
            )

        used = int(
            result.get(
                usage_field,
                0
            )
        )

        result["id"] = str(
            result["_id"]
        )

        result.pop(
            "_id",
            None
        )

        return {
            "reserved": True,
            "organization_id": organization_id,
            "usage_field": usage_field,
            "used": used,
            "limit": -1,
            "requested": amount,
            "remaining": None,
            "unlimited": True
        }

    # --------------------------------------------------------
    # Ensure usage document exists
    # --------------------------------------------------------

    ensure_current_usage(
        organization_id
    )

    period_start, _ = _get_month_period()

    now = datetime.now(
        timezone.utc
    )

    # --------------------------------------------------------
    # Atomic conditional update
    # --------------------------------------------------------

    result = USAGE.find_one_and_update(
        {
            "organization_id": organization_id,
            "period_start": period_start,
            usage_field: {
                "$lte": limit - amount
            }
        },
        {
            "$inc": {
                usage_field: amount
            },
            "$set": {
                "updated_at": now
            }
        },
        return_document=True
    )

    # --------------------------------------------------------
    # Quota exceeded
    # --------------------------------------------------------

    if not result:

        current_usage = get_current_usage(
            organization_id
        )

        used = int(
            current_usage.get(
                usage_field,
                0
            )
        )

        return {
            "reserved": False,
            "organization_id": organization_id,
            "usage_field": usage_field,
            "used": used,
            "limit": limit,
            "requested": amount,
            "remaining": max(
                limit - used,
                0
            ),
            "unlimited": False
        }

    # --------------------------------------------------------
    # Reservation successful
    # --------------------------------------------------------

    used = int(
        result.get(
            usage_field,
            0
        )
    )

    result["id"] = str(
        result["_id"]
    )

    result.pop(
        "_id",
        None
    )

    return {
        "reserved": True,
        "organization_id": organization_id,
        "usage_field": usage_field,
        "used": used,
        "limit": limit,
        "requested": amount,
        "remaining": max(
            limit - used,
            0
        ),
        "unlimited": False
    }


# ============================================================
# RELEASE USAGE RESERVATION
# ============================================================

def release_usage(
    organization_id: str,
    usage_field: str,
    amount: int = 1
):
    """
    Release previously reserved usage.

    This is used when a resource creation operation fails
    after quota reservation.
    """

    return decrement_usage(
        organization_id=organization_id,
        usage_field=usage_field,
        amount=amount
    )   