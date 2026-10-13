from datetime import datetime, timedelta, timezone

from bson import ObjectId

from app.database.connection import db


ORGANIZATIONS = db.organizations
SUBSCRIPTIONS = db.organization_subscriptions


# ============================================================
# FREE TRIAL CONFIGURATION
# ============================================================

TRIAL_DURATION_DAYS = 14


# ============================================================
# DATETIME HELPERS
# ============================================================

def _utc_now():
    """
    Return the current UTC time as a timezone-aware datetime.
    """

    return datetime.now(
        timezone.utc
    )


def _ensure_utc(
    value
):
    """
    Normalize a datetime to timezone-aware UTC.

    MongoDB/PyMongo may return UTC datetimes as either
    timezone-aware or timezone-naive depending on configuration.
    """

    if value is None:
        return None

    if value.tzinfo is None:

        return value.replace(
            tzinfo=timezone.utc
        )

    return value.astimezone(
        timezone.utc
    )


# ============================================================
# CALCULATE TRIAL END
# ============================================================

def calculate_trial_end(
    start_time=None,
    duration_days=TRIAL_DURATION_DAYS
):
    """
    Calculate the end time of a free trial.
    """

    start_time = (
        start_time
        or _utc_now()
    )

    start_time = _ensure_utc(
        start_time
    )

    try:

        duration_days = int(
            duration_days
        )

    except (
        ValueError,
        TypeError
    ):

        raise ValueError(
            "Trial duration must be an integer"
        )

    if duration_days <= 0:

        raise ValueError(
            "Trial duration must be greater than zero"
        )

    return start_time + timedelta(
        days=duration_days
    )


# ============================================================
# START FREE TRIAL
# ============================================================

def start_free_trial(
    organization_id: str,
    duration_days=TRIAL_DURATION_DAYS
):
    """
    Start a free trial for an organization.

    An active trial cannot be restarted or extended.

    An organization with an active paid subscription
    cannot start a free trial.
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

        organization_object_id = ObjectId(
            organization_id
        )

    except Exception:

        raise ValueError(
            "Invalid organization ID"
        )

    organization = ORGANIZATIONS.find_one(
        {
            "_id": organization_object_id
        }
    )

    if not organization:

        raise ValueError(
            "Organization not found"
        )

    # --------------------------------------------------------
    # Prevent starting trial when paid subscription is active
    # --------------------------------------------------------

    existing_subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id,
            "status": {
                "$in": [
                    "active",
                    "past_due"
                ]
            },
            "plan": {
                "$nin": [
                    "free"
                ]
            }
        },
        {
            "plan": 1,
            "status": 1
        }
    )

    if existing_subscription:

        raise ValueError(
            "Organization already has an active paid subscription"
        )

    now = _utc_now()

    existing_trial_end = _ensure_utc(
        organization.get(
            "trial_ends_at"
        )
    )

    # --------------------------------------------------------
    # Prevent restarting an active trial
    # --------------------------------------------------------

    if (
        existing_trial_end
        and existing_trial_end > now
    ):

        return {
            "started": False,
            "organization_id": organization_id,
            "trial_ends_at": existing_trial_end,
            "message": "Free trial is already active"
        }

    # --------------------------------------------------------
    # Calculate trial end
    # --------------------------------------------------------

    trial_ends_at = calculate_trial_end(
        start_time=now,
        duration_days=duration_days
    )

    # --------------------------------------------------------
    # Update organization
    # --------------------------------------------------------

    result = ORGANIZATIONS.update_one(
        {
            "_id": organization_object_id
        },
        {
            "$set": {
                "trial_ends_at": trial_ends_at,
                "updated_at": now
            }
        }
    )

    if result.matched_count == 0:

        raise ValueError(
            "Organization not found"
        )

    return {
        "started": True,
        "organization_id": organization_id,
        "trial_started_at": now,
        "trial_ends_at": trial_ends_at,
        "duration_days": duration_days,
        "message": "Free trial started successfully"
    }


# ============================================================
# GET TRIAL STATUS
# ============================================================

def get_trial_status(
    organization_id: str
):
    """
    Return the current free trial status.

    An active paid subscription takes precedence over
    any old trial_ends_at value stored on the organization.
    """

    if not organization_id:

        raise ValueError(
            "Organization ID is required"
        )

    organization_id = str(
        organization_id
    ).strip()

    try:

        organization_object_id = ObjectId(
            organization_id
        )

    except Exception:

        raise ValueError(
            "Invalid organization ID"
        )

    organization = ORGANIZATIONS.find_one(
        {
            "_id": organization_object_id
        },
        {
            "trial_ends_at": 1,
            "plan": 1,
            "status": 1
        }
    )

    if not organization:

        raise ValueError(
            "Organization not found"
        )

    now = _utc_now()

    trial_ends_at = _ensure_utc(
        organization.get(
            "trial_ends_at"
        )
    )

    # --------------------------------------------------------
    # PAID SUBSCRIPTION OVERRIDES TRIAL STATE
    # --------------------------------------------------------

    subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id,
            "status": {
                "$in": [
                    "active",
                    "past_due"
                ]
            }
        },
        {
            "plan": 1,
            "status": 1,
            "trial_ends_at": 1
        }
    )

    if subscription:

        subscription_plan = str(
            subscription.get(
                "plan",
                "free"
            )
        ).strip().lower()

        # ----------------------------------------------------
        # Only paid plans override the free-trial state.
        # ----------------------------------------------------

        if subscription_plan != "free":

            return {
                "organization_id": organization_id,
                "trial_active": False,
                "trial_expired": False,
                "trial_configured": bool(
                    trial_ends_at
                ),
                "trial_ends_at": trial_ends_at,
                "days_remaining": 0,
                "plan": subscription.get(
                    "plan",
                    organization.get(
                        "plan",
                        "free"
                    )
                ),
                "organization_status": organization.get(
                    "status",
                    "active"
                ),
                "subscription_status": subscription.get(
                    "status"
                ),
                "subscription_active": True
            }

    # --------------------------------------------------------
    # No trial configured
    # --------------------------------------------------------

    if not trial_ends_at:

        return {
            "organization_id": organization_id,
            "trial_active": False,
            "trial_expired": False,
            "trial_configured": False,
            "trial_ends_at": None,
            "days_remaining": 0,
            "plan": organization.get(
                "plan",
                "free"
            ),
            "organization_status": organization.get(
                "status",
                "active"
            ),
            "subscription_active": False
        }

    # --------------------------------------------------------
    # Active trial
    # --------------------------------------------------------

    if trial_ends_at > now:

        remaining_seconds = (
            trial_ends_at - now
        ).total_seconds()

        days_remaining = max(
            1,
            int(
                remaining_seconds / 86400
            )
        )

        return {
            "organization_id": organization_id,
            "trial_active": True,
            "trial_expired": False,
            "trial_configured": True,
            "trial_ends_at": trial_ends_at,
            "days_remaining": days_remaining,
            "plan": organization.get(
                "plan",
                "free"
            ),
            "organization_status": organization.get(
                "status",
                "active"
            ),
            "subscription_active": False
        }

    # --------------------------------------------------------
    # Expired trial
    # --------------------------------------------------------

    return {
        "organization_id": organization_id,
        "trial_active": False,
        "trial_expired": True,
        "trial_configured": True,
        "trial_ends_at": trial_ends_at,
        "days_remaining": 0,
        "plan": organization.get(
            "plan",
            "free"
        ),
        "organization_status": organization.get(
            "status",
            "active"
        ),
        "subscription_active": False
    }


# ============================================================
# TRIAL ACTIVE CHECK
# ============================================================

def is_trial_active(
    organization_id: str
):
    """
    Return True when the organization's free trial
    is currently active.
    """

    status = get_trial_status(
        organization_id
    )

    return status[
        "trial_active"
    ]


# ============================================================
# EXPIRE TRIALS
# ============================================================

def expire_trials():
    """
    Mark organizations with expired trials as inactive
    when they are still in the trial lifecycle.

    This function can later be called by the background
    scheduler.
    """

    now = _utc_now()

    result = ORGANIZATIONS.update_many(
        {
            "trial_ends_at": {
                "$lte": now
            },
            "status": "active",
            "plan": "free"
        },
        {
            "$set": {
                "status": "trial_expired",
                "updated_at": now
            }
        }
    )

    return {
        "expired_count": result.modified_count,
        "checked_at": now
    }


# ============================================================
# TRIAL SERVICE HEALTH
# ============================================================

def trial_service_health():
    """
    Return trial service health information.
    """

    return {
        "service": "trial_service",
        "status": "healthy",
        "trial_duration_days": TRIAL_DURATION_DAYS
    }