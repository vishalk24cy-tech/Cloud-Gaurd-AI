from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId

from app.database.connection import db
from app.services.subscription_plan_service import get_plan


SUBSCRIPTIONS = db.organization_subscriptions
ORGANIZATIONS = db.organizations


# ============================================================
# VALID SUBSCRIPTION STATUSES
# ============================================================

VALID_STATUSES = {
    "trialing",
    "active",
    "past_due",
    "cancelled",
    "expired",
}


# ============================================================
# HELPERS
# ============================================================

def _utc_now() -> datetime:
    """
    Return the current UTC time.
    """
    return datetime.now(timezone.utc)


def _validate_organization_id(
    organization_id: str
) -> ObjectId:
    """
    Validate and convert organization ID to ObjectId.
    """

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    organization_id = str(
        organization_id
    ).strip()

    try:
        return ObjectId(
            organization_id
        )
    except Exception:
        raise ValueError(
            "Invalid organization ID."
        )


def _normalize_plan(
    plan_name: str
) -> dict:
    """
    Validate and return the requested subscription plan.
    """

    plan_name = str(
        plan_name or ""
    ).strip().lower()

    if not plan_name:
        raise ValueError(
            "Subscription plan is required."
        )

    plan = get_plan(
        plan_name
    )

    if not plan:
        raise ValueError(
            f"Invalid subscription plan: {plan_name}"
        )

    if not plan.get(
        "active",
        True
    ):
        raise ValueError(
            f"Subscription plan '{plan_name}' is not active."
        )

    return plan


# ============================================================
# INDEX INITIALIZATION
# ============================================================

def initialize_subscription_indexes() -> dict:
    """
    Create indexes required for production
    subscription lookups.
    """

    unique_org_index = SUBSCRIPTIONS.create_index(
        [("organization_id", 1)],
        unique=True,
        name="subscription_org_unique_idx"
    )

    status_index = SUBSCRIPTIONS.create_index(
        [("status", 1)],
        name="subscription_status_idx"
    )

    provider_subscription_index = SUBSCRIPTIONS.create_index(
        [
            ("provider", 1),
            ("subscription_id", 1)
        ],
        sparse=True,
        name="subscription_provider_id_idx"
    )

    return {
        "organization_index": unique_org_index,
        "status_index": status_index,
        "provider_subscription_index": provider_subscription_index,
    }


# ============================================================
# CREATE SUBSCRIPTION
# ============================================================

def create_subscription(
    organization_id: str,
    plan_name: str = "free",
    status: str = "trialing",
    trial_ends_at: Optional[datetime] = None,
    billing_cycle: Optional[str] = None,
    provider: Optional[str] = None,
    billing_customer_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
) -> dict:
    """
    Create the subscription record for an organization.

    Each organization can have only one subscription.
    """

    object_id = _validate_organization_id(
        organization_id
    )

    plan = _normalize_plan(
        plan_name
    )

    status = str(
        status or "trialing"
    ).strip().lower()

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid subscription status: {status}"
        )

    organization = ORGANIZATIONS.find_one(
        {
            "_id": object_id
        },
        {
            "_id": 1
        }
    )

    if not organization:
        raise ValueError(
            "Organization not found."
        )

    organization_id = str(
        organization_id
    ).strip()

    existing = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id
        }
    )

    if existing:
        raise ValueError(
            "Organization already has a subscription."
        )

    now = _utc_now()

    subscription = {
        "organization_id": organization_id,

        "plan": plan["name"],

        "status": status,

        # Billing provider information
        "provider": provider,

        "billing_customer_id": billing_customer_id,

        "subscription_id": subscription_id,

        # Billing cycle
        "billing_cycle": billing_cycle,

        "current_period_start": None,

        "current_period_end": None,

        "cancel_at_period_end": False,

        # Trial
        "trial_ends_at": trial_ends_at,

        # Timestamps
        "created_at": now,

        "updated_at": now,
    }

    result = SUBSCRIPTIONS.insert_one(
        subscription
    )

    subscription["_id"] = result.inserted_id

    return subscription


# ============================================================
# GET ORGANIZATION SUBSCRIPTION
# ============================================================

def get_organization_subscription(
    organization_id: str
) -> Optional[dict]:
    """
    Return the subscription belonging to an organization.
    """

    _validate_organization_id(
        organization_id
    )

    organization_id = str(
        organization_id
    ).strip()

    subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id
        }
    )

    return subscription


# ============================================================
# UPDATE SUBSCRIPTION STATUS
# ============================================================

def update_subscription_status(
    organization_id: str,
    status: str
) -> dict:
    """
    Update the lifecycle status of a subscription.
    """

    _validate_organization_id(
        organization_id
    )

    status = str(
        status or ""
    ).strip().lower()

    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid subscription status: {status}"
        )

    organization_id = str(
        organization_id
    ).strip()

    now = _utc_now()

    result = SUBSCRIPTIONS.update_one(
        {
            "organization_id": organization_id
        },
        {
            "$set": {
                "status": status,
                "updated_at": now
            }
        }
    )

    if result.matched_count != 1:
        raise ValueError(
            "Subscription not found."
        )

    return {
        "updated": True,

        "organization_id": organization_id,

        "status": status,

        "updated_at": now,
    }


# ============================================================
# CANCEL SUBSCRIPTION
# ============================================================

def cancel_subscription(
    organization_id: str,
    immediately: bool = False
) -> dict:
    """
    Cancel an organization's subscription.

    immediately=False:
        Subscription remains active until the
        current billing period ends.

    immediately=True:
        Subscription becomes cancelled immediately.
    """

    _validate_organization_id(
        organization_id
    )

    organization_id = str(
        organization_id
    ).strip()

    now = _utc_now()

    subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id
        }
    )

    if not subscription:
        raise ValueError(
            "Subscription not found."
        )

    if immediately:

        update = {
            "$set": {
                "status": "cancelled",

                "cancel_at_period_end": False,

                "updated_at": now
            }
        }

    else:

        update = {
            "$set": {
                "cancel_at_period_end": True,

                "updated_at": now
            }
        }

    SUBSCRIPTIONS.update_one(
        {
            "organization_id": organization_id
        },
        update
    )

    return {
        "cancelled": True,

        "immediately": immediately,

        "organization_id": organization_id,

        "status": (
            "cancelled"
            if immediately
            else subscription.get(
                "status",
                "active"
            )
        ),

        "cancel_at_period_end": (
            False
            if immediately
            else True
        ),

        "updated_at": now,
    }


# ============================================================
# SERVICE HEALTH
# ============================================================

def organization_subscription_service_health() -> dict:
    """
    Return subscription service health information.
    """

    return {
        "service": "organization_subscription_service",

        "status": "healthy",

        "collection": "organization_subscriptions",

        "supported_statuses": sorted(
            VALID_STATUSES
        ),
    }
# ============================================================
# SYNCHRONIZE ORGANIZATION SUBSCRIPTION
# ============================================================

def synchronize_subscription(
    organization_id: str
) -> dict:
    """
    Synchronize the dedicated subscription record with
    the organization's current SaaS plan and status.

    This keeps the legacy organization subscription state
    and the dedicated subscription collection consistent.
    """

    object_id = _validate_organization_id(
        organization_id
    )

    organization_id = str(
        organization_id
    ).strip()

    organization = ORGANIZATIONS.find_one(
        {
            "_id": object_id
        },
        {
            "plan": 1,
            "status": 1,
            "trial_ends_at": 1,
            "updated_at": 1
        }
    )

    if not organization:
        raise ValueError(
            "Organization not found."
        )

    plan_name = str(
        organization.get(
            "plan",
            "free"
        )
    ).strip().lower()

    plan = _normalize_plan(
        plan_name
    )

    organization_status = str(
        organization.get(
            "status",
            "active"
        )
    ).strip().lower()

    existing_subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id
        }
    )

    now = _utc_now()

    if not existing_subscription:
        subscription = {
            "organization_id": organization_id,

            "plan": plan["name"],

            "status": (
                "trialing"
                if organization_status == "active"
                and organization.get("trial_ends_at")
                else "active"
            ),

            "provider": None,

            "billing_customer_id": None,

            "subscription_id": None,

            "billing_cycle": None,

            "current_period_start": None,

            "current_period_end": None,

            "cancel_at_period_end": False,

            "trial_ends_at": organization.get(
                "trial_ends_at"
            ),

            "created_at": now,

            "updated_at": now,
        }

        result = SUBSCRIPTIONS.insert_one(
            subscription
        )

        subscription["_id"] = result.inserted_id

        return {
            "created": True,
            "updated": False,
            "organization_id": organization_id,
            "plan": plan["name"],
            "status": subscription["status"],
            "subscription_id": str(
                result.inserted_id
            ),
        }

    update_result = SUBSCRIPTIONS.update_one(
        {
            "organization_id": organization_id
        },
        {
            "$set": {
                "plan": plan["name"],
                "trial_ends_at": organization.get(
                    "trial_ends_at"
                ),
                "updated_at": now
            }
        }
    )

    return {
        "created": False,
        "updated": update_result.modified_count > 0,
        "organization_id": organization_id,
        "plan": plan["name"],
        "status": existing_subscription.get(
            "status",
            "active"
        ),
        "subscription_id": str(
            existing_subscription.get(
                "_id"
            )
        ),
    }
# ============================================================
# ACTIVATE VERIFIED RAZORPAY PAYMENT
# ============================================================

def activate_razorpay_subscription(
    organization_id: str,
    plan_name: str,
    billing_cycle: str,
    razorpay_order_id: str,
    razorpay_payment_id: str,
) -> dict:
    """
    Activate or upgrade an organization's subscription after
    a Razorpay payment has been successfully verified.

    This function updates both:
        1. organization_subscriptions
        2. organizations

    The operation is idempotent for the same Razorpay payment.
    """

    organization_id = str(
        organization_id or ""
    ).strip()

    plan_name = str(
        plan_name or ""
    ).strip().lower()

    billing_cycle = str(
        billing_cycle or ""
    ).strip().lower()

    razorpay_order_id = str(
        razorpay_order_id or ""
    ).strip()

    razorpay_payment_id = str(
        razorpay_payment_id or ""
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    if not razorpay_order_id:
        raise ValueError(
            "Razorpay order ID is required."
        )

    if not razorpay_payment_id:
        raise ValueError(
            "Razorpay payment ID is required."
        )

    if billing_cycle not in {
        "monthly",
        "yearly"
    }:
        raise ValueError(
            "Billing cycle must be 'monthly' or 'yearly'."
        )

    object_id = _validate_organization_id(
        organization_id
    )

    plan = _normalize_plan(
        plan_name
    )

    if plan["name"] == "free":
        raise ValueError(
            "The free plan does not require payment."
        )

    now = _utc_now()

    existing_subscription = SUBSCRIPTIONS.find_one(
        {
            "organization_id": organization_id
        }
    )

    # --------------------------------------------------------
    # Calculate billing period
    # --------------------------------------------------------

    if billing_cycle == "monthly":
        from datetime import timedelta

        period_end = now + timedelta(
            days=30
        )
    else:
        from datetime import timedelta

        period_end = now + timedelta(
            days=365
        )

    # --------------------------------------------------------
    # Idempotency check
    # --------------------------------------------------------

    if existing_subscription:
        if (
            existing_subscription.get(
                "subscription_id"
            )
            == razorpay_payment_id
            and existing_subscription.get(
                "provider"
            )
            == "razorpay"
        ):
            return {
                "activated": True,
                "already_processed": True,
                "organization_id": organization_id,
                "plan": existing_subscription.get(
                    "plan"
                ),
                "status": existing_subscription.get(
                    "status"
                ),
                "provider": "razorpay",
                "subscription_id": razorpay_payment_id,
                "billing_cycle": existing_subscription.get(
                    "billing_cycle"
                ),
            }

    # --------------------------------------------------------
    # Create subscription if missing
    # --------------------------------------------------------

    if not existing_subscription:

        subscription = {
            "organization_id": organization_id,
            "plan": plan["name"],
            "status": "active",
            "provider": "razorpay",
            "billing_customer_id": None,
            "subscription_id": razorpay_payment_id,
            "razorpay_order_id": razorpay_order_id,
            "billing_cycle": billing_cycle,
            "current_period_start": now,
            "current_period_end": period_end,
            "cancel_at_period_end": False,
            "trial_ends_at": None,
            "created_at": now,
            "updated_at": now,
        }

        result = SUBSCRIPTIONS.insert_one(
            subscription
        )

    else:

        # ----------------------------------------------------
        # Update existing subscription
        # ----------------------------------------------------

        update_result = SUBSCRIPTIONS.update_one(
            {
                "organization_id": organization_id
            },
            {
                "$set": {
                    "plan": plan["name"],
                    "status": "active",
                    "provider": "razorpay",
                    "subscription_id": razorpay_payment_id,
                    "razorpay_order_id": razorpay_order_id,
                    "billing_cycle": billing_cycle,
                    "current_period_start": now,
                    "current_period_end": period_end,
                    "cancel_at_period_end": False,
                    "trial_ends_at": None,
                    "updated_at": now,
                }
            }
        )

        if update_result.matched_count != 1:
            raise ValueError(
                "Subscription could not be updated."
            )

    # --------------------------------------------------------
    # Update organization SaaS plan
    # --------------------------------------------------------

    organization_result = ORGANIZATIONS.update_one(
        {
            "_id": object_id
        },
        {
            "$set": {
                "plan": plan["name"],
                "status": "active",
                "trial_ends_at": None,
                "updated_at": now,
            }
        }
    )

    if organization_result.matched_count != 1:
        raise ValueError(
            "Organization not found."
        )

    return {
        "activated": True,
        "already_processed": False,
        "organization_id": organization_id,
        "plan": plan["name"],
        "status": "active",
        "provider": "razorpay",
        "subscription_id": razorpay_payment_id,
        "razorpay_order_id": razorpay_order_id,
        "billing_cycle": billing_cycle,
        "current_period_start": now,
        "current_period_end": period_end,
    }