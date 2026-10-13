from datetime import datetime, timezone
from typing import Optional

from bson import ObjectId

from app.database.connection import db
from app.services.subscription_plan_service import get_plan
from app.services.organization_usage_service import get_current_usage


ORGANIZATIONS = db.organizations


# ============================================================
# GET CURRENT SUBSCRIPTION
# ============================================================

def get_subscription(organization_id: str) -> Optional[dict]:
    """
    Return the current subscription state of an organization.

    Billing-provider integration will be connected later.
    """

    if not organization_id:
        return None

    organization_id = str(organization_id).strip()

    if not organization_id:
        return None

    try:
        object_id = ObjectId(organization_id)
    except Exception:
        raise ValueError("Invalid organization ID.")

    organization = ORGANIZATIONS.find_one(
        {"_id": object_id},
        {
            "plan": 1,
            "status": 1,

            # Billing provider state
            "billing_provider": 1,
            "billing_customer_id": 1,
            "subscription_id": 1,

            # Billing lifecycle
            "billing_cycle": 1,
            "current_period_start": 1,
            "current_period_end": 1,
            "cancel_at_period_end": 1,

            # Trial
            "trial_ends_at": 1,

            # Organization timestamps
            "created_at": 1,
            "updated_at": 1,
        }
    )

    if not organization:
        return None

    plan_name = str(
        organization.get("plan", "free")
    ).strip().lower()

    plan = get_plan(plan_name)

    if not plan:
        raise ValueError(
            f"Invalid subscription plan configured for organization: {plan_name}"
        )

    return {
        "organization_id": organization_id,

        "plan": plan,
        "plan_name": plan_name,

        "organization_status": organization.get(
            "status",
            "active"
        ),

        # Billing provider
        "billing_provider": organization.get(
            "billing_provider"
        ),

        "billing_customer_id": organization.get(
            "billing_customer_id"
        ),

        "subscription_id": organization.get(
            "subscription_id"
        ),

        # Billing lifecycle
        "billing_cycle": organization.get(
            "billing_cycle"
        ),

        "current_period_start": organization.get(
            "current_period_start"
        ),

        "current_period_end": organization.get(
            "current_period_end"
        ),

        "cancel_at_period_end": organization.get(
            "cancel_at_period_end",
            False
        ),

        # Trial
        "trial_ends_at": organization.get(
            "trial_ends_at"
        ),

        # Organization timestamps
        "created_at": organization.get(
            "created_at"
        ),

        "updated_at": organization.get(
            "updated_at"
        ),
    }


# ============================================================
# PLAN CHANGE VALIDATION
# ============================================================

def _validate_plan_change(
    organization_id: str,
    current_plan: dict,
    target_plan: dict
):
    """
    Validate whether an organization can move to
    the requested subscription plan.

    Downgrades are blocked when existing usage exceeds
    the target plan's limits.
    """

    usage = get_current_usage(
        organization_id
    )

    if not usage:
        return

    usage_limit_pairs = [
        (
            "aws_accounts_used",
            "max_aws_accounts",
            "AWS account"
        ),
        (
            "team_members_used",
            "max_team_members",
            "team member"
        ),
        (
            "scans_used",
            "max_scans_per_month",
            "monthly scan"
        ),
        (
            "reports_used",
            "max_reports_per_month",
            "monthly report"
        ),
        (
            "storage_mb_used",
            "max_storage_mb",
            "MB of storage"
        ),
    ]

    for usage_field, limit_field, resource_name in usage_limit_pairs:

        current_usage = int(
            usage.get(
                usage_field,
                0
            )
        )

        target_limit = int(
            target_plan.get(
                limit_field,
                0
            )
        )

        # -1 means unlimited.
        if target_limit == -1:
            continue

        if current_usage > target_limit:
            raise ValueError(
                f"Cannot change to {target_plan['name']} plan. "
                f"Current usage is {current_usage} {resource_name}(s), "
                f"but the target plan allows only {target_limit}."
            )


# ============================================================
# CHANGE ORGANIZATION PLAN
# ============================================================

def change_subscription_plan(
    organization_id: str,
    target_plan_name: str
) -> dict:
    """
    Change an organization's subscription plan.

    This is the SaaS subscription state layer.
    Payment processing will be connected later.

    Rules:
    - Organization must exist.
    - Target plan must exist and be active.
    - Downgrades cannot exceed target-plan limits.
    - Billing identifiers are preserved.
    """

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    try:
        object_id = ObjectId(
            organization_id
        )
    except Exception:
        raise ValueError(
            "Invalid organization ID."
        )

    target_plan_name = str(
        target_plan_name or ""
    ).strip().lower()

    if not target_plan_name:
        raise ValueError(
            "Target subscription plan is required."
        )

    target_plan = get_plan(
        target_plan_name
    )

    if not target_plan:
        raise ValueError(
            f"Invalid subscription plan: {target_plan_name}"
        )

    if not target_plan.get(
        "active",
        True
    ):
        raise ValueError(
            f"Subscription plan '{target_plan_name}' is not active."
        )

    organization = ORGANIZATIONS.find_one(
        {"_id": object_id},
        {
            "plan": 1,
            "status": 1
        }
    )

    if not organization:
        raise ValueError(
            "Organization not found."
        )

    organization_status = organization.get(
        "status",
        "active"
    )

    if organization_status not in {
        "active",
        "trial_expired"
    }:
        raise ValueError(
            "Organization subscription is not active."
        )

    current_plan_name = str(
        organization.get(
            "plan",
            "free"
        )
    ).strip().lower()

    current_plan = get_plan(
        current_plan_name
    )

    if not current_plan:
        raise ValueError(
            f"Invalid current subscription plan: {current_plan_name}"
        )

    # No-op protection.
    if current_plan_name == target_plan_name:
        return {
            "changed": False,
            "message": "Organization is already on this plan.",
            "organization_id": organization_id,
            "previous_plan": current_plan_name,
            "current_plan": target_plan_name,
            "plan": target_plan
        }

    # Validate usage before a downgrade or upgrade.
    _validate_plan_change(
        organization_id=organization_id,
        current_plan=current_plan,
        target_plan=target_plan
    )

    now = datetime.now(
        timezone.utc
    )

    result = ORGANIZATIONS.update_one(
        {
            "_id": object_id,
            "plan": current_plan_name
        },
        {
            "$set": {
                "plan": target_plan_name,
                "updated_at": now
            }
        }
    )

    if result.modified_count != 1:
        raise ValueError(
            "Subscription plan was not changed."
        )

    return {
        "changed": True,
        "message": "Subscription plan changed successfully.",
        "organization_id": organization_id,
        "previous_plan": current_plan_name,
        "current_plan": target_plan_name,
        "plan": target_plan,
        "changed_at": now
    }


# ============================================================
# HEALTH
# ============================================================

def subscription_service_health() -> dict:
    """
    Basic health information for the subscription service.
    """

    return {
        "service": "subscription_service",
        "status": "healthy",
        "billing_provider": "not_configured"
    }