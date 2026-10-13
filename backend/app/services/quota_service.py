from typing import Optional

from app.services.organization_plan_service import (
    get_organization_plan
)

from app.services.organization_usage_service import (
    get_current_usage,
    reserve_usage
)


# ============================================================
# SUPPORTED QUOTA TYPES
# ============================================================

SUPPORTED_QUOTAS = {
    "aws_accounts": {
        "usage_field": "aws_accounts_used",
        "limit_field": "max_aws_accounts",
    },
    "team_members": {
        "usage_field": "team_members_used",
        "limit_field": "max_team_members",
    },
    "scans": {
        "usage_field": "scans_used",
        "limit_field": "max_scans_per_month",
    },
    "reports": {
        "usage_field": "reports_used",
        "limit_field": "max_reports_per_month",
    },
    "storage_mb": {
        "usage_field": "storage_mb_used",
        "limit_field": "max_storage_mb",
    },
}


# ============================================================
# QUOTA RESULT
# ============================================================

def check_quota(
    organization_id: str,
    quota_type: str,
    amount: int = 1
) -> dict:
    """
    Check whether an organization has enough quota
    available for a requested operation.

    This function does not modify usage.
    """

    organization_id = str(
        organization_id
    ).strip()

    quota_type = str(
        quota_type
    ).strip().lower()

    if not organization_id:
        return {
            "allowed": False,
            "reason": "Organization ID is required."
        }

    if quota_type not in SUPPORTED_QUOTAS:
        return {
            "allowed": False,
            "reason": f"Unsupported quota type: {quota_type}"
        }

    if amount < 1:
        return {
            "allowed": False,
            "reason": "Quota amount must be at least 1."
        }

    organization_plan = get_organization_plan(
        organization_id
    )

    if not organization_plan:
        return {
            "allowed": False,
            "reason": "Organization plan could not be resolved."
        }

    plan = organization_plan["plan"]

    organization_status = organization_plan.get(
        "organization_status",
        "active"
    )

    if organization_status != "active":
        return {
            "allowed": False,
            "reason": "Organization is not active.",
            "organization_status": organization_status
        }

    quota_config = SUPPORTED_QUOTAS[
        quota_type
    ]

    usage_field = quota_config[
        "usage_field"
    ]

    limit_field = quota_config[
        "limit_field"
    ]

    current_usage = get_current_usage(
        organization_id
    )

    used = int(
        current_usage.get(
            usage_field,
            0
        )
    )

    limit = int(
        plan.get(
            limit_field,
            0
        )
    )

    # --------------------------------------------------------
    # Unlimited quota
    # --------------------------------------------------------

    if limit == -1:
        return {
            "allowed": True,
            "quota_type": quota_type,
            "used": used,
            "requested": amount,
            "limit": -1,
            "remaining": -1,
            "unlimited": True,
            "plan": plan["name"]
        }

    remaining = max(
        limit - used,
        0
    )

    allowed = (
        used + amount <= limit
    )

    return {
        "allowed": allowed,
        "quota_type": quota_type,
        "used": used,
        "requested": amount,
        "limit": limit,
        "remaining": remaining,
        "unlimited": False,
        "plan": plan["name"],
    }


# ============================================================
# QUOTA ENFORCEMENT
# ============================================================

def enforce_quota(
    organization_id: str,
    quota_type: str,
    amount: int = 1
) -> dict:
    """
    Enforce an organization's SaaS quota.

    Returns the quota information when allowed.

    Raises ValueError when the quota is exceeded.
    """

    result = check_quota(
        organization_id=organization_id,
        quota_type=quota_type,
        amount=amount
    )

    if not result.get("allowed"):
        reason = result.get(
            "reason",
            "Quota exceeded."
        )

        if "reason" not in result:
            quota_type_display = quota_type.replace(
                "_",
                " "
            ).title()

            reason = (
                f"{quota_type_display} quota exceeded. "
                f"Current usage: {result.get('used', 0)}, "
                f"limit: {result.get('limit', 0)}."
            )

        raise ValueError(
            reason
        )

    return result


# ============================================================
# ATOMIC QUOTA RESERVATION
# ============================================================

def reserve_quota(
    organization_id: str,
    quota_type: str,
    amount: int = 1
) -> dict:
    """
    Atomically reserve quota for an organization.

    This is used when quota must be reserved before
    creating a resource.

    Example:
        Team-member invitation

    The reservation prevents concurrent requests from
    exceeding the organization's quota.
    """

    organization_id = str(
        organization_id
    ).strip()

    quota_type = str(
        quota_type
    ).strip().lower()

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    if quota_type not in SUPPORTED_QUOTAS:
        raise ValueError(
            f"Unsupported quota type: {quota_type}"
        )

    if amount < 1:
        raise ValueError(
            "Quota amount must be at least 1."
        )

    organization_plan = get_organization_plan(
        organization_id
    )

    if not organization_plan:
        raise ValueError(
            "Organization plan could not be resolved."
        )

    organization_status = organization_plan.get(
        "organization_status",
        "active"
    )

    if organization_status != "active":
        raise ValueError(
            "Organization is not active."
        )

    plan = organization_plan["plan"]

    quota_config = SUPPORTED_QUOTAS[
        quota_type
    ]

    usage_field = quota_config[
        "usage_field"
    ]

    limit_field = quota_config[
        "limit_field"
    ]

    limit = int(
        plan.get(
            limit_field,
            0
        )
    )

    # --------------------------------------------------------
    # Unlimited quota
    # --------------------------------------------------------

    if limit == -1:
        return {
            "reserved": True,
            "quota_type": quota_type,
            "amount": amount,
            "limit": -1,
            "unlimited": True,
            "plan": plan["name"]
        }

    # --------------------------------------------------------
    # Atomic reservation
    # --------------------------------------------------------

    result = reserve_usage(
        organization_id=organization_id,
        usage_field=usage_field,
        amount=amount,
        limit=limit
    )

    if not result.get("reserved"):
        current_usage = get_current_usage(
            organization_id
        )

        used = int(
            current_usage.get(
                usage_field,
                0
            )
        )

        quota_type_display = quota_type.replace(
            "_",
            " "
        ).title()

        raise ValueError(
            f"{quota_type_display} quota exceeded. "
            f"Current usage: {used}, "
            f"limit: {limit}."
        )

    return {
        "reserved": True,
        "quota_type": quota_type,
        "amount": amount,
        "limit": limit,
        "unlimited": False,
        "plan": plan["name"],
        "usage": result
    }


# ============================================================
# QUOTA HELPERS
# ============================================================

def get_quota_status(
    organization_id: str
) -> dict:
    """
    Return the current quota status for all supported
    organization resources.
    """

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        return {
            "organization_id": organization_id,
            "status": "error",
            "message": "Organization ID is required."
        }

    organization_plan = get_organization_plan(
        organization_id
    )

    if not organization_plan:
        return {
            "organization_id": organization_id,
            "status": "error",
            "message": "Organization plan could not be resolved."
        }

    plan = organization_plan["plan"]

    current_usage = get_current_usage(
        organization_id
    )

    quotas = {}

    for quota_type, config in SUPPORTED_QUOTAS.items():

        usage_field = config[
            "usage_field"
        ]

        limit_field = config[
            "limit_field"
        ]

        used = int(
            current_usage.get(
                usage_field,
                0
            )
        )

        limit = int(
            plan.get(
                limit_field,
                0
            )
        )

        if limit == -1:
            remaining: Optional[int] = -1
            percentage = 0

        else:
            remaining = max(
                limit - used,
                0
            )

            percentage = (
                round(
                    (used / limit) * 100,
                    2
                )
                if limit > 0
                else 100
            )

        quotas[quota_type] = {
            "used": used,
            "limit": limit,
            "remaining": remaining,
            "percentage_used": percentage,
            "unlimited": limit == -1,
        }

    return {
        "organization_id": organization_id,
        "plan": plan["name"],
        "organization_status": organization_plan.get(
            "organization_status",
            "active"
        ),
        "quotas": quotas
    }


# ============================================================
# SERVICE HEALTH CHECK
# ============================================================

def quota_service_health() -> dict:
    """
    Basic service health information.
    """

    return {
        "service": "quota_service",
        "status": "healthy",
        "supported_quotas": list(
            SUPPORTED_QUOTAS.keys()
        )
    }