from datetime import datetime, timezone

from app.database.connection import db
from app.services.organization_usage_service import (
    ensure_current_usage,
    _get_month_period
)


# ============================================================
# COLLECTIONS
# ============================================================

ORGANIZATIONS = db.organizations
AWS_ACCOUNTS = db.aws_accounts
ORGANIZATION_MEMBERS = db.organization_members


# ============================================================
# RESOURCE COUNTERS
# ============================================================

def count_organization_aws_accounts(
    organization_id: str
) -> int:
    """
    Count all AWS accounts belonging to an organization.
    """

    return AWS_ACCOUNTS.count_documents({
        "organization_id": str(organization_id)
    })


def count_organization_team_members(
    organization_id: str
) -> int:
    """
    Count active organization members.

    The owner is included in the team-member usage count.
    """

    return ORGANIZATION_MEMBERS.count_documents({
        "organization_id": str(organization_id),
        "status": "active"
    })


# ============================================================
# SYNCHRONIZE ONE ORGANIZATION
# ============================================================

def synchronize_organization_usage(
    organization_id: str
) -> dict:
    """
    Synchronize persistent monthly usage counters with
    the organization's current resource state.

    This function is safe to run repeatedly.
    """

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    organization = ORGANIZATIONS.find_one({
        "_id": __import__("bson").ObjectId(
            organization_id
        )
    })

    if not organization:
        raise ValueError(
            "Organization not found."
        )

    # --------------------------------------------------------
    # Ensure current monthly usage record exists
    # --------------------------------------------------------

    ensure_current_usage(
        organization_id
    )

    # --------------------------------------------------------
    # Calculate actual resource usage
    # --------------------------------------------------------

    aws_accounts_used = count_organization_aws_accounts(
        organization_id
    )

    team_members_used = count_organization_team_members(
        organization_id
    )

    # --------------------------------------------------------
    # Current monthly period
    # --------------------------------------------------------

    period_start, period_end = _get_month_period()

    # --------------------------------------------------------
    # Update synchronized counters
    #
    # Scans, reports and storage are intentionally NOT
    # recalculated here yet because their historical/monthly
    # semantics require dedicated synchronization logic.
    # --------------------------------------------------------

    updated_at = datetime.now(
        timezone.utc
    )

    db.organization_usage.update_one(
        {
            "organization_id": organization_id,
            "period_start": period_start
        },
        {
            "$set": {
                "period_end": period_end,
                "aws_accounts_used": aws_accounts_used,
                "team_members_used": team_members_used,
                "updated_at": updated_at
            }
        }
    )

    return {
        "organization_id": organization_id,
        "aws_accounts_used": aws_accounts_used,
        "team_members_used": team_members_used,
        "synced_at": updated_at
    }


# ============================================================
# SYNCHRONIZE ALL ORGANIZATIONS
# ============================================================

def synchronize_all_organizations() -> dict:
    """
    Synchronize usage for every organization.

    Intended for controlled administrative jobs,
    migrations and production maintenance tasks.
    """

    total = 0
    successful = 0
    failed = 0
    errors = []

    for organization in ORGANIZATIONS.find(
        {},
        {
            "_id": 1
        }
    ):

        total += 1

        organization_id = str(
            organization["_id"]
        )

        try:

            synchronize_organization_usage(
                organization_id
            )

            successful += 1

        except Exception as exc:

            failed += 1

            errors.append({
                "organization_id": organization_id,
                "error": type(exc).__name__
            })

    return {
        "total_organizations": total,
        "successful": successful,
        "failed": failed,
        "errors": errors
    }


# ============================================================
# SERVICE HEALTH CHECK
# ============================================================

def usage_sync_service_health() -> dict:
    """
    Basic health information for the usage synchronization service.
    """

    return {
        "service": "organization_usage_sync_service",
        "status": "healthy",
        "synchronized_resources": [
            "aws_accounts",
            "team_members"
        ]
    }