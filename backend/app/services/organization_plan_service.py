from typing import Optional

from app.database.connection import db
from app.services.subscription_plan_service import get_plan


ORGANIZATIONS = db.organizations


def get_organization_plan(
    organization_id: str
) -> Optional[dict]:
    """
    Resolve an organization's subscription plan.

    Returns the complete plan definition from the
    centralized subscription plan catalog.
    """

    if not organization_id:
        return None

    organization_id = str(organization_id).strip()

    if not organization_id:
        return None

    organization = ORGANIZATIONS.find_one(
        {
            "_id": __import__("bson").ObjectId(organization_id)
        },
        {
            "plan": 1,
            "status": 1
        }
    )

    if not organization:
        return None

    plan_name = organization.get("plan", "free")

    plan = get_plan(plan_name)

    if not plan:
        return None

    return {
        "organization_id": organization_id,
        "plan": plan,
        "organization_status": organization.get(
            "status",
            "active"
        )
    }


def get_organization_plan_name(
    organization_id: str
) -> Optional[str]:
    """
    Return only the organization's plan name.
    """

    if not organization_id:
        return None

    organization_id = str(organization_id).strip()

    if not organization_id:
        return None

    organization = ORGANIZATIONS.find_one(
        {
            "_id": __import__("bson").ObjectId(organization_id)
        },
        {
            "plan": 1
        }
    )

    if not organization:
        return None

    plan_name = organization.get("plan", "free")

    if not get_plan(plan_name):
        return None

    return plan_name