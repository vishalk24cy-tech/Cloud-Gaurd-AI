from datetime import datetime, timezone
import re

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.database.connection import db, client
from app.services.subscription_plan_service import get_plan


ORGANIZATIONS = db.organizations
MEMBERS = db.organization_members
USERS = db.users


def _slugify(name: str) -> str:
    """
    Convert an organization name into a URL-safe SaaS slug.
    """
    slug = name.strip().lower()

    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    slug = re.sub(r"-+", "-", slug)
    slug = slug.strip("-")

    return slug[:90]


def initialize_organization_indexes():
    """
    Initialize indexes required for SaaS organization management.
    """

    ORGANIZATIONS.create_index(
        "slug",
        unique=True,
        name="organization_slug_unique_idx"
    )

    ORGANIZATIONS.create_index(
        "owner_id",
        name="organization_owner_idx"
    )

    ORGANIZATIONS.create_index(
        "status",
        name="organization_status_idx"
    )


# ============================================================
# GET ORGANIZATION DETAILS
# ============================================================

def get_organization(
    organization_id: str
) -> dict:
    """
    Return organization details for SaaS management.

    Returns:
    - organization ID
    - organization name
    - slug
    - owner ID
    - subscription plan
    - organization status
    - trial end date
    - billing customer ID
    - subscription ID
    - created timestamp
    - updated timestamp
    """

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required"
        )

    # --------------------------------------------------------
    # Validate MongoDB ObjectId
    # --------------------------------------------------------

    if not ObjectId.is_valid(
        organization_id
    ):
        raise ValueError(
            "Invalid organization ID"
        )

    # --------------------------------------------------------
    # Find organization
    # --------------------------------------------------------

    organization = ORGANIZATIONS.find_one(
        {
            "_id": ObjectId(
                organization_id
            )
        },
        {
            "_id": 1,
            "name": 1,
            "slug": 1,
            "owner_id": 1,
            "plan": 1,
            "status": 1,
            "trial_ends_at": 1,
            "billing_customer_id": 1,
            "subscription_id": 1,
            "created_at": 1,
            "updated_at": 1
        }
    )

    if not organization:
        raise ValueError(
            "Organization not found"
        )

    # --------------------------------------------------------
    # Return clean SaaS organization response
    # --------------------------------------------------------

    return {
        "organization_id": str(
            organization["_id"]
        ),
        "name": organization.get(
            "name"
        ),
        "slug": organization.get(
            "slug"
        ),
        "owner_id": organization.get(
            "owner_id"
        ),
        "plan": organization.get(
            "plan",
            "free"
        ),
        "status": organization.get(
            "status",
            "active"
        ),
        "trial_ends_at": organization.get(
            "trial_ends_at"
        ),
        "billing_customer_id": organization.get(
            "billing_customer_id"
        ),
        "subscription_id": organization.get(
            "subscription_id"
        ),
        "created_at": organization.get(
            "created_at"
        ),
        "updated_at": organization.get(
            "updated_at"
        )
    }


# ============================================================
# CREATE ORGANIZATION
# ============================================================

def create_organization(
    name: str,
    owner_id: str,
    plan: str = "free"
):
    """
    Create a SaaS organization and owner membership atomically.

    Organization creation and owner membership creation happen
    inside one MongoDB transaction.
    """

    if not name or not name.strip():
        raise ValueError(
            "Organization name is required"
        )

    if not owner_id or not str(owner_id).strip():
        raise ValueError(
            "Organization owner is required"
        )

    clean_name = name.strip()
    owner_id = str(owner_id)

    slug = _slugify(clean_name)

    if not slug:
        raise ValueError(
            "Invalid organization name"
        )

    # -----------------------------------------
    # Validate SaaS subscription plan
    # -----------------------------------------

    plan = str(plan).strip().lower()

    if not get_plan(plan):
        raise ValueError(
            f"Invalid subscription plan: {plan}"
        )

    now = datetime.now(timezone.utc)

    organization = {
        "name": clean_name,
        "slug": slug,
        "owner_id": owner_id,
        "plan": plan,
        "status": "active",
        "trial_ends_at": None,
        "billing_customer_id": None,
        "subscription_id": None,
        "created_at": now,
        "updated_at": now,
    }

    try:

        # -----------------------------------------
        # Start MongoDB transaction
        # -----------------------------------------

        with client.start_session() as session:

            with session.start_transaction():

                # -----------------------------------------
                # Create organization
                # -----------------------------------------

                result = ORGANIZATIONS.insert_one(
                    organization,
                    session=session
                )

                organization_id = str(
                    result.inserted_id
                )

                # -----------------------------------------
                # Create owner membership
                # -----------------------------------------

                membership = {
                    "organization_id": organization_id,
                    "user_id": owner_id,
                    "role": "owner",
                    "status": "active",
                    "invited_by": None,
                    "invited_at": None,
                    "joined_at": now,
                    "created_at": now,
                    "updated_at": now,
                }

                MEMBERS.insert_one(
                    membership,
                    session=session
                )

        # -----------------------------------------
        # Transaction committed successfully
        # -----------------------------------------

        organization["_id"] = organization_id

        return organization

    except DuplicateKeyError:

        raise ValueError(
            "An organization with this name already exists"
        )

    except ValueError:

        raise

    except Exception as error:

        print(
            f"[ERROR] Organization transaction failed: {error}"
        )

        raise ValueError(
            "Unable to create organization"
        )


# ============================================================
# REMOVE ORGANIZATION MEMBER
# ============================================================

def remove_member(
    organization_id: str,
    user_id: str,
    requester_id: str
):
    """
    Remove an active member from an organization.

    Rules:
    - Requester must be an active owner/admin.
    - Organization owner cannot be removed.
    - Requester cannot remove themselves.
    - Admin cannot remove another admin.
    - Membership is marked as removed instead of deleted.
    """

    organization_id = str(
        organization_id
    ).strip()

    user_id = str(
        user_id
    ).strip()

    requester_id = str(
        requester_id
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required"
        )

    if not user_id:
        raise ValueError(
            "Member user ID is required"
        )

    if not requester_id:
        raise ValueError(
            "Requester ID is required"
        )

    if user_id == requester_id:

        raise ValueError(
            "You cannot remove yourself from the organization"
        )

    requester = MEMBERS.find_one({
        "organization_id": organization_id,
        "user_id": requester_id,
        "status": "active"
    })

    if not requester:

        raise ValueError(
            "You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise ValueError(
            "Only organization owners and admins can remove members"
        )

    target = MEMBERS.find_one({
        "organization_id": organization_id,
        "user_id": user_id,
        "status": "active"
    })

    if not target:

        raise ValueError(
            "Active organization member not found"
        )

    target_role = target.get(
        "role",
        "viewer"
    )

    if target_role == "owner":

        raise ValueError(
            "The organization owner cannot be removed"
        )

    if (
        requester_role == "admin"
        and target_role == "admin"
    ):

        raise ValueError(
            "Admins cannot remove other admins"
        )

    now = datetime.now(timezone.utc)

    try:

        # -----------------------------------------
        # Start transaction
        # -----------------------------------------

        with client.start_session() as session:

            with session.start_transaction():

                # -----------------------------------------
                # Mark membership as removed
                # -----------------------------------------

                result = MEMBERS.update_one(
                    {
                        "_id": target["_id"],
                        "organization_id": organization_id,
                        "user_id": user_id,
                        "status": "active"
                    },
                    {
                        "$set": {
                            "status": "removed",
                            "updated_at": now
                        }
                    },
                    session=session
                )

                if result.modified_count != 1:

                    raise ValueError(
                        "Member could not be removed"
                    )

                # -----------------------------------------
                # Keep legacy users collection compatible
                # -----------------------------------------
                # Only clear the user's organization if
                # they have no other active memberships.
                # -----------------------------------------

                other_active_membership = MEMBERS.find_one(
                    {
                        "user_id": user_id,
                        "status": "active",
                        "organization_id": {
                            "$ne": organization_id
                        }
                    },
                    session=session
                )

                if not other_active_membership:

                    user_object_id = ObjectId(
                        user_id
                    )

                    USERS.update_one(
                        {
                            "_id": user_object_id,
                            "organization": organization_id
                        },
                        {
                            "$set": {
                                "organization": None,
                                "role": "viewer"
                            }
                        },
                        session=session
                    )

        # -----------------------------------------
        # Transaction committed successfully
        # -----------------------------------------

        return {
            "organization_id": organization_id,
            "user_id": user_id,
            "status": "removed",
            "removed_at": now
        }

    except ValueError:

        raise

    except Exception as error:

        print(
            f"[ERROR] Member removal failed: {error}"
        )

        raise ValueError(
            "Unable to remove organization member"
        )