from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr

from app.middleware.auth_middleware import verify_token
from app.database.connection import db

from app.services.organization_invitation_service import (
    create_invitation,
    accept_invitation,
    list_invitations,
    revoke_invitation,
    get_invitation_by_token
)

from app.services.organization_service import (
    get_organization,
    remove_member
)

from app.services.trial_service import (
    start_free_trial,
    get_trial_status
)

from app.services.subscription_service import (
    get_subscription,
    change_subscription_plan
)

from app.services.subscription_plan_service import get_plan

from app.services.organization_subscription_service import (
    get_organization_subscription as get_subscription_details
)

from app.services.quota_service import (
    get_quota_status
)


router = APIRouter(
    prefix="/organizations",
    tags=["Organizations"]
)


# ============================================================
# REQUEST MODELS
# ============================================================

class OrganizationInvitationCreate(BaseModel):
    email: EmailStr
    role: str = "viewer"


class OrganizationInvitationAccept(BaseModel):
    token: str


class SubscriptionPlanUpdate(BaseModel):
    plan: str


class MemberRoleUpdate(BaseModel):
    role: str


# ============================================================
# ALLOWED MEMBER ROLES
# ============================================================

ALLOWED_MEMBER_ROLES = {
    "owner",
    "admin",
    "analyst",
    "viewer"
}


# ============================================================
# CREATE ORGANIZATION INVITATION
# ============================================================

@router.post(
    "/{organization_id}/invitations"
)
def create_organization_invitation(
    organization_id: str,
    invitation: OrganizationInvitationCreate,
    current_user=Depends(verify_token)
):
    """
    Create an organization member invitation.

    Only active organization owners and admins
    can create invitations.
    """

    organization_id = str(
        organization_id
    ).strip()

    current_user_id = str(
        current_user["_id"]
    )

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can invite members"
            )
        )

    try:

        result = create_invitation(
            organization_id=organization_id,
            email=str(invitation.email),
            invited_by=current_user_id,
            role=invitation.role
        )

        return result

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# ============================================================
# LIST ORGANIZATION INVITATIONS
# ============================================================

@router.get(
    "/{organization_id}/invitations"
)
def get_organization_invitations(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return organization invitations.

    Only active organization owners and admins
    can view invitations.
    """

    organization_id = str(
        organization_id
    ).strip()

    current_user_id = str(
        current_user["_id"]
    )

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can view invitations"
            )
        )

    try:

        invitations = list_invitations(
            organization_id
        )

        return {
            "organization_id": organization_id,
            "invitations": invitations
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# ============================================================
# ACCEPT ORGANIZATION INVITATION
# ============================================================

@router.post(
    "/{organization_id}/invitations/accept"
)
def accept_organization_invitation(
    organization_id: str,
    invitation: OrganizationInvitationAccept,
    current_user=Depends(verify_token)
):
    """
    Accept an organization invitation.

    The invitation token must belong to the organization
    specified in the URL before any state-changing operation
    is performed.
    """

    organization_id = str(
        organization_id
    ).strip()

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Validate invitation BEFORE accepting it
    # --------------------------------------------------------

    invitation_record = get_invitation_by_token(
        invitation.token
    )

    if not invitation_record:
        raise HTTPException(
            status_code=400,
            detail="Invitation is invalid or expired"
        )

    invitation_organization_id = str(
        invitation_record.get(
            "organization_id",
            ""
        )
    ).strip()

    if invitation_organization_id != organization_id:
        raise HTTPException(
            status_code=403,
            detail="Invitation does not belong to this organization"
        )

    # --------------------------------------------------------
    # Accept invitation
    # --------------------------------------------------------

    try:

        result = accept_invitation(
            token=invitation.token,
            user_id=current_user_id
        )

        return result

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


# ============================================================
# REVOKE ORGANIZATION INVITATION
# ============================================================

@router.delete(
    "/{organization_id}/invitations/{invitation_id}"
)
def revoke_organization_invitation(
    organization_id: str,
    invitation_id: str,
    current_user=Depends(verify_token)
):
    """
    Revoke a pending organization invitation.

    Only active organization owners and admins
    can revoke invitations.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify requester membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    # --------------------------------------------------------
    # Only owner/admin can revoke invitations
    # --------------------------------------------------------

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can revoke invitations"
            )
        )

    # --------------------------------------------------------
    # Revoke invitation
    # --------------------------------------------------------

    try:

        revoke_invitation(
            invitation_id=invitation_id,
            organization_id=organization_id
        )

        return {
            "message": "Invitation revoked successfully",
            "organization_id": organization_id,
            "invitation_id": str(
                invitation_id
            ),
            "status": "revoked"
        }

    except ValueError as error:

        message = str(error)

        if message == "Invalid invitation ID":

            raise HTTPException(
                status_code=400,
                detail=message
            )

        if message == "Pending invitation not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# GET ORGANIZATION DETAILS
# ============================================================

@router.get(
    "/{organization_id}"
)
def get_organization_details(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return organization details for SaaS management.

    Any active organization member can view
    organization information.
    """

    organization_id = str(
        organization_id
    ).strip()

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active organization membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    # --------------------------------------------------------
    # Get organization details
    # --------------------------------------------------------

    try:

        organization = get_organization(
            organization_id
        )

        return organization

    except ValueError as error:

        message = str(error)

        if message == "Organization not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        if message in {
            "Invalid organization ID",
            "Organization ID is required"
        }:

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )

    except Exception as error:

        print(
            f"[ERROR] Organization details API failed: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve organization details"
        ) from error


# ============================================================
# GET ORGANIZATION ONBOARDING STATUS
# ============================================================

@router.get(
    "/{organization_id}/onboarding"
)
def get_organization_onboarding(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return the organization's SaaS onboarding progress.

    This endpoint is read-only.
    It does not modify organization data.
    """

    organization_id = str(
        organization_id
    ).strip()

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active organization membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    # --------------------------------------------------------
    # Verify organization exists
    # --------------------------------------------------------

    try:

        organization = get_organization(
            organization_id
        )

    except ValueError as error:

        message = str(error)

        if message == "Organization not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )

    # --------------------------------------------------------
    # Check active team members
    # --------------------------------------------------------

    team_members_count = db.organization_members.count_documents({
        "organization_id": organization_id,
        "status": "active"
    })

    # --------------------------------------------------------
    # Check AWS accounts
    # --------------------------------------------------------

    aws_accounts_count = db.aws_accounts.count_documents({
        "organization_id": organization_id,
        "status": "connected"
    })

    # --------------------------------------------------------
    # Check completed scans
    # --------------------------------------------------------

    completed_scans_count = db.scan_history.count_documents({
        "organization_id": organization_id,
        "status": "completed"
    })

    # --------------------------------------------------------
    # Check subscription / trial
    # --------------------------------------------------------

    subscription = get_subscription_details(
        organization_id
    )

    plan_name = "free"

    if subscription:

        plan_name = str(
            subscription.get(
                "plan",
                "free"
            )
        ).strip().lower()

    # --------------------------------------------------------
    # Determine onboarding steps
    # --------------------------------------------------------

    steps = {
        "organization_created": True,
        "plan_selected": plan_name != "free",
        "team_setup": team_members_count >= 1,
        "aws_connected": aws_accounts_count >= 1,
        "first_scan_completed": completed_scans_count >= 1
    }

    completed_steps = sum(
        1
        for completed in steps.values()
        if completed
    )

    total_steps = len(steps)

    onboarding_completed = (
        completed_steps == total_steps
    )

    # --------------------------------------------------------
    # Response
    # --------------------------------------------------------

    return {
        "organization_id": organization_id,
        "organization_name": organization.get(
            "name"
        ),
        "plan": plan_name,
        "steps": steps,
        "completed_steps": completed_steps,
        "total_steps": total_steps,
        "progress_percentage": int(
            (
                completed_steps /
                total_steps
            ) * 100
        ),
        "onboarding_completed": onboarding_completed
    }


# ============================================================
# GET ORGANIZATION TRIAL STATUS
# ============================================================

@router.get(
    "/{organization_id}/trial"
)
def get_organization_trial(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return the current free-trial status.

    Any active organization member can view
    the trial status.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    try:

        return get_trial_status(
            organization_id
        )

    except ValueError as error:

        message = str(error)

        if message == "Organization not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        if message == "Invalid organization ID":

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# START ORGANIZATION FREE TRIAL
# ============================================================

@router.post(
    "/{organization_id}/trial"
)
def start_organization_trial(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Start the organization's free trial.

    Only active organization owners and admins
    can start a trial.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    # --------------------------------------------------------
    # Owner/Admin only
    # --------------------------------------------------------

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can start the free trial"
            )
        )

    try:

        result = start_free_trial(
            organization_id=organization_id
        )

        return result

    except ValueError as error:

        message = str(error)

        if message == "Organization not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        if message == "Invalid organization ID":

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# GET ORGANIZATION SUBSCRIPTION
# ============================================================

@router.get(
    "/{organization_id}/subscription"
)
def get_organization_subscription(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return the current subscription and plan information.

    Any active organization member can view
    the subscription status.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    try:

        # --------------------------------------------------------
        # Read the dedicated subscription lifecycle record.
        # This contains provider, billing cycle, payment/subscription
        # identifiers and billing period information.
        # --------------------------------------------------------

        subscription = get_subscription_details(
            organization_id
        )

        if not subscription:

            raise HTTPException(
                status_code=404,
                detail="Organization subscription not found"
            )

        # --------------------------------------------------------
        # Resolve the current plan catalog entry.
        # --------------------------------------------------------

        plan_name = str(
            subscription.get(
                "plan",
                "free"
            )
        ).strip().lower()

        plan = get_plan(
            plan_name
        )

        if not plan:

            raise HTTPException(
                status_code=400,
                detail="Invalid subscription plan."
            )

        # --------------------------------------------------------
        # Return unified subscription response.
        # --------------------------------------------------------

        return {
            "organization_id": organization_id,
            "plan": plan,
            "plan_name": plan_name,
            "organization_status": "active",
            "billing_provider": subscription.get(
                "provider"
            ),
            "billing_customer_id": subscription.get(
                "billing_customer_id"
            ),
            "subscription_id": subscription.get(
                "subscription_id"
            ),
            "billing_cycle": subscription.get(
                "billing_cycle"
            ),
            "current_period_start": subscription.get(
                "current_period_start"
            ),
            "current_period_end": subscription.get(
                "current_period_end"
            ),
            "cancel_at_period_end": subscription.get(
                "cancel_at_period_end",
                False
            ),
            "trial_ends_at": subscription.get(
                "trial_ends_at"
            ),
            "created_at": subscription.get(
                "created_at"
            ),
            "updated_at": subscription.get(
                "updated_at"
            )
        }

    except ValueError as error:

        message = str(error)

        if message == "Invalid organization ID.":

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# GET DEDICATED ORGANIZATION SUBSCRIPTION
# ============================================================

@router.get(
    "/{organization_id}/subscription/details"
)
def get_organization_subscription_details(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return the dedicated subscription lifecycle record.

    Any active organization member can view
    the subscription details.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    try:

        # IMPORTANT:
        # Use the aliased service function here.
        # This avoids collision with the API endpoint
        # function named get_organization_subscription.

        subscription = get_subscription_details(
            organization_id
        )

        if not subscription:

            raise HTTPException(
                status_code=404,
                detail="Organization subscription not found"
            )

        subscription["_id"] = str(
            subscription["_id"]
        )

        return subscription

    except ValueError as error:

        message = str(error)

        if message == "Invalid organization ID.":

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# GET ORGANIZATION USAGE & QUOTA
# ============================================================

@router.get(
    "/{organization_id}/usage"
)
def get_organization_usage(
    organization_id: str,
    current_user=Depends(verify_token)
):
    """
    Return organization SaaS usage and quota status.

    Any active organization member can view
    organization usage.

    Includes:
    - AWS accounts
    - Team members
    - Monthly scans
    - Monthly reports
    - Storage
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active organization membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    # --------------------------------------------------------
    # Get quota status
    # --------------------------------------------------------

    try:

        usage = get_quota_status(
            organization_id
        )

        return {
            "organization_id": organization_id,
            "usage": usage
        }

    except ValueError as error:

        message = str(error)

        if message in {
            "Organization not found",
            "Organization ID is required"
        }:

            status_code = (
                404
                if message == "Organization not found"
                else 400
            )

            raise HTTPException(
                status_code=status_code,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve organization usage"
        ) from error


# ============================================================
# CHANGE ORGANIZATION SUBSCRIPTION PLAN
# ============================================================

@router.patch(
    "/{organization_id}/subscription"
)
def change_organization_subscription(
    organization_id: str,
    plan_update: SubscriptionPlanUpdate,
    current_user=Depends(verify_token)
):
    """
    Change the organization's subscription plan.

    Only active organization owners and admins
    can change the subscription plan.
    """

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active membership
    # --------------------------------------------------------

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    # --------------------------------------------------------
    # Owner/Admin only
    # --------------------------------------------------------

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can change the subscription plan"
            )
        )

    try:

        result = change_subscription_plan(
            organization_id=organization_id,
            target_plan_name=plan_update.plan
        )

        return result

    except ValueError as error:

        message = str(error)

        if message == "Organization not found":

            raise HTTPException(
                status_code=404,
                detail=message
            )

        if message in {
            "Invalid organization ID.",
            "Organization ID is required.",
            "Target subscription plan is required."
        }:

            raise HTTPException(
                status_code=400,
                detail=message
            )

        if message.startswith(
            "Invalid subscription plan:"
        ):

            raise HTTPException(
                status_code=400,
                detail=message
            )

        if message.endswith(
            "is not active."
        ):

            raise HTTPException(
                status_code=400,
                detail=message
            )

        if message.startswith(
            "Cannot change to "
        ):

            raise HTTPException(
                status_code=400,
                detail=message
            )

        if message.startswith(
            "Invalid current subscription plan:"
        ):

            raise HTTPException(
                status_code=400,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )


# ============================================================
# GET ORGANIZATION MEMBERS
# ============================================================

@router.get(
    "/{organization_id}/members"
)
def get_organization_members(
    organization_id: str,
    current_user=Depends(verify_token)
):

    user_id = str(
        current_user["_id"]
    )

    requester = db.organization_members.find_one({
        "organization_id": str(
            organization_id
        ),
        "user_id": user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    members = list(
        db.organization_members.find(
            {
                "organization_id": str(
                    organization_id
                ),
                "status": "active"
            },
            {
                "_id": 0,
                "user_id": 1,
                "role": 1,
                "status": 1,
                "joined_at": 1,
                "created_at": 1
            }
        )
    )

    user_ids = [
        member["user_id"]
        for member in members
    ]

    users = {}

    if user_ids:

        user_documents = db.users.find(
            {
                "_id": {
                    "$in": [
                        __import__(
                            "bson"
                        ).ObjectId(
                            user_id
                        )
                        for user_id in user_ids
                    ]
                }
            },
            {
                "_id": 1,
                "name": 1,
                "email": 1
            }
        )

        users = {
            str(user["_id"]): user
            for user in user_documents
        }

    result = []

    for member in members:

        user = users.get(
            member["user_id"]
        )

        if not user:
            continue

        result.append({
            "user_id": member["user_id"],
            "name": user.get("name"),
            "email": user.get("email"),
            "role": member.get(
                "role",
                "viewer"
            ),
            "status": member.get(
                "status"
            ),
            "joined_at": member.get(
                "joined_at"
            ),
            "created_at": member.get(
                "created_at"
            )
        })

    return {
        "organization_id": str(
            organization_id
        ),
        "total_members": len(result),
        "members": result
    }


# ============================================================
# UPDATE MEMBER ROLE
# ============================================================

@router.patch(
    "/{organization_id}/members/{user_id}/role"
)
def update_member_role(
    organization_id: str,
    user_id: str,
    role_update: MemberRoleUpdate,
    current_user=Depends(verify_token)
):

    organization_id = str(
        organization_id
    )

    current_user_id = str(
        current_user["_id"]
    )

    new_role = role_update.role.strip().lower()

    if new_role not in ALLOWED_MEMBER_ROLES:

        raise HTTPException(
            status_code=400,
            detail="Invalid member role"
        )

    requester = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": current_user_id,
        "status": "active"
    })

    if not requester:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    requester_role = requester.get(
        "role",
        "viewer"
    )

    if requester_role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can change member roles"
            )
        )

    target_member = db.organization_members.find_one({
        "organization_id": organization_id,
        "user_id": str(user_id),
        "status": "active"
    })

    if not target_member:

        raise HTTPException(
            status_code=404,
            detail="Active organization member not found"
        )

    target_role = target_member.get(
        "role",
        "viewer"
    )

    if target_role == "owner":

        raise HTTPException(
            status_code=400,
            detail="The organization owner role cannot be changed"
        )

    if (
        requester_role == "admin"
        and target_role == "admin"
    ):

        raise HTTPException(
            status_code=403,
            detail="Admins cannot change another admin's role"
        )

    result = db.organization_members.update_one(
        {
            "organization_id": organization_id,
            "user_id": str(user_id),
            "status": "active"
        },
        {
            "$set": {
                "role": new_role
            }
        }
    )

    if result.modified_count == 0:

        raise HTTPException(
            status_code=400,
            detail="Member role was not changed"
        )

    try:

        db.users.update_one(
            {
                "_id": __import__(
                    "bson"
                ).ObjectId(
                    user_id
                ),
                "organization": organization_id
            },
            {
                "$set": {
                    "role": new_role
                }
            }
        )

    except Exception:
        pass

    return {
        "message": "Member role updated successfully",
        "organization_id": organization_id,
        "user_id": str(user_id),
        "role": new_role
    }


# ============================================================
# REMOVE ORGANIZATION MEMBER
# ============================================================

@router.delete(
    "/{organization_id}/members/{user_id}"
)
def remove_organization_member(
    organization_id: str,
    user_id: str,
    current_user=Depends(verify_token)
):
    """
    Remove an active member from an organization.

    Rules:
    - Only owners/admins can remove members.
    - Owner cannot be removed.
    - Members cannot remove themselves.
    - Admins cannot remove other admins.
    """

    try:

        result = remove_member(
            organization_id=organization_id,
            user_id=user_id,
            requester_id=current_user["_id"]
        )

        return {
            "message": "Member removed successfully",
            "membership": result
        }

    except ValueError as error:

        message = str(error)

        if message == (
            "You do not have access to this organization"
        ):

            raise HTTPException(
                status_code=403,
                detail=message
            )

        if message in {
            "You cannot remove yourself from the organization",
            "The organization owner cannot be removed",
            "Admins cannot remove other admins",
            "Only organization owners and admins can remove members"
        }:

            raise HTTPException(
                status_code=403,
                detail=message
            )

        if message == (
            "Active organization member not found"
        ):

            raise HTTPException(
                status_code=404,
                detail=message
            )

        raise HTTPException(
            status_code=400,
            detail=message
        )