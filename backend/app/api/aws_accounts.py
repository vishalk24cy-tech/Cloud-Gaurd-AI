from fastapi import APIRouter, HTTPException, Depends

from app.models.aws_account import (
    create_aws_account,
    get_organization_accounts,
    get_account,
    delete_account
)

from app.middleware.auth_middleware import verify_token
from app.database.connection import db

from app.services.quota_service import enforce_quota
from app.services.organization_usage_service import (
    reserve_usage,
    release_usage
)


router = APIRouter()


# ============================================================
# ACTIVE ORGANIZATION MEMBERSHIP
# ============================================================

def get_active_membership(current_user):
    """
    Return the authenticated user's active organization membership.
    """

    user_id = str(current_user["_id"])

    organization_id = current_user.get("organization")

    if not organization_id:
        raise HTTPException(
            status_code=400,
            detail="User is not associated with an organization"
        )

    membership = db.organization_members.find_one(
        {
            "organization_id": str(organization_id),
            "user_id": user_id,
            "status": "active"
        }
    )

    if not membership:
        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization"
        )

    return membership


# ============================================================
# CONNECT AWS ACCOUNT
# ============================================================

@router.post("/connect")
def connect_aws_account(
    data: dict,
    current_user=Depends(verify_token)
):
    """
    Connect a new AWS account.

    SaaS protections:
        1. Validate active organization membership
        2. Enforce RBAC
        3. Check organization quota
        4. Atomically reserve AWS account quota
        5. Create AWS account
        6. Release quota if creation fails
    """

    # --------------------------------------------------------
    # Active membership
    # --------------------------------------------------------

    membership = get_active_membership(current_user)

    role = membership.get(
        "role",
        "viewer"
    )

    # --------------------------------------------------------
    # RBAC
    # --------------------------------------------------------

    if role not in {
        "owner",
        "admin"
    }:
        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can connect AWS accounts"
            )
        )

    organization_id = str(
        membership["organization_id"]
    )

    user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # SaaS quota enforcement
    # --------------------------------------------------------

    try:

        quota = enforce_quota(
            organization_id=organization_id,
            quota_type="aws_accounts",
            amount=1
        )

    except ValueError as error:

        raise HTTPException(
            status_code=403,
            detail=str(error)
        )

    # --------------------------------------------------------
    # Atomic quota reservation
    # --------------------------------------------------------

    reservation = None

    try:

        reservation = reserve_usage(
            organization_id=organization_id,
            usage_field="aws_accounts_used",
            limit=quota["limit"],
            amount=1
        )

        if not reservation.get(
            "reserved",
            False
        ):

            raise HTTPException(
                status_code=403,
                detail=(
                    "AWS account quota exceeded. "
                    f"Your plan allows "
                    f"{quota['limit']} AWS account(s)."
                )
            )

    except HTTPException:
        raise

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to reserve AWS account quota: "
                f"{type(error).__name__}"
            )
        )

    # --------------------------------------------------------
    # AWS account creation
    # --------------------------------------------------------

    try:

        data["user_id"] = user_id

        data["organization_id"] = organization_id

        account = create_aws_account(
            data
        )

        return {
            "status": "success",
            "message": "AWS Account Connected Successfully",
            "account": account
        }

    except Exception as error:

        # ----------------------------------------------------
        # Release quota when account creation fails
        # ----------------------------------------------------

        if (
            reservation
            and reservation.get("reserved")
        ):

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="aws_accounts_used",
                    amount=1
                )

            except Exception:
                # Do not expose internal quota rollback errors.
                pass

        raise HTTPException(
            status_code=500,
            detail=(
                "AWS account creation failed: "
                f"{type(error).__name__}"
            )
        )


# ============================================================
# GET ORGANIZATION AWS ACCOUNTS
# ============================================================

@router.get("/accounts")
def accounts(
    current_user=Depends(verify_token)
):
    """
    Return all AWS accounts belonging to the user's organization.
    """

    membership = get_active_membership(
        current_user
    )

    organization_id = str(
        membership["organization_id"]
    )

    accounts = get_organization_accounts(
        organization_id
    )

    return {
        "organization_id": organization_id,
        "total_accounts": len(accounts),
        "accounts": accounts
    }


# ============================================================
# GET AWS ACCOUNT DETAILS
# ============================================================

@router.get("/account/{account_id}")
def account_details(
    account_id: str,
    current_user=Depends(verify_token)
):
    """
    Return a specific AWS account belonging
    to the authenticated organization.
    """

    membership = get_active_membership(
        current_user
    )

    organization_id = str(
        membership["organization_id"]
    )

    account = get_account(
        account_id,
        organization_id=organization_id
    )

    if not account:

        raise HTTPException(
            status_code=404,
            detail="AWS Account not found"
        )

    return account


# ============================================================
# DELETE AWS ACCOUNT
# ============================================================

@router.delete("/account/{account_id}")
def remove_account(
    account_id: str,
    current_user=Depends(verify_token)
):
    """
    Delete an AWS account.

    Only organization owners and admins are allowed.
    """

    membership = get_active_membership(
        current_user
    )

    role = membership.get(
        "role",
        "viewer"
    )

    if role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail=(
                "Only organization owners and admins "
                "can delete AWS accounts"
            )
        )

    organization_id = str(
        membership["organization_id"]
    )

    deleted = delete_account(
        account_id,
        organization_id=organization_id
    )

    if not deleted:

        raise HTTPException(
            status_code=404,
            detail="Account not found"
        )

    # --------------------------------------------------------
    # Synchronize quota usage after successful deletion
    # --------------------------------------------------------

    try:

        release_usage(
            organization_id=organization_id,
            usage_field="aws_accounts_used",
            amount=1
        )

    except Exception:
        # Account deletion already succeeded.
        # Do not turn a successful deletion into a failed API response.
        pass

    return {
        "message": "AWS Account removed successfully"
    }