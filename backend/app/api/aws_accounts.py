import os
from fastapi import APIRouter, HTTPException, Depends, Request

from app.models.aws_account import (
    create_aws_account,
    get_organization_accounts,
    get_account,
    delete_account,
    generate_external_id,
    verify_external_id_binding,
    update_account_verification,
    ensure_external_id,
)

from app.services.aws_connection import verify_aws_role_connection
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
# AWS SETUP INTENT (OBTAIN EXTERNAL ID & TRUST POLICY TEMPLATE)
# ============================================================

@router.get("/setup-intent")
def get_aws_setup_intent(
    current_user=Depends(verify_token)
):
    """
    Return a cryptographically secure, unpredictable ExternalId bound strictly
    to the caller's active organization, along with the required IAM trust policy template.

    Security guarantees:
    - Enforces active organization membership
    - Restricted to Owner and Admin roles (Viewers/Analysts rejected 403)
    - ExternalId cannot be forged or cross-used across tenants
    - ExternalId is never exposed on unauthenticated/public endpoints or logs
    """
    membership = get_active_membership(current_user)
    role = membership.get("role", "viewer")
    if role not in {"owner", "admin"}:
        raise HTTPException(
            status_code=403,
            detail="Only organization owners and admins can initiate AWS connection setup."
        )

    organization_id = str(membership["organization_id"])
    external_id = generate_external_id(organization_id)

    cloudguard_account_id = os.getenv("CLOUDGUAARDAI_AWS_ACCOUNT_ID", "123456789012")

    return {
        "status": "success",
        "organization_id": organization_id,
        "external_id": external_id,
        "trust_policy_template": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{cloudguard_account_id}:root"
                    },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {
                            "sts:ExternalId": external_id
                        }
                    }
                }
            ]
        },
        "instructions": {
            "step_1": "Create an IAM Role in your AWS account with CloudGuardAI read-only permissions.",
            "step_2": "In the IAM Role Trust Policy, require sts:AssumeRole with the ExternalId condition below.",
            "step_3": "Register the role ARN and AWS Account ID in CloudGuardAI, then execute test-connection."
        }
    }


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

    except ValueError as error:

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
                pass

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

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


# ============================================================
# TEST AWS CONNECTION (PRE-FLIGHT STS HANDSHAKE & VERIFICATION)
# ============================================================

@router.post("/account/{account_id}/test-connection")
@router.post("/account/{account_id}/verify")
def test_aws_account_connection(
    account_id: str,
    current_user=Depends(verify_token)
):
    """
    Perform pre-flight verification on a connected AWS account:
    1. Authenticate user and verify active organization membership.
    2. Enforce Owner or Admin RBAC permissions.
    3. Verify account ownership within the organization tenant.
    4. Retrieve the stored ExternalId (or safely backfill for legacy accounts).
    5. Perform STS AssumeRole using the exact stored ExternalId.
    6. Verify sts:GetCallerIdentity account matches the registered account ID.
    7. Update account status to 'connected' on success, or 'failed' with safe error message on failure.
    """
    membership = get_active_membership(current_user)
    role = membership.get("role", "viewer")
    if role not in {"owner", "admin"}:
        raise HTTPException(
            status_code=403,
            detail="Only organization owners and admins can verify AWS account connections."
        )

    organization_id = str(membership["organization_id"])

    account = get_account(
        account_id,
        organization_id=organization_id
    )
    if not account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found."
        )

    role_arn = account.get("role_arn")
    aws_account_id = account.get("aws_account_id")
    region = account.get("region", "ap-south-1")
    external_id = account.get("external_id")

    if not external_id:
        external_id = ensure_external_id(account_id, organization_id=organization_id)

    try:
        identity = verify_aws_role_connection(
            role_arn=role_arn,
            expected_account_id=aws_account_id,
            external_id=external_id,
            region=region,
        )

        update_account_verification(
            account_id=account_id,
            status="connected",
            organization_id=organization_id,
        )

        return {
            "status": "success",
            "verified": True,
            "account_status": "connected",
            "message": "AWS connection verified successfully.",
            "account_id": account_id,
            "aws_account_id": aws_account_id,
            "identity": {
                "arn": identity.get("arn"),
                "account": identity.get("account_id"),
                "user_id": identity.get("user_id"),
            }
        }

    except (PermissionError, ValueError, TimeoutError, RuntimeError) as exc:
        error_message = str(exc)
        update_account_verification(
            account_id=account_id,
            status="failed",
            verification_error=error_message,
            organization_id=organization_id,
        )
        raise HTTPException(
            status_code=400,
            detail=error_message,
        )


# ============================================================
# SCAN ROUTE COMPATIBILITY ALIAS
# ============================================================

@router.get("/scan/{account_id}")
def scan_aws_alias(
    account_id: str,
    current_user=Depends(verify_token)
):
    """
    Backward-compatibility alias forwarding /aws/scan/{account_id}
    to the cloud scanner endpoint (/cloud/aws/scan/{account_id}).
    """
    from app.api.cloud import scan_aws
    return scan_aws(
        account_id=account_id,
        current_user=current_user
    )
