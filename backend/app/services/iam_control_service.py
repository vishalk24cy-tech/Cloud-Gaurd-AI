# ============================================================
# CloudGuardAI - Secure IAM Resource Control Service
# Phase 6: AWS IAM Identity & Access Management
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from botocore.exceptions import BotoCoreError, ClientError

from app.models.audit_log import (
    ACTOR_USER,
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_RESOURCE_CONTROL_COMPLETED,
    EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
    EVENT_RESOURCE_CONTROL_FAILED,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
)
from app.models.aws_account import get_account
from app.services.audit_log_service import record_event
from app.services.aws_connection import (
    assume_aws_role,
    get_aws_clients,
    verify_aws_account,
)

logger = logging.getLogger("cloudguardai.iam_controls")

ALLOWED_ACTIONS = {"disable_access_key", "detach_policy", "delete_inline_policy"}
MUTATION_ALLOWED_ROLES = {"owner", "admin"}

class IAMControlExecutionError(Exception):
    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        category: str,
        message: str,
        audit_recorded: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.category = category
        self.public_message = message
        self.audit_recorded = audit_recorded

def _safe_string(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()

def fetch_iam_inventory(
    iam_client: Any,
    max_items: Optional[int] = 100,
    marker: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query IAM for Users, Roles, and Policies in a strictly read-only manner.
    """
    if not iam_client:
        raise ValueError("IAM client is required.")
        
    users = []
    roles = []
    policies = []
    
    try:
        # Get Users
        user_response = iam_client.list_users(MaxItems=max_items, Marker=marker) if marker else iam_client.list_users(MaxItems=max_items)
        for user in user_response.get('Users', []):
            username = user.get("UserName")
            # Get Access Keys for user
            keys_resp = iam_client.list_access_keys(UserName=username)
            access_keys = [
                {
                    "access_key_id": k.get("AccessKeyId"),
                    "status": k.get("Status"),
                    "create_date": k.get("CreateDate").isoformat() if k.get("CreateDate") else None,
                }
                for k in keys_resp.get("AccessKeyMetadata", [])
            ]
            
            # Check MFA
            mfa_resp = iam_client.list_mfa_devices(UserName=username)
            mfa_enabled = len(mfa_resp.get("MFADevices", [])) > 0
            
            # Check Console Access
            console_access = False
            try:
                iam_client.get_login_profile(UserName=username)
                console_access = True
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code != "NoSuchEntity":
                    console_access = False # or unknown

            users.append({
                "user_name": username,
                "user_id": user.get("UserId"),
                "arn": user.get("Arn"),
                "create_date": user.get("CreateDate").isoformat() if user.get("CreateDate") else None,
                "access_keys": access_keys,
                "mfa_enabled": mfa_enabled,
                "console_access": console_access,
            })
                
        # Get Roles
        role_response = iam_client.list_roles(MaxItems=max_items)
        for role in role_response.get('Roles', []):
            roles.append({
                "role_name": role.get("RoleName"),
                "role_id": role.get("RoleId"),
                "arn": role.get("Arn"),
                "create_date": role.get("CreateDate").isoformat() if role.get("CreateDate") else None,
            })
                
        # Get Policies (Local/Customer managed)
        policy_response = iam_client.list_policies(Scope='Local', MaxItems=max_items)
        for policy in policy_response.get('Policies', []):
            policies.append({
                "policy_name": policy.get("PolicyName"),
                "policy_id": policy.get("PolicyId"),
                "arn": policy.get("Arn"),
                "attachment_count": policy.get("AttachmentCount", 0),
                "create_date": policy.get("CreateDate").isoformat() if policy.get("CreateDate") else None,
            })

    except ClientError as e:
        logger.error("Error fetching IAM inventory: %s", e)
        raise
        
    return {
        "users": users,
        "roles": roles,
        "policies": policies,
        "total_users": len(users),
        "total_roles": len(roles),
        "total_policies": len(policies),
    }

def execute_iam_action(
    *,
    account_id: str,
    resource_id: str,
    resource_type: str,
    action: str,
    parameters: Optional[Dict[str, Any]] = None,
    confirmed: bool = False,
    user_id: str,
    organization_id: str,
    role: str = "viewer",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a secure action on an IAM resource.
    """
    clean_action = _safe_string(action).lower()
    clean_resource_id = _safe_string(resource_id)
    clean_account_id = _safe_string(account_id)
    clean_role = _safe_string(role).lower() or "viewer"

    if clean_action not in ALLOWED_ACTIONS:
        raise IAMControlExecutionError(
            status_code=400,
            code="INVALID_ACTION",
            category="ACTION_VALIDATION",
            message=f"Disallowed action '{action}'.",
        )

    if confirmed is not True:
        raise IAMControlExecutionError(
            status_code=400,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_VALIDATION",
            message="Explicit user confirmation is required.",
        )

    if clean_role not in MUTATION_ALLOWED_ROLES:
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"IAM_{clean_action.upper()}",
            result=RESULT_DENIED,
            actor_type=ACTOR_USER,
            service="IAM",
            resource_type=resource_type,
            resource_id=clean_resource_id,
            account_id=clean_account_id,
            message="User lacks admin/owner role for IAM resource mutation.",
            metadata={
                "action": clean_action,
                "role": clean_role,
                "error_code": "ROLE_NOT_ALLOWED",
            },
        )
        raise IAMControlExecutionError(
            status_code=403,
            code="ROLE_NOT_ALLOWED",
            category="AUTHORIZATION",
            message="You must have an Admin or Owner role to perform IAM resource controls.",
            audit_recorded=True,
        )

    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise IAMControlExecutionError(
            status_code=404,
            code="ACCOUNT_NOT_FOUND",
            category="TENANT_VALIDATION",
            message="Connected AWS Account not found or belongs to another organization.",
        )

    # Verify organization remediation setting for IAM
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, clean_account_id, "iam"):
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"IAM_{clean_action.upper()}",
            result=RESULT_DENIED,
            actor_type=ACTOR_USER,
            service="IAM",
            resource_type=resource_type,
            resource_id=clean_resource_id,
            account_id=clean_account_id,
            message="Remediation setting is disabled for IAM.",
            metadata={
                "action": clean_action,
                "role": clean_role,
                "error_code": "REMEDIATION_SETTING_DISABLED",
            },
        )
        raise IAMControlExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="AUTHORIZATION",
            message="Remediation is disabled for IAM for this account.",
            audit_recorded=True,
        )

    role_arn = _safe_string(aws_account.get("role_arn"))
    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )

    if not role_arn:
        raise IAMControlExecutionError(
            status_code=400,
            code="MISSING_ROLE_ARN",
            category="ACCOUNT_CONFIGURATION",
            message="AWS account is missing configured role_arn.",
        )

    try:
        session = assume_aws_role(role_arn, region="us-east-1")
    except Exception as err:
        logger.warning("IAM control assume_role failed: %s", err)
        raise IAMControlExecutionError(
            status_code=403,
            code="ROLE_ASSUMPTION_FAILED",
            category="AWS_AUTHENTICATION",
            message="Failed to assume AWS role for the connected account.",
        )

    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise IAMControlExecutionError(
            status_code=403,
            code="ACCOUNT_IDENTITY_MISMATCH",
            category="AWS_VERIFICATION",
            message=str(perm_err),
        )
    except Exception:
        raise IAMControlExecutionError(
            status_code=403,
            code="ACCOUNT_VERIFICATION_FAILED",
            category="AWS_VERIFICATION",
            message="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    iam_client = clients.get("iam")
    if not iam_client:
        raise IAMControlExecutionError(
            status_code=500,
            code="CLIENT_INITIALIZATION_FAILED",
            category="AWS_CLIENT",
            message="Failed to initialize IAM service client.",
        )

    record_event(
        user_id=user_id,
        organization_id=organization_id,
        request_id=request_id,
        event_type=EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
        action=f"IAM_{clean_action.upper()}",
        actor_type=ACTOR_USER,
        service="IAM",
        resource_type=resource_type,
        resource_id=clean_resource_id,
        account_id=str(aws_account.get("_id", clean_account_id)),
        aws_account_id=stored_aws_account_id,
        metadata={
            "action": clean_action,
        },
    )

    try:
        if clean_action == "disable_access_key":
            if not parameters or not parameters.get("username"):
                raise ValueError("username is required for disable_access_key")
            iam_client.update_access_key(
                UserName=parameters["username"],
                AccessKeyId=clean_resource_id,
                Status="Inactive"
            )
        elif clean_action == "detach_policy":
            if not parameters or not parameters.get("policy_arn"):
                raise ValueError("policy_arn is required for detach_policy")
            if resource_type == "user":
                iam_client.detach_user_policy(
                    UserName=clean_resource_id,
                    PolicyArn=parameters["policy_arn"]
                )
            elif resource_type == "role":
                iam_client.detach_role_policy(
                    RoleName=clean_resource_id,
                    PolicyArn=parameters["policy_arn"]
                )
        elif clean_action == "delete_inline_policy":
            if not parameters or not parameters.get("policy_name"):
                raise ValueError("policy_name is required for delete_inline_policy")
            if resource_type == "user":
                iam_client.delete_user_policy(
                    UserName=clean_resource_id,
                    PolicyName=parameters["policy_name"]
                )
            elif resource_type == "role":
                iam_client.delete_role_policy(
                    RoleName=clean_resource_id,
                    PolicyName=parameters["policy_name"]
                )

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "AWS_ERROR")
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"IAM_{clean_action.upper()}",
            result=RESULT_FAILURE,
            actor_type=ACTOR_USER,
            service="IAM",
            resource_type=resource_type,
            resource_id=clean_resource_id,
            account_id=str(aws_account.get("_id", clean_account_id)),
            aws_account_id=stored_aws_account_id,
            message="IAM control execution failed.",
            metadata={"error_code": code}
        )
        raise IAMControlExecutionError(
            status_code=502,
            code=code,
            category="AWS_ERROR",
            message=f"AWS IAM service error: {code}",
        )
    except Exception as exc:
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"IAM_{clean_action.upper()}",
            result=RESULT_FAILURE,
            actor_type=ACTOR_USER,
            service="IAM",
            resource_type=resource_type,
            resource_id=clean_resource_id,
            account_id=str(aws_account.get("_id", clean_account_id)),
            aws_account_id=stored_aws_account_id,
            message="IAM control execution failed unexpectedly.",
        )
        raise IAMControlExecutionError(
            status_code=500,
            code="INTERNAL_ERROR",
            category="SYSTEM_ERROR",
            message="An unexpected error occurred.",
        )

    record_event(
        user_id=user_id,
        organization_id=organization_id,
        request_id=request_id,
        event_type=EVENT_RESOURCE_CONTROL_COMPLETED,
        action=f"IAM_{clean_action.upper()}",
        result=RESULT_SUCCESS,
        actor_type=ACTOR_USER,
        service="IAM",
        resource_type=resource_type,
        resource_id=clean_resource_id,
        account_id=str(aws_account.get("_id", clean_account_id)),
        aws_account_id=stored_aws_account_id,
        message=f"IAM action {clean_action} completed successfully.",
    )

    return {
        "status": "success",
        "action": clean_action,
        "resource_id": clean_resource_id,
        "message": f"IAM action {clean_action} executed successfully."
    }
