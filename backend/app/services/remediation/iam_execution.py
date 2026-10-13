from __future__ import annotations

import re
from typing import Any, Dict, Optional

from botocore.exceptions import BotoCoreError, ClientError

from app.models.aws_account import get_account
from app.models.audit_log import (
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_REMEDIATION_COMPLETED,
    EVENT_REMEDIATION_EXECUTION_STARTED,
    EVENT_REMEDIATION_FAILED,
)
from app.models.remediation import (
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_EXECUTING,
    STATUS_FAILED,
    transition_to_completed,
    transition_to_executing,
    transition_to_failed,
    update_execution_result,
)
from app.services.audit_log_service import record_remediation_event
from app.services.aws_connection import AWS_CONFIG, assume_aws_role, verify_aws_account
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.remediation_models import IAM_DISABLE_ACCESS_KEY_ACTION_ID


IAM_DISABLE_ACCESS_KEY_ACTION = IAM_DISABLE_ACCESS_KEY_ACTION_ID
IAM_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9+=,.@_-]{1,64}$")
IAM_ACCESS_KEY_ID_PATTERN = re.compile(r"^AKIA[0-9A-Z]{16}$")


class IAMAccessKeyExecutionError(Exception):
    """Safe public error details for IAM access-key execution."""

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


def is_valid_iam_username(username: str) -> bool:
    return isinstance(username, str) and bool(IAM_USERNAME_PATTERN.fullmatch(username))


def is_valid_iam_access_key_id(access_key_id: str) -> bool:
    return isinstance(access_key_id, str) and bool(IAM_ACCESS_KEY_ID_PATTERN.fullmatch(access_key_id))


def mask_iam_access_key_id(access_key_id: Optional[str]) -> Optional[str]:
    if not access_key_id:
        return None
    value = str(access_key_id)
    if not is_valid_iam_access_key_id(value):
        return "[redacted]"
    return f"{value[:4]}...{value[-4:]}"


def _aws_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(code))[:100] or "AWS_ERROR"


def _aws_request_id(response: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(response, dict):
        return None
    metadata = response.get("ResponseMetadata") or {}
    value = metadata.get("RequestId") or metadata.get("RequestID")
    return str(value)[:128] if value else None


def _aws_request_id(response: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(response, dict):
        return None
    metadata = response.get("ResponseMetadata") or {}
    value = metadata.get("RequestId") or metadata.get("RequestID")
    return str(value)[:128] if value else None


def _record_event(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    request_id: Optional[str],
    event_type: str,
    action: str,
    execution_state: str,
    authorization_result: str = "AUTHORIZED",
    approval_state: Optional[str] = None,
    confirmation_state: str = "CONFIRMED",
    success: Optional[bool] = None,
    error_code: Optional[str] = None,
    error_category: Optional[str] = None,
    verification_result: Optional[str] = None,
    aws_request_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    return record_remediation_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=event_type,
        action_id=IAM_DISABLE_ACCESS_KEY_ACTION,
        action=action,
        authorization_result=authorization_result,
        approval_state=approval_state or remediation.get("status"),
        confirmation_state=confirmation_state,
        execution_state=execution_state,
        success=success,
        error_code=error_code,
        error_category=error_category,
        verification_result=verification_result,
        account_id=remediation.get("account_id"),
        aws_account_id=remediation.get("aws_account_id"),
        remediation_id=remediation.get("_id"),
        resource_id=mask_iam_access_key_id(remediation.get("resource")),
        request_id=request_id,
        aws_request_id=aws_request_id,
    )


def _find_key(iam_client: Any, username: str, access_key_id: str) -> tuple[Optional[str], Optional[str]]:
    response = iam_client.list_access_keys(UserName=username)
    request_id = _aws_request_id(response)
    matches = [
        item
        for item in response.get("AccessKeyMetadata", [])
        if item.get("AccessKeyId") == access_key_id
        and item.get("UserName") == username
    ]
    if len(matches) != 1:
        raise IAMAccessKeyExecutionError(
            status_code=404,
            code="ACCESS_KEY_OWNERSHIP_NOT_VERIFIED",
            category="RESOURCE_VALIDATION",
            message="The access key could not be verified for the specified IAM user.",
        )
    return str(matches[0].get("Status") or ""), request_id


def execute_iam_disable_access_key(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Disable exactly one owned IAM access key and verify it is inactive."""

    action = get_default_engine().get_action(IAM_DISABLE_ACCESS_KEY_ACTION)
    if action is None or action.service != "IAM" or action.resource_type != "IAM_ACCESS_KEY":
        raise IAMAccessKeyExecutionError(
            status_code=503,
            code="ACTION_DEFINITION_UNAVAILABLE",
            category="REGISTRY_VALIDATION",
            message="The IAM remediation action is unavailable.",
        )

    if not action.allowed_roles or role.strip().lower() not in {
        allowed_role.strip().lower() for allowed_role in action.allowed_roles
    }:
        _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action="IAM access-key authorization denied",
            authorization_result="DENIED",
            confirmation_state="NOT_CONFIRMED",
            execution_state="NOT_STARTED",
            success=False,
            error_code="ROLE_NOT_ALLOWED",
            error_category="AUTHORIZATION",
        )
        raise IAMAccessKeyExecutionError(
            status_code=403,
            code="ROLE_NOT_ALLOWED",
            category="AUTHORIZATION",
            message="You are not authorized to execute this remediation action.",
            audit_recorded=True,
        )

    if (
        remediation.get("action_type") != IAM_DISABLE_ACCESS_KEY_ACTION
        or action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise IAMAccessKeyExecutionError(
            status_code=409,
            code="ACTION_POLICY_MISMATCH",
            category="ACTION_VALIDATION",
            message="The remediation action does not satisfy the required approval policy.",
        )

    if str(remediation.get("user_id")) != str(user_id):
        raise IAMAccessKeyExecutionError(
            status_code=404,
            code="REMEDIATION_NOT_FOUND",
            category="TENANT_VALIDATION",
            message="Remediation not found.",
        )

    if str(remediation.get("organization_id") or "") != str(organization_id):
        raise IAMAccessKeyExecutionError(
            status_code=403,
            code="ORGANIZATION_MISMATCH",
            category="TENANT_VALIDATION",
            message="Remediation does not belong to the active organization.",
        )

    if (
        str(remediation.get("status", "")).upper() != STATUS_APPROVED
        or not remediation.get("approved_by")
        or not remediation.get("approved_at")
    ):
        raise IAMAccessKeyExecutionError(
            status_code=409,
            code="APPROVAL_REQUIRED",
            category="APPROVAL_VALIDATION",
            message="Remediation must be approved before execution.",
        )

    if confirmed is not True:
        raise IAMAccessKeyExecutionError(
            status_code=409,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_VALIDATION",
            message="Explicit confirmation is required before execution.",
        )

    operation = remediation.get("operation") or {}
    username = str(operation.get("username") or "").strip() if isinstance(operation, dict) else ""
    access_key_id = str(remediation.get("resource") or "").strip()
    if not is_valid_iam_username(username):
        raise IAMAccessKeyExecutionError(
            status_code=400,
            code="INVALID_IAM_USERNAME",
            category="RESOURCE_VALIDATION",
            message="A valid IAM username is required.",
        )
    if not is_valid_iam_access_key_id(access_key_id):
        raise IAMAccessKeyExecutionError(
            status_code=400,
            code="INVALID_ACCESS_KEY_ID",
            category="RESOURCE_VALIDATION",
            message="A valid IAM access-key identifier is required.",
        )

    execution_started = False
    aws_request_id = None
    try:
        account = get_account(
            str(remediation.get("account_id") or ""),
            user_id=user_id,
            organization_id=organization_id,
        )
        if not account or account.get("status") != "connected":
            raise IAMAccessKeyExecutionError(
                status_code=404,
                code="AWS_ACCOUNT_NOT_FOUND",
                category="ACCOUNT_VALIDATION",
                message="Connected AWS account not found for this organization.",
            )

        expected_account_id = str(account.get("aws_account_id") or "").strip()
        if (
            not re.fullmatch(r"[0-9]{12}", expected_account_id)
            or str(remediation.get("aws_account_id") or "") != expected_account_id
        ):
            raise IAMAccessKeyExecutionError(
                status_code=409,
                code="AWS_ACCOUNT_MISMATCH",
                category="ACCOUNT_VALIDATION",
                message="Remediation AWS account does not match the connected account.",
            )

        role_arn = str(account.get("role_arn") or "").strip()
        region = str(account.get("region") or "ap-south-1").strip()
        if not role_arn or not region:
            raise IAMAccessKeyExecutionError(
                status_code=409,
                code="AWS_CONNECTION_INCOMPLETE",
                category="ACCOUNT_VALIDATION",
                message="The connected AWS account is missing execution configuration.",
            )

        # Verify organization remediation setting for IAM
        from app.models.remediation_settings import is_remediation_enabled
        if not is_remediation_enabled(organization_id, str(remediation.get("account_id") or ""), "iam"):
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action="IAM disable access key authorization denied (setting disabled)",
                authorization_result="DENIED",
                confirmation_state="CONFIRMED",
                execution_state="NOT_STARTED",
                success=False,
                error_code="REMEDIATION_SETTING_DISABLED",
                error_category="GOVERNANCE",
            )
            raise IAMAccessKeyExecutionError(
                status_code=403,
                code="REMEDIATION_SETTING_DISABLED",
                category="GOVERNANCE",
                message="Remediation setting is disabled for IAM for this account.",
                audit_recorded=True,
            )

        session = assume_aws_role(
            role_arn=role_arn,
            region=region,
            session_name=f"CloudGuardAI-IAMKey-{str(remediation.get('_id', ''))[:24]}",
        )
        verify_aws_account(session, expected_account_id)
        iam_client = session.client("iam", config=AWS_CONFIG)

        current_status, aws_request_id = _find_key(iam_client, username, access_key_id)
        if current_status != "Active":
            raise IAMAccessKeyExecutionError(
                status_code=409,
            code="ACCESS_KEY_NOT_ACTIVE",
                category="RESOURCE_VALIDATION",
            message="The IAM access key is not active and requires no disable operation.",
            )

        if not transition_to_executing(remediation["_id"], user_id):
            raise IAMAccessKeyExecutionError(
                status_code=409,
                code="EXECUTION_ALREADY_CLAIMED",
                category="WORKFLOW_VALIDATION",
                message="This remediation is already being processed or is no longer approved.",
            )
        execution_started = True

        start_audit = _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_EXECUTION_STARTED,
            action="IAM access-key disable execution started",
            execution_state=STATUS_EXECUTING,
            verification_result="PENDING",
            aws_request_id=aws_request_id,
        )
        if not start_audit:
            raise IAMAccessKeyExecutionError(
                status_code=503,
                code="AUDIT_UNAVAILABLE",
                category="AUDIT_FAILURE",
                message="Execution could not start because the audit event could not be recorded.",
            )

        mutation_response = iam_client.update_access_key(
            UserName=username,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
        aws_request_id = _aws_request_id(mutation_response) or aws_request_id

        verified_status, verification_request_id = _find_key(
            iam_client,
            username,
            access_key_id,
        )
        aws_request_id = verification_request_id or aws_request_id
        if verified_status != "Inactive":
            raise IAMAccessKeyExecutionError(
                status_code=502,
                code="ACCESS_KEY_VERIFICATION_FAILED",
                category="AWS_STATE_VERIFICATION",
                message="The IAM access key was not verified as inactive.",
            )

        after_state = {
            "success": True,
            "resource_id": mask_iam_access_key_id(access_key_id),
            "status": "Inactive",
        }
        verification = {
            "verified": True,
            "expected_status": "Inactive",
            "observed_status": verified_status,
        }
        if not update_execution_result(
            remediation["_id"],
            user_id,
            after_state=after_state,
            verification=verification,
        ):
            raise IAMAccessKeyExecutionError(
                status_code=500,
                code="RESULT_PERSISTENCE_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="IAM state was verified but the remediation result could not be saved.",
            )
        if not transition_to_completed(remediation["_id"], user_id):
            raise IAMAccessKeyExecutionError(
                status_code=500,
                code="COMPLETION_TRANSITION_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="IAM state was verified but the remediation could not be completed.",
            )

        completion_audit = _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_COMPLETED,
            action="IAM access-key disable execution completed",
            execution_state=STATUS_COMPLETED,
            success=True,
            verification_result="VERIFIED_INACTIVE",
            aws_request_id=aws_request_id,
        )

        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "remediation_id": remediation["_id"],
            "action_id": IAM_DISABLE_ACCESS_KEY_ACTION,
            "service": "IAM",
            "resource_type": "IAM_ACCESS_KEY",
            "resource_id": mask_iam_access_key_id(access_key_id),
            "aws_account_id": expected_account_id,
            "verification": verification,
            "audit_recorded": bool(completion_audit),
        }
    except IAMAccessKeyExecutionError as error:
        if not getattr(error, "audit_recorded", False):
            if execution_started:
                transition_to_failed(
                    remediation["_id"],
                    user_id,
                    execution_error=f"{error.code}:{error.category}",
                )
                _record_event(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    request_id=request_id,
                    event_type=EVENT_REMEDIATION_FAILED,
                    action="IAM access-key disable execution failed",
                    execution_state=STATUS_FAILED,
                    success=False,
                    error_code=error.code,
                    error_category=error.category,
                    verification_result="FAILED",
                    aws_request_id=aws_request_id,
                )
            else:
                _record_event(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    request_id=request_id,
                    event_type=EVENT_REMEDIATION_FAILED,
                    action="IAM access-key disable attempt failed before mutation",
                    execution_state="NOT_STARTED",
                    confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED",
                    success=False,
                    error_code=error.code,
                    error_category=error.category,
                    verification_result="NOT_RUN",
                    aws_request_id=aws_request_id,
                )
            error.audit_recorded = True
        raise
    except Exception as error:
        error_code = _aws_error_code(error)
        if isinstance(error, ClientError):
            aws_request_id = _aws_request_id(error.response) or aws_request_id
            if error_code in {"AccessDenied", "AccessDeniedException", "403"}:
                error_category = "AWS_AUTHORIZATION"
                status_code = 403
                message = "The assumed role cannot access or update this IAM access key."
            elif error_code in {"NoSuchEntity", "NoSuchEntityException", "InvalidUserName", "InvalidAccessKeyId"}:
                error_category = "RESOURCE_VALIDATION"
                status_code = 404
                message = "The IAM user or access key was not found in the connected account."
            else:
                error_category = "AWS_API"
                status_code = 502
                message = "The IAM remediation could not be completed."
        elif isinstance(error, PermissionError):
            error_code = "AWS_ACCOUNT_MISMATCH"
            error_category = "ACCOUNT_VALIDATION"
            status_code = 403
            message = "The assumed AWS role does not belong to the connected account."
        else:
            error_category = "AWS_API"
            status_code = 502 if execution_started else 503
            message = "The IAM remediation could not be completed."

        if execution_started:
            transition_to_failed(
                remediation["_id"],
                user_id,
                execution_error=f"{error_code}:{error_category}",
            )
        _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_FAILED,
            action="IAM access-key disable execution failed" if execution_started else "IAM access-key validation failed",
            execution_state=STATUS_FAILED if execution_started else "NOT_STARTED",
            confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED",
            success=False,
            error_code=error_code,
            error_category=error_category,
            verification_result="FAILED" if execution_started else "NOT_RUN",
            aws_request_id=aws_request_id,
        )
        raise IAMAccessKeyExecutionError(
            status_code=status_code,
            code=error_code,
            category=error_category,
            message=message,
            audit_recorded=True,
        ) from None
