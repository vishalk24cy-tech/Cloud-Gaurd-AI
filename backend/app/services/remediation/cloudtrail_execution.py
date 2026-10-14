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
from app.services.remediation.remediation_models import CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID


CLOUDTRAIL_ENABLE_LOGGING_ACTION = CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID
TRAIL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


class CloudTrailEnableLoggingError(Exception):
    """Safe public error details for CloudTrail logging remediation."""

    def __init__(self, *, status_code: int, code: str, category: str, message: str, audit_recorded: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.category = category
        self.public_message = message
        self.audit_recorded = audit_recorded


def is_valid_trail_name(value: str) -> bool:
    return isinstance(value, str) and bool(TRAIL_NAME_PATTERN.fullmatch(value))


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
        action_id=CLOUDTRAIL_ENABLE_LOGGING_ACTION,
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
        finding_id=remediation.get("finding_id"),
        remediation_id=remediation.get("_id"),
        resource_id=remediation.get("resource"),
        request_id=request_id,
        aws_request_id=aws_request_id,
    )


def _load_trail(cloudtrail: Any, trail_name: str, expected_account_id: str) -> tuple[Dict[str, Any], Optional[str]]:
    response = cloudtrail.describe_trails(trailNameList=[trail_name], includeShadowTrails=False)
    matches = [trail for trail in response.get("trailList", []) or [] if trail.get("Name") == trail_name]
    if len(matches) != 1:
        raise CloudTrailEnableLoggingError(status_code=404, code="TRAIL_NOT_FOUND", category="RESOURCE_VALIDATION", message="The CloudTrail trail was not found in the connected account.")
    trail = matches[0]
    arn_parts = str(trail.get("TrailARN") or "").split(":", 5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[1] != "aws"
        or arn_parts[2] != "cloudtrail"
        or arn_parts[4] != expected_account_id
        or arn_parts[5] != f"trail/{trail_name}"
    ):
        raise CloudTrailEnableLoggingError(status_code=403, code="TRAIL_ACCOUNT_MISMATCH", category="RESOURCE_VALIDATION", message="The CloudTrail trail does not belong to the connected AWS account.")
    return trail, _aws_request_id(response)


def execute_cloudtrail_enable_logging(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    action = get_default_engine().get_action(CLOUDTRAIL_ENABLE_LOGGING_ACTION)
    if action is None or action.service != "CLOUDTRAIL" or action.resource_type != "CLOUDTRAIL_TRAIL":
        raise CloudTrailEnableLoggingError(status_code=503, code="ACTION_DEFINITION_UNAVAILABLE", category="REGISTRY_VALIDATION", message="The CloudTrail remediation action is unavailable.")

    if not action.allowed_roles or role.strip().lower() not in {item.strip().lower() for item in action.allowed_roles}:
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_AUTHORIZATION, action="CloudTrail logging authorization denied", authorization_result="DENIED", confirmation_state="NOT_CONFIRMED", execution_state="NOT_STARTED", success=False, error_code="ROLE_NOT_ALLOWED", error_category="AUTHORIZATION")
        raise CloudTrailEnableLoggingError(status_code=403, code="ROLE_NOT_ALLOWED", category="AUTHORIZATION", message="You are not authorized to execute this remediation action.", audit_recorded=True)

    if remediation.get("action_type") != CLOUDTRAIL_ENABLE_LOGGING_ACTION or action.classification.value != "APPROVAL_REQUIRED" or not action.requires_confirmation or not action.requires_approval:
        raise CloudTrailEnableLoggingError(status_code=409, code="ACTION_POLICY_MISMATCH", category="ACTION_VALIDATION", message="The remediation action does not satisfy the required approval policy.")
    rem_org = str(remediation.get("organization_id") or "").strip()
    if not rem_org or rem_org != str(organization_id).strip():
        raise CloudTrailEnableLoggingError(status_code=403, code="ORGANIZATION_MISMATCH", category="TENANT_VALIDATION", message="Remediation does not belong to the active organization.")
    if not remediation.get("user_id"):
        raise CloudTrailEnableLoggingError(status_code=404, code="REMEDIATION_NOT_FOUND", category="TENANT_VALIDATION", message="Remediation proposer not found.")
    if str(remediation.get("status", "")).upper() != STATUS_APPROVED or not remediation.get("approved_by") or not remediation.get("approved_at"):
        raise CloudTrailEnableLoggingError(status_code=409, code="APPROVAL_REQUIRED", category="APPROVAL_VALIDATION", message="Remediation must be approved before execution.")
    if confirmed is not True:
        raise CloudTrailEnableLoggingError(status_code=409, code="CONFIRMATION_REQUIRED", category="CONFIRMATION_VALIDATION", message="Explicit confirmation is required before execution.")

    trail_name = str(remediation.get("resource") or "").strip()
    if not is_valid_trail_name(trail_name):
        raise CloudTrailEnableLoggingError(status_code=400, code="INVALID_TRAIL_NAME", category="RESOURCE_VALIDATION", message="A valid CloudTrail trail name is required.")

    execution_started = False
    aws_request_id = None
    try:
        account = get_account(str(remediation.get("account_id") or ""), user_id=user_id, organization_id=organization_id)
        if not account or account.get("status") != "connected":
            raise CloudTrailEnableLoggingError(status_code=404, code="AWS_ACCOUNT_NOT_FOUND", category="ACCOUNT_VALIDATION", message="Connected AWS account not found for this organization.")
        expected_account_id = str(account.get("aws_account_id") or "").strip()
        if not re.fullmatch(r"[0-9]{12}", expected_account_id) or str(remediation.get("aws_account_id") or "") != expected_account_id:
            raise CloudTrailEnableLoggingError(status_code=409, code="AWS_ACCOUNT_MISMATCH", category="ACCOUNT_VALIDATION", message="Remediation AWS account does not match the connected account.")
        role_arn = str(account.get("role_arn") or "").strip()
        region = str(account.get("region") or "ap-south-1").strip()
        if not role_arn or not region:
            raise CloudTrailEnableLoggingError(status_code=409, code="AWS_CONNECTION_INCOMPLETE", category="ACCOUNT_VALIDATION", message="The connected AWS account is missing execution configuration.")

        # Verify organization remediation setting for CloudTrail
        from app.models.remediation_settings import is_remediation_enabled
        if not is_remediation_enabled(organization_id, str(remediation.get("account_id") or ""), "cloudtrail"):
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action="CloudTrail enable logging authorization denied (setting disabled)",
                authorization_result="DENIED",
                confirmation_state="CONFIRMED",
                execution_state="NOT_STARTED",
                success=False,
                error_code="REMEDIATION_SETTING_DISABLED",
                error_category="GOVERNANCE",
            )
            raise CloudTrailEnableLoggingError(
                status_code=403,
                code="REMEDIATION_SETTING_DISABLED",
                category="GOVERNANCE",
                message="Remediation setting is disabled for CloudTrail for this account.",
                audit_recorded=True,
            )

        session = assume_aws_role(role_arn=role_arn, region=region, session_name=f"CloudGuardAI-CloudTrail-{str(remediation.get('_id', ''))[:24]}")
        verify_aws_account(session, expected_account_id)
        describe_client = session.client("cloudtrail", region_name=region, config=AWS_CONFIG)
        trail, aws_request_id = _load_trail(describe_client, trail_name, expected_account_id)
        arn_parts = str(trail["TrailARN"]).split(":", 5)
        arn_region = arn_parts[3]
        home_region = str(trail.get("HomeRegion") or arn_region)
        if trail.get("HomeRegion") and home_region != arn_region:
            raise CloudTrailEnableLoggingError(status_code=409, code="TRAIL_REGION_MISMATCH", category="RESOURCE_VALIDATION", message="The CloudTrail trail home region does not match its ARN.")
        cloudtrail = session.client("cloudtrail", region_name=home_region, config=AWS_CONFIG)
        before = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        aws_request_id = _aws_request_id(before) or aws_request_id
        if before.get("IsLogging") is True:
            raise CloudTrailEnableLoggingError(status_code=409, code="TRAIL_ALREADY_LOGGING", category="RESOURCE_VALIDATION", message="The CloudTrail trail is already logging and requires no remediation.")

        if not transition_to_executing(remediation["_id"], user_id, organization_id=organization_id):
            raise CloudTrailEnableLoggingError(status_code=409, code="EXECUTION_ALREADY_CLAIMED", category="WORKFLOW_VALIDATION", message="This remediation is already being processed or is no longer approved.")
        execution_started = True
        start_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_EXECUTION_STARTED, action="CloudTrail logging enablement started", execution_state=STATUS_EXECUTING, verification_result="PENDING", aws_request_id=aws_request_id)
        if not start_audit:
            raise CloudTrailEnableLoggingError(status_code=503, code="AUDIT_UNAVAILABLE", category="AUDIT_FAILURE", message="Execution could not start because the audit event could not be recorded.")

        mutation = cloudtrail.start_logging(Name=trail["TrailARN"])
        aws_request_id = _aws_request_id(mutation) or aws_request_id
        verified = cloudtrail.get_trail_status(Name=trail["TrailARN"])
        aws_request_id = _aws_request_id(verified) or aws_request_id
        if verified.get("IsLogging") is not True:
            raise CloudTrailEnableLoggingError(status_code=502, code="TRAIL_LOGGING_VERIFICATION_FAILED", category="AWS_STATE_VERIFICATION", message="CloudTrail logging was not verified as enabled.")

        after_state = {"success": True, "resource_id": trail_name, "is_logging": True}
        verification = {"verified": True, "expected_is_logging": True, "observed_is_logging": True}
        if not update_execution_result(remediation["_id"], user_id, after_state=after_state, verification=verification, organization_id=organization_id):
            raise CloudTrailEnableLoggingError(status_code=500, code="RESULT_PERSISTENCE_FAILED", category="WORKFLOW_PERSISTENCE", message="CloudTrail state was verified but the remediation result could not be saved.")
        if not transition_to_completed(remediation["_id"], user_id, organization_id=organization_id):
            raise CloudTrailEnableLoggingError(status_code=500, code="COMPLETION_TRANSITION_FAILED", category="WORKFLOW_PERSISTENCE", message="CloudTrail state was verified but the remediation could not be completed.")
        completion_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_COMPLETED, action="CloudTrail logging enabled and verified", execution_state=STATUS_COMPLETED, success=True, verification_result="VERIFIED_LOGGING_ENABLED", aws_request_id=aws_request_id)
        return {"success": True, "status": STATUS_COMPLETED, "remediation_id": remediation["_id"], "action_id": CLOUDTRAIL_ENABLE_LOGGING_ACTION, "service": "CLOUDTRAIL", "resource_type": "CLOUDTRAIL_TRAIL", "resource_id": trail_name, "aws_account_id": expected_account_id, "verification": verification, "audit_recorded": bool(completion_audit)}
    except CloudTrailEnableLoggingError as error:
        if not getattr(error, "audit_recorded", False):
            if execution_started:
                transition_to_failed(remediation["_id"], user_id, execution_error=f"{error.code}:{error.category}", organization_id=organization_id)
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="CloudTrail logging enablement failed", execution_state=STATUS_FAILED, success=False, error_code=error.code, error_category=error.category, verification_result="FAILED", aws_request_id=aws_request_id)
            else:
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="CloudTrail logging attempt failed before mutation", execution_state="NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error.code, error_category=error.category, verification_result="NOT_RUN", aws_request_id=aws_request_id)
            error.audit_recorded = True
        raise
    except Exception as error:
        error_code = _aws_error_code(error)
        if isinstance(error, ClientError):
            aws_request_id = _aws_request_id(error.response) or aws_request_id
            if error_code in {"AccessDenied", "AccessDeniedException", "InsufficientPrivilegesException", "403"}:
                category, status_code, message = "AWS_AUTHORIZATION", 403, "The assumed role cannot access or enable this CloudTrail trail."
            elif error_code in {"TrailNotFoundException", "ResourceNotFoundException"}:
                category, status_code, message = "RESOURCE_VALIDATION", 404, "The CloudTrail trail was not found in the connected account."
            else:
                category, status_code, message = "AWS_API", 502, "The CloudTrail remediation could not be completed."
        elif isinstance(error, PermissionError):
            error_code, category, status_code, message = "AWS_ACCOUNT_MISMATCH", "ACCOUNT_VALIDATION", 403, "The assumed AWS role does not belong to the connected account."
        else:
            category, status_code, message = "AWS_API", 502 if execution_started else 503, "The CloudTrail remediation could not be completed."
        if execution_started:
            transition_to_failed(remediation["_id"], user_id, execution_error=f"{error_code}:{category}", organization_id=organization_id)
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="CloudTrail logging enablement failed" if execution_started else "CloudTrail validation failed", execution_state=STATUS_FAILED if execution_started else "NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error_code, error_category=category, verification_result="FAILED" if execution_started else "NOT_RUN", aws_request_id=aws_request_id)
        raise CloudTrailEnableLoggingError(status_code=status_code, code=error_code, category=category, message=message, audit_recorded=True) from None
