from __future__ import annotations

import re
from typing import Any, Dict, Optional

from botocore.exceptions import BotoCoreError, ClientError, WaiterError

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
from app.services.remediation.remediation_models import RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID


RDS_DISABLE_PUBLIC_ACCESS_ACTION = RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID
RDS_INSTANCE_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class RDSDisablePublicAccessError(Exception):
    """Safe public error details for RDS public-access remediation."""

    def __init__(self, *, status_code: int, code: str, category: str, message: str, audit_recorded: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.category = category
        self.public_message = message
        self.audit_recorded = audit_recorded


def is_valid_rds_instance_identifier(identifier: str) -> bool:
    return (
        isinstance(identifier, str)
        and bool(RDS_INSTANCE_ID_PATTERN.fullmatch(identifier))
        and not identifier.endswith("-")
        and "--" not in identifier
    )


def _aws_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, (BotoCoreError, WaiterError)):
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
        action_id=RDS_DISABLE_PUBLIC_ACCESS_ACTION,
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


def _get_db_instance(rds: Any, identifier: str) -> tuple[Dict[str, Any], Optional[str]]:
    response = rds.describe_db_instances(DBInstanceIdentifier=identifier)
    instances = response.get("DBInstances") or []
    if len(instances) != 1 or instances[0].get("DBInstanceIdentifier") != identifier:
        raise RDSDisablePublicAccessError(status_code=404, code="RDS_INSTANCE_NOT_FOUND", category="RESOURCE_VALIDATION", message="The RDS instance was not found in the connected AWS account.")
    return instances[0], _aws_request_id(response)


def _validate_instance_arn(instance: Dict[str, Any], account_id: str, region: str, identifier: str) -> None:
    arn_parts = str(instance.get("DBInstanceArn") or "").split(":", 5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[1] != "aws"
        or arn_parts[2] != "rds"
        or arn_parts[3] != region
        or arn_parts[4] != account_id
        or arn_parts[5] != f"db:{identifier}"
    ):
        raise RDSDisablePublicAccessError(status_code=403, code="RDS_ACCOUNT_MISMATCH", category="RESOURCE_VALIDATION", message="The RDS instance does not belong to the connected AWS account and region.")


def execute_rds_disable_public_access(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    action = get_default_engine().get_action(RDS_DISABLE_PUBLIC_ACCESS_ACTION)
    if action is None or action.service != "RDS" or action.resource_type != "RDS_INSTANCE":
        raise RDSDisablePublicAccessError(status_code=503, code="ACTION_DEFINITION_UNAVAILABLE", category="REGISTRY_VALIDATION", message="The RDS remediation action is unavailable.")

    if not action.allowed_roles or role.strip().lower() not in {item.strip().lower() for item in action.allowed_roles}:
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_AUTHORIZATION, action="RDS public-access authorization denied", authorization_result="DENIED", confirmation_state="NOT_CONFIRMED", execution_state="NOT_STARTED", success=False, error_code="ROLE_NOT_ALLOWED", error_category="AUTHORIZATION")
        raise RDSDisablePublicAccessError(status_code=403, code="ROLE_NOT_ALLOWED", category="AUTHORIZATION", message="You are not authorized to execute this remediation action.", audit_recorded=True)

    if (
        remediation.get("action_type") != RDS_DISABLE_PUBLIC_ACCESS_ACTION
        or action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise RDSDisablePublicAccessError(status_code=409, code="ACTION_POLICY_MISMATCH", category="ACTION_VALIDATION", message="The remediation action does not satisfy the required approval policy.")
    rem_org = str(remediation.get("organization_id") or "").strip()
    if not rem_org or rem_org != str(organization_id).strip():
        raise RDSDisablePublicAccessError(status_code=403, code="ORGANIZATION_MISMATCH", category="TENANT_VALIDATION", message="Remediation does not belong to the active organization.")
    if not remediation.get("user_id"):
        raise RDSDisablePublicAccessError(status_code=404, code="REMEDIATION_NOT_FOUND", category="TENANT_VALIDATION", message="Remediation proposer not found.")
    if str(remediation.get("status", "")).upper() != STATUS_APPROVED or not remediation.get("approved_by") or not remediation.get("approved_at"):
        raise RDSDisablePublicAccessError(status_code=409, code="APPROVAL_REQUIRED", category="APPROVAL_VALIDATION", message="Remediation must be approved before execution.")
    if confirmed is not True:
        raise RDSDisablePublicAccessError(status_code=409, code="CONFIRMATION_REQUIRED", category="CONFIRMATION_VALIDATION", message="Explicit confirmation is required before execution.")

    identifier = str(remediation.get("resource") or "").strip()
    if not is_valid_rds_instance_identifier(identifier):
        raise RDSDisablePublicAccessError(status_code=400, code="INVALID_RDS_IDENTIFIER", category="RESOURCE_VALIDATION", message="A valid RDS instance identifier is required.")

    execution_started = False
    aws_request_id = None
    try:
        account = get_account(str(remediation.get("account_id") or ""), user_id=user_id, organization_id=organization_id)
        if not account or account.get("status") != "connected":
            raise RDSDisablePublicAccessError(status_code=404, code="AWS_ACCOUNT_NOT_FOUND", category="ACCOUNT_VALIDATION", message="Connected AWS account not found for this organization.")
        expected_account_id = str(account.get("aws_account_id") or "").strip()
        if not re.fullmatch(r"[0-9]{12}", expected_account_id) or str(remediation.get("aws_account_id") or "") != expected_account_id:
            raise RDSDisablePublicAccessError(status_code=409, code="AWS_ACCOUNT_MISMATCH", category="ACCOUNT_VALIDATION", message="Remediation AWS account does not match the connected account.")
        role_arn = str(account.get("role_arn") or "").strip()
        region = str(account.get("region") or "ap-south-1").strip()
        if not role_arn or not region:
            raise RDSDisablePublicAccessError(status_code=409, code="AWS_CONNECTION_INCOMPLETE", category="ACCOUNT_VALIDATION", message="The connected AWS account is missing execution configuration.")

        # Verify organization remediation setting for RDS
        from app.models.remediation_settings import is_remediation_enabled
        if not is_remediation_enabled(organization_id, str(remediation.get("account_id") or ""), "rds"):
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action="RDS public-access disable authorization denied (setting disabled)",
                authorization_result="DENIED",
                confirmation_state="CONFIRMED",
                execution_state="NOT_STARTED",
                success=False,
                error_code="REMEDIATION_SETTING_DISABLED",
                error_category="GOVERNANCE",
            )
            raise RDSDisablePublicAccessError(
                status_code=403,
                code="REMEDIATION_SETTING_DISABLED",
                category="GOVERNANCE",
                message="Remediation setting is disabled for RDS for this account.",
                audit_recorded=True,
            )

        session = assume_aws_role(role_arn=role_arn, region=region, session_name=f"CloudGuardAI-RDSPublic-{str(remediation.get('_id', ''))[:24]}")
        verify_aws_account(session, expected_account_id)
        rds = session.client("rds", region_name=region, config=AWS_CONFIG)
        instance, aws_request_id = _get_db_instance(rds, identifier)
        _validate_instance_arn(instance, expected_account_id, region, identifier)
        if instance.get("PubliclyAccessible") is not True:
            raise RDSDisablePublicAccessError(status_code=409, code="RDS_NOT_PUBLIC", category="RESOURCE_VALIDATION", message="The RDS instance is not publicly accessible and requires no public-access remediation.")

        if not transition_to_executing(remediation["_id"], user_id, organization_id=organization_id):
            raise RDSDisablePublicAccessError(status_code=409, code="EXECUTION_ALREADY_CLAIMED", category="WORKFLOW_VALIDATION", message="This remediation is already being processed or is no longer approved.")
        execution_started = True
        start_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_EXECUTION_STARTED, action="RDS public-access disable started", execution_state=STATUS_EXECUTING, verification_result="PENDING", aws_request_id=aws_request_id)
        if not start_audit:
            raise RDSDisablePublicAccessError(status_code=503, code="AUDIT_UNAVAILABLE", category="AUDIT_FAILURE", message="Execution could not start because the audit event could not be recorded.")

        mutation = rds.modify_db_instance(DBInstanceIdentifier=identifier, PubliclyAccessible=False, ApplyImmediately=True)
        aws_request_id = _aws_request_id(mutation) or aws_request_id
        rds.get_waiter("db_instance_available").wait(DBInstanceIdentifier=identifier, WaiterConfig={"Delay": 10, "MaxAttempts": 30})
        verified_instance, verify_request_id = _get_db_instance(rds, identifier)
        aws_request_id = verify_request_id or aws_request_id
        _validate_instance_arn(verified_instance, expected_account_id, region, identifier)
        if verified_instance.get("PubliclyAccessible") is not False:
            raise RDSDisablePublicAccessError(status_code=502, code="RDS_PUBLIC_ACCESS_VERIFICATION_FAILED", category="AWS_STATE_VERIFICATION", message="RDS public accessibility was not verified as disabled.")

        after_state = {"success": True, "resource_id": identifier, "publicly_accessible": False}
        verification = {"verified": True, "expected_publicly_accessible": False, "observed_publicly_accessible": False}
        if not update_execution_result(remediation["_id"], user_id, after_state=after_state, verification=verification, organization_id=organization_id):
            raise RDSDisablePublicAccessError(status_code=500, code="RESULT_PERSISTENCE_FAILED", category="WORKFLOW_PERSISTENCE", message="RDS state was verified but the remediation result could not be saved.")
        if not transition_to_completed(remediation["_id"], user_id, organization_id=organization_id):
            raise RDSDisablePublicAccessError(status_code=500, code="COMPLETION_TRANSITION_FAILED", category="WORKFLOW_PERSISTENCE", message="RDS state was verified but the remediation could not be completed.")
        completion_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_COMPLETED, action="RDS public access disabled and verified", execution_state=STATUS_COMPLETED, success=True, verification_result="VERIFIED_NOT_PUBLIC", aws_request_id=aws_request_id)
        return {"success": True, "status": STATUS_COMPLETED, "remediation_id": remediation["_id"], "action_id": RDS_DISABLE_PUBLIC_ACCESS_ACTION, "service": "RDS", "resource_type": "RDS_INSTANCE", "resource_id": identifier, "aws_account_id": expected_account_id, "verification": verification, "audit_recorded": bool(completion_audit)}
    except RDSDisablePublicAccessError as error:
        if not getattr(error, "audit_recorded", False):
            if execution_started:
                transition_to_failed(remediation["_id"], user_id, execution_error=f"{error.code}:{error.category}", organization_id=organization_id)
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="RDS public-access disable failed", execution_state=STATUS_FAILED, success=False, error_code=error.code, error_category=error.category, verification_result="FAILED", aws_request_id=aws_request_id)
            else:
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="RDS public-access attempt failed before mutation", execution_state="NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error.code, error_category=error.category, verification_result="NOT_RUN", aws_request_id=aws_request_id)
            error.audit_recorded = True
        raise
    except Exception as error:
        error_code = _aws_error_code(error)
        if isinstance(error, ClientError):
            aws_request_id = _aws_request_id(error.response) or aws_request_id
            if error_code in {"AccessDenied", "AccessDeniedException", "403"}:
                category, status_code, message = "AWS_AUTHORIZATION", 403, "The assumed role cannot access or modify this RDS instance."
            elif error_code in {"DBInstanceNotFound", "DBInstanceNotFoundFault", "NotFound"}:
                category, status_code, message = "RESOURCE_VALIDATION", 404, "The RDS instance was not found in the connected AWS account."
            else:
                category, status_code, message = "AWS_API", 502, "The RDS remediation could not be completed."
        elif isinstance(error, WaiterError):
            category, status_code, message = "AWS_STATE_VERIFICATION", 502, "The RDS instance did not become available for verification."
        elif isinstance(error, PermissionError):
            error_code, category, status_code, message = "AWS_ACCOUNT_MISMATCH", "ACCOUNT_VALIDATION", 403, "The assumed AWS role does not belong to the connected account."
        else:
            category, status_code, message = "AWS_API", 502 if execution_started else 503, "The RDS remediation could not be completed."
        if execution_started:
            transition_to_failed(remediation["_id"], user_id, execution_error=f"{error_code}:{category}", organization_id=organization_id)
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="RDS public-access disable failed" if execution_started else "RDS public-access validation failed", execution_state=STATUS_FAILED if execution_started else "NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error_code, error_category=category, verification_result="FAILED" if execution_started else "NOT_RUN", aws_request_id=aws_request_id)
        raise RDSDisablePublicAccessError(status_code=status_code, code=error_code, category=category, message=message, audit_recorded=True) from None
