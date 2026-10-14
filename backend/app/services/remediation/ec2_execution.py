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
from app.services.aws_connection import (
    AWS_CONFIG,
    assume_aws_role,
    verify_aws_account,
)
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.remediation_models import EC2_STOP_INSTANCE_ACTION_ID


EC2_STOP_ACTION_ID = EC2_STOP_INSTANCE_ACTION_ID
INSTANCE_ID_PATTERN = re.compile(r"^i-[0-9a-fA-F]{8}(?:[0-9a-fA-F]{9})?$")


class EC2StopExecutionError(Exception):
    """Safe public error details for the EC2 stop workflow."""

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


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, WaiterError):
        response = getattr(error, "last_response", {}) or {}
        code = response.get("Error", {}).get("Code", "STATE_VERIFICATION_TIMEOUT")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__

    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(code))[:100] or "AWS_ERROR"


def _load_instance(ec2_client: Any, instance_id: str, expected_account_id: str) -> Dict[str, Any]:
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    reservations = response.get("Reservations") or []
    instances = [
        instance
        for reservation in reservations
        for instance in reservation.get("Instances") or []
    ]

    if len(instances) != 1 or instances[0].get("InstanceId") != instance_id:
        raise EC2StopExecutionError(
            status_code=404,
            code="INSTANCE_NOT_FOUND",
            category="RESOURCE_VALIDATION",
            message="The EC2 instance was not found in the connected AWS account.",
        )

    owner_ids = {
        str(reservation.get("OwnerId"))
        for reservation in reservations
        if reservation.get("OwnerId")
    }
    if owner_ids != {expected_account_id}:
        raise EC2StopExecutionError(
            status_code=403,
            code="INSTANCE_ACCOUNT_MISMATCH",
            category="RESOURCE_VALIDATION",
            message="The EC2 instance does not belong to the connected AWS account.",
        )

    return instances[0]


def _record_event(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    request_id: Optional[str],
    event_type: str,
    action: str,
    authorization_result: str = "AUTHORIZED",
    confirmation_state: str = "CONFIRMED",
    approval_state: Optional[str] = None,
    execution_state: str,
    success: Optional[bool] = None,
    error_code: Optional[str] = None,
    error_category: Optional[str] = None,
    verification_result: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    return record_remediation_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=event_type,
        action_id=EC2_STOP_ACTION_ID,
        action=action,
        authorization_result=authorization_result,
        confirmation_state=confirmation_state,
        approval_state=approval_state or remediation.get("status"),
        execution_state=execution_state,
        success=success,
        error_code=error_code,
        error_category=error_category,
        verification_result=verification_result,
        account_id=remediation.get("account_id"),
        aws_account_id=remediation.get("aws_account_id"),
        remediation_id=remediation.get("_id"),
        resource_id=remediation.get("resource"),
        request_id=request_id,
    )


def execute_ec2_stop(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute only the approved EC2 stop action and verify the final state."""

    engine = get_default_engine()
    action = engine.get_action(EC2_STOP_ACTION_ID)

    if action is None or action.service != "EC2" or action.resource_type != "EC2_INSTANCE":
        raise EC2StopExecutionError(
            status_code=503,
            code="ACTION_DEFINITION_UNAVAILABLE",
            category="REGISTRY_VALIDATION",
            message="The EC2 remediation action is unavailable.",
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
            action="EC2 stop authorization denied",
            authorization_result="DENIED",
            confirmation_state="NOT_CONFIRMED",
            execution_state="NOT_STARTED",
            success=False,
            error_code="ROLE_NOT_ALLOWED",
            error_category="AUTHORIZATION",
        )
        raise EC2StopExecutionError(
            status_code=403,
            code="ROLE_NOT_ALLOWED",
            category="AUTHORIZATION",
            message="You are not authorized to execute this remediation action.",
            audit_recorded=True,
        )

    if (
        remediation.get("action_type") != EC2_STOP_ACTION_ID
        or action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise EC2StopExecutionError(
            status_code=409,
            code="ACTION_POLICY_MISMATCH",
            category="ACTION_VALIDATION",
            message="The remediation action does not satisfy the required approval policy.",
        )

    rem_org = str(remediation.get("organization_id") or "").strip()
    if not rem_org or rem_org != str(organization_id).strip():
        raise EC2StopExecutionError(
            status_code=403,
            code="ORGANIZATION_MISMATCH",
            category="TENANT_VALIDATION",
            message="Remediation does not belong to the active organization.",
        )

    if not remediation.get("user_id"):
        raise EC2StopExecutionError(
            status_code=404,
            code="REMEDIATION_NOT_FOUND",
            category="TENANT_VALIDATION",
            message="Remediation proposer not found.",
        )

    if (
        str(remediation.get("status", "")).upper() != STATUS_APPROVED
        or not remediation.get("approved_by")
        or not remediation.get("approved_at")
    ):
        raise EC2StopExecutionError(
            status_code=409,
            code="APPROVAL_REQUIRED",
            category="APPROVAL_VALIDATION",
            message="Remediation must be approved before execution.",
        )

    if confirmed is not True:
        raise EC2StopExecutionError(
            status_code=409,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_VALIDATION",
            message="Explicit confirmation is required before execution.",
        )

    instance_id = str(remediation.get("resource") or "").strip()
    if not INSTANCE_ID_PATTERN.fullmatch(instance_id):
        raise EC2StopExecutionError(
            status_code=400,
            code="INVALID_INSTANCE_ID",
            category="RESOURCE_VALIDATION",
            message="A valid EC2 instance ID is required.",
        )

    account_id = str(remediation.get("account_id") or "").strip()
    try:
        account = get_account(
            account_id,
            user_id=user_id,
            organization_id=organization_id,
        )
    except Exception:
        raise EC2StopExecutionError(
            status_code=503,
            code="ACCOUNT_LOOKUP_FAILED",
            category="ACCOUNT_VALIDATION",
            message="Connected AWS account could not be validated.",
        ) from None
    if not account or account.get("status") != "connected":
        raise EC2StopExecutionError(
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
        raise EC2StopExecutionError(
            status_code=409,
            code="AWS_ACCOUNT_MISMATCH",
            category="ACCOUNT_VALIDATION",
            message="Remediation AWS account does not match the connected account.",
        )

    role_arn = str(account.get("role_arn") or "").strip()
    region = str(account.get("region") or "ap-south-1").strip()
    if not role_arn or not region:
        raise EC2StopExecutionError(
            status_code=409,
            code="AWS_CONNECTION_INCOMPLETE",
            category="ACCOUNT_VALIDATION",
            message="The connected AWS account is missing execution configuration.",
        )

    # Verify organization remediation setting for EC2
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, account_id, "ec2"):
        _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action="EC2 stop authorization denied (setting disabled)",
            authorization_result="DENIED",
            confirmation_state="CONFIRMED",
            execution_state="NOT_STARTED",
            success=False,
            error_code="REMEDIATION_SETTING_DISABLED",
            error_category="GOVERNANCE",
        )
        raise EC2StopExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="GOVERNANCE",
            message="Remediation setting is disabled for EC2 for this account.",
            audit_recorded=True,
        )

    execution_started = False
    try:
        session = assume_aws_role(
            role_arn=role_arn,
            region=region,
            session_name=f"CloudGuardAI-EC2Stop-{str(remediation.get('_id', ''))[:24]}",
        )
        verify_aws_account(session, expected_account_id)
        ec2_client = session.client("ec2", region_name=region, config=AWS_CONFIG)
        instance = _load_instance(ec2_client, instance_id, expected_account_id)
        initial_state = str(instance.get("State", {}).get("Name", "")).lower()

        if initial_state not in {"running", "stopped"}:
            raise EC2StopExecutionError(
                status_code=409,
                code="INSTANCE_STATE_NOT_STOPPABLE",
                category="RESOURCE_VALIDATION",
                message="The EC2 instance is not in a stoppable state.",
            )

        if not transition_to_executing(
            remediation_id=remediation["_id"],
            user_id=user_id,
            organization_id=organization_id,
        ):
            raise EC2StopExecutionError(
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
            action="EC2 stop execution started",
            execution_state=STATUS_EXECUTING,
            success=None,
            verification_result="PENDING",
        )
        if not start_audit:
            raise EC2StopExecutionError(
                status_code=503,
                code="AUDIT_UNAVAILABLE",
                category="AUDIT_FAILURE",
                message="Execution could not start because the audit event could not be recorded.",
            )

        if initial_state == "running":
            ec2_client.stop_instances(InstanceIds=[instance_id])
            ec2_client.get_waiter("instance_stopped").wait(
                InstanceIds=[instance_id],
                WaiterConfig={"Delay": 5, "MaxAttempts": 24},
            )

        final_instance = _load_instance(ec2_client, instance_id, expected_account_id)
        final_state = str(final_instance.get("State", {}).get("Name", "")).lower()
        if final_state != "stopped":
            raise EC2StopExecutionError(
                status_code=502,
                code="STATE_VERIFICATION_FAILED",
                category="AWS_STATE_VERIFICATION",
                message="The EC2 instance did not reach the required stopped state.",
            )

        after_state = {
            "success": True,
            "resource_id": instance_id,
            "state": final_state,
            "already_stopped": initial_state == "stopped",
        }
        verification = {
            "verified": True,
            "expected_state": "stopped",
            "observed_state": final_state,
        }
        if not update_execution_result(
            remediation["_id"],
            user_id,
            after_state=after_state,
            verification=verification,
            organization_id=organization_id,
        ):
            raise EC2StopExecutionError(
                status_code=500,
                code="RESULT_PERSISTENCE_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="AWS state was verified but the remediation result could not be saved.",
            )
        if not transition_to_completed(
            remediation["_id"],
            user_id,
            organization_id=organization_id,
        ):
            raise EC2StopExecutionError(
                status_code=500,
                code="COMPLETION_TRANSITION_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="AWS state was verified but the remediation could not be completed.",
            )

        completion_audit = _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_COMPLETED,
            action="EC2 stop execution completed",
            execution_state=STATUS_COMPLETED,
            success=True,
            verification_result="VERIFIED_STOPPED",
        )

        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "remediation_id": remediation["_id"],
            "action_id": EC2_STOP_ACTION_ID,
            "service": "EC2",
            "resource_id": instance_id,
            "aws_account_id": expected_account_id,
            "verification": verification,
            "audit_recorded": bool(completion_audit),
        }
    except EC2StopExecutionError as error:
        if execution_started:
            transition_to_failed(
                remediation["_id"],
                user_id,
                execution_error=f"{error.code}:{error.category}",
                organization_id=organization_id,
            )
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_FAILED,
                action="EC2 stop execution failed",
                execution_state=STATUS_FAILED,
                success=False,
                error_code=error.code,
                error_category=error.category,
                verification_result="FAILED",
            )
        else:
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_FAILED,
                action="EC2 stop attempt rejected before AWS mutation",
                confirmation_state=("CONFIRMED" if confirmed else "NOT_CONFIRMED"),
                execution_state="NOT_STARTED",
                success=False,
                error_code=error.code,
                error_category=error.category,
                verification_result="NOT_RUN",
            )
        error.audit_recorded = True
        raise
    except Exception as error:
        error_code = _safe_error_code(error)
        error_category = (
            "AWS_STATE_VERIFICATION"
            if isinstance(error, WaiterError)
            else "AWS_EXECUTION"
        )
        if execution_started:
            transition_to_failed(
                remediation["_id"],
                user_id,
                execution_error=f"{error_code}:{error_category}",
                organization_id=organization_id,
            )
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_FAILED,
                action="EC2 stop execution failed",
                execution_state=STATUS_FAILED,
                success=False,
                error_code=error_code,
                error_category=error_category,
                verification_result="FAILED",
            )
        else:
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_FAILED,
                action="EC2 stop attempt failed before AWS mutation",
                confirmation_state=("CONFIRMED" if confirmed else "NOT_CONFIRMED"),
                approval_state=remediation.get("status"),
                execution_state="NOT_STARTED",
                success=False,
                error_code=error_code,
                error_category=error_category,
                verification_result="NOT_RUN",
            )
        raise EC2StopExecutionError(
            status_code=502 if execution_started else 503,
            code=error_code,
            category=error_category,
            message="The EC2 remediation could not be completed. See the audit record for safe error details.",
            audit_recorded=True,
        ) from None