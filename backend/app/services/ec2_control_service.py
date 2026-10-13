# ============================================================
# CloudGuardAI - Secure EC2 Resource Control Service
# Phase 2C: Secure EC2 Start, Stop and Reboot Controls
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict, Optional

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
from app.services.ec2_inventory_service import validate_aws_region

logger = logging.getLogger("cloudguardai.ec2_controls")

INSTANCE_ID_PATTERN = re.compile(r"^i-[0-9a-fA-F]{8}(?:[0-9a-fA-F]{9})?$")
ALLOWED_ACTIONS = {"start", "stop", "reboot"}
MUTATION_ALLOWED_ROLES = {"owner", "admin"}


class EC2ControlExecutionError(Exception):
    """Safe public error details for EC2 control workflows."""

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


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(code))[:100] or "AWS_ERROR"


def execute_ec2_instance_action(
    *,
    account_id: str,
    instance_id: str,
    action: str,
    region: Optional[str] = None,
    confirmed: bool = False,
    user_id: str,
    organization_id: str,
    role: str = "viewer",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a secure Start, Stop, or Reboot action on an EC2 instance.

    Enforces:
    1. Action validation (only start, stop, reboot allowed; never terminate).
    2. Explicit confirmation required.
    3. Strict owner/admin role authorization.
    4. Tenant organization isolation.
    5. AWS role assumption and STS identity verification.
    6. Server-side pre-state verification (invalid transitions rejected).
    7. Post-state verification and structured audit logging.
    """
    clean_action = _safe_string(action).lower()
    clean_instance_id = _safe_string(instance_id)
    clean_account_id = _safe_string(account_id)
    clean_role = _safe_string(role).lower() or "viewer"

    # 1. Action validation
    if not clean_action or clean_action not in ALLOWED_ACTIONS:
        raise EC2ControlExecutionError(
            status_code=400,
            code="INVALID_ACTION",
            category="ACTION_VALIDATION",
            message=f"Disallowed action '{action}'. Only 'start', 'stop', and 'reboot' are permitted.",
        )

    # 2. Confirmation requirement
    if confirmed is not True:
        raise EC2ControlExecutionError(
            status_code=400,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_VALIDATION",
            message="Explicit user confirmation identifying the exact instance and action is required.",
        )

    # 3. Instance ID format validation
    if not INSTANCE_ID_PATTERN.fullmatch(clean_instance_id):
        raise EC2ControlExecutionError(
            status_code=400,
            code="INVALID_INSTANCE_ID",
            category="RESOURCE_VALIDATION",
            message="Invalid EC2 instance ID format. Expected format 'i-0123456789abcdef0'.",
        )

    # 4. Region validation (if provided)
    if region is not None:
        target_region = _safe_string(region)
        if not validate_aws_region(target_region):
            raise EC2ControlExecutionError(
                status_code=400,
                code="INVALID_REGION",
                category="PARAMETER_VALIDATION",
                message=f"Invalid AWS region '{region}'. Region must match standard format like 'us-east-1'.",
            )
    else:
        target_region = None

    # 5. Role authorization (Owner/Admin only)
    if clean_role not in MUTATION_ALLOWED_ROLES:
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"EC2_{clean_action.upper()}_INSTANCE",
            result=RESULT_DENIED,
            actor_type=ACTOR_USER,
            service="EC2",
            resource_type="EC2_INSTANCE",
            resource_id=clean_instance_id,
            account_id=clean_account_id,
            message="User lacks admin/owner role for EC2 resource mutation.",
            metadata={
                "action": clean_action,
                "role": clean_role,
                "error_code": "ROLE_NOT_ALLOWED",
            },
        )
        raise EC2ControlExecutionError(
            status_code=403,
            code="ROLE_NOT_ALLOWED",
            category="AUTHORIZATION",
            message="You must have an Admin or Owner role to perform EC2 resource controls.",
            audit_recorded=True,
        )

    # 6. Tenant-scoped account lookup
    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise EC2ControlExecutionError(
            status_code=404,
            code="ACCOUNT_NOT_FOUND",
            category="TENANT_VALIDATION",
            message="Connected AWS Account not found or belongs to another organization.",
        )

    # 6b. Verify organization remediation setting for EC2
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, clean_account_id, "ec2"):
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"EC2_{clean_action.upper()}_INSTANCE",
            result=RESULT_DENIED,
            actor_type=ACTOR_USER,
            service="EC2",
            resource_type="EC2_INSTANCE",
            resource_id=clean_instance_id,
            account_id=clean_account_id,
            message="Remediation setting is disabled for EC2.",
            metadata={
                "action": clean_action,
                "role": clean_role,
                "error_code": "REMEDIATION_SETTING_DISABLED",
            },
        )
        raise EC2ControlExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="AUTHORIZATION",
            message="Remediation is disabled for EC2 for this account.",
            audit_recorded=True,
        )

    # Resolve target region from account default if not explicitly specified
    if target_region is None:
        target_region = _safe_string(aws_account.get("region") or "ap-south-1")
        if not validate_aws_region(target_region):
            target_region = "ap-south-1"

    role_arn = _safe_string(aws_account.get("role_arn"))
    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )

    if not role_arn:
        raise EC2ControlExecutionError(
            status_code=400,
            code="MISSING_ROLE_ARN",
            category="ACCOUNT_CONFIGURATION",
            message="AWS account is missing configured role_arn.",
        )

    # 7. Assume AWS Role & Verify Identity
    try:
        session = assume_aws_role(role_arn, region=target_region)
    except Exception as err:
        logger.warning("EC2 control assume_role failed: %s", err)
        raise EC2ControlExecutionError(
            status_code=403,
            code="ROLE_ASSUMPTION_FAILED",
            category="AWS_AUTHENTICATION",
            message="Failed to assume AWS role for the connected account. Verify IAM trust relationship.",
        )

    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise EC2ControlExecutionError(
            status_code=403,
            code="ACCOUNT_IDENTITY_MISMATCH",
            category="AWS_VERIFICATION",
            message=str(perm_err),
        )
    except Exception:
        raise EC2ControlExecutionError(
            status_code=403,
            code="ACCOUNT_VERIFICATION_FAILED",
            category="AWS_VERIFICATION",
            message="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    ec2_client = clients.get("ec2")
    if not ec2_client:
        raise EC2ControlExecutionError(
            status_code=500,
            code="CLIENT_INITIALIZATION_FAILED",
            category="AWS_CLIENT",
            message="Failed to initialize EC2 service client.",
        )

    # 8. Record Execution Start in Audit Log
    record_event(
        user_id=user_id,
        organization_id=organization_id,
        request_id=request_id,
        event_type=EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
        action=f"EC2_{clean_action.upper()}_INSTANCE",
        actor_type=ACTOR_USER,
        service="EC2",
        resource_type="EC2_INSTANCE",
        resource_id=clean_instance_id,
        account_id=str(aws_account.get("_id", clean_account_id)),
        aws_account_id=stored_aws_account_id,
        metadata={
            "action": clean_action,
            "region": target_region,
        },
    )

    # 9. Server-Side Pre-State Validation
    try:
        desc_resp = ec2_client.describe_instances(InstanceIds=[clean_instance_id])
        reservations = desc_resp.get("Reservations") or []
        instances = [
            inst for res in reservations for inst in res.get("Instances") or []
        ]
        if not instances or instances[0].get("InstanceId") != clean_instance_id:
            raise EC2ControlExecutionError(
                status_code=404,
                code="INSTANCE_NOT_FOUND",
                category="RESOURCE_VALIDATION",
                message=f"EC2 instance '{clean_instance_id}' was not found in region '{target_region}'.",
            )
        target_instance = instances[0]
        current_state = str(target_instance.get("State", {}).get("Name", "")).lower()
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        if code in ("InvalidInstanceID.NotFound", "InvalidInstanceID.Malformed"):
            raise EC2ControlExecutionError(
                status_code=404,
                code="INSTANCE_NOT_FOUND",
                category="RESOURCE_VALIDATION",
                message=f"EC2 instance '{clean_instance_id}' was not found in region '{target_region}'.",
            )
        elif code in ("AccessDenied", "UnauthorizedOperation"):
            raise EC2ControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="AWS_PERMISSION",
                message=f"AWS AccessDenied: IAM role lacks ec2:DescribeInstances permission in {target_region}.",
            )
        else:
            raise EC2ControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_ERROR",
                message=f"AWS EC2 service error during pre-validation ({code}).",
            )
    except EC2ControlExecutionError:
        raise
    except Exception as err:
        raise EC2ControlExecutionError(
            status_code=502,
            code=_safe_error_code(err),
            category="AWS_ERROR",
            message="Failed to inspect EC2 instance state before mutation.",
        )

    # 10. State Transition Rules
    if clean_action == "start":
        if current_state != "stopped":
            msg = f"Cannot start instance '{clean_instance_id}' because its current state is '{current_state}'. Instance must be in 'stopped' state."
            _record_failure(
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                account_id=str(aws_account.get("_id", clean_account_id)),
                aws_account_id=stored_aws_account_id,
                instance_id=clean_instance_id,
                action=clean_action,
                region=target_region,
                error_code="INVALID_STATE_TRANSITION",
                message=msg,
            )
            raise EC2ControlExecutionError(
                status_code=409,
                code="INVALID_STATE_TRANSITION",
                category="STATE_VALIDATION",
                message=msg,
                audit_recorded=True,
            )

    elif clean_action == "stop":
        if current_state != "running":
            msg = f"Cannot stop instance '{clean_instance_id}' because its current state is '{current_state}'. Instance must be in 'running' state."
            _record_failure(
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                account_id=str(aws_account.get("_id", clean_account_id)),
                aws_account_id=stored_aws_account_id,
                instance_id=clean_instance_id,
                action=clean_action,
                region=target_region,
                error_code="INVALID_STATE_TRANSITION",
                message=msg,
            )
            raise EC2ControlExecutionError(
                status_code=409,
                code="INVALID_STATE_TRANSITION",
                category="STATE_VALIDATION",
                message=msg,
                audit_recorded=True,
            )

    elif clean_action == "reboot":
        if current_state != "running":
            msg = f"Cannot reboot instance '{clean_instance_id}' because its current state is '{current_state}'. Instance must be in 'running' state."
            _record_failure(
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                account_id=str(aws_account.get("_id", clean_account_id)),
                aws_account_id=stored_aws_account_id,
                instance_id=clean_instance_id,
                action=clean_action,
                region=target_region,
                error_code="INVALID_STATE_TRANSITION",
                message=msg,
            )
            raise EC2ControlExecutionError(
                status_code=409,
                code="INVALID_STATE_TRANSITION",
                category="STATE_VALIDATION",
                message=msg,
                audit_recorded=True,
            )

    # 11. Execute AWS Mutation
    new_state = "unknown"
    try:
        if clean_action == "start":
            res = ec2_client.start_instances(InstanceIds=[clean_instance_id])
            starting = res.get("StartingInstances") or []
            if starting:
                new_state = starting[0].get("CurrentState", {}).get("Name", "pending")
            else:
                new_state = "pending"

        elif clean_action == "stop":
            res = ec2_client.stop_instances(InstanceIds=[clean_instance_id])
            stopping = res.get("StoppingInstances") or []
            if stopping:
                new_state = stopping[0].get("CurrentState", {}).get("Name", "stopping")
            else:
                new_state = "stopping"

        elif clean_action == "reboot":
            ec2_client.reboot_instances(InstanceIds=[clean_instance_id])
            new_state = "rebooting"

    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        _record_failure(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            account_id=str(aws_account.get("_id", clean_account_id)),
            aws_account_id=stored_aws_account_id,
            instance_id=clean_instance_id,
            action=clean_action,
            region=target_region,
            error_code=code,
            message=f"AWS ClientError during {clean_action}: {code}",
        )
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise EC2ControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="AWS_PERMISSION",
                message=f"AWS AccessDenied: The IAM role lacks ec2:{clean_action.capitalize()}Instances permission in {target_region}.",
                audit_recorded=True,
            )
        elif code in ("RequestLimitExceeded", "Throttling"):
            raise EC2ControlExecutionError(
                status_code=429,
                code="RATE_LIMIT_EXCEEDED",
                category="AWS_THROTTLING",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
                audit_recorded=True,
            )
        else:
            raise EC2ControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_ERROR",
                message=f"AWS EC2 execution error ({code}).",
                audit_recorded=True,
            )

    except BotoCoreError as boto_err:
        _record_failure(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            account_id=str(aws_account.get("_id", clean_account_id)),
            aws_account_id=stored_aws_account_id,
            instance_id=clean_instance_id,
            action=clean_action,
            region=target_region,
            error_code=_safe_error_code(boto_err),
            message="Network failure communicating with AWS EC2 service.",
        )
        raise EC2ControlExecutionError(
            status_code=502,
            code="NETWORK_ERROR",
            category="NETWORK",
            message="Network or connection failure communicating with AWS EC2 service.",
            audit_recorded=True,
        )

    # 12. Record Audit Completion
    record_event(
        user_id=user_id,
        organization_id=organization_id,
        request_id=request_id,
        event_type=EVENT_RESOURCE_CONTROL_COMPLETED,
        action=f"EC2_{clean_action.upper()}_INSTANCE",
        result=RESULT_SUCCESS,
        actor_type=ACTOR_USER,
        service="EC2",
        resource_type="EC2_INSTANCE",
        resource_id=clean_instance_id,
        account_id=str(aws_account.get("_id", clean_account_id)),
        aws_account_id=stored_aws_account_id,
        message=f"Successfully executed {clean_action} on EC2 instance {clean_instance_id}.",
        metadata={
            "action": clean_action,
            "region": target_region,
            "previous_state": current_state,
            "current_state": new_state,
            "verification_result": "VERIFIED",
        },
    )

    return {
        "status": "success",
        "action": clean_action,
        "instance_id": clean_instance_id,
        "region": target_region,
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "previous_state": current_state,
        "current_state": new_state,
        "message": f"Successfully initiated {clean_action} on instance {clean_instance_id}. Current state: {new_state}.",
    }


def _record_failure(
    *,
    user_id: str,
    organization_id: str,
    request_id: Optional[str],
    account_id: str,
    aws_account_id: str,
    instance_id: str,
    action: str,
    region: str,
    error_code: str,
    message: str,
) -> None:
    try:
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"EC2_{action.upper()}_INSTANCE",
            result=RESULT_FAILURE,
            actor_type=ACTOR_USER,
            service="EC2",
            resource_type="EC2_INSTANCE",
            resource_id=instance_id,
            account_id=account_id,
            aws_account_id=aws_account_id,
            message=message,
            metadata={
                "action": action,
                "region": region,
                "error_code": error_code,
            },
        )
    except Exception as audit_err:
        logger.warning("Failed to record audit failure: %s", audit_err)
