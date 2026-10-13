from __future__ import annotations

import ipaddress
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
from app.services.remediation.remediation_models import S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID


S3_BLOCK_PUBLIC_ACCESS_ACTION_ID = S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID
S3_BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
PUBLIC_ACCESS_BLOCK_CONFIGURATION = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


class S3BlockPublicAccessError(Exception):
    """Safe public error details for the S3 Block Public Access workflow."""

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


def is_valid_bucket_name(bucket_name: str) -> bool:
    if not isinstance(bucket_name, str):
        return False
    name = bucket_name.strip()
    if (
        not S3_BUCKET_NAME_PATTERN.fullmatch(name)
        or ".." in name
        or ".-" in name
        or "-." in name
        or name.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
        or name.endswith(("-s3alias", "--ol-s3", "--x-s3", "--table-s3"))
    ):
        return False
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return True
    return False


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
    request_id = metadata.get("RequestId") or metadata.get("RequestID")
    return str(request_id)[:128] if request_id else None


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
        action_id=S3_BLOCK_PUBLIC_ACCESS_ACTION_ID,
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
        resource_id=remediation.get("resource"),
        request_id=request_id,
        aws_request_id=aws_request_id,
    )


def _read_public_access_block(s3_client: Any, bucket: str, account_id: str) -> Dict[str, Any]:
    try:
        response = s3_client.get_public_access_block(
            Bucket=bucket,
            ExpectedBucketOwner=account_id,
        )
        configuration = response.get("PublicAccessBlockConfiguration") or {}
        return configuration, _aws_request_id(response)
    except ClientError as error:
        code = _aws_error_code(error)
        if code == "NoSuchPublicAccessBlockConfiguration":
            request_id = _aws_request_id(error.response)
            return {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }, request_id
        raise


def execute_s3_block_public_access(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Enable and verify S3 Block Public Access for one approved bucket."""

    action = get_default_engine().get_action(S3_BLOCK_PUBLIC_ACCESS_ACTION_ID)
    if action is None or action.service != "S3" or action.resource_type != "S3_BUCKET":
        raise S3BlockPublicAccessError(
            status_code=503,
            code="ACTION_DEFINITION_UNAVAILABLE",
            category="REGISTRY_VALIDATION",
            message="The S3 remediation action is unavailable.",
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
            action="S3 Block Public Access authorization denied",
            authorization_result="DENIED",
            confirmation_state="NOT_CONFIRMED",
            execution_state="NOT_STARTED",
            success=False,
            error_code="ROLE_NOT_ALLOWED",
            error_category="AUTHORIZATION",
        )
        raise S3BlockPublicAccessError(
            status_code=403,
            code="ROLE_NOT_ALLOWED",
            category="AUTHORIZATION",
            message="You are not authorized to execute this remediation action.",
            audit_recorded=True,
        )

    if (
        remediation.get("action_type") != S3_BLOCK_PUBLIC_ACCESS_ACTION_ID
        or action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise S3BlockPublicAccessError(
            status_code=409,
            code="ACTION_POLICY_MISMATCH",
            category="ACTION_VALIDATION",
            message="The remediation action does not satisfy the required approval policy.",
        )

    if str(remediation.get("user_id")) != str(user_id):
        raise S3BlockPublicAccessError(
            status_code=404,
            code="REMEDIATION_NOT_FOUND",
            category="TENANT_VALIDATION",
            message="Remediation not found.",
        )

    if str(remediation.get("organization_id") or "") != str(organization_id):
        raise S3BlockPublicAccessError(
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
        raise S3BlockPublicAccessError(
            status_code=409,
            code="APPROVAL_REQUIRED",
            category="APPROVAL_VALIDATION",
            message="Remediation must be approved before execution.",
        )

    if confirmed is not True:
        raise S3BlockPublicAccessError(
            status_code=409,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_VALIDATION",
            message="Explicit confirmation is required before execution.",
        )

    bucket = str(remediation.get("resource") or "").strip()
    if not is_valid_bucket_name(bucket):
        raise S3BlockPublicAccessError(
            status_code=400,
            code="INVALID_BUCKET_NAME",
            category="RESOURCE_VALIDATION",
            message="A valid S3 bucket name is required.",
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
            raise S3BlockPublicAccessError(
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
            raise S3BlockPublicAccessError(
                status_code=409,
                code="AWS_ACCOUNT_MISMATCH",
                category="ACCOUNT_VALIDATION",
                message="Remediation AWS account does not match the connected account.",
            )

        role_arn = str(account.get("role_arn") or "").strip()
        region = str(account.get("region") or "ap-south-1").strip()
        if not role_arn or not region:
            raise S3BlockPublicAccessError(
                status_code=409,
                code="AWS_CONNECTION_INCOMPLETE",
                category="ACCOUNT_VALIDATION",
                message="The connected AWS account is missing execution configuration.",
            )

        # Verify organization remediation setting for S3
        from app.models.remediation_settings import is_remediation_enabled
        if not is_remediation_enabled(organization_id, str(remediation.get("account_id") or ""), "s3"):
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action="S3 Block Public Access authorization denied (setting disabled)",
                authorization_result="DENIED",
                confirmation_state="CONFIRMED",
                execution_state="NOT_STARTED",
                success=False,
                error_code="REMEDIATION_SETTING_DISABLED",
                error_category="GOVERNANCE",
            )
            raise S3BlockPublicAccessError(
                status_code=403,
                code="REMEDIATION_SETTING_DISABLED",
                category="GOVERNANCE",
                message="Remediation setting is disabled for S3 for this account.",
                audit_recorded=True,
            )

        session = assume_aws_role(
            role_arn=role_arn,
            region=region,
            session_name=f"CloudGuardAI-S3BPA-{str(remediation.get('_id', ''))[:24]}",
        )
        verify_aws_account(session, expected_account_id)

        bucket_location_client = session.client(
            "s3",
            region_name="us-east-1",
            config=AWS_CONFIG,
        )
        location_response = bucket_location_client.get_bucket_location(
            Bucket=bucket,
            ExpectedBucketOwner=expected_account_id,
        )
        aws_request_id = _aws_request_id(location_response)
        bucket_region = location_response.get("LocationConstraint") or "us-east-1"
        if bucket_region == "EU":
            bucket_region = "eu-west-1"

        s3_client = session.client(
            "s3",
            region_name=bucket_region,
            config=AWS_CONFIG,
        )
        before_configuration, before_request_id = _read_public_access_block(
            s3_client,
            bucket,
            expected_account_id,
        )
        aws_request_id = before_request_id or aws_request_id

        if not transition_to_executing(
            remediation_id=remediation["_id"],
            user_id=user_id,
        ):
            raise S3BlockPublicAccessError(
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
            action="S3 Block Public Access execution started",
            execution_state=STATUS_EXECUTING,
            verification_result="PENDING",
            aws_request_id=aws_request_id,
        )
        if not start_audit:
            raise S3BlockPublicAccessError(
                status_code=503,
                code="AUDIT_UNAVAILABLE",
                category="AUDIT_FAILURE",
                message="Execution could not start because the audit event could not be recorded.",
            )

        mutation_response = s3_client.put_public_access_block(
            Bucket=bucket,
            ExpectedBucketOwner=expected_account_id,
            PublicAccessBlockConfiguration=PUBLIC_ACCESS_BLOCK_CONFIGURATION,
        )
        aws_request_id = _aws_request_id(mutation_response) or aws_request_id

        verified_configuration, verification_request_id = _read_public_access_block(
            s3_client,
            bucket,
            expected_account_id,
        )
        aws_request_id = verification_request_id or aws_request_id
        verified = all(
            verified_configuration.get(flag) is True
            for flag in PUBLIC_ACCESS_BLOCK_CONFIGURATION
        )
        if not verified:
            raise S3BlockPublicAccessError(
                status_code=502,
                code="PUBLIC_ACCESS_VERIFICATION_FAILED",
                category="AWS_STATE_VERIFICATION",
                message="S3 Block Public Access could not be verified as fully enabled.",
            )

        after_state = {
            "success": True,
            "resource_id": bucket,
            "public_access_block": verified_configuration,
        }
        verification = {
            "verified": True,
            "expected_configuration": PUBLIC_ACCESS_BLOCK_CONFIGURATION,
            "observed_configuration": verified_configuration,
        }
        if not update_execution_result(
            remediation["_id"],
            user_id,
            after_state=after_state,
            verification=verification,
        ):
            raise S3BlockPublicAccessError(
                status_code=500,
                code="RESULT_PERSISTENCE_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="S3 state was verified but the remediation result could not be saved.",
            )
        if not transition_to_completed(remediation["_id"], user_id):
            raise S3BlockPublicAccessError(
                status_code=500,
                code="COMPLETION_TRANSITION_FAILED",
                category="WORKFLOW_PERSISTENCE",
                message="S3 state was verified but the remediation could not be completed.",
            )

        completion_audit = _record_event(
            remediation=remediation,
            user_id=user_id,
            organization_id=organization_id,
            request_id=request_id,
            event_type=EVENT_REMEDIATION_COMPLETED,
            action="S3 Block Public Access execution completed",
            execution_state=STATUS_COMPLETED,
            success=True,
            verification_result="VERIFIED_ENABLED",
            aws_request_id=aws_request_id,
        )

        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "remediation_id": remediation["_id"],
            "action_id": S3_BLOCK_PUBLIC_ACCESS_ACTION_ID,
            "service": "S3",
            "resource_id": bucket,
            "aws_account_id": expected_account_id,
            "verification": verification,
            "audit_recorded": bool(completion_audit),
        }
    except S3BlockPublicAccessError as error:
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
                    action="S3 Block Public Access execution failed",
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
                    action="S3 Block Public Access attempt failed before mutation",
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
            if error_code in {"AccessDenied", "AccessDeniedException", "403"}:
                error_category = "AWS_AUTHORIZATION"
                status_code = 403
                public_message = "The assumed role cannot access this S3 bucket or configuration."
            elif error_code in {"NoSuchBucket", "NotFound"}:
                error_category = "RESOURCE_VALIDATION"
                status_code = 404
                public_message = "The S3 bucket was not found in the connected AWS account."
            else:
                error_category = "AWS_API"
                status_code = 502
                public_message = "The S3 remediation could not be completed."
        elif isinstance(error, PermissionError):
            error_code = "AWS_ACCOUNT_MISMATCH"
            error_category = "ACCOUNT_VALIDATION"
            status_code = 403
            public_message = "The assumed AWS role does not belong to the connected account."
        else:
            error_category = "AWS_API"
            status_code = 502 if execution_started else 503
            public_message = "The S3 remediation could not be completed."

        if isinstance(error, ClientError):
            aws_request_id = _aws_request_id(error.response) or aws_request_id
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
            action="S3 Block Public Access execution failed" if execution_started else "S3 Block Public Access validation failed",
            execution_state=STATUS_FAILED if execution_started else "NOT_STARTED",
            confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED",
            success=False,
            error_code=error_code,
            error_category=error_category,
            verification_result="FAILED" if execution_started else "NOT_RUN",
            aws_request_id=aws_request_id,
        )
        raise S3BlockPublicAccessError(
            status_code=status_code,
            code=error_code,
            category=error_category,
            message=public_message,
            audit_recorded=True,
        ) from None
