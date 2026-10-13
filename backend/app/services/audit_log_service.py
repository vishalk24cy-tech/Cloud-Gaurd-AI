# ============================================================
# CloudGuardAI - Audit Log Service
# Phase 3 / Step 1
# Production / Commercial SaaS
# ============================================================

import logging
from typing import Any, Dict, Optional

from app.models.audit_log import (
    ACTOR_AWS,
    ACTOR_SYSTEM,
    ACTOR_USER,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_INFO,
    RESULT_SUCCESS,
    create_audit_log,
    get_audit_log,
    get_audit_statistics,
    get_finding_audit_history,
    get_remediation_audit_history,
    get_user_audit_logs,
    verify_audit_integrity,
)
from app.services.remediation.remediation_engine import get_default_engine

_logger = logging.getLogger("cloudguardai.audit")


def record_event(
    *,
    user_id: Any = None,
    actor_id: Any = None,
    event_type: str,
    action: str,
    result: str = RESULT_INFO,
    actor_type: str = ACTOR_SYSTEM,
    organization_id: Any = None,
    account_id: Any = None,
    aws_account_id: Any = None,
    finding_id: Any = None,
    remediation_id: Any = None,
    action_id: Any = None,
    resource_id: Any = None,
    service: Any = None,
    resource_type: Any = None,
    request_id: Any = None,
    ip_address: Any = None,
    user_agent: Any = None,
    message: Any = None,
    details: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Single service entry point for audit recording.

    Callers should pass trusted server-side identity/context.
    """
    effective_user_id = user_id or actor_id
    effective_metadata = {}
    if metadata:
        effective_metadata.update(metadata)
    if details:
        effective_metadata.update(details)

    return create_audit_log(
        user_id=effective_user_id,
        event_type=event_type,
        action=action,
        result=result,
        actor_type=actor_type,
        organization_id=organization_id,
        account_id=account_id,
        aws_account_id=aws_account_id,
        finding_id=finding_id,
        remediation_id=remediation_id,
        action_id=action_id,
        resource_id=resource_id,
        service=service,
        resource_type=resource_type,
        request_id=request_id,
        ip_address=ip_address,
        user_agent=user_agent,
        message=message,
        metadata=effective_metadata,
    )


def record_success(**kwargs) -> Dict[str, Any]:
    kwargs["result"] = RESULT_SUCCESS
    return record_event(**kwargs)


def record_failure(**kwargs) -> Dict[str, Any]:
    kwargs["result"] = RESULT_FAILURE
    return record_event(**kwargs)


def record_denied(**kwargs) -> Dict[str, Any]:
    kwargs["result"] = RESULT_DENIED
    return record_event(**kwargs)


def record_info(**kwargs) -> Dict[str, Any]:
    kwargs["result"] = RESULT_INFO
    return record_event(**kwargs)


def record_remediation_event(
    *,
    user_id: Any,
    organization_id: Any,
    event_type: str,
    action_id: str,
    action: str,
    authorization_result: Optional[str] = None,
    confirmation_state: Optional[str] = None,
    approval_state: Optional[str] = None,
    execution_state: Optional[str] = None,
    success: Optional[bool] = None,
    error_code: Optional[str] = None,
    error_category: Optional[str] = None,
    verification_result: Optional[str] = None,
    aws_request_id: Optional[str] = None,
    account_id: Any = None,
    aws_account_id: Any = None,
    finding_id: Any = None,
    remediation_id: Any = None,
    resource_id: Any = None,
    request_id: Any = None,
) -> Optional[Dict[str, Any]]:
    """Record remediation context in the shared audit log.

    Emit execution events only when execution actually starts or completes.
    Error details are restricted to codes/categories; raw exception messages
    and credential-bearing payloads must not be passed here.
    """

    normalized_authorization = (
        str(authorization_result).strip().upper()
        if authorization_result is not None
        else None
    )
    if normalized_authorization not in {None, "AUTHORIZED", "DENIED"}:
        raise ValueError("Unsupported remediation authorization result")

    action_spec = get_default_engine().get_action(action_id)
    if action_spec is None:
        raise ValueError("Unsupported remediation action")

    error_information = {
        key: str(value).strip()[:100]
        for key, value in (
            ("code", error_code),
            ("category", error_category),
        )
        if value is not None and str(value).strip()
    }
    metadata = {
        "authorization_result": normalized_authorization,
        "confirmation_state": confirmation_state,
        "approval_state": approval_state,
        "execution_state": execution_state,
        "success": success,
        "error_information": error_information or None,
        "verification_result": verification_result,
        "aws_request_id": (
            str(aws_request_id).strip()[:128]
            if aws_request_id
            else None
        ),
    }
    result = (
        RESULT_DENIED
        if normalized_authorization == "DENIED"
        else RESULT_SUCCESS
        if success is True
        else RESULT_FAILURE
        if success is False
        else RESULT_INFO
    )

    try:
        return record_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=event_type,
            action=action,
            result=result,
            actor_type=ACTOR_USER,
            account_id=account_id,
            aws_account_id=aws_account_id,
            finding_id=finding_id,
            remediation_id=remediation_id,
            action_id=action_id,
            resource_id=resource_id,
            service=action_spec.service,
            resource_type=action_spec.resource_type,
            request_id=request_id,
            metadata=metadata,
        )
    except Exception:
        _logger.error(
            "REMEDIATION_AUDIT_WRITE_FAILED event_type=%s user_id=%s",
            event_type,
            user_id,
        )
        return None


__all__ = [
    "ACTOR_AWS",
    "ACTOR_SYSTEM",
    "ACTOR_USER",
    "RESULT_DENIED",
    "RESULT_FAILURE",
    "RESULT_INFO",
    "RESULT_SUCCESS",
    "get_audit_log",
    "get_audit_statistics",
    "get_finding_audit_history",
    "get_remediation_audit_history",
    "get_user_audit_logs",
    "record_denied",
    "record_event",
    "record_failure",
    "record_info",
    "record_remediation_event",
    "record_success",
    "verify_audit_integrity",
]
