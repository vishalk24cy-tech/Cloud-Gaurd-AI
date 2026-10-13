# ============================================================
# CloudGuardAI - Audit History API
# Phase 3 / Step 1B
# Production / Commercial SaaS
# ============================================================

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.middleware.auth_middleware import verify_token
from app.models.audit_log import (
    ALLOWED_EVENT_TYPES,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_INFO,
    RESULT_SUCCESS,
    get_audit_log,
    get_audit_statistics,
    get_finding_audit_history,
    get_remediation_audit_history,
    get_user_audit_logs,
    verify_audit_integrity,
)


router = APIRouter(
    prefix="/audit",
)


# ============================================================
# HELPERS
# ============================================================


def _user_id(current_user: dict) -> str:
    value = current_user.get("_id") if isinstance(current_user, dict) else None

    if value is None:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user identity is unavailable",
        )

    return str(value)


def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None

    cleaned = str(value).strip()
    return cleaned or None


def _normalize_event_type(value: Optional[str]) -> Optional[str]:
    value = _clean_optional(value)

    if not value:
        return None

    normalized = value.upper()

    if normalized not in ALLOWED_EVENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported audit event type",
        )

    return normalized


def _normalize_result(value: Optional[str]) -> Optional[str]:
    value = _clean_optional(value)

    if not value:
        return None

    normalized = value.upper()

    allowed = {
        RESULT_SUCCESS,
        RESULT_FAILURE,
        RESULT_DENIED,
        RESULT_INFO,
    }

    if normalized not in allowed:
        raise HTTPException(
            status_code=400,
            detail="Unsupported audit result",
        )

    return normalized


# ============================================================
# AUDIT HISTORY
# ============================================================


@router.get("/")
def list_audit_logs(
    account_id: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    result: Optional[str] = Query(default=None),
    finding_id: Optional[str] = Query(default=None),
    remediation_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    skip: int = Query(default=0, ge=0),
    current_user: dict = Depends(verify_token),
):
    """
    Return tenant-scoped audit history.

    The user identity is always taken from the authenticated JWT.
    Clients cannot select another tenant through the query parameters.
    """

    user_id = _user_id(current_user)

    return {
        "status": "success",
        **get_user_audit_logs(
            user_id=user_id,
            account_id=_clean_optional(account_id),
            event_type=_normalize_event_type(event_type),
            result=_normalize_result(result),
            finding_id=_clean_optional(finding_id),
            remediation_id=_clean_optional(remediation_id),
            limit=limit,
            skip=skip,
        ),
    }


# ============================================================
# STATISTICS
# ============================================================


@router.get("/statistics")
def audit_statistics(
    account_id: Optional[str] = Query(default=None),
    current_user: dict = Depends(verify_token),
):
    """Return tenant-scoped audit statistics."""

    user_id = _user_id(current_user)

    return {
        "status": "success",
        "statistics": get_audit_statistics(
            user_id=user_id,
            account_id=_clean_optional(account_id),
        ),
    }


# ============================================================
# FINDING HISTORY
# ============================================================


@router.get("/finding/{finding_id}")
def finding_audit_history(
    finding_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(verify_token),
):
    """Return tenant-scoped audit history for one finding."""

    finding_id = _clean_optional(finding_id)

    if not finding_id:
        raise HTTPException(
            status_code=400,
            detail="finding_id is required",
        )

    return {
        "status": "success",
        "finding_id": finding_id,
        **get_finding_audit_history(
            user_id=_user_id(current_user),
            finding_id=finding_id,
            limit=limit,
        ),
    }


# ============================================================
# REMEDIATION HISTORY
# ============================================================


@router.get("/remediation/{remediation_id}")
def remediation_audit_history(
    remediation_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    current_user: dict = Depends(verify_token),
):
    """Return tenant-scoped audit history for one remediation."""

    remediation_id = _clean_optional(remediation_id)

    if not remediation_id:
        raise HTTPException(
            status_code=400,
            detail="remediation_id is required",
        )

    return {
        "status": "success",
        "remediation_id": remediation_id,
        **get_remediation_audit_history(
            user_id=_user_id(current_user),
            remediation_id=remediation_id,
            limit=limit,
        ),
    }


# ============================================================
# SINGLE AUDIT EVENT
# ============================================================


@router.get("/{audit_id}")
def audit_details(
    audit_id: str,
    current_user: dict = Depends(verify_token),
):
    """Return one tenant-scoped audit event."""

    audit = get_audit_log(
        user_id=_user_id(current_user),
        audit_id=audit_id,
    )

    if audit is None:
        raise HTTPException(
            status_code=404,
            detail="Audit event not found",
        )

    return {
        "status": "success",
        "audit": audit,
    }


# ============================================================
# INTEGRITY VERIFICATION
# ============================================================


@router.get("/{audit_id}/integrity")
def audit_integrity(
    audit_id: str,
    current_user: dict = Depends(verify_token),
):
    """
    Verify the tamper-evident integrity fingerprint of one audit event.

    This verifies the stored event against its recorded hash. It does not
    claim WORM/immutable storage guarantees.
    """

    result = verify_audit_integrity(
        user_id=_user_id(current_user),
        audit_id=audit_id,
    )

    if not result.get("audit_id"):
        raise HTTPException(
            status_code=404,
            detail="Audit event not found",
        )

    return {
        "status": "success",
        "integrity": result,
    }
