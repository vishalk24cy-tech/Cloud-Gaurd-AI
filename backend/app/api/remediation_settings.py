# ============================================================
# CloudGuardAI - Remediation Settings API Routes
# Phase 10: Step 2 - Per-Organization & Per-Account Settings API
# ============================================================

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict

from app.database.connection import db
from app.middleware.auth_middleware import verify_token
from app.models.aws_account import get_account
from app.models.remediation_settings import (
    DEFAULT_SERVICES,
    get_remediation_settings,
    update_remediation_settings,
)

logger = logging.getLogger("cloudguardai.remediation_settings_api")

router = APIRouter(tags=["Remediation Settings"])


def _safe_string(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


class RemediationSettingsUpdateRequest(BaseModel):
    """
    Request model for partial updates to remediation service toggles.
    Only recognized service keys are allowed; all others are strictly forbidden.
    Strict boolean types are enforced to reject non-boolean values.
    """
    model_config = ConfigDict(extra="forbid", strict=True)

    ec2: Optional[bool] = None
    s3: Optional[bool] = None
    vpc: Optional[bool] = None
    rds: Optional[bool] = None
    iam: Optional[bool] = None
    cloudtrail: Optional[bool] = None


def _resolve_authenticated_member(current_user: Any) -> tuple[str, str, str]:
    """
    Resolves authenticated user ID, organization ID, and verified organization role.
    Fails closed if organization context is missing, membership is not found,
    or membership is not active.
    """
    if isinstance(current_user, dict):
        user_id = str(current_user.get("_id") or current_user.get("id") or current_user.get("user_id") or "")
        organization_id = _safe_string(current_user.get("organization") or current_user.get("organization_id"))
    else:
        user_id = str(getattr(current_user, "_id", None) or getattr(current_user, "id", None) or getattr(current_user, "user_id", None) or "")
        organization_id = _safe_string(getattr(current_user, "organization", None) or getattr(current_user, "organization_id", None))

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization context is required.",
        )

    try:
        member = db.organization_members.find_one({
            "organization_id": organization_id,
            "user_id": user_id,
        })

        if not member:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership not found. Access denied.",
            )

        status_val = _safe_string(member.get("status")).lower()
        if status_val in ("inactive", "revoked", "suspended", "removed"):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Organization membership is {status_val}. Access denied.",
            )

        if status_val != "active":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Organization membership is not active. Access denied.",
            )

        role = _safe_string(member.get("role")).lower() or "viewer"
        return user_id, organization_id, role
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Database error resolving organization membership: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error resolving organization membership.",
        )


def _get_settings_handler(account_id: str, current_user: Dict[str, Any]) -> Dict[str, Any]:
    """Internal handler for retrieving remediation settings."""
    user_id, organization_id, _ = _resolve_authenticated_member(current_user)
    clean_account_id = _safe_string(account_id)

    # Validate that AWS account belongs to organization
    try:
        aws_account = get_account(clean_account_id, organization_id=organization_id)
        if not aws_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connected AWS Account not found for this organization.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Database error validating AWS account for settings lookup: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error validating AWS account ownership.",
        )

    try:
        settings = get_remediation_settings(organization_id, clean_account_id)
    except Exception as exc:
        logger.error("Database error fetching remediation settings: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error retrieving remediation settings.",
        )

    return {
        "status": "success",
        "organization_id": organization_id,
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": str(aws_account.get("aws_account_id") or ""),
        "services": settings.get("services", DEFAULT_SERVICES.copy()),
        "exists": settings.get("exists", False),
        "updated_at": settings.get("updated_at"),
        "updated_by": settings.get("updated_by"),
    }


def _update_settings_handler(
    account_id: str,
    payload: RemediationSettingsUpdateRequest,
    current_user: Dict[str, Any],
) -> Dict[str, Any]:
    """Internal handler for updating remediation settings."""
    user_id, organization_id, role = _resolve_authenticated_member(current_user)
    clean_account_id = _safe_string(account_id)

    # Require Owner or Admin role in active organization membership
    if role not in ("owner", "admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organization Owners and Admins can update remediation settings.",
        )

    # Validate that AWS account belongs to organization and is connected
    try:
        aws_account = get_account(clean_account_id, organization_id=organization_id)
        if not aws_account:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connected AWS Account not found for this organization.",
            )
        if aws_account.get("status") != "connected":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot update remediation settings for a disconnected AWS account.",
            )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Database error validating AWS account for settings update: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error validating AWS account ownership.",
        )

    # Extract non-null service toggles
    toggles = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not toggles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one service setting toggle must be provided.",
        )

    try:
        updated = update_remediation_settings(
            organization_id=organization_id,
            account_id=str(aws_account.get("_id", clean_account_id)),
            service_toggles=toggles,
            user_id=user_id,
        )
    except Exception as exc:
        logger.error("Database error updating remediation settings: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error updating remediation settings.",
        )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to update remediation settings.",
        )

    return {
        "status": "success",
        "message": "Remediation settings updated successfully.",
        "organization_id": organization_id,
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": str(aws_account.get("aws_account_id") or ""),
        "services": updated.get("services", DEFAULT_SERVICES.copy()),
        "updated_at": updated.get("updated_at"),
        "updated_by": updated.get("updated_by"),
    }


# ============================================================
# API Route Endpoints
# (Supporting both with and without /api prefix)
# ============================================================

@router.get("/api/remediation/settings/{account_id}")
@router.get("/remediation/settings/{account_id}")
def get_settings_endpoint(
    account_id: str,
    current_user=Depends(verify_token),
):
    """
    Retrieve remediation governance settings for a connected AWS account.
    Fails closed: Missing settings default all six services to disabled (false).
    """
    return _get_settings_handler(account_id, current_user)


@router.put("/api/remediation/settings/{account_id}")
@router.put("/remediation/settings/{account_id}")
def update_settings_endpoint(
    account_id: str,
    payload: RemediationSettingsUpdateRequest,
    current_user=Depends(verify_token),
):
    """
    Update remediation governance settings for a connected AWS account.
    Restricted to active organization Owners and Admins only.
    """
    return _update_settings_handler(account_id, payload, current_user)
