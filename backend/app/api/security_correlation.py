# ============================================================
# CloudGuardAI - Security Correlation API
# Phase 2 / Step 3
# Finding <-> Graph <-> Remediation Correlation
# ============================================================

from fastapi import APIRouter, Depends, HTTPException, Query

from app.middleware.auth_middleware import verify_token
from app.models.aws_account import get_account, get_account_by_aws_id
from app.services.security_correlation_service import (
    correlate_finding,
    correlate_resource,
)


router = APIRouter(
    prefix="/security-correlation",
    tags=["Security Correlation"],
)


def _get_user_id(current_user):
    if isinstance(current_user, dict):
        user_id = (
            current_user.get("_id")
            or current_user.get("id")
            or current_user.get("user_id")
        )
    else:
        user_id = (
            getattr(current_user, "_id", None)
            or getattr(current_user, "id", None)
            or getattr(current_user, "user_id", None)
        )

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user not found",
        )

    return str(user_id)


def _clean(value):
    return str(value).strip() if value is not None else ""


def _verify_account(user_id: str, account_id: str):
    account_id = _clean(account_id)

    if not account_id:
        raise HTTPException(
            status_code=400,
            detail="account_id is required",
        )

    # Correlation clients may have either the CloudGuardAI internal
    # account ID or the real 12-digit AWS account ID. Resolve both
    # through the authenticated tenant boundary; never search globally.
    account = get_account(
        account_id,
        user_id=user_id,
    )

    if not account and account_id.isdigit() and len(account_id) == 12:
        account = get_account_by_aws_id(
            account_id,
            user_id=user_id,
        )

    if not account:
        raise HTTPException(
            status_code=404,
            detail="AWS account not found for the authenticated tenant",
        )

    return account


@router.get("/resource/{resource_id}")
def resource_correlation(
    resource_id: str,
    account_id: str = Query(...),
    current_user=Depends(verify_token),
):
    """
    Correlate one AWS graph resource with its findings,
    verified relationships, and remediation workflow.
    """
    user_id = _get_user_id(current_user)
    account = _verify_account(user_id, account_id)

    resource_id = _clean(resource_id)

    if not resource_id:
        raise HTTPException(
            status_code=400,
            detail="resource_id is required",
        )

    try:
        result = correlate_resource(
            user_id=user_id,
            account_id=str(account.get("_id")),
            resource_id=resource_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception as exc:
        print(
            "[ERROR] Security resource correlation failed: "
            f"{exc}"
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve resource security correlation",
        )

    return result


@router.get("/finding/{finding_id}")
def finding_correlation(
    finding_id: str,
    account_id: str = Query(...),
    current_user=Depends(verify_token),
):
    """
    Correlate one finding with its graph resource and
    remediation workflow.
    """
    user_id = _get_user_id(current_user)
    account = _verify_account(user_id, account_id)

    finding_id = _clean(finding_id)

    if not finding_id:
        raise HTTPException(
            status_code=400,
            detail="finding_id is required",
        )

    try:
        result = correlate_finding(
            user_id=user_id,
            account_id=str(account.get("_id")),
            finding_id=finding_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )
    except Exception as exc:
        print(
            "[ERROR] Security finding correlation failed: "
            f"{exc}"
        )
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve finding security correlation",
        )

    if result.get("status") == "not_found":
        raise HTTPException(
            status_code=404,
            detail="Finding not found for the specified AWS account",
        )

    return result


@router.get("/health")
def correlation_health(
    current_user=Depends(verify_token),
):
    """
    Authenticated capability check.
    No AWS access.
    """
    _get_user_id(current_user)

    return {
        "status": "success",
        "engine_version": "1.0",
        "capabilities": {
            "finding_graph_correlation": True,
            "finding_remediation_correlation": True,
            "resource_remediation_correlation": True,
            "tenant_isolation": True,
            "account_isolation": True,
            "read_only": True,
            "aws_mutation": False,
        },
    }
