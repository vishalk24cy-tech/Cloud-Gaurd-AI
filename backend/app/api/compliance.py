# ============================================================
# CloudGuardAI - Compliance API 2.1
# Production / Commercial SaaS
# ============================================================
# Security:
#   - JWT authentication required
#   - Tenant-scoped scan access
#   - Tenant-scoped compliance history
#   - Account/framework filtering
#   - Completed-scan evidence only
#   - Version/coverage/confidence exposed
#   - No false compliance claims when not assessed
#   - Snapshot persistence is observable
# ============================================================

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.middleware.auth_middleware import verify_token
from app.services.scan_service import get_all_scans
from app.services.compliance_engine import calculate_compliance
from app.models.compliance import (
    FRAMEWORK_CIS,
    FRAMEWORK_NIST,
    FRAMEWORK_PCI,
    SUPPORTED_FRAMEWORKS,
    create_compliance_snapshot,
    get_compliance_history,
    get_latest_compliance_snapshot,
    get_compliance_trend,
    get_compliance_statistics,
)

router = APIRouter()

STATUS_NOT_ASSESSED = "NOT_ASSESSED"

COMPLIANCE_FRAMEWORKS = [
    FRAMEWORK_CIS,
    FRAMEWORK_NIST,
    FRAMEWORK_PCI,
]


def _get_user_id(current_user):
    if not current_user:
        raise HTTPException(status_code=401, detail="Authenticated user not found")

    user_id = current_user.get("_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="Authenticated user ID not found")

    return str(user_id)


def _clean(value):
    return "" if value is None else str(value).strip()


def _validate_framework(framework):
    if not framework:
        return None

    framework = _clean(framework)
    if framework not in SUPPORTED_FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail="Invalid framework. Supported values: CIS_AWS_Benchmark, NIST_CSF, PCI_DSS",
        )

    return framework


def _get_scan_id(scan):
    if not isinstance(scan, dict):
        return ""
    return _clean(scan.get("_id", scan.get("scan_id", "")))


def _get_account_id(scan):
    if not isinstance(scan, dict):
        return ""
    return _clean(scan.get("account_id"))


def _get_aws_account_id(scan):
    if not isinstance(scan, dict):
        return ""
    return _clean(scan.get("aws_account_id"))


def _get_account_name(scan):
    if not isinstance(scan, dict):
        return ""
    return _clean(scan.get("account_name", scan.get("account", "")))


def _is_completed_scan(scan):
    """
    Only completed scans can become compliance evidence.

    Missing status is accepted only for legacy scan documents.
    """
    if not isinstance(scan, dict):
        return False

    if "status" not in scan:
        return True

    return _clean(scan.get("status")).upper() in {
        "COMPLETED",
        "SUCCESS",
        "FINISHED",
    }


def _get_scan_sort_value(scan):
    """
    Normalize the timestamp used to choose the newest scan.
    ISO strings sort correctly when generated consistently.
    """
    return _clean(
        scan.get("scan_time")
        or scan.get("completed_at")
        or scan.get("updated_at")
        or scan.get("created_at")
    )


def _get_latest_completed_scan(scans, account_id=None):
    """
    Return the newest completed scan already scoped to the tenant.
    """
    account_id = _clean(account_id)

    candidates = []
    for scan in scans or []:
        if not isinstance(scan, dict):
            continue

        if account_id and _get_account_id(scan) != account_id:
            continue

        if _is_completed_scan(scan):
            candidates.append(scan)

    candidates.sort(key=_get_scan_sort_value, reverse=True)
    return candidates[0] if candidates else None


def _empty_compliance_response():
    return {
        "compliance_score": 0,
        "status": STATUS_NOT_ASSESSED,
        "assessment": {
            "state": STATUS_NOT_ASSESSED,
            "has_evaluated_controls": False,
            "evidence_sufficient": False,
        },
        "assessment_coverage": {
            "assessed_controls": 0,
            "catalog_controls": 0,
            "coverage_percent": 0,
        },
        "evidence_confidence": {
            "overall": "UNKNOWN",
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "frameworks": {},
        "summary": {
            "frameworks_evaluated": 0,
            "total_controls": 0,
            "passed": 0,
            "failed": 0,
            "review": 0,
        },
        "controls": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "review": 0,
        },
        "passed_controls": [],
        "failed_controls": [],
        "review_controls": [],
    }


def _persist_framework_snapshots(
    *,
    user_id,
    account_id,
    aws_account_id,
    account_name,
    scan_id,
    compliance,
):
    """
    Persist one versioned snapshot for every supported framework.

    Persistence failures are returned individually so the API can
    distinguish successful evaluation from incomplete history storage.
    """
    errors = []

    for framework in COMPLIANCE_FRAMEWORKS:
        try:
            create_compliance_snapshot(
                user_id=user_id,
                account_id=account_id,
                aws_account_id=aws_account_id,
                account_name=account_name,
                scan_id=scan_id,
                framework=framework,
                compliance_result=compliance,
            )
        except Exception as exc:
            print(
                f"[WARNING] Compliance snapshot persistence failed "
                f"for {framework}: {exc}"
            )
            errors.append(framework)

    return errors


@router.get("/")
def compliance_dashboard(
    account_id: Optional[str] = Query(default=None),
    current_user: dict = Depends(verify_token),
):
    """
    Return the authenticated tenant's latest compliance posture.

    Evidence source:
        latest completed tenant-owned scan
    """
    user_id = _get_user_id(current_user)
    requested_account_id = _clean(account_id) or None

    try:
        scans = get_all_scans(user_id)
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to retrieve scan history")

    if not scans:
        return {
            "status": "success",
            "message": "No scan data available",
            "account": "",
            "account_id": requested_account_id or "",
            "aws_account_id": "",
            "scan_id": "",
            "compliance": _empty_compliance_response(),
        }

    latest_scan = _get_latest_completed_scan(
        scans,
        account_id=requested_account_id,
    )

    if not latest_scan:
        return {
            "status": "success",
            "message": "No completed scan available",
            "account": "",
            "account_id": requested_account_id or "",
            "aws_account_id": "",
            "scan_id": "",
            "compliance": _empty_compliance_response(),
        }

    findings = latest_scan.get("findings", [])
    if not isinstance(findings, list):
        findings = []

    try:
        compliance = calculate_compliance(findings)
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to calculate compliance posture",
        )

    scan_id = _get_scan_id(latest_scan)
    resolved_account_id = _get_account_id(latest_scan)
    aws_account_id = _get_aws_account_id(latest_scan)
    account_name = _get_account_name(latest_scan)

    snapshot_errors = _persist_framework_snapshots(
        user_id=user_id,
        account_id=resolved_account_id,
        aws_account_id=aws_account_id,
        account_name=account_name,
        scan_id=scan_id,
        compliance=compliance,
    )

    response = {
        "status": "success",
        "account": account_name,
        "account_id": resolved_account_id,
        "aws_account_id": aws_account_id,
        "scan_id": scan_id,
        "scan_time": latest_scan.get(
            "scan_time",
            latest_scan.get("completed_at", latest_scan.get("created_at")),
        ),
        "compliance": compliance,
        "history_persistence": {
            "requested_frameworks": len(COMPLIANCE_FRAMEWORKS),
            "persisted_frameworks": len(COMPLIANCE_FRAMEWORKS) - len(snapshot_errors),
            "failed_frameworks": snapshot_errors,
            "complete": not snapshot_errors,
        },
    }

    if snapshot_errors:
        response["history_warning"] = (
            "Compliance was calculated successfully, but one or more "
            "history snapshots could not be persisted."
        )

    return response


@router.get("/history")
def compliance_history(
    framework: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    skip: int = Query(default=0, ge=0, le=100000),
    current_user: dict = Depends(verify_token),
):
    user_id = _get_user_id(current_user)
    framework = _validate_framework(framework)

    try:
        history = get_compliance_history(
            user_id=user_id,
            account_id=_clean(account_id) or None,
            framework=framework,
            limit=limit,
            skip=skip,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve compliance history",
        )

    return {
        "status": "success",
        "count": len(history),
        "limit": limit,
        "skip": skip,
        "history": history,
    }


@router.get("/latest")
def latest_compliance(
    framework: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    current_user: dict = Depends(verify_token),
):
    user_id = _get_user_id(current_user)
    framework = _validate_framework(framework)

    try:
        snapshot = get_latest_compliance_snapshot(
            user_id=user_id,
            account_id=_clean(account_id) or None,
            framework=framework,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve latest compliance",
        )

    return {
        "status": "success",
        "snapshot": snapshot,
    }


@router.get("/trend")
def compliance_trend(
    framework: str = Query(default=FRAMEWORK_CIS),
    account_id: Optional[str] = Query(default=None),
    limit: int = Query(default=30, ge=1, le=200),
    current_user: dict = Depends(verify_token),
):
    user_id = _get_user_id(current_user)
    framework = _validate_framework(framework)

    try:
        trend = get_compliance_trend(
            user_id=user_id,
            framework=framework,
            account_id=_clean(account_id) or None,
            limit=limit,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve compliance trend",
        )

    return {
        "status": "success",
        "framework": framework,
        "count": len(trend),
        "trend": trend,
    }


@router.get("/statistics")
def compliance_statistics(
    account_id: Optional[str] = Query(default=None),
    current_user: dict = Depends(verify_token),
):
    user_id = _get_user_id(current_user)

    try:
        statistics = get_compliance_statistics(
            user_id=user_id,
            account_id=_clean(account_id) or None,
        )
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to retrieve compliance statistics",
        )

    return {
        "status": "success",
        "statistics": statistics,
    }
