# ============================================================
# CloudGuardAI - Scan Remediation Reconciler
# Phase 8: Authoritative Scan-Driven Finding Resolution
# ============================================================

from datetime import datetime
import logging
from typing import Any, Dict, List, Optional, Set

from bson import ObjectId

from app.models.audit_log import (
    EVENT_FINDING_RESOLVED,
    RESULT_SUCCESS,
)
from app.models.finding import (
    WORKFLOW_OPEN,
    WORKFLOW_IN_PROGRESS,
    WORKFLOW_RESOLVED,
    findings_collection,
)
from app.models.remediation import (
    STATUS_COMPLETED,
    remediations_collection,
)
from app.services.audit_log_service import record_event

logger = logging.getLogger("cloudguardai.scan_reconciler")


def _parse_datetime(value: Any) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            return None
    return None


def reconcile_scan_remediations(
    *,
    account_id: str,
    user_id: str,
    scan_id: str,
    scan_started_at: datetime,
    scan_completed_at: datetime,
    detected_finding_ids: Set[str],
    evaluated_services: Optional[Set[str]] = None,
    uninspected_resources: Optional[Set[str]] = None,
    organization_id: Optional[str] = None,
    aws_account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Authoritatively resolve findings that:
    1. Belong to this exact tenant (user_id / organization_id) and connected AWS account (account_id).
    2. Are currently in an unresolved workflow status (OPEN or IN_PROGRESS).
    3. Have an associated remediation proposal in COMPLETED status.
    4. Were executed prior to or at the start of this scan (executed_at <= scan_started_at).
    5. The relevant AWS service was evaluated during this scan.
    6. Are absent from the detected findings in this completed scan.

    Returns:
        Summary dict containing resolved count and resolved finding IDs.
    """
    if not account_id or not user_id or not scan_id:
        return {"resolved_count": 0, "resolved_findings": []}

    if not isinstance(scan_started_at, datetime) or not isinstance(scan_completed_at, datetime):
        return {"resolved_count": 0, "resolved_findings": []}

    # Fail closed on inconsistent timestamps
    if scan_completed_at < scan_started_at:
        logger.warning(
            "Scan timestamps inverted: started_at=%s completed_at=%s. Skipping reconciliation.",
            scan_started_at,
            scan_completed_at,
        )
        return {"resolved_count": 0, "resolved_findings": []}

    clean_detected = {str(fid).strip() for fid in (detected_finding_ids or set()) if fid}
    clean_evaluated = (
        {str(s).strip().upper() for s in evaluated_services if s}
        if evaluated_services is not None
        else None
    )
    clean_uninspected = (
        {str(r).strip() for r in uninspected_resources if r}
        if uninspected_resources is not None
        else set()
    )

    finding_query = {
        "user_id": str(user_id),
        "account_id": str(account_id),
        "status": {"$in": [WORKFLOW_OPEN, WORKFLOW_IN_PROGRESS]},
    }
    if organization_id:
        finding_query["organization_id"] = str(organization_id)

    candidates = list(findings_collection.find(finding_query))
    if not candidates:
        return {"resolved_count": 0, "resolved_findings": []}

    resolved_findings: List[str] = []

    for finding in candidates:
        finding_id = str(finding.get("finding_id", "")).strip()
        if not finding_id:
            continue

        # Service evaluation check
        service = str(finding.get("service", "")).strip().upper()
        if clean_evaluated is not None and service and service not in clean_evaluated:
            logger.debug(
                "Skipping finding %s: service %s not evaluated in scan %s",
                finding_id,
                service,
                scan_id,
            )
            continue

        # Uninspected resource check
        resource = str(finding.get("resource", "")).strip()
        if clean_uninspected and resource and resource in clean_uninspected:
            logger.debug(
                "Skipping finding %s: resource %s was not fully inspected in scan %s",
                finding_id,
                resource,
                scan_id,
            )
            continue

        # If still detected in active scan, misconfiguration remains active
        if finding_id in clean_detected:
            logger.debug(
                "Finding %s is still detected in scan %s; leaving open",
                finding_id,
                scan_id,
            )
            continue

        # Check for associated COMPLETED remediation
        rem_query: Dict[str, Any] = {
            "user_id": str(user_id),
            "account_id": str(account_id),
            "finding_id": finding_id,
            "status": STATUS_COMPLETED,
        }
        remediation = remediations_collection.find_one(
            rem_query,
            sort=[("completed_at", -1), ("executed_at", -1), ("updated_at", -1)],
        )
        if not remediation:
            # Unremediated missing findings are never resolved automatically
            continue

        # Stale scan check: remediation execution must precede this scan start
        raw_exec_time = (
            remediation.get("executed_at")
            or remediation.get("completed_at")
            or remediation.get("updated_at")
        )
        exec_time = _parse_datetime(raw_exec_time)
        if exec_time and exec_time > scan_started_at:
            logger.debug(
                "Remediation for finding %s executed at %s after scan started at %s; skipping",
                finding_id,
                exec_time,
                scan_started_at,
            )
            continue

        # Atomically resolve finding
        update_result = findings_collection.update_one(
            {
                "_id": finding["_id"],
                "user_id": str(user_id),
                "status": {"$in": [WORKFLOW_OPEN, WORKFLOW_IN_PROGRESS]},
            },
            {
                "$set": {
                    "status": WORKFLOW_RESOLVED,
                    "workflow_status": WORKFLOW_RESOLVED,
                    "resolution": f"Verified resolved by scan {scan_id}",
                    "resolved_at": scan_completed_at,
                    "verifying_scan_id": str(scan_id),
                    "updated_at": scan_completed_at,
                }
            },
        )

        if update_result.modified_count > 0:
            # Mark remediation verified
            remediations_collection.update_one(
                {"_id": remediation["_id"]},
                {
                    "$set": {
                        "verification.verified": True,
                        "verification.scan_verified": True,
                        "verification.scan_id": str(scan_id),
                        "verification.scan_verified_at": scan_completed_at,
                        "updated_at": scan_completed_at,
                    }
                },
            )

            # Record audit event fail-safely
            try:
                record_event(
                    user_id=user_id,
                    organization_id=organization_id,
                    event_type=EVENT_FINDING_RESOLVED,
                    action="SCAN_VERIFIED_RESOLUTION",
                    result=RESULT_SUCCESS,
                    account_id=account_id,
                    aws_account_id=aws_account_id or finding.get("aws_account_id"),
                    finding_id=finding_id,
                    remediation_id=str(remediation["_id"]),
                    service=finding.get("service"),
                    resource_id=finding.get("resource"),
                    message=f"Finding {finding_id} verified resolved by scan {scan_id}",
                    metadata={
                        "scan_id": str(scan_id),
                        "remediation_id": str(remediation["_id"]),
                        "scan_started_at": (
                            scan_started_at.isoformat()
                            if isinstance(scan_started_at, datetime)
                            else str(scan_started_at)
                        ),
                        "resolved_at": (
                            scan_completed_at.isoformat()
                            if isinstance(scan_completed_at, datetime)
                            else str(scan_completed_at)
                        ),
                    },
                )
            except Exception as audit_err:
                logger.warning(
                    "Audit recording failed for finding resolution %s: %s",
                    finding_id,
                    audit_err,
                )

            resolved_findings.append(finding_id)
            logger.info(
                "Finding %s authoritatively resolved by scan %s (remediation=%s)",
                finding_id,
                scan_id,
                remediation.get("_id"),
            )

    return {
        "resolved_count": len(resolved_findings),
        "resolved_findings": resolved_findings,
    }
