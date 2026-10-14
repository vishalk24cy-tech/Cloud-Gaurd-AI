# ============================================================
# CloudGuardAI - Findings Management API
# Production / Commercial SaaS
# ============================================================

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.models.finding import (
    get_user_findings,
    get_finding,
    update_finding_status,
    assign_finding,
    update_finding_notes,
    delete_finding,
    get_finding_statistics,
    get_findings_by_service,
    get_findings_by_severity,
    is_finding_actionable,
)
from app.services.tenant_context import (
    TenantContext,
    get_tenant_context,
    require_analyst_or_above,
    require_owner_or_admin,
)

router = APIRouter(prefix="/findings", tags=["Findings"])

STATUS_OPEN = "OPEN"
STATUS_IN_PROGRESS = "IN_PROGRESS"
STATUS_RESOLVED = "RESOLVED"
STATUS_IGNORED = "IGNORED"
STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

ALLOWED_STATUSES = {
    STATUS_OPEN,
    STATUS_IN_PROGRESS,
    STATUS_RESOLVED,
    STATUS_IGNORED,
    STATUS_NOT_APPLICABLE,
}

ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., min_length=2, max_length=50)
    resolution: Optional[str] = Field(default=None, max_length=2000)


class AssignFindingRequest(BaseModel):
    assigned_to: Optional[str] = Field(default=None, max_length=200)


class FindingNotesRequest(BaseModel):
    notes: str = Field(default="", max_length=5000)


def _clean_optional(value):
    if value is None:
        return None
    value = str(value).strip()
    return value if value else None


def _normalize_status(value):
    if value is None:
        raise HTTPException(status_code=400, detail="Finding status is required")
    status = str(value).strip().upper()
    if status not in ALLOWED_STATUSES:
        raise HTTPException(
            status_code=400,
            detail="Invalid status. Allowed values: OPEN, IN_PROGRESS, RESOLVED, IGNORED, NOT_APPLICABLE",
        )
    return status


def _normalize_severity(value):
    if value is None:
        return None
    severity = str(value).strip().upper()
    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(
            status_code=400,
            detail="Invalid severity. Allowed values: CRITICAL, HIGH, MEDIUM, LOW",
        )
    return severity


def _normalize_service(value):
    if value is None:
        return None
    service = str(value).strip().upper()
    if not service:
        return None
    if len(service) > 100:
        raise HTTPException(status_code=400, detail="Service filter is too long")
    return service


def _normalize_account_id(value):
    if value is None:
        return None
    account_id = str(value).strip()
    if not account_id:
        return None
    if len(account_id) > 100:
        raise HTTPException(status_code=400, detail="Account ID is too long")
    return account_id


@router.get("/")
def list_findings(
    status: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    service: Optional[str] = Query(default=None),
    account_id: Optional[str] = Query(default=None),
    context: TenantContext = Depends(get_tenant_context),
):
    """
    List security findings scoped strictly to the authenticated tenant organization.
    Accessible to all active organization roles: viewer, analyst, admin, owner.
    """
    clean_status = _normalize_status(status) if status is not None else None
    findings = get_user_findings(
        user_id=context.user_id,
        organization_id=context.organization_id,
        status=clean_status,
        severity=_normalize_severity(severity),
        service=_normalize_service(service),
        account_id=_normalize_account_id(account_id),
    )
    return {"status": "success", "count": len(findings), "findings": findings}


@router.get("/statistics")
def finding_statistics(
    context: TenantContext = Depends(get_tenant_context),
):
    """
    Return finding statistics scoped strictly to the authenticated tenant organization.
    """
    return {
        "status": "success",
        "statistics": get_finding_statistics(
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.get("/by-service")
def findings_by_service(
    context: TenantContext = Depends(get_tenant_context),
):
    """
    Return finding counts grouped by service for the authenticated tenant organization.
    """
    return {
        "status": "success",
        "services": get_findings_by_service(
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.get("/by-severity")
def findings_by_severity(
    context: TenantContext = Depends(get_tenant_context),
):
    """
    Return finding counts grouped by severity for the authenticated tenant organization.
    """
    return {
        "status": "success",
        "severity": get_findings_by_severity(
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.get("/{finding_id}")
def get_single_finding(
    finding_id: str,
    context: TenantContext = Depends(get_tenant_context),
):
    """
    Get a single security finding belonging to the authenticated tenant organization.
    Cross-tenant access fails closed with 404 Not Found without disclosing existence.
    """
    finding = get_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "success", "finding": finding}


@router.patch("/{finding_id}/status")
def change_finding_status(
    finding_id: str,
    payload: StatusUpdateRequest,
    context: TenantContext = Depends(require_analyst_or_above),
):
    """
    Update finding workflow status.
    Requires role analyst, admin, or owner. Viewers are denied (403 Forbidden).
    """
    new_status = _normalize_status(payload.status)
    resolution = _clean_optional(payload.resolution)
    existing = get_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not is_finding_actionable(existing) and new_status not in {STATUS_NOT_APPLICABLE, STATUS_OPEN}:
        raise HTTPException(
            status_code=409,
            detail="This finding is not actionable and cannot enter remediation workflow.",
        )

    if new_status == STATUS_RESOLVED and not resolution:
        resolution = "Resolved"

    updated = update_finding_status(
        finding_id=finding_id,
        user_id=context.user_id,
        status=new_status,
        resolution=resolution,
        organization_id=context.organization_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "status": "success",
        "message": "Finding workflow status updated successfully",
        "finding": get_finding(
            finding_id=finding_id,
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.patch("/{finding_id}/assign")
def assign_finding_to_user(
    finding_id: str,
    payload: AssignFindingRequest,
    context: TenantContext = Depends(require_analyst_or_above),
):
    """
    Assign a finding within the organization.
    Requires role analyst, admin, or owner. Viewers are denied (403 Forbidden).
    """
    existing = get_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")

    updated = assign_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        assigned_to=_clean_optional(payload.assigned_to),
        organization_id=context.organization_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "status": "success",
        "message": "Finding assignment updated successfully",
        "finding": get_finding(
            finding_id=finding_id,
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.patch("/{finding_id}/notes")
def update_notes(
    finding_id: str,
    payload: FindingNotesRequest,
    context: TenantContext = Depends(require_analyst_or_above),
):
    """
    Update analyst notes on a finding.
    Requires role analyst, admin, or owner. Viewers are denied (403 Forbidden).
    """
    existing = get_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")

    updated = update_finding_notes(
        finding_id=finding_id,
        user_id=context.user_id,
        notes=payload.notes.strip(),
        organization_id=context.organization_id,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "status": "success",
        "message": "Finding notes updated successfully",
        "finding": get_finding(
            finding_id=finding_id,
            user_id=context.user_id,
            organization_id=context.organization_id,
        ),
    }


@router.delete("/{finding_id}")
def remove_finding(
    finding_id: str,
    context: TenantContext = Depends(require_owner_or_admin),
):
    """
    Permanently delete a finding.
    Strictly restricted to organization owners and admins. Analysts and viewers are denied (403 Forbidden).
    """
    existing = get_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not existing:
        raise HTTPException(status_code=404, detail="Finding not found")

    deleted = delete_finding(
        finding_id=finding_id,
        user_id=context.user_id,
        organization_id=context.organization_id,
    )
    if not deleted:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {"status": "success", "message": "Finding deleted successfully"}
