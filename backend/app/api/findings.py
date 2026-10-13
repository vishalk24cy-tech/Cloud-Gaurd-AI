# CloudGuardAI - Findings Management API
# Production / Commercial SaaS
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from app.middleware.auth_middleware import verify_token
from app.models.finding import (
    get_user_findings, get_finding, update_finding_status, assign_finding,
    update_finding_notes, delete_finding, get_finding_statistics,
    get_findings_by_service, get_findings_by_severity, is_finding_actionable,
)

router = APIRouter(prefix="/findings", tags=["Findings"])
STATUS_OPEN="OPEN"; STATUS_IN_PROGRESS="IN_PROGRESS"; STATUS_RESOLVED="RESOLVED"; STATUS_IGNORED="IGNORED"; STATUS_NOT_APPLICABLE="NOT_APPLICABLE"
ALLOWED_STATUSES={STATUS_OPEN,STATUS_IN_PROGRESS,STATUS_RESOLVED,STATUS_IGNORED,STATUS_NOT_APPLICABLE}
ALLOWED_SEVERITIES={"CRITICAL","HIGH","MEDIUM","LOW"}

class StatusUpdateRequest(BaseModel):
    status: str = Field(..., min_length=2, max_length=50)
    resolution: Optional[str] = Field(default=None, max_length=2000)
class AssignFindingRequest(BaseModel):
    assigned_to: Optional[str] = Field(default=None, max_length=200)
class FindingNotesRequest(BaseModel):
    notes: str = Field(default="", max_length=5000)

def _get_user_id(current_user):
    if not current_user or not current_user.get("_id"):
        raise HTTPException(status_code=401, detail="Authenticated user not found")
    return str(current_user["_id"])

def _clean_optional(value):
    if value is None: return None
    value=str(value).strip()
    return value if value else None

def _normalize_status(value):
    if value is None: raise HTTPException(status_code=400, detail="Finding status is required")
    status=str(value).strip().upper()
    if status not in ALLOWED_STATUSES:
        raise HTTPException(status_code=400, detail="Invalid status. Allowed values: OPEN, IN_PROGRESS, RESOLVED, IGNORED, NOT_APPLICABLE")
    return status

def _normalize_severity(value):
    if value is None: return None
    severity=str(value).strip().upper()
    if severity not in ALLOWED_SEVERITIES:
        raise HTTPException(status_code=400, detail="Invalid severity. Allowed values: CRITICAL, HIGH, MEDIUM, LOW")
    return severity

def _normalize_service(value):
    if value is None: return None
    service=str(value).strip().upper()
    if not service: return None
    if len(service)>100: raise HTTPException(status_code=400, detail="Service filter is too long")
    return service

def _normalize_account_id(value):
    if value is None: return None
    account_id=str(value).strip()
    if not account_id: return None
    if len(account_id)>100: raise HTTPException(status_code=400, detail="Account ID is too long")
    return account_id

@router.get("/")
def list_findings(status: Optional[str]=Query(default=None), severity: Optional[str]=Query(default=None), service: Optional[str]=Query(default=None), account_id: Optional[str]=Query(default=None), current_user=Depends(verify_token)):
    user_id=_get_user_id(current_user)
    clean_status=_normalize_status(status) if status is not None else None
    findings=get_user_findings(user_id=user_id,status=clean_status,severity=_normalize_severity(severity),service=_normalize_service(service),account_id=_normalize_account_id(account_id))
    return {"status":"success","count":len(findings),"findings":findings}

@router.get("/statistics")
def finding_statistics(current_user=Depends(verify_token)):
    return {"status":"success","statistics":get_finding_statistics(_get_user_id(current_user))}

@router.get("/by-service")
def findings_by_service(current_user=Depends(verify_token)):
    return {"status":"success","services":get_findings_by_service(_get_user_id(current_user))}

@router.get("/by-severity")
def findings_by_severity(current_user=Depends(verify_token)):
    return {"status":"success","severity":get_findings_by_severity(_get_user_id(current_user))}

@router.get("/{finding_id}")
def get_single_finding(finding_id: str,current_user=Depends(verify_token)):
    finding=get_finding(finding_id,_get_user_id(current_user))
    if not finding: raise HTTPException(status_code=404,detail="Finding not found")
    return {"status":"success","finding":finding}

@router.patch("/{finding_id}/status")
def change_finding_status(finding_id: str,payload: StatusUpdateRequest,current_user=Depends(verify_token)):
    user_id=_get_user_id(current_user); new_status=_normalize_status(payload.status); resolution=_clean_optional(payload.resolution)
    existing=get_finding(finding_id,user_id)
    if not existing: raise HTTPException(status_code=404,detail="Finding not found")
    if not is_finding_actionable(existing) and new_status not in {STATUS_NOT_APPLICABLE,STATUS_OPEN}:
        raise HTTPException(status_code=409,detail="This finding is not actionable and cannot enter remediation workflow.")
    if new_status==STATUS_RESOLVED and not resolution:
        resolution="Resolved"
    updated=update_finding_status(finding_id,user_id,new_status,resolution)
    if not updated: raise HTTPException(status_code=404,detail="Finding not found")
    return {"status":"success","message":"Finding workflow status updated successfully","finding":get_finding(finding_id,user_id)}

@router.patch("/{finding_id}/assign")
def assign_finding_to_user(finding_id: str,payload: AssignFindingRequest,current_user=Depends(verify_token)):
    user_id=_get_user_id(current_user)
    if not get_finding(finding_id,user_id): raise HTTPException(status_code=404,detail="Finding not found")
    if not assign_finding(finding_id,user_id,_clean_optional(payload.assigned_to)): raise HTTPException(status_code=404,detail="Finding not found")
    return {"status":"success","message":"Finding assignment updated successfully","finding":get_finding(finding_id,user_id)}

@router.patch("/{finding_id}/notes")
def update_notes(finding_id: str,payload: FindingNotesRequest,current_user=Depends(verify_token)):
    user_id=_get_user_id(current_user)
    if not get_finding(finding_id,user_id): raise HTTPException(status_code=404,detail="Finding not found")
    if not update_finding_notes(finding_id,user_id,payload.notes.strip()): raise HTTPException(status_code=404,detail="Finding not found")
    return {"status":"success","message":"Finding notes updated successfully","finding":get_finding(finding_id,user_id)}

@router.delete("/{finding_id}")
def remove_finding(finding_id: str,current_user=Depends(verify_token)):
    user_id=_get_user_id(current_user)
    if not get_finding(finding_id,user_id): raise HTTPException(status_code=404,detail="Finding not found")
    if not delete_finding(finding_id,user_id): raise HTTPException(status_code=404,detail="Finding not found")
    return {"status":"success","message":"Finding deleted successfully"}
