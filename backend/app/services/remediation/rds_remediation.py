from __future__ import annotations

from app.services.remediation.remediation_models import (
    RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id=RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID,
            service="RDS",
            resource_type="RDS_INSTANCE",
            action_name="Disable public access",
            risk_level="HIGH",
            classification=RemediationClassification.APPROVAL_REQUIRED,
            requires_confirmation=True,
            requires_approval=True,
            allowed_roles=("owner", "admin"),
            supported_statuses=(
                RemediationStatus.AVAILABLE,
                RemediationStatus.PENDING_APPROVAL,
                RemediationStatus.APPROVED,
                RemediationStatus.EXECUTING,
                RemediationStatus.VERIFYING,
                RemediationStatus.COMPLETED,
                RemediationStatus.FAILED,
                RemediationStatus.REJECTED,
            ),
            description="Disable public accessibility only when the finding provides sufficient evidence.",
            notes="No database deletion or data mutation is performed.",
        ),
        RemediationActionSpec(
            action_id="RDS_ENABLE_ENCRYPTION",
            service="RDS",
            resource_type="RDS_INSTANCE",
            action_name="Enable encryption configuration",
            risk_level="MEDIUM",
            classification=RemediationClassification.APPROVAL_REQUIRED,
            requires_confirmation=True,
            requires_approval=True,
            allowed_roles=("owner", "admin"),
            supported_statuses=(
                RemediationStatus.AVAILABLE,
                RemediationStatus.PENDING_APPROVAL,
                RemediationStatus.APPROVED,
                RemediationStatus.EXECUTING,
                RemediationStatus.VERIFYING,
                RemediationStatus.COMPLETED,
                RemediationStatus.FAILED,
                RemediationStatus.REJECTED,
            ),
            description="Apply secure RDS configuration changes for encryption or access controls.",
            notes="Safe configuration remediation only; no destructive database operation occurs.",
        ),
    ]
