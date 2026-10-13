from __future__ import annotations

from app.services.remediation.remediation_models import (
    S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id=S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID,
            service="S3",
            resource_type="S3_BUCKET",
            action_name="Enable S3 Block Public Access",
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
            description="Apply secure S3 public access settings to the identified bucket.",
            notes="No bucket deletion or object deletion is performed.",
        ),
    ]
