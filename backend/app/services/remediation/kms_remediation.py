from __future__ import annotations

from app.services.remediation.remediation_models import (
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id="KMS_UPDATE_KEY_POLICY",
            service="KMS",
            resource_type="KMS_KEY",
            action_name="Update KMS key policy",
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
            description="Apply only a safe, explicitly defined KMS configuration remediation.",
            notes="No automatic deletion or scheduled deletion is allowed.",
        ),
    ]
