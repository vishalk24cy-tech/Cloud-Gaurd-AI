from __future__ import annotations

from app.services.remediation.remediation_models import (
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id="LAMBDA_RESTRICT_EXECUTION_ROLE",
            service="LAMBDA",
            resource_type="LAMBDA_FUNCTION",
            action_name="Restrict Lambda execution role",
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
            description="Apply a least-privilege Lambda execution role configuration.",
            notes="No function deletion or application code modification is performed.",
        ),
    ]
