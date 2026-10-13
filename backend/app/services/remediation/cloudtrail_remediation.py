from __future__ import annotations

from app.services.remediation.remediation_models import (
    CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id=CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID,
            service="CLOUDTRAIL",
            resource_type="CLOUDTRAIL_TRAIL",
            action_name="Enable CloudTrail logging",
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
            description="Enable or configure a CloudTrail trail when a finding identifies missing logging.",
            notes="Configuration is verified after the change.",
        ),
    ]
