from __future__ import annotations

from app.services.remediation.remediation_models import (
    EC2_STOP_INSTANCE_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id="EC2_GET_INSTANCE_STATE",
            service="EC2",
            resource_type="EC2_INSTANCE",
            action_name="Get instance state",
            risk_level="LOW",
            classification=RemediationClassification.SAFE,
            requires_confirmation=False,
            requires_approval=False,
            allowed_roles=("owner", "admin"),
            supported_statuses=(
                RemediationStatus.AVAILABLE,
                RemediationStatus.COMPLETED,
                RemediationStatus.FAILED,
                RemediationStatus.NOT_SUPPORTED,
            ),
            description="Read-only inspection of the current EC2 instance state.",
            notes="No AWS state change is made.",
        ),
        RemediationActionSpec(
            action_id="EC2_START_INSTANCE",
            service="EC2",
            resource_type="EC2_INSTANCE",
            action_name="Start instance",
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
            description="Start a stopped EC2 instance after explicit approval.",
            notes="Do not start terminated instances.",
        ),
        RemediationActionSpec(
            action_id=EC2_STOP_INSTANCE_ACTION_ID,
            service="EC2",
            resource_type="EC2_INSTANCE",
            action_name="Stop instance",
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
            description="Stop an active EC2 instance after explicit approval.",
            notes="Do not stop terminated instances.",
        ),
    ]
