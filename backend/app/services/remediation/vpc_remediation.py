from __future__ import annotations

from app.services.remediation.remediation_models import (
    VPC_REMOVE_INSECURE_INGRESS_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id=VPC_REMOVE_INSECURE_INGRESS_ACTION_ID,
            service="VPC",
            resource_type="SECURITY_GROUP",
            action_name="Remove insecure ingress rule",
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
            description="Remove only the specific unrestricted ingress rule identified in the finding.",
            notes="Do not remove all security group rules or break existing infrastructure.",
        ),
        RemediationActionSpec(
            action_id="VPC_REPLACE_UNRESTRICTED_SOURCE",
            service="VPC",
            resource_type="SECURITY_GROUP",
            action_name="Replace unrestricted source with approved source",
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
            description="Replace a public source range with an explicitly approved replacement only when provided by the finding.",
            notes="No blind network rewrites are allowed.",
        ),
    ]
