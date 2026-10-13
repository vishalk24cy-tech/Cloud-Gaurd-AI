from __future__ import annotations

from app.services.remediation.remediation_models import (
    IAM_DISABLE_ACCESS_KEY_ACTION_ID,
    RemediationActionSpec,
    RemediationClassification,
    RemediationStatus,
)


def get_actions():
    return [
        RemediationActionSpec(
            action_id=IAM_DISABLE_ACCESS_KEY_ACTION_ID,
            service="IAM",
            resource_type="IAM_ACCESS_KEY",
            action_name="Disable compromised access key",
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
            description="Disable a compromised IAM access key when a finding explicitly identifies it.",
            notes="No IAM user or role deletion occurs automatically.",
        ),
        RemediationActionSpec(
            action_id="IAM_REMOVE_EXCESSIVE_POLICY",
            service="IAM",
            resource_type="IAM_POLICY",
            action_name="Remove excessive managed policy",
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
            description="Detach a specific excessive managed policy only when the finding identifies it.",
            notes="No arbitrary policy rewrite or AdministratorAccess grant is allowed.",
        ),
        RemediationActionSpec(
            action_id="IAM_REVIEW_POLICY",
            service="IAM",
            resource_type="IAM_POLICY",
            action_name="Review IAM policy",
            risk_level="LOW",
            classification=RemediationClassification.RECOMMENDATION_ONLY,
            requires_confirmation=False,
            requires_approval=False,
            allowed_roles=("owner", "admin", "viewer"),
            supported_statuses=(
                RemediationStatus.AVAILABLE,
                RemediationStatus.REJECTED,
                RemediationStatus.NOT_SUPPORTED,
            ),
            description="Provide a review-only recommendation for excessive or risky IAM access.",
            notes="This is not an automatic AWS change.",
        ),
    ]
