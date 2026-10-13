from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Tuple

EC2_STOP_INSTANCE_ACTION_ID = "EC2_STOP_INSTANCE"
S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID = "S3_ENABLE_BLOCK_PUBLIC_ACCESS"
IAM_DISABLE_ACCESS_KEY_ACTION_ID = "IAM_DISABLE_ACCESS_KEY"
VPC_REMOVE_INSECURE_INGRESS_ACTION_ID = "VPC_REMOVE_INSECURE_INGRESS"
RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID = "RDS_DISABLE_PUBLIC_ACCESS"
CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID = "CLOUDTRAIL_ENABLE_LOGGING"


class RemediationClassification(str, Enum):
    SAFE = "SAFE"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    RECOMMENDATION_ONLY = "RECOMMENDATION_ONLY"


class RemediationStatus(str, Enum):
    AVAILABLE = "AVAILABLE"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    REJECTED = "REJECTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"


@dataclass(frozen=True)
class RemediationActionSpec:
    """
    Metadata contract for a CloudGuardAI remediation action.

    This layer is intentionally metadata-only. It defines what a remediation is,
    whether it requires confirmation/approval, and how it should be classified.
    It does not execute AWS operations.
    """

    action_id: str
    service: str
    resource_type: str
    action_name: str
    risk_level: str = "MEDIUM"
    classification: RemediationClassification = RemediationClassification.APPROVAL_REQUIRED
    requires_confirmation: bool = True
    requires_approval: bool = True
    allowed_roles: Tuple[str, ...] = ("owner", "admin")
    supported_statuses: Tuple[RemediationStatus, ...] = (
        RemediationStatus.AVAILABLE,
        RemediationStatus.PENDING_APPROVAL,
        RemediationStatus.APPROVED,
        RemediationStatus.EXECUTING,
        RemediationStatus.VERIFYING,
        RemediationStatus.COMPLETED,
        RemediationStatus.FAILED,
        RemediationStatus.REJECTED,
        RemediationStatus.NOT_SUPPORTED,
    )
    description: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "action_id", str(self.action_id).strip())
        object.__setattr__(self, "service", str(self.service).strip().upper())
        object.__setattr__(self, "resource_type", str(self.resource_type).strip().upper())
        object.__setattr__(self, "action_name", str(self.action_name).strip())
        object.__setattr__(self, "risk_level", str(self.risk_level).strip().upper())
        object.__setattr__(self, "description", str(self.description).strip())
        object.__setattr__(self, "notes", str(self.notes).strip())

        if not self.action_id:
            raise ValueError("action_id is required")

        if not self.service:
            raise ValueError("service is required")

        if not self.resource_type:
            raise ValueError("resource_type is required")

        if not self.action_name:
            raise ValueError("action_name is required")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "service": self.service,
            "resource_type": self.resource_type,
            "action_name": self.action_name,
            "risk_level": self.risk_level,
            "classification": self.classification.value,
            "requires_confirmation": self.requires_confirmation,
            "requires_approval": self.requires_approval,
            "allowed_roles": list(self.allowed_roles),
            "supported_statuses": [status.value for status in self.supported_statuses],
            "description": self.description,
            "notes": self.notes,
        }


def list_supported_statuses() -> Tuple[str, ...]:
    return tuple(status.value for status in RemediationStatus)


def list_classifications() -> Tuple[str, ...]:
    return tuple(item.value for item in RemediationClassification)
