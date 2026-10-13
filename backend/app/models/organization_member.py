from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class OrganizationMember(BaseModel):
    """
    Represents a user's membership inside a CloudGuardAI organization.
    """

    organization_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)

    # SaaS RBAC role
    role: str = Field(default="viewer")

    # Membership lifecycle
    status: str = Field(default="active")

    # Invitation support
    invited_by: Optional[str] = None
    invited_at: Optional[datetime] = None
    joined_at: Optional[datetime] = None

    # Audit timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )