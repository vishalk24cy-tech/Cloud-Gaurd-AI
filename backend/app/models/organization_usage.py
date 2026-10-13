from datetime import datetime, timezone

from pydantic import BaseModel, Field


class OrganizationUsage(BaseModel):
    """
    Monthly SaaS usage record for an organization.

    Usage is tracked independently from the individual
    resource collections so quota enforcement can remain
    centralized and scalable.
    """

    organization_id: str = Field(
        ...,
        min_length=1
    )

    # Usage period
    period_start: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    period_end: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # Monthly usage counters
    aws_accounts_used: int = Field(
        default=0,
        ge=0
    )

    team_members_used: int = Field(
        default=0,
        ge=0
    )

    scans_used: int = Field(
        default=0,
        ge=0
    )

    reports_used: int = Field(
        default=0,
        ge=0
    )

    storage_mb_used: int = Field(
        default=0,
        ge=0
    )

    # Lifecycle timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )