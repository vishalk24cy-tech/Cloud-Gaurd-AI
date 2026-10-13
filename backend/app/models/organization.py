from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Organization(BaseModel):
    """
    SaaS tenant / workspace.

    Every organization represents an isolated CloudGuardAI customer
    environment. Resources such as users, cloud accounts, scans,
    findings, reports and audit events will eventually be scoped
    to this organization.
    """

    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=100)

    owner_id: str = Field(..., min_length=1)

    # Subscription readiness
    plan: str = Field(default="free")
    status: str = Field(default="active")

    # SaaS lifecycle
    trial_ends_at: Optional[datetime] = None

    # Future billing integration
    billing_customer_id: Optional[str] = None
    subscription_id: Optional[str] = None

    # Audit / lifecycle timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )