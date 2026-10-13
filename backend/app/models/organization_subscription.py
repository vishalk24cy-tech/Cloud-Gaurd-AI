from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class OrganizationSubscription(BaseModel):
    """
    Subscription state for a CloudGuardAI organization.

    This model is provider-agnostic so Stripe/Razorpay
    or another billing provider can be integrated later.
    """

    organization_id: str = Field(
        ...,
        min_length=1
    )

    plan: str = Field(
        default="free",
        min_length=2,
        max_length=50
    )

    status: str = Field(
        default="trialing"
    )

    provider: Optional[str] = None

    billing_customer_id: Optional[str] = None

    subscription_id: Optional[str] = None

    billing_cycle: Optional[str] = None

    current_period_start: Optional[datetime] = None

    current_period_end: Optional[datetime] = None

    cancel_at_period_end: bool = False

    trial_ends_at: Optional[datetime] = None

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )