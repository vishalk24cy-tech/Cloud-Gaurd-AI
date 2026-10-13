from datetime import datetime, timezone
from typing import List

from pydantic import BaseModel, Field


class SubscriptionPlan(BaseModel):
    """
    Defines the limits and features available
    for a CloudGuardAI SaaS subscription plan.
    """

    name: str = Field(
        ...,
        min_length=2,
        max_length=50
    )

    display_name: str = Field(
        ...,
        min_length=2,
        max_length=100
    )

    description: str = Field(
        default="",
        max_length=500
    )

    price_monthly: float = Field(
        default=0.0,
        ge=0
    )

    price_yearly: float = Field(
        default=0.0,
        ge=0
    )

    # ==============================
    # Usage Limits
    # ==============================

    max_aws_accounts: int = Field(
        default=1,
        ge=-1
    )

    max_team_members: int = Field(
        default=2,
        ge=-1
    )

    max_scans_per_month: int = Field(
        default=10,
        ge=-1
    )

    max_reports_per_month: int = Field(
        default=5,
        ge=-1
    )

    max_storage_mb: int = Field(
        default=500,
        ge=-1
    )

    # ==============================
    # Features
    # ==============================

    ai_analysis: bool = False

    advanced_monitoring: bool = False

    security_graph: bool = False

    compliance_reports: bool = False

    audit_logs: bool = False

    priority_support: bool = False

    # ==============================
    # Plan Status
    # ==============================

    active: bool = True

    features: List[str] = Field(
        default_factory=list
    )

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )