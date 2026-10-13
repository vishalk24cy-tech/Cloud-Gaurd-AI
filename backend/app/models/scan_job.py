from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class ScanJob(BaseModel):
    """
    Production SaaS scan-job model.

    This model tracks the lifecycle of an AWS security scan
    independently from the final ScanModel result.
    """

    # --------------------------------------------------------
    # Tenant / ownership
    # --------------------------------------------------------

    organization_id: str = Field(..., min_length=1)
    user_id: str = Field(..., min_length=1)

    # --------------------------------------------------------
    # AWS account
    # --------------------------------------------------------

    account_id: str = Field(..., min_length=1)

    aws_account_id: Optional[str] = None

    # --------------------------------------------------------
    # Job lifecycle
    #
    # queued
    # running
    # completed
    # failed
    # retrying
    # --------------------------------------------------------

    status: str = Field(default="queued")

    # --------------------------------------------------------
    # Retry handling
    # --------------------------------------------------------

    attempts: int = Field(default=0, ge=0)

    max_attempts: int = Field(default=3, ge=1)

    # --------------------------------------------------------
    # Result
    #
    # Once the scan finishes successfully, this points to the
    # persisted scan-history document.
    # --------------------------------------------------------

    scan_id: Optional[str] = None

    # --------------------------------------------------------
    # Error information
    # --------------------------------------------------------

    error_message: Optional[str] = None

    # --------------------------------------------------------
    # Processing timestamps
    # --------------------------------------------------------

    queued_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    started_at: Optional[datetime] = None

    completed_at: Optional[datetime] = None

    failed_at: Optional[datetime] = None

    # --------------------------------------------------------
    # Worker information
    #
    # Useful later when multiple workers/processes are running.
    # --------------------------------------------------------

    worker_id: Optional[str] = None

    # --------------------------------------------------------
    # Retry scheduling
    # --------------------------------------------------------

    next_retry_at: Optional[datetime] = None

    # --------------------------------------------------------
    # Audit timestamps
    # --------------------------------------------------------

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )