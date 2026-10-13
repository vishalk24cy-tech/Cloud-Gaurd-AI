# ============================================================
# CloudGuardAI - Notification Service
# Production / Commercial SaaS
# ============================================================

from typing import Any, Dict, Optional

from app.models.notification import create_notification


# ============================================================
# CREATE SECURITY ALERT
# ============================================================

def create_alert(
    title: str,
    message: str,
    severity: str,
    user_id: str,
    finding_id: Optional[str] = None,
    account_id: Optional[str] = None,
    aws_account_id: Optional[str] = None,
    account_name: Optional[str] = None,
    service: Optional[str] = None,
    resource: Optional[str] = None,
    detection_status: Optional[str] = None,
) -> Optional[str]:
    """
    Create a tenant-scoped CloudGuardAI security notification.

    Notification creation is centralized here so the scanner,
    remediation system, scheduled scans, and future workers
    can all use the same notification pipeline.

    Deduplication is handled by the notification model.
    """

    # --------------------------------------------------------
    # Validate tenant
    # --------------------------------------------------------

    if not user_id:
        raise ValueError(
            "Notification creation requires user_id"
        )

    # --------------------------------------------------------
    # Normalize severity
    # --------------------------------------------------------

    normalized_severity = str(
        severity or "LOW"
    ).strip().upper()

    if normalized_severity not in {
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    }:
        normalized_severity = "LOW"

    # --------------------------------------------------------
    # Build notification
    # --------------------------------------------------------

    alert: Dict[str, Any] = {
        "title": str(
            title or "Security Alert"
        ).strip(),

        "message": str(
            message or "Security issue detected."
        ).strip(),

        "severity": normalized_severity,

        "status": "unread",

        # Notification classification
        "notification_type": "SECURITY_FINDING",

        "source": "CloudGuardAI",

        # Tenant isolation
        "user_id": str(user_id),
    }

    # --------------------------------------------------------
    # Finding context
    # --------------------------------------------------------

    if finding_id:
        alert["finding_id"] = str(
            finding_id
        )

    if account_id:
        alert["account_id"] = str(
            account_id
        )

    if aws_account_id:
        alert["aws_account_id"] = str(
            aws_account_id
        )

    if account_name:
        alert["account_name"] = str(
            account_name
        )

    if service:
        alert["service"] = str(
            service
        ).strip().upper()

    if resource:
        alert["resource"] = str(
            resource
        ).strip()

    if detection_status:
        alert["detection_status"] = str(
            detection_status
        ).strip().upper()

    # --------------------------------------------------------
    # Persist
    #
    # The notification model performs deduplication.
    # --------------------------------------------------------

    notification_id = create_notification(
        alert,
        user_id=str(user_id),
        deduplicate=True,
    )

    # --------------------------------------------------------
    # Logging
    # --------------------------------------------------------

    if notification_id:
        print(
            "[INFO] CloudGuardAI notification processed: "
            f"{notification_id}"
        )
    else:
        print(
            "[INFO] CloudGuardAI notification skipped "
            "because tenant context was missing."
        )

    return notification_id