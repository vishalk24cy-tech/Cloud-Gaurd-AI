from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from bson import ObjectId

from app.database.connection import db


notification_collection = db.notifications


# ============================================================
# CONSTANTS
# ============================================================

STATUS_UNREAD = "unread"
STATUS_READ = "read"

SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

# Prevent repeated notifications for the same finding
# while the finding remains at the same severity.
DEFAULT_DEDUP_COOLDOWN_MINUTES = 60


# ============================================================
# HELPERS
# ============================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_object_id(value: str) -> Optional[ObjectId]:
    """
    Safely convert a string to MongoDB ObjectId.
    """
    try:
        if not value:
            return None

        if not ObjectId.is_valid(value):
            return None

        return ObjectId(value)

    except Exception:
        return None


def _serialize_notification(notification: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert MongoDB notification into API-safe JSON.
    """
    item = dict(notification)

    if "_id" in item:
        item["_id"] = str(item["_id"])

    for field in (
        "created_at",
        "updated_at",
        "read_at",
        "last_notified_at",
        "expires_at",
    ):
        if isinstance(item.get(field), datetime):
            item[field] = item[field].isoformat()

    return item


def _normalize_severity(value: Optional[str]) -> str:
    """
    Normalize severity values.
    """
    if not value:
        return "LOW"

    severity = str(value).strip().upper()

    if severity not in SEVERITY_ORDER:
        return "LOW"

    return severity


def _severity_changed(previous: Optional[str], current: str) -> bool:
    """
    Returns True when severity has increased.
    """
    previous_level = SEVERITY_ORDER.get(
        _normalize_severity(previous),
        1,
    )

    current_level = SEVERITY_ORDER.get(
        _normalize_severity(current),
        1,
    )

    return current_level > previous_level


# ============================================================
# INDEXES
# ============================================================

def ensure_notification_indexes():
    """
    Production indexes for notification queries and deduplication.
    """
    try:
        notification_collection.create_index(
            [
                ("user_id", 1),
                ("created_at", -1),
            ],
            name="user_created_at_idx",
        )

        notification_collection.create_index(
            [
                ("user_id", 1),
                ("status", 1),
                ("created_at", -1),
            ],
            name="user_status_created_at_idx",
        )

        notification_collection.create_index(
            [
                ("user_id", 1),
                ("finding_id", 1),
                ("severity", 1),
                ("created_at", -1),
            ],
            name="user_finding_severity_idx",
        )

        notification_collection.create_index(
            [
                ("user_id", 1),
                ("account_id", 1),
                ("created_at", -1),
            ],
            name="user_account_created_at_idx",
        )

    except Exception:
        # Index creation should never prevent application startup.
        pass


# ============================================================
# CREATE NOTIFICATION
# ============================================================

def create_notification(
    data: Dict[str, Any],
    user_id: Optional[str] = None,
    deduplicate: bool = True,
    cooldown_minutes: int = DEFAULT_DEDUP_COOLDOWN_MINUTES,
) -> Optional[str]:
    """
    Create a tenant-scoped notification.

    Production behavior:
    - Adds timestamps
    - Adds unread status
    - Stores severity
    - Supports finding-based deduplication
    - Allows severity escalation notifications
    """

    now = _utc_now()

    notification = dict(data)

    # --------------------------------------------------------
    # Tenant ownership
    # --------------------------------------------------------

    if user_id is not None:
        notification["user_id"] = str(user_id)

    notification_user_id = notification.get("user_id")

    if not notification_user_id:
        # Do not create ownerless notifications in production.
        return None

    notification["user_id"] = str(notification_user_id)

    # --------------------------------------------------------
    # Normalize core fields
    # --------------------------------------------------------

    notification["severity"] = _normalize_severity(
        notification.get("severity")
    )

    notification.setdefault(
        "status",
        STATUS_UNREAD,
    )

    notification.setdefault(
        "notification_type",
        "SECURITY_FINDING",
    )

    notification.setdefault(
        "source",
        "CloudGuardAI",
    )

    notification.setdefault(
        "created_at",
        now,
    )

    notification["updated_at"] = now

    # --------------------------------------------------------
    # Finding-based deduplication
    # --------------------------------------------------------

    finding_id = notification.get("finding_id")

    if deduplicate and finding_id:

        try:
            cooldown = max(
                1,
                int(cooldown_minutes),
            )

            cutoff = now - timedelta(
                minutes=cooldown
            )

            existing = notification_collection.find_one(
                {
                    "user_id": notification["user_id"],
                    "finding_id": str(finding_id),
                    "created_at": {
                        "$gte": cutoff
                    },
                },
                sort=[
                    ("created_at", -1)
                ],
            )

            if existing:

                existing_severity = _normalize_severity(
                    existing.get("severity")
                )

                current_severity = notification["severity"]

                # ------------------------------------------------
                # Same or lower severity:
                # suppress duplicate notification.
                # ------------------------------------------------

                if not _severity_changed(
                    existing_severity,
                    current_severity,
                ):
                    return str(existing["_id"])

                # ------------------------------------------------
                # Higher severity:
                # allow escalation notification.
                # ------------------------------------------------

                notification["notification_type"] = (
                    "SECURITY_FINDING_ESCALATION"
                )

                notification["previous_severity"] = (
                    existing_severity
                )

        except Exception:
            # Fail safely: notification creation should continue.
            pass

    # --------------------------------------------------------
    # Insert
    # --------------------------------------------------------

    result = notification_collection.insert_one(
        notification
    )

    return str(result.inserted_id)


# ============================================================
# GET NOTIFICATIONS
# ============================================================

def get_notifications(
    user_id: str,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    account_id: Optional[str] = None,
    finding_id: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
) -> List[Dict[str, Any]]:
    """
    Get notifications belonging ONLY to the authenticated user.
    """

    query: Dict[str, Any] = {
        "user_id": str(user_id)
    }

    if status:
        query["status"] = str(status).strip().lower()

    if severity:
        query["severity"] = _normalize_severity(
            severity
        )

    if account_id:
        query["account_id"] = str(account_id)

    if finding_id:
        query["finding_id"] = str(finding_id)

    limit = min(
        max(int(limit), 1),
        100,
    )

    skip = max(
        int(skip),
        0,
    )

    notifications = list(
        notification_collection.find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    return [
        _serialize_notification(item)
        for item in notifications
    ]


# ============================================================
# UNREAD COUNT
# ============================================================

def get_unread_count(
    user_id: str,
) -> int:
    """
    Return unread notification count for one tenant/user.
    """

    return notification_collection.count_documents(
        {
            "user_id": str(user_id),
            "status": STATUS_UNREAD,
        }
    )


# ============================================================
# MARK AS READ
# ============================================================

def mark_as_read(
    notification_id: str,
    user_id: str,
) -> bool:
    """
    Mark a notification as read.

    IMPORTANT:
    Ownership is enforced using user_id.
    """

    object_id = _safe_object_id(
        notification_id
    )

    if not object_id:
        return False

    now = _utc_now()

    result = notification_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
        },
        {
            "$set": {
                "status": STATUS_READ,
                "read_at": now,
                "updated_at": now,
            }
        },
    )

    return result.modified_count > 0


# ============================================================
# MARK ALL AS READ
# ============================================================

def mark_all_as_read(
    user_id: str,
) -> int:
    """
    Mark all unread notifications for the user as read.
    """

    now = _utc_now()

    result = notification_collection.update_many(
        {
            "user_id": str(user_id),
            "status": STATUS_UNREAD,
        },
        {
            "$set": {
                "status": STATUS_READ,
                "read_at": now,
                "updated_at": now,
            }
        },
    )

    return result.modified_count


# ============================================================
# DELETE NOTIFICATION
# ============================================================

def delete_notification(
    notification_id: str,
    user_id: str,
) -> bool:
    """
    Delete one notification owned by the user.
    """

    object_id = _safe_object_id(
        notification_id
    )

    if not object_id:
        return False

    result = notification_collection.delete_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
        }
    )

    return result.deleted_count > 0


# ============================================================
# DELETE ALL READ NOTIFICATIONS
# ============================================================

def delete_read_notifications(
    user_id: str,
) -> int:
    """
    Delete only read notifications.
    """

    result = notification_collection.delete_many(
        {
            "user_id": str(user_id),
            "status": STATUS_READ,
        }
    )

    return result.deleted_count


# ============================================================
# STATISTICS
# ============================================================

def get_notification_statistics(
    user_id: str,
) -> Dict[str, Any]:
    """
    Tenant-scoped notification statistics.
    """

    user_id = str(user_id)

    total = notification_collection.count_documents(
        {
            "user_id": user_id
        }
    )

    unread = notification_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_UNREAD,
        }
    )

    read = notification_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_READ,
        }
    )

    critical = notification_collection.count_documents(
        {
            "user_id": user_id,
            "severity": "CRITICAL",
        }
    )

    high = notification_collection.count_documents(
        {
            "user_id": user_id,
            "severity": "HIGH",
        }
    )

    medium = notification_collection.count_documents(
        {
            "user_id": user_id,
            "severity": "MEDIUM",
        }
    )

    low = notification_collection.count_documents(
        {
            "user_id": user_id,
            "severity": "LOW",
        }
    )

    return {
        "total": total,
        "unread": unread,
        "read": read,
        "by_severity": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
    }


# ============================================================
# FINDING NOTIFICATION HISTORY
# ============================================================

def get_finding_notifications(
    user_id: str,
    finding_id: str,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """
    Return notification history for one finding.
    """

    limit = min(
        max(int(limit), 1),
        100,
    )

    notifications = list(
        notification_collection.find(
            {
                "user_id": str(user_id),
                "finding_id": str(finding_id),
            }
        )
        .sort("created_at", -1)
        .limit(limit)
    )

    return [
        _serialize_notification(item)
        for item in notifications
    ]


# ============================================================
# INITIALIZE INDEXES
# ============================================================

ensure_notification_indexes()