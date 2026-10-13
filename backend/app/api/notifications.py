from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.models.notification import (
    get_notifications,
    get_unread_count,
    mark_as_read,
    mark_all_as_read,
    delete_notification,
    delete_read_notifications,
    get_notification_statistics,
    get_finding_notifications,
)

from app.middleware.auth_middleware import verify_token


router = APIRouter()


# ============================================================
# AUTHENTICATED USER HELPER
# ============================================================

def _get_user_id(current_user):
    """
    Extract authenticated user ID.
    """

    if not current_user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    user_id = current_user.get("_id")

    if not user_id:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user ID is missing",
        )

    return str(user_id)


# ============================================================
# GET NOTIFICATIONS
# ============================================================

@router.get("/")
def notifications(
    status: Optional[str] = Query(
        default=None,
        description="Filter by unread or read",
    ),
    severity: Optional[str] = Query(
        default=None,
        description="Filter by CRITICAL, HIGH, MEDIUM or LOW",
    ),
    account_id: Optional[str] = Query(
        default=None,
    ),
    finding_id: Optional[str] = Query(
        default=None,
    ),
    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),
    skip: int = Query(
        default=0,
        ge=0,
    ),
    current_user=Depends(verify_token),
):
    """
    Get notifications for the authenticated tenant only.
    """

    user_id = _get_user_id(
        current_user
    )

    items = get_notifications(
        user_id=user_id,
        status=status,
        severity=severity,
        account_id=account_id,
        finding_id=finding_id,
        limit=limit,
        skip=skip,
    )

    return {
        "success": True,
        "notifications": items,
        "count": len(items),
        "limit": limit,
        "skip": skip,
    }


# ============================================================
# UNREAD COUNT
# ============================================================

@router.get("/unread-count")
def unread_count(
    current_user=Depends(verify_token),
):
    """
    Get unread notification count.
    """

    user_id = _get_user_id(
        current_user
    )

    count = get_unread_count(
        user_id
    )

    return {
        "success": True,
        "unread_count": count,
    }


# ============================================================
# STATISTICS
# ============================================================

@router.get("/statistics")
def notification_statistics(
    current_user=Depends(verify_token),
):
    """
    Get notification statistics.
    """

    user_id = _get_user_id(
        current_user
    )

    return {
        "success": True,
        "statistics": get_notification_statistics(
            user_id
        ),
    }


# ============================================================
# FINDING NOTIFICATION HISTORY
# ============================================================

@router.get("/finding/{finding_id}")
def finding_notification_history(
    finding_id: str,
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    current_user=Depends(verify_token),
):
    """
    Get notification history for a specific finding.
    """

    user_id = _get_user_id(
        current_user
    )

    return {
        "success": True,
        "finding_id": finding_id,
        "notifications": get_finding_notifications(
            user_id=user_id,
            finding_id=finding_id,
            limit=limit,
        ),
    }


# ============================================================
# MARK ONE AS READ
# ============================================================

@router.put("/read/{notification_id}")
def read_notification(
    notification_id: str,
    current_user=Depends(verify_token),
):
    """
    Mark one notification as read.
    """

    user_id = _get_user_id(
        current_user
    )

    result = mark_as_read(
        notification_id=notification_id,
        user_id=user_id,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Notification not found",
        )

    return {
        "success": True,
        "message": "Notification marked as read",
    }


# ============================================================
# MARK ALL AS READ
# ============================================================

@router.put("/read-all")
def read_all_notifications(
    current_user=Depends(verify_token),
):
    """
    Mark all notifications as read.
    """

    user_id = _get_user_id(
        current_user
    )

    count = mark_all_as_read(
        user_id
    )

    return {
        "success": True,
        "message": "All notifications marked as read",
        "updated_count": count,
    }


# ============================================================
# DELETE ONE
# ============================================================

@router.delete("/{notification_id}")
def remove_notification(
    notification_id: str,
    current_user=Depends(verify_token),
):
    """
    Delete one notification owned by the user.
    """

    user_id = _get_user_id(
        current_user
    )

    result = delete_notification(
        notification_id=notification_id,
        user_id=user_id,
    )

    if not result:
        raise HTTPException(
            status_code=404,
            detail="Notification not found",
        )

    return {
        "success": True,
        "message": "Notification deleted",
    }


# ============================================================
# DELETE ALL READ
# ============================================================

@router.delete("/read")
def remove_read_notifications(
    current_user=Depends(verify_token),
):
    """
    Delete all read notifications for the user.
    """

    user_id = _get_user_id(
        current_user
    )

    count = delete_read_notifications(
        user_id
    )

    return {
        "success": True,
        "message": "Read notifications deleted",
        "deleted_count": count,
    }