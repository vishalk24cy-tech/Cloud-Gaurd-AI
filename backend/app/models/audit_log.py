# ============================================================
# CloudGuardAI - Audit Log Model
# Phase 3 / Step 1
# Production / Commercial SaaS
# ============================================================

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, Optional

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


# ============================================================
# MongoDB Collection
# ============================================================

audit_logs_collection = db["auditlogs"]


# ============================================================
# Event Types
# ============================================================

EVENT_SCAN_STARTED = "SCAN_STARTED"
EVENT_SCAN_COMPLETED = "SCAN_COMPLETED"
EVENT_SCAN_FAILED = "SCAN_FAILED"

EVENT_AWS_ACCOUNT_CONNECTED = "AWS_ACCOUNT_CONNECTED"
EVENT_AWS_ACCOUNT_UPDATED = "AWS_ACCOUNT_UPDATED"
EVENT_AWS_ACCOUNT_DISCONNECTED = "AWS_ACCOUNT_DISCONNECTED"

EVENT_FINDING_CREATED = "FINDING_CREATED"
EVENT_FINDING_UPDATED = "FINDING_UPDATED"
EVENT_FINDING_RESOLVED = "FINDING_RESOLVED"
EVENT_FINDING_IGNORED = "FINDING_IGNORED"

EVENT_REMEDIATION_CREATED = "REMEDIATION_CREATED"
EVENT_REMEDIATION_DEDUPLICATED = "REMEDIATION_DEDUPLICATED"
EVENT_REMEDIATION_AUTHORIZATION = "REMEDIATION_AUTHORIZATION"
EVENT_REMEDIATION_APPROVED = "REMEDIATION_APPROVED"
EVENT_REMEDIATION_REJECTED = "REMEDIATION_REJECTED"
EVENT_REMEDIATION_CANCELLED = "REMEDIATION_CANCELLED"
EVENT_REMEDIATION_EXECUTION_STARTED = "REMEDIATION_EXECUTION_STARTED"
EVENT_REMEDIATION_COMPLETED = "REMEDIATION_COMPLETED"
EVENT_REMEDIATION_FAILED = "REMEDIATION_FAILED"
EVENT_AWS_STATE_VERIFIED = "AWS_STATE_VERIFIED"
EVENT_REMEDIATION_VERIFICATION_REQUESTED = "REMEDIATION_VERIFICATION_REQUESTED"

EVENT_RESOURCE_CONTROL_EXECUTION_STARTED = "RESOURCE_CONTROL_EXECUTION_STARTED"
EVENT_RESOURCE_CONTROL_COMPLETED = "RESOURCE_CONTROL_COMPLETED"
EVENT_RESOURCE_CONTROL_FAILED = "RESOURCE_CONTROL_FAILED"

EVENT_LOGIN_SUCCESS = "LOGIN_SUCCESS"
EVENT_LOGIN_FAILED = "LOGIN_FAILED"
EVENT_LOGOUT = "LOGOUT"


ALLOWED_EVENT_TYPES = {
    value
    for name, value in globals().items()
    if name.startswith("EVENT_")
}


# ============================================================
# Result / Actor Constants
# ============================================================

RESULT_SUCCESS = "SUCCESS"
RESULT_FAILURE = "FAILURE"
RESULT_DENIED = "DENIED"
RESULT_INFO = "INFO"

ACTOR_USER = "USER"
ACTOR_SYSTEM = "SYSTEM"
ACTOR_AWS = "AWS"


# ============================================================
# Helpers
# ============================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _safe_object_id(value: Any) -> Optional[ObjectId]:
    if isinstance(value, ObjectId):
        return value

    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        return None


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _json_safe(value: Any) -> Any:
    """
    Convert common MongoDB/Python values into deterministic JSON-safe data.
    Used only for hashing and API serialization.
    """
    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            str(key): _json_safe(val)
            for key, val in sorted(value.items(), key=lambda item: str(item[0]))
        }

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(value)


def _serialize_audit_log(document: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not document:
        return None

    result = dict(document)

    if result.get("_id") is not None:
        result["_id"] = str(result["_id"])

    return _json_safe(result)


def _build_integrity_hash(document: Dict[str, Any]) -> str:
    """
    Create a deterministic integrity fingerprint for an audit event.

    This is tamper-evident metadata, not a replacement for an immutable
    database/WORM storage layer.
    """
    payload = {
        key: _json_safe(value)
        for key, value in document.items()
        if key not in {"_id", "integrity_hash"}
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ============================================================
# Create Audit Event
# ============================================================

def create_audit_log(
    *,
    user_id: Any,
    event_type: str,
    action: str,
    result: str = RESULT_INFO,
    actor_type: str = ACTOR_USER,
    organization_id: Any = None,
    account_id: Any = None,
    aws_account_id: Any = None,
    finding_id: Any = None,
    remediation_id: Any = None,
    action_id: Any = None,
    resource_id: Any = None,
    service: Any = None,
    resource_type: Any = None,
    request_id: Any = None,
    ip_address: Any = None,
    user_agent: Any = None,
    message: Any = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Append one tenant-scoped audit event.

    Security rule:
    - user_id is always server-supplied.
    - account/finding/remediation IDs are stored as context.
    - secrets, JWTs, AWS credentials and authorization headers must NEVER
      be placed into metadata.
    """

    normalized_event = _string(event_type).strip().upper()
    if normalized_event not in ALLOWED_EVENT_TYPES:
        raise ValueError(f"Unsupported audit event type: {normalized_event}")

    normalized_result = _string(result, RESULT_INFO).strip().upper()
    if normalized_result not in {
        RESULT_SUCCESS,
        RESULT_FAILURE,
        RESULT_DENIED,
        RESULT_INFO,
    }:
        normalized_result = RESULT_INFO

    normalized_actor = _string(actor_type, ACTOR_SYSTEM).strip().upper()
    if normalized_actor not in {ACTOR_USER, ACTOR_SYSTEM, ACTOR_AWS}:
        normalized_actor = ACTOR_SYSTEM

    forbidden_keys = {
        "authorization",
        "accesstoken",
        "refreshtoken",
        "password",
        "secret",
        "secretkey",
        "secretaccesskey",
        "awssecretaccesskey",
        "awsaccesskeyid",
        "accesskeyid",
        "sessiontoken",
        "awssessiontoken",
        "token",
        "credentials",
    }

    def sanitize_metadata(value):
        if isinstance(value, dict):
            sanitized = {}
            for key, item in value.items():
                normalized_key = str(key).lower().replace("_", "").replace("-", "")
                if normalized_key not in forbidden_keys:
                    sanitized[key] = sanitize_metadata(item)
            return sanitized
        if isinstance(value, list):
            return [sanitize_metadata(item) for item in value]
        if isinstance(value, tuple):
            return [sanitize_metadata(item) for item in value]
        return value

    safe_metadata = sanitize_metadata(dict(metadata or {}))

    now = _utc_now()

    document = {
        "user_id": _string(user_id),
        "organization_id": (
            _string(organization_id)
            if organization_id is not None
            else None
        ),
        "event_type": normalized_event,
        "action": _string(action, normalized_event),
        "result": normalized_result,
        "actor_type": normalized_actor,

        "account_id": _string(account_id) if account_id is not None else None,
        "aws_account_id": (
            _string(aws_account_id)
            if aws_account_id is not None
            else None
        ),

        "finding_id": _string(finding_id) if finding_id is not None else None,
        "remediation_id": (
            _string(remediation_id)
            if remediation_id is not None
            else None
        ),
        "action_id": _string(action_id) if action_id is not None else None,

        "resource_id": (
            _string(resource_id)
            if resource_id is not None
            else None
        ),
        "service": _string(service) if service is not None else None,
        "resource_type": (
            _string(resource_type)
            if resource_type is not None
            else None
        ),

        "request_id": _string(request_id) if request_id is not None else None,
        "ip_address": _string(ip_address) if ip_address is not None else None,
        "user_agent": _string(user_agent)[:1000] if user_agent else None,

        "message": _string(message)[:2000] if message else None,
        "metadata": safe_metadata,

        "created_at": now,
        "schema_version": "1.0",
    }

    document["integrity_hash"] = _build_integrity_hash(document)

    inserted = audit_logs_collection.insert_one(document)
    document["_id"] = inserted.inserted_id

    return _serialize_audit_log(document)


# ============================================================
# Tenant-Scoped Reads
# ============================================================

def get_audit_log(
    *,
    user_id: Any,
    audit_id: Any,
) -> Optional[Dict[str, Any]]:
    object_id = _safe_object_id(audit_id)
    if not object_id:
        return None

    document = audit_logs_collection.find_one(
        {
            "_id": object_id,
            "user_id": _string(user_id),
        }
    )

    return _serialize_audit_log(document)


def get_user_audit_logs(
    *,
    user_id: Any,
    account_id: Any = None,
    event_type: Any = None,
    result: Any = None,
    finding_id: Any = None,
    remediation_id: Any = None,
    limit: int = 100,
    skip: int = 0,
) -> Dict[str, Any]:
    """
    Tenant-isolated paginated audit history.
    """

    limit = max(1, min(int(limit), 500))
    skip = max(0, int(skip))

    query: Dict[str, Any] = {
        "user_id": _string(user_id),
    }

    if account_id:
        query["account_id"] = _string(account_id)

    if event_type:
        query["event_type"] = _string(event_type).strip().upper()

    if result:
        query["result"] = _string(result).strip().upper()

    if finding_id:
        query["finding_id"] = _string(finding_id)

    if remediation_id:
        query["remediation_id"] = _string(remediation_id)

    total = audit_logs_collection.count_documents(query)

    cursor = (
        audit_logs_collection
        .find(query)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    items = [
        _serialize_audit_log(document)
        for document in cursor
    ]

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "skip": skip,
        "has_more": (skip + len(items)) < total,
    }


def get_finding_audit_history(
    *,
    user_id: Any,
    finding_id: Any,
    limit: int = 100,
) -> Dict[str, Any]:
    return get_user_audit_logs(
        user_id=user_id,
        finding_id=finding_id,
        limit=limit,
        skip=0,
    )


def get_remediation_audit_history(
    *,
    user_id: Any,
    remediation_id: Any,
    limit: int = 100,
) -> Dict[str, Any]:
    return get_user_audit_logs(
        user_id=user_id,
        remediation_id=remediation_id,
        limit=limit,
        skip=0,
    )


# ============================================================
# Statistics
# ============================================================

def get_audit_statistics(
    *,
    user_id: Any,
    account_id: Any = None,
) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "user_id": _string(user_id),
    }

    if account_id:
        query["account_id"] = _string(account_id)

    pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": None,
                "total": {"$sum": 1},
                "success": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$result", RESULT_SUCCESS]},
                            1,
                            0,
                        ]
                    }
                },
                "failure": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$result", RESULT_FAILURE]},
                            1,
                            0,
                        ]
                    }
                },
                "denied": {
                    "$sum": {
                        "$cond": [
                            {"$eq": ["$result", RESULT_DENIED]},
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]

    result = list(audit_logs_collection.aggregate(pipeline))

    if not result:
        return {
            "total": 0,
            "success": 0,
            "failure": 0,
            "denied": 0,
        }

    summary = result[0]
    summary.pop("_id", None)

    return summary


# ============================================================
# Integrity Verification
# ============================================================

def verify_audit_integrity(
    *,
    user_id: Any,
    audit_id: Any,
) -> Dict[str, Any]:
    document = audit_logs_collection.find_one(
        {
            "_id": _safe_object_id(audit_id),
            "user_id": _string(user_id),
        }
    )

    if not document:
        return {
            "valid": False,
            "reason": "Audit event not found",
        }

    stored_hash = document.get("integrity_hash")
    calculated_hash = _build_integrity_hash(document)

    valid = bool(stored_hash) and stored_hash == calculated_hash

    return {
        "valid": valid,
        "audit_id": str(document["_id"]),
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "reason": "Integrity verified" if valid else "Integrity mismatch",
    }


# ============================================================
# Indexes
# ============================================================

def ensure_indexes() -> None:
    """
    Safe non-unique indexes for the append-only audit collection.
    """

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("created_at", -1),
        ],
        name="user_created_at",
    )

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("created_at", -1),
        ],
        name="user_account_created_at",
    )

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("event_type", 1),
            ("created_at", -1),
        ],
        name="user_event_created_at",
    )

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("finding_id", 1),
            ("created_at", -1),
        ],
        name="user_finding_created_at",
    )

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("remediation_id", 1),
            ("created_at", -1),
        ],
        name="user_remediation_created_at",
    )

    audit_logs_collection.create_index(
        [
            ("user_id", 1),
            ("result", 1),
            ("created_at", -1),
        ],
        name="user_result_created_at",
    )


# Initialize indexes when the model is imported.
try:
    ensure_indexes()
except Exception as exc:
    # Index creation must not prevent application startup.
    print(f"[WARNING] Audit log indexes not initialized: {exc}")
