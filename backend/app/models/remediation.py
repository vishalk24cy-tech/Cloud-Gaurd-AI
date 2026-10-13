# ============================================================
# CloudGuardAI - Remediation Model
# Production / Commercial SaaS
# ============================================================

from datetime import datetime
from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db
from app.services.remediation.remediation_models import (
    CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID,
    CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID,
    EC2_STOP_INSTANCE_ACTION_ID,
    IAM_DISABLE_ACCESS_KEY_ACTION_ID,
    RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID,
    S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID,
    VPC_REMOVE_INSECURE_INGRESS_ACTION_ID,
)


# ============================================================
# COLLECTION
# ============================================================

remediations_collection = db["remediations"]


# ============================================================
# REMEDIATION STATUSES
# ============================================================

STATUS_PROPOSED = "PROPOSED"
STATUS_PENDING_APPROVAL = "PENDING_APPROVAL"
STATUS_APPROVED = "APPROVED"
STATUS_EXECUTING = "EXECUTING"
STATUS_COMPLETED = "COMPLETED"
STATUS_FAILED = "FAILED"
STATUS_REJECTED = "REJECTED"
STATUS_CANCELLED = "CANCELLED"


VALID_STATUSES = {
    STATUS_PROPOSED,
    STATUS_PENDING_APPROVAL,
    STATUS_APPROVED,
    STATUS_EXECUTING,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_REJECTED,
    STATUS_CANCELLED,
}


# ============================================================
# ACTION TYPES
# ============================================================

ACTION_DISABLE_PUBLIC_ACCESS = "DISABLE_PUBLIC_ACCESS"
ACTION_RESTRICT_SECURITY_GROUP = "RESTRICT_SECURITY_GROUP"
ACTION_ENABLE_MFA = "ENABLE_MFA"
ACTION_ENABLE_CLOUDTRAIL = "ENABLE_CLOUDTRAIL"
ACTION_ENABLE_RDS_ENCRYPTION = "ENABLE_RDS_ENCRYPTION"
ACTION_DISABLE_RDS_PUBLIC_ACCESS = "DISABLE_RDS_PUBLIC_ACCESS"
ACTION_ENABLE_RDS_BACKUPS = "ENABLE_RDS_BACKUPS"
ACTION_ENABLE_S3_ENCRYPTION = "ENABLE_S3_ENCRYPTION"
ACTION_ENABLE_ENCRYPTION = "ENABLE_ENCRYPTION"
ACTION_REVIEW_IAM_POLICY = "REVIEW_IAM_POLICY"
ACTION_REMOVE_PUBLIC_POLICY = "REMOVE_PUBLIC_POLICY"
ACTION_EC2_STOP_INSTANCE = EC2_STOP_INSTANCE_ACTION_ID
ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS = S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID
ACTION_IAM_DISABLE_ACCESS_KEY = IAM_DISABLE_ACCESS_KEY_ACTION_ID
ACTION_VPC_REMOVE_INSECURE_INGRESS = VPC_REMOVE_INSECURE_INGRESS_ACTION_ID
ACTION_RDS_DISABLE_PUBLIC_ACCESS = RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID
ACTION_CLOUDTRAIL_ENABLE_LOGGING = CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID


VALID_ACTION_TYPES = {
    ACTION_DISABLE_PUBLIC_ACCESS,
    ACTION_RESTRICT_SECURITY_GROUP,
    ACTION_ENABLE_MFA,
    ACTION_ENABLE_CLOUDTRAIL,
    ACTION_ENABLE_RDS_ENCRYPTION,
    ACTION_DISABLE_RDS_PUBLIC_ACCESS,
    ACTION_ENABLE_RDS_BACKUPS,
    ACTION_ENABLE_S3_ENCRYPTION,
    ACTION_ENABLE_ENCRYPTION,
    ACTION_REVIEW_IAM_POLICY,
    ACTION_REMOVE_PUBLIC_POLICY,
    ACTION_EC2_STOP_INSTANCE,
    ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
    ACTION_IAM_DISABLE_ACCESS_KEY,
    ACTION_VPC_REMOVE_INSECURE_INGRESS,
    ACTION_RDS_DISABLE_PUBLIC_ACCESS,
    ACTION_CLOUDTRAIL_ENABLE_LOGGING,
}


# ============================================================
# HELPERS
# ============================================================

def _utc_now():
    return datetime.utcnow()


def _to_object_id(value):
    try:
        if isinstance(value, ObjectId):
            return value

        return ObjectId(str(value))

    except (InvalidId, TypeError, ValueError):
        return None


def _clean(value):
    if value is None:
        return None

    if isinstance(value, str):
        return value.strip()

    return value


def _serialize(value):
    """
    Convert MongoDB values into JSON-safe values.
    """

    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {
            key: _serialize(val)
            for key, val in value.items()
        }

    if isinstance(value, list):
        return [
            _serialize(item)
            for item in value
        ]

    return value


def _normalize_status(status):
    if status is None:
        return None

    value = str(status).strip().upper()

    if value not in VALID_STATUSES:
        raise ValueError(
            f"Invalid remediation status: {value}"
        )

    return value


# ============================================================
# ACTIVE PROPOSAL DEDUPLICATION
# ============================================================

ACTIVE_PROPOSAL_STATUSES = {
    STATUS_PROPOSED,
    STATUS_PENDING_APPROVAL,
    STATUS_APPROVED,
    STATUS_EXECUTING,
}


def get_active_remediation(
    user_id,
    finding_id=None,
    account_id=None,
    action_type=None,
    resource_id=None,
):
    """
    Return the existing active remediation for the same
    tenant + account + finding + action.

    Historical records (COMPLETED, FAILED, REJECTED,
    CANCELLED) are intentionally ignored so a future
    remediation cycle can create a new proposal.
    """
    user_id = _clean(user_id)
    finding_id = _clean(finding_id)
    account_id = _clean(account_id)
    action_type = _clean(action_type)

    if not all((user_id, account_id, action_type)):
        return None

    query = {
        "user_id": str(user_id),
        "account_id": str(account_id),
        "action_type": str(action_type).upper(),
        "status": {"$in": list(ACTIVE_PROPOSAL_STATUSES)},
    }

    if finding_id:
        query["finding_id"] = str(finding_id)
    elif resource_id:
        query["resource"] = str(resource_id)
    else:
        return None

    record = remediations_collection.find_one(
        query,
        sort=[("created_at", -1)],
    )

    if not record:
        return None

    return _serialize(record)


# ============================================================
# CREATE REMEDIATION
# ============================================================

def create_remediation(data):
    """
    Create a remediation proposal.

    AWS execution is NOT performed here.
    """

    if not isinstance(data, dict):
        raise ValueError(
            "Remediation data must be a dictionary"
        )

    now = _utc_now()

    user_id = _clean(data.get("user_id"))
    finding_id = _clean(data.get("finding_id"))
    account_id = _clean(data.get("account_id"))
    aws_account_id = _clean(data.get("aws_account_id"))

    action_type = _clean(
        data.get("action_type")
    )

    if not user_id:
        raise ValueError("user_id is required")

    resource_id = _clean(data.get("resource"))
    findingless_resource_action = (
        action_type in {
            ACTION_EC2_STOP_INSTANCE,
            ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
            ACTION_IAM_DISABLE_ACCESS_KEY,
        }
        and bool(resource_id)
    )

    if not finding_id and not findingless_resource_action:
        raise ValueError("finding_id is required")

    if not account_id:
        raise ValueError("account_id is required")

    if not action_type:
        raise ValueError("action_type is required")

    action_type = str(action_type).upper()

    if action_type not in VALID_ACTION_TYPES:
        raise ValueError(
            f"Unsupported remediation action: {action_type}"
        )

    # ------------------------------------------------------------
    # Active-proposal deduplication
    # ------------------------------------------------------------
    # Only one active proposal is allowed for the same
    # tenant + account + finding + action.
    #
    # Historical records remain untouched, so a later scan can
    # legitimately create a new remediation cycle.
    # ------------------------------------------------------------
    existing = get_active_remediation(
        user_id=user_id,
        finding_id=finding_id,
        account_id=account_id,
        action_type=action_type,
        resource_id=resource_id if findingless_resource_action else None,
    )

    if existing:
        return existing

    remediation = {

        # ----------------------------------------------------
        # Tenant
        # ----------------------------------------------------

        "user_id": str(user_id),

        # ----------------------------------------------------
        # Finding
        # ----------------------------------------------------

        "organization_id": (
            str(data.get("organization_id"))
            if data.get("organization_id") is not None
            else None
        ),

        "finding_id": str(finding_id) if finding_id else None,

        # ----------------------------------------------------
        # CloudGuardAI account
        # ----------------------------------------------------

        "account_id": str(account_id),

        # ----------------------------------------------------
        # Real AWS account
        # ----------------------------------------------------

        "aws_account_id": (
            str(aws_account_id)
            if aws_account_id
            else None
        ),

        # ----------------------------------------------------
        # Finding metadata
        # ----------------------------------------------------

        "service": _clean(
            data.get("service")
        ),

        "resource": _clean(
            data.get("resource")
        ),

        "resource_type": _clean(
            data.get("resource_type")
        ),

        "severity": (
            str(data.get("severity")).upper()
            if data.get("severity") is not None
            else None
        ),

        # ----------------------------------------------------
        # Remediation action
        # ----------------------------------------------------

        "action_type": action_type,

        # Deterministic correlation key used for deduplication,
        # diagnostics, and future migration to an atomic partial
        # unique index.
        "active_dedup_key": (
            f"{user_id}:{account_id}:{finding_id or resource_id}:{action_type}"
        ),

        # ----------------------------------------------------
        # Server-generated proposal
        # ----------------------------------------------------

        "title": _clean(
            data.get("title")
        ),

        "description": _clean(
            data.get("description")
        ),

        "reason": _clean(
            data.get("reason")
        ),

        "recommendation": _clean(
            data.get("recommendation")
        ),

        # ----------------------------------------------------
        # Trusted execution definition
        # ----------------------------------------------------

        "operation": data.get(
            "operation",
            {}
        ),

        # ----------------------------------------------------
        # AWS state before execution
        # ----------------------------------------------------

        "before_state": data.get(
            "before_state",
            {}
        ),

        # ----------------------------------------------------
        # AWS state after execution
        # ----------------------------------------------------

        "after_state": None,

        # ----------------------------------------------------
        # Verification
        # ----------------------------------------------------

        "verification": None,

        # ----------------------------------------------------
        # Workflow
        # ----------------------------------------------------

        "status": STATUS_PROPOSED,

        # ----------------------------------------------------
        # Approval
        # ----------------------------------------------------

        "approved_by": None,
        "approved_at": None,
        "approval_comment": None,

        # ----------------------------------------------------
        # Rejection
        # ----------------------------------------------------

        "rejected_by": None,
        "rejected_at": None,
        "rejection_reason": None,

        # ----------------------------------------------------
        # Execution
        # ----------------------------------------------------

        "started_at": None,
        "completed_at": None,
        "execution_error": None,

        # ----------------------------------------------------
        # Audit timestamps
        # ----------------------------------------------------

        "created_at": now,
        "updated_at": now,
    }

    result = remediations_collection.insert_one(
        remediation
    )

    remediation["_id"] = str(
        result.inserted_id
    )

    return _serialize(remediation)


# ============================================================
# GET SINGLE REMEDIATION
# ============================================================

def get_remediation(
    remediation_id,
    user_id=None,
):
    """
    Tenant-scoped remediation lookup.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return None

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    remediation = remediations_collection.find_one(
        query
    )

    if not remediation:
        return None

    return _serialize(remediation)


# ============================================================
# GET USER REMEDIATIONS
# ============================================================

def get_user_remediations(
    user_id,
    status=None,
    finding_id=None,
    account_id=None,
    severity=None,
    limit=100,
):
    """
    Return only remediations belonging to the
    authenticated tenant.
    """

    query = {
        "user_id": str(user_id)
    }

    if status:
        clean_status = str(
            status
        ).strip().upper()

        if clean_status in VALID_STATUSES:
            query["status"] = clean_status

    if finding_id:
        query["finding_id"] = str(
            finding_id
        ).strip()

    if account_id:
        query["account_id"] = str(
            account_id
        ).strip()

    if severity:
        query["severity"] = str(
            severity
        ).strip().upper()

    try:
        limit = int(limit)

    except (TypeError, ValueError):
        limit = 100

    limit = max(
        1,
        min(limit, 500)
    )

    records = list(
        remediations_collection.find(query)
        .sort("created_at", -1)
        .limit(limit)
    )

    return [
        _serialize(record)
        for record in records
    ]


# ============================================================
# UPDATE REMEDIATION STATUS
# ============================================================

def update_remediation_status(
    remediation_id,
    status,
    user_id=None,
    approved_by=None,
    rejected_by=None,
    approval_comment=None,
    rejection_reason=None,
    execution_error=None,
    expected_status=None,
):
    """
    General status update.

    user_id provides tenant isolation.

    expected_status can be supplied for
    optimistic/atomic workflow transitions.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    new_status = _normalize_status(
        status
    )

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(
            user_id
        )

    if expected_status is not None:
        query["status"] = _normalize_status(
            expected_status
        )

    now = _utc_now()

    update = {
        "$set": {
            "status": new_status,
            "updated_at": now,
        }
    }

    # --------------------------------------------------------
    # Approval
    # --------------------------------------------------------

    if new_status == STATUS_APPROVED:

        update["$set"]["approved_at"] = now

        if approved_by is not None:
            update["$set"]["approved_by"] = str(
                approved_by
            )

        if approval_comment is not None:
            update["$set"]["approval_comment"] = (
                _clean(approval_comment)
            )

    # --------------------------------------------------------
    # Rejection
    # --------------------------------------------------------

    if new_status == STATUS_REJECTED:

        update["$set"]["rejected_at"] = now

        if rejected_by is not None:
            update["$set"]["rejected_by"] = str(
                rejected_by
            )

        if rejection_reason is not None:
            update["$set"]["rejection_reason"] = (
                _clean(rejection_reason)
            )

    # --------------------------------------------------------
    # Execution start
    # --------------------------------------------------------

    if new_status == STATUS_EXECUTING:

        update["$set"]["started_at"] = now

        update["$set"]["execution_error"] = None

    # --------------------------------------------------------
    # Execution completed
    # --------------------------------------------------------

    if new_status == STATUS_COMPLETED:

        update["$set"]["completed_at"] = now

        update["$set"]["execution_error"] = None

    # --------------------------------------------------------
    # Execution failed
    # --------------------------------------------------------

    if new_status == STATUS_FAILED:

        update["$set"]["execution_error"] = (
            _clean(execution_error)
        )

    result = remediations_collection.update_one(
        query,
        update
    )

    return result.modified_count > 0


# ============================================================
# ATOMIC APPROVED -> EXECUTING
# ============================================================

def transition_to_executing(
    remediation_id,
    user_id,
):
    """
    Atomically move:

        APPROVED -> EXECUTING

    This prevents two concurrent requests from
    executing the same remediation.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    now = _utc_now()

    result = remediations_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": STATUS_APPROVED,
        },
        {
            "$set": {
                "status": STATUS_EXECUTING,
                "started_at": now,
                "updated_at": now,
                "execution_error": None,
            }
        }
    )

    return result.modified_count > 0


# ============================================================
# ATOMIC EXECUTING -> COMPLETED
# ============================================================

def transition_to_completed(
    remediation_id,
    user_id,
):
    """
    Atomically move:

        EXECUTING -> COMPLETED
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    now = _utc_now()

    result = remediations_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": STATUS_EXECUTING,
        },
        {
            "$set": {
                "status": STATUS_COMPLETED,
                "completed_at": now,
                "updated_at": now,
                "execution_error": None,
            }
        }
    )

    return result.modified_count > 0


# ============================================================
# ATOMIC EXECUTING -> FAILED
# ============================================================

def transition_to_failed(
    remediation_id,
    user_id,
    execution_error=None,
):
    """
    Atomically move:

        EXECUTING -> FAILED
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    now = _utc_now()

    result = remediations_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": STATUS_EXECUTING,
        },
        {
            "$set": {
                "status": STATUS_FAILED,
                "updated_at": now,
                "execution_error": _clean(
                    execution_error
                ),
            }
        }
    )

    return result.modified_count > 0


# ============================================================
# UPDATE EXECUTION RESULT
# ============================================================

def update_execution_result(
    remediation_id,
    user_id,
    after_state=None,
    verification=None,
    execution_error=None,
):
    """
    Store the AWS execution result.

    This function does not call AWS.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    query = {
        "_id": object_id,
        "user_id": str(user_id),
    }

    update_fields = {
        "updated_at": _utc_now(),
    }

    if after_state is not None:
        update_fields[
            "after_state"
        ] = after_state

    if verification is not None:
        update_fields[
            "verification"
        ] = verification

    if execution_error is not None:
        update_fields[
            "execution_error"
        ] = _clean(execution_error)

    result = remediations_collection.update_one(
        query,
        {
            "$set": update_fields
        }
    )

    return result.modified_count > 0


# ============================================================
# RECONCILE SUCCESSFUL EXECUTION
# ============================================================

def reconcile_successful_execution(
    remediation_id,
    user_id,
):
    """
    Recovery helper.

    IMPORTANT:

    This function NEVER calls AWS.

    It only reconciles a database record when
    the stored execution evidence proves success.

    Requirements:

        after_state.success == True

        verification.verified == True

    It can recover:

        APPROVED -> COMPLETED
        EXECUTING -> COMPLETED

    This is useful if AWS execution succeeded but
    the process crashed before the final DB status update.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    remediation = remediations_collection.find_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
        }
    )

    if not remediation:
        return False

    current_status = str(
        remediation.get(
            "status",
            ""
        )
    ).upper()

    if current_status not in {
        STATUS_APPROVED,
        STATUS_EXECUTING,
    }:
        return False

    after_state = remediation.get(
        "after_state"
    ) or {}

    # Verification may be stored either at the top level
    # or inside after_state by older executor versions.
    verification = remediation.get(
        "verification"
    ) or {}

    if not isinstance(verification, dict):
        verification = {}

    nested_verification = {}

    if isinstance(after_state, dict):
        nested_verification = (
            after_state.get("verification")
            or {}
        )

    if not isinstance(nested_verification, dict):
        nested_verification = {}

    # Prefer the explicit top-level verification record.
    # Fall back to the nested record for legacy execution data.
    effective_verification = (
        verification
        if verification.get("verified") is True
        else nested_verification
    )

    execution_success = (
        isinstance(after_state, dict)
        and after_state.get("success") is True
    )

    verification_success = (
        isinstance(effective_verification, dict)
        and effective_verification.get("verified") is True
    )

    if not execution_success:
        return False

    if not verification_success:
        return False

    now = _utc_now()

    result = remediations_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": {
                "$in": [
                    STATUS_APPROVED,
                    STATUS_EXECUTING,
                ]
            },
        },
        {
            "$set": {
                "status": STATUS_COMPLETED,
                "completed_at": now,
                "updated_at": now,
                "execution_error": None,
            }
        }
    )

    return result.modified_count > 0


# ============================================================
# CANCEL REMEDIATION
# ============================================================

def cancel_remediation(
    remediation_id,
    user_id,
):
    """
    Cancel a remediation before execution.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    result = remediations_collection.update_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": {
                "$in": [
                    STATUS_PROPOSED,
                    STATUS_PENDING_APPROVAL,
                    STATUS_APPROVED,
                ]
            },
        },
        {
            "$set": {
                "status": STATUS_CANCELLED,
                "updated_at": _utc_now(),
            }
        }
    )

    return result.modified_count > 0


# ============================================================
# DELETE REMEDIATION
# ============================================================

def delete_remediation(
    remediation_id,
    user_id,
):
    """
    Delete only non-executed proposal records.

    Completed/failed/executing records are retained
    for auditability.
    """

    object_id = _to_object_id(
        remediation_id
    )

    if object_id is None:
        return False

    result = remediations_collection.delete_one(
        {
            "_id": object_id,
            "user_id": str(user_id),
            "status": {
                "$in": [
                    STATUS_PROPOSED,
                    STATUS_PENDING_APPROVAL,
                    STATUS_REJECTED,
                    STATUS_CANCELLED,
                ]
            },
        }
    )

    return result.deleted_count > 0


# ============================================================
# STATISTICS
# ============================================================

def get_remediation_statistics(
    user_id,
):
    """
    Tenant-scoped remediation statistics.
    """

    user_id = str(user_id)

    total = remediations_collection.count_documents(
        {
            "user_id": user_id
        }
    )

    proposed = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_PROPOSED,
        }
    )

    pending_approval = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_PENDING_APPROVAL,
        }
    )

    approved = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_APPROVED,
        }
    )

    executing = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_EXECUTING,
        }
    )

    completed = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_COMPLETED,
        }
    )

    failed = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_FAILED,
        }
    )

    rejected = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_REJECTED,
        }
    )

    cancelled = remediations_collection.count_documents(
        {
            "user_id": user_id,
            "status": STATUS_CANCELLED,
        }
    )

    return {
        "total": total,
        "proposed": proposed,
        "pending_approval": pending_approval,
        "approved": approved,
        "executing": executing,
        "completed": completed,
        "failed": failed,
        "rejected": rejected,
        "cancelled": cancelled,
    }


# ============================================================
# MARK REMEDIATION SCAN VERIFIED
# ============================================================

def mark_remediation_scan_verified(
    remediation_id,
    scan_id,
    verified_at=None,
    user_id=None,
):
    """
    Record authoritative scan verification on the exact remediation proposal.
    """
    object_id = _to_object_id(remediation_id)
    if object_id is None:
        return False

    now = verified_at or _utc_now()
    query = {"_id": object_id}
    if user_id is not None:
        query["user_id"] = str(user_id)

    result = remediations_collection.update_one(
        query,
        {
            "$set": {
                "verification.verified": True,
                "verification.scan_verified": True,
                "verification.scan_id": str(scan_id),
                "verification.scan_verified_at": now,
                "updated_at": now,
            }
        },
    )
    return result.modified_count > 0


# ============================================================
# INDEXES
# ============================================================

def ensure_indexes():
    """
    Create indexes required for production queries.

    Safe to call multiple times.
    """

    try:

        # ----------------------------------------------------
        # User + created_at
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("created_at", -1),
            ],
            name="user_created_at",
        )

        # ----------------------------------------------------
        # User + status + created_at
        # ----------------------------------------------------
        # IMPORTANT:
        # MongoDB already has this index under the name
        # user_status_created_at.
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("status", 1),
                ("created_at", -1),
            ],
            name="user_status_created_at",
        )

        # ----------------------------------------------------
        # User + finding
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("finding_id", 1),
            ],
            name="user_finding",
        )

        # ----------------------------------------------------
        # User + account
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("account_id", 1),
            ],
            name="user_account",
        )

        # ----------------------------------------------------
        # Active deduplication lookup
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("account_id", 1),
                ("finding_id", 1),
                ("action_type", 1),
                ("status", 1),
                ("created_at", -1),
            ],
            name="active_remediation_lookup",
        )

        # ----------------------------------------------------
        # User + action
        # ----------------------------------------------------

        remediations_collection.create_index(
            [
                ("user_id", 1),
                ("action_type", 1),
            ],
            name="user_action_index",
        )

        return True

    except Exception as exc:

        print(
            "[WARNING] Failed to create remediation "
            f"indexes: {exc}"
        )

        return False


# ============================================================
# INITIALIZE INDEXES
# ============================================================

ensure_indexes()