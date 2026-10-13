# ============================================================
# CloudGuardAI - Scan History Service
# Production / SaaS Version
# ============================================================

from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


COLLECTION = db.scan_history


# ============================================================
# CONSTANTS
# ============================================================

DEFAULT_SCAN_STATUS = "completed"


# ============================================================
# HELPERS
# ============================================================

def _safe_object_id(value):
    """
    Safely convert a value into MongoDB ObjectId.

    Returns:
        ObjectId | None
    """

    try:
        return ObjectId(value)

    except (InvalidId, TypeError):
        return None


def _normalize_string(value):
    """
    Safely normalize a value into a stripped string.

    Returns:
        str | None
    """

    if value is None:
        return None

    value = str(value).strip()

    return value if value else None


def _serialize_scan(scan):
    """
    Convert MongoDB-specific values into API-safe values.
    """

    if not scan:
        return None

    scan = dict(scan)

    if scan.get("_id") is not None:
        scan["_id"] = str(scan["_id"])

    # --------------------------------------------------------
    # Normalize ObjectId-style account references
    # --------------------------------------------------------

    if isinstance(scan.get("account_id"), ObjectId):
        scan["account_id"] = str(scan["account_id"])

    # --------------------------------------------------------
    # Normalize datetime values
    #
    # FastAPI/Pydantic can usually handle datetimes, but keeping
    # Mongo serialization predictable makes this service safer
    # for future report/export integrations.
    # --------------------------------------------------------

    return scan


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    data: dict,
    user_id: str,
    account_id: str = None,
):
    """
    Save a completed or in-progress AWS scan.

    Tenant-safe fields:
        user_id
        organization_id
        account_id
        aws_account_id

    `account_id` is the internal CloudGuardAI AWS-account
    document ID. This is intentionally stored separately from
    `aws_account_id`, which is the real 12-digit AWS account ID.
    """

    now = datetime.utcnow()

    scan = dict(data or {})

    # ========================================================
    # TENANT / OWNER
    # ========================================================

    normalized_user_id = _normalize_string(user_id)

    if not normalized_user_id:
        raise ValueError(
            "A valid user_id is required to save a scan."
        )

    scan["user_id"] = normalized_user_id

    # ========================================================
    # INTERNAL CLOUDGUARDAI ACCOUNT ID
    # ========================================================

    # Priority:
    #
    # 1. Explicit account_id function argument
    # 2. account_id already present in scan data
    #
    # This preserves compatibility with existing scan callers.

    normalized_account_id = _normalize_string(
        account_id
        if account_id is not None
        else scan.get("account_id")
    )

    if normalized_account_id:

        account_object_id = _safe_object_id(
            normalized_account_id
        )

        if account_object_id:

            # Store as string for consistent application-level
            # tenant/account filtering.
            scan["account_id"] = str(
                account_object_id
            )

        else:

            # Do not silently store malformed Mongo IDs.
            raise ValueError(
                "Invalid CloudGuardAI account_id."
            )

    else:

        # Backward compatibility:
        #
        # Existing historical scans may not have account_id.
        # We don't fail those old-style callers here.
        #
        # New scan creation code should always provide account_id.

        scan.pop(
            "account_id",
            None
        )

    # ========================================================
    # AWS ACCOUNT ID
    # ========================================================

    aws_account_id = _normalize_string(
        scan.get("aws_account_id")
    )

    if aws_account_id:
        scan["aws_account_id"] = aws_account_id

    # ========================================================
    # ACCOUNT NAME
    # ========================================================

    account_name = _normalize_string(
        scan.get("account_name")
    )

    if account_name:
        scan["account_name"] = account_name

    # ========================================================
    # SCAN TIMESTAMPS
    # ========================================================

    # Only create these timestamps here when saving a new scan.

    scan["scan_time"] = now
    scan["created_at"] = now
    scan["updated_at"] = now

    # ========================================================
    # SCAN LIFECYCLE
    # ========================================================

    status = _normalize_string(
        scan.get("status")
    )

    scan["status"] = (
        status
        if status
        else DEFAULT_SCAN_STATUS
    )

    # ========================================================
    # SAVE
    # ========================================================

    result = COLLECTION.insert_one(
        scan
    )

    return str(
        result.inserted_id
    )


# ============================================================
# GET ALL SCANS
# ============================================================

def get_all_scans(
    user_id: str,
    projection: dict = None,
    limit: int = None,
    organization_id: str = None,
):
    """
    Get scan history.

    SaaS behavior:
        - If organization_id is provided, return scans belonging
          to that organization.
        - Otherwise, preserve legacy user-level filtering.

    This keeps existing callers compatible while allowing
    organization-level SaaS scan history.
    """

    normalized_user_id = _normalize_string(
        user_id
    )

    normalized_organization_id = _normalize_string(
        organization_id
    )

    if not normalized_user_id and not normalized_organization_id:
        return []

    # --------------------------------------------------------
    # SaaS TENANT FILTER
    # --------------------------------------------------------

    if normalized_organization_id:

        query = {
            "organization_id": normalized_organization_id
        }

    else:

        query = {
            "user_id": normalized_user_id
        }

    cursor = (
        COLLECTION.find(
            query,
            projection
        )
        .sort(
            "scan_time",
            -1
        )
    )

    # --------------------------------------------------------
    # Optional result limit
    # --------------------------------------------------------

    if limit is not None:

        try:
            limit = int(limit)

        except (
            ValueError,
            TypeError
        ):
            limit = 20

        limit = max(
            1,
            min(
                limit,
                100
            )
        )

        cursor = cursor.limit(
            limit
        )

    scans = list(
        cursor
    )

    return [
        _serialize_scan(scan)
        for scan in scans
    ]


# ============================================================
# GET USER SCANS FOR ONE ACCOUNT
# ============================================================

def get_account_scans(
    user_id: str,
    account_id: str,
):

    normalized_user_id = _normalize_string(
        user_id
    )

    account_object_id = _safe_object_id(
        account_id
    )

    if not normalized_user_id:
        return []

    if account_object_id is None:
        return []

    scans = list(
        COLLECTION.find(
            {
                "user_id": normalized_user_id,
                "account_id": str(
                    account_object_id
                ),
            }
        )
        .sort(
            "scan_time",
            -1
        )
    )

    return [
        _serialize_scan(scan)
        for scan in scans
    ]


# ============================================================
# GET SINGLE SCAN
# ============================================================

def get_scan(
    scan_id: str,
    user_id: str,
    organization_id: str = None,
):
    """
    Get a single scan safely.

    Supports both:
        - MongoDB ObjectId _id
        - String _id

    Access is restricted to:
        - authenticated organization
        OR
        - authenticated user for legacy scans
    """

    normalized_scan_id = _normalize_string(
        scan_id
    )

    normalized_user_id = _normalize_string(
        user_id
    )

    normalized_organization_id = _normalize_string(
        organization_id
    )

    if not normalized_scan_id:
        return None

    if not normalized_user_id and not normalized_organization_id:
        return None

    possible_ids = [normalized_scan_id]

    object_id = _safe_object_id(
        normalized_scan_id
    )

    if object_id is not None:
        possible_ids.append(object_id)

    scan = None

    for possible_id in possible_ids:
        scan = COLLECTION.find_one(
            {
                "_id": possible_id
            }
        )

        if scan:
            break

    if not scan:
        return None

    stored_organization_id = _normalize_string(
        scan.get("organization_id")
    )

    stored_user_id = _normalize_string(
        scan.get("user_id")
    )

    if normalized_organization_id:

        if stored_organization_id:
            if stored_organization_id != normalized_organization_id:
                return None
        else:
            if not normalized_user_id:
                return None

            if stored_user_id != normalized_user_id:
                return None

    else:

        if not normalized_user_id:
            return None

        if stored_user_id != normalized_user_id:
            return None

    return _serialize_scan(
        scan
    )


# ============================================================
# GET SINGLE USER + ACCOUNT SCAN
# ============================================================

def get_account_scan(
    scan_id: str,
    user_id: str,
    account_id: str,
):

    scan_object_id = _safe_object_id(
        scan_id
    )

    account_object_id = _safe_object_id(
        account_id
    )

    normalized_user_id = _normalize_string(
        user_id
    )

    if scan_object_id is None:
        return None

    if account_object_id is None:
        return None

    if not normalized_user_id:
        return None

    scan = COLLECTION.find_one(
        {
            "_id": scan_object_id,
            "user_id": normalized_user_id,
            "account_id": str(
                account_object_id
            ),
        }
    )

    return _serialize_scan(
        scan
    )


# ============================================================
# DELETE USER SCAN
# ============================================================

def delete_scan(
    scan_id: str,
    user_id: str,
    organization_id: str = None,
):
    """
    Delete a scan safely.

    SaaS behavior:
        - If organization_id is provided, deletion is scoped
          to that organization.
        - Otherwise, preserve legacy user-level filtering.
    """

    object_id = _safe_object_id(scan_id)

    normalized_user_id = _normalize_string(user_id)
    normalized_organization_id = _normalize_string(organization_id)

    if object_id is None:
        return False

    if not normalized_user_id and not normalized_organization_id:
        return False

    # --------------------------------------------------------
    # TENANT-SAFE DELETE FILTER
    # --------------------------------------------------------

    query = {
        "_id": object_id,
    }

    if normalized_organization_id:
        query["organization_id"] = normalized_organization_id
    else:
        query["user_id"] = normalized_user_id

    result = COLLECTION.delete_one(query)

    return result.deleted_count > 0


# ============================================================
# SEARCH SCANS
# ============================================================

def search_scans(
    keyword: str,
    user_id: str,
    organization_id: str = None,
):
    """
    Search scans within the organization when organization_id
    is provided.

    Otherwise, use legacy user-level filtering.
    """

    keyword = str(
        keyword or ""
    ).strip().lower()

    if not keyword:

        return get_all_scans(
            user_id,
            organization_id=organization_id
        )

    scans = get_all_scans(
        user_id,
        organization_id=organization_id
    )

    result = []

    for scan in scans:

        searchable_fields = [

            scan.get(
                "account",
                ""
            ),

            scan.get(
                "account_name",
                ""
            ),

            scan.get(
                "aws_account_id",
                ""
            ),

            scan.get(
                "account_id",
                ""
            ),

            scan.get(
                "security_level",
                ""
            ),

            scan.get(
                "security_posture",
                ""
            ),

            scan.get(
                "status",
                ""
            ),

            scan.get(
                "arn",
                ""
            ),

        ]

        searchable_text = " ".join(
            str(value or "").lower()
            for value in searchable_fields
        )

        if keyword in searchable_text:

            result.append(
                scan
            )

    return result


# ============================================================
# FILTER SCANS
# ============================================================

def filter_scans(
    level: str,
    user_id: str,
    organization_id: str = None,
):
    """
    Filter scans by security level within the organization when
    organization_id is provided.

    Otherwise, use legacy user-level filtering.
    """

    level = str(
        level or ""
    ).strip().lower()

    scans = get_all_scans(
        user_id,
        organization_id=organization_id
    )

    result = []

    for scan in scans:

        scan_level = str(
            scan.get(
                "security_level",
                ""
            )
        ).lower()

        if scan_level == level:

            result.append(
                scan
            )

    return result


# ============================================================
# FILTER SCANS BY ACCOUNT
# ============================================================

def filter_scans_by_account(
    account_id: str,
    user_id: str,
):

    account_object_id = _safe_object_id(
        account_id
    )

    normalized_user_id = _normalize_string(
        user_id
    )

    if account_object_id is None:
        return []

    if not normalized_user_id:
        return []

    scans = list(
        COLLECTION.find(
            {
                "user_id": normalized_user_id,
                "account_id": str(
                    account_object_id
                ),
            }
        )
        .sort(
            "scan_time",
            -1
        )
    )

    return [
        _serialize_scan(scan)
        for scan in scans
    ]


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def statistics(
    user_id: str
):

    scans = get_all_scans(
        user_id
    )

    if not scans:

        return {
            "total_scans": 0,
            "latest_risk_score": 0,
            "average_risk_score": 0,
            "security_level": "Unknown",
            "aws_accounts": 0,
        }

    total = len(
        scans
    )

    latest = scans[0]

    # ========================================================
    # RISK SCORES
    # ========================================================

    risk_scores = []

    for scan in scans:

        try:

            score = float(
                scan.get(
                    "risk_score",
                    0
                )
            )

            risk_scores.append(
                score
            )

        except (
            ValueError,
            TypeError
        ):

            continue

    if risk_scores:

        average = round(
            sum(risk_scores)
            /
            len(risk_scores)
        )

    else:

        average = 0

    # ========================================================
    # AWS ACCOUNTS
    # ========================================================

    accounts = set()

    for scan in scans:

        account_id = scan.get(
            "account_id"
        )

        aws_account_id = scan.get(
            "aws_account_id"
        )

        account = scan.get(
            "account"
        )

        if account_id:

            accounts.add(
                f"internal:{account_id}"
            )

        elif aws_account_id:

            accounts.add(
                f"aws:{aws_account_id}"
            )

        elif account:

            accounts.add(
                f"name:{account}"
            )

    # ========================================================
    # LATEST SCAN
    # ========================================================

    latest_risk_score = latest.get(
        "risk_score",
        0
    )

    latest_security_level = latest.get(
        "security_level",
        "Unknown"
    )

    # ========================================================
    # RESPONSE
    # ========================================================

    return {

        "total_scans":
            total,

        "latest_risk_score":
            latest_risk_score,

        "average_risk_score":
            average,

        "security_level":
            latest_security_level,

        "aws_accounts":
            len(accounts),

    }


# ============================================================
# FINDINGS COUNT FOR USER
# ============================================================

def get_findings_count(
    user_id: str
):

    normalized_user_id = _normalize_string(
        user_id
    )

    if not normalized_user_id:
        return 0

    pipeline = [

        {
            "$match": {
                "user_id": normalized_user_id
            }
        },

        {
            "$project": {
                "finding_count": {
                    "$size": {
                        "$ifNull": [
                            "$findings",
                            []
                        ]
                    }
                }
            }
        },

        {
            "$group": {
                "_id": None,
                "total": {
                    "$sum": "$finding_count"
                }
            }
        }

    ]

    result = list(
        COLLECTION.aggregate(
            pipeline
        )
    )

    if not result:

        return 0

    return int(
        result[0].get(
            "total",
            0
        )
    )


# ============================================================
# GET LATEST USER SCAN
# ============================================================

def get_latest_scan(
    user_id: str
):

    normalized_user_id = _normalize_string(
        user_id
    )

    if not normalized_user_id:
        return None

    scan = COLLECTION.find_one(
        {
            "user_id": normalized_user_id
        },
        sort=[
            (
                "scan_time",
                -1
            )
        ]
    )

    return _serialize_scan(
        scan
    )


# ============================================================
# GET LATEST SCAN FOR ACCOUNT
# ============================================================

def get_latest_account_scan(
    user_id: str,
    account_id: str,
):

    normalized_user_id = _normalize_string(
        user_id
    )

    account_object_id = _safe_object_id(
        account_id
    )

    if not normalized_user_id:
        return None

    if account_object_id is None:
        return None

    scan = COLLECTION.find_one(
        {
            "user_id": normalized_user_id,
            "account_id": str(
                account_object_id
            ),
        },
        sort=[
            (
                "scan_time",
                -1
            )
        ]
    )

    return _serialize_scan(
        scan
    )


# ============================================================
# UPDATE SCAN STATUS
# ============================================================

def update_scan_status(
    scan_id: str,
    user_id: str,
    status: str
):

    object_id = _safe_object_id(
        scan_id
    )

    normalized_user_id = _normalize_string(
        user_id
    )

    normalized_status = _normalize_string(
        status
    )

    if object_id is None:
        return False

    if not normalized_user_id:
        return False

    if not normalized_status:
        return False

    result = COLLECTION.update_one(

        {
            "_id": object_id,
            "user_id": normalized_user_id
        },

        {
            "$set": {
                "status": normalized_status,
                "updated_at": datetime.utcnow()
            }
        }

    )

    return result.modified_count > 0


# ============================================================
# UPDATE SCAN ACCOUNT REFERENCE
# ============================================================

def update_scan_account(
    scan_id: str,
    user_id: str,
    account_id: str,
    aws_account_id: str = None,
    account_name: str = None,
):
    """
    Attach the canonical CloudGuardAI account reference to an
    existing scan.

    Useful for migrating/fixing older scan records that were
    created before account_id was persisted.
    """

    scan_object_id = _safe_object_id(
        scan_id
    )

    account_object_id = _safe_object_id(
        account_id
    )

    normalized_user_id = _normalize_string(
        user_id
    )

    if scan_object_id is None:
        return False

    if account_object_id is None:
        return False

    if not normalized_user_id:
        return False

    set_fields = {
        "account_id": str(
            account_object_id
        ),
        "updated_at": datetime.utcnow(),
    }

    normalized_aws_account_id = _normalize_string(
        aws_account_id
    )

    if normalized_aws_account_id:

        set_fields[
            "aws_account_id"
        ] = normalized_aws_account_id

    normalized_account_name = _normalize_string(
        account_name
    )

    if normalized_account_name:

        set_fields[
            "account_name"
        ] = normalized_account_name

    result = COLLECTION.update_one(

        {
            "_id": scan_object_id,
            "user_id": normalized_user_id,
        },

        {
            "$set": set_fields
        }

    )

    return result.modified_count > 0