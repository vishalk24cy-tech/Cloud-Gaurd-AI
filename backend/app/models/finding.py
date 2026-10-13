# ============================================================
# CloudGuardAI - Finding Model
# Production / Commercial SaaS
# ============================================================

from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


# ============================================================
# MongoDB Collection
# ============================================================

findings_collection = db["findings"]


# ============================================================
# Workflow Constants
# ============================================================

WORKFLOW_OPEN = "OPEN"
WORKFLOW_IN_PROGRESS = "IN_PROGRESS"
WORKFLOW_RESOLVED = "RESOLVED"
WORKFLOW_IGNORED = "IGNORED"
WORKFLOW_NOT_APPLICABLE = "NOT_APPLICABLE"


ALLOWED_WORKFLOW_STATUSES = {
    WORKFLOW_OPEN,
    WORKFLOW_IN_PROGRESS,
    WORKFLOW_RESOLVED,
    WORKFLOW_IGNORED,
    WORKFLOW_NOT_APPLICABLE,
}


# ============================================================
# Detection Constants
# ============================================================

PROTECTED_DETECTION_STATUSES = {
    "PROTECTED",
    "PASS",
    "PASSED",
}


ACTIONABLE_DETECTION_STATUSES = {
    "PUBLIC",
    "FAILED",
    "FAIL",
    "RISK",
    "HIGH PRIVILEGE",
    "REVIEW",
    "WARNING",
    "UNKNOWN",
    "ACTIVE",
}


# ============================================================
# Severity Constants
# ============================================================

ALLOWED_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
}


# ============================================================
# Security Graph Relationship Constants
# ============================================================

GRAPH_SCHEMA_VERSION = "1.0"

ALLOWED_RELATIONSHIP_TYPES = {
    "CONTAINS", "ATTACHED_TO", "ASSOCIATED_WITH", "ASSUMES_ROLE",
    "USES", "PROTECTS", "EXPOSES", "ROUTES_TO", "DEPENDS_ON",
    "TRUSTS", "GRANTS", "HOSTS", "TARGETS", "MEMBER_OF", "CONNECTED_TO",
}

ALLOWED_GRAPH_NODE_TYPES = {
    "AWS_ACCOUNT", "EC2", "SECURITY_GROUP", "IAM_ROLE", "IAM_USER",
    "IAM_POLICY", "S3_BUCKET", "RDS_INSTANCE", "LAMBDA_FUNCTION",
    "CLOUDTRAIL", "KMS_KEY", "VPC", "SUBNET", "RESOURCE",
    "INTERNET", "FINDING",
}



# ============================================================
# Safe ObjectId Conversion
# ============================================================

def _to_object_id(value):
    """
    Safely convert a value into MongoDB ObjectId.

    Returns:
        ObjectId | None
    """

    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        return None


# ============================================================
# Serialization
# ============================================================

def _serialize_finding(finding):
    """
    Convert MongoDB-specific values into API-safe values.
    """

    if not finding:
        return None

    finding = dict(finding)

    if finding.get("_id") is not None:
        finding["_id"] = str(finding["_id"])

    return finding


# ============================================================
# Detection Status Normalization
# ============================================================

def _normalize_detection_status(value):
    """
    Normalize scanner detection status.

    Examples:
        passed -> PASSED
        protected -> PROTECTED
        high privilege -> HIGH PRIVILEGE
    """

    if value is None:
        return "UNKNOWN"

    return str(value).strip().upper()


# ============================================================
# Severity Normalization
# ============================================================

def _normalize_severity(value, default="LOW"):
    """
    Normalize finding severity.
    """

    if value is None:
        return default

    severity = str(value).strip().upper()

    if severity not in ALLOWED_SEVERITIES:
        return default

    return severity


# ============================================================
# Security Graph Normalization
# ============================================================

def _clean_graph_value(value, max_length=1000):
    """Normalize and bound graph values from scanner evidence."""
    if value is None:
        return None
    value = str(value).strip()
    return value[:max_length] if value else None


def _normalize_graph_node_type(value):
    """Normalize AWS/security graph node types."""
    if value is None:
        return "RESOURCE"

    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")

    aliases = {
        "EC2_INSTANCE": "EC2",
        "SECURITY_GROUP_RULE": "SECURITY_GROUP",
        "ROLE": "IAM_ROLE",
        "IAM": "IAM_ROLE",
        "BUCKET": "S3_BUCKET",
        "RDS": "RDS_INSTANCE",
        "LAMBDA": "LAMBDA_FUNCTION",
        "KMS": "KMS_KEY",
        "SG": "SECURITY_GROUP",
        "EC2_SECURITY_GROUP": "SECURITY_GROUP",
        "VPC_NETWORK": "VPC",
    }

    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in ALLOWED_GRAPH_NODE_TYPES else "RESOURCE"


def _normalize_relationship_type(value):
    """Normalize a graph relationship type against the allowlist."""
    if value is None:
        return None

    normalized = str(value).strip().upper().replace("-", "_").replace(" ", "_")
    return normalized if normalized in ALLOWED_RELATIONSHIP_TYPES else None


def _normalize_graph_evidence(value, max_depth=3):
    """Safely normalize relationship evidence for MongoDB persistence."""
    if not isinstance(value, dict):
        return {}

    def clean(obj, depth):
        if depth > max_depth:
            return None
        if isinstance(obj, dict):
            result = {}
            for key, val in list(obj.items())[:50]:
                key_text = _clean_graph_value(key, 120)
                if not key_text:
                    continue
                cleaned = clean(val, depth + 1)
                if cleaned is not None:
                    result[key_text] = cleaned
            return result
        if isinstance(obj, list):
            return [clean(item, depth + 1) for item in obj[:50]]
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            if isinstance(obj, str):
                return _clean_graph_value(obj, 2048)
            return obj
        return _clean_graph_value(obj, 2048)

    return clean(value, 0) or {}


def _normalize_graph_relationship(value):
    """Validate one scanner-supplied graph relationship."""
    if not isinstance(value, dict):
        return None

    source_type = _normalize_graph_node_type(value.get("source_type"))
    target_type = _normalize_graph_node_type(value.get("target_type"))
    relationship_type = _normalize_relationship_type(
        value.get("relationship_type")
    )
    source_id = _clean_graph_value(value.get("source_id"), 500)
    target_id = _clean_graph_value(value.get("target_id"), 500)

    if not source_id or not target_id or not relationship_type:
        return None

    return {
        "source_type": source_type,
        "source_id": source_id,
        "target_type": target_type,
        "target_id": target_id,
        "relationship_type": relationship_type,
        "evidence": _normalize_graph_evidence(
            value.get("evidence") or {}
        ),
    }


def _normalize_related_resource(value):
    """Validate one scanner-supplied related AWS resource."""
    if not isinstance(value, dict):
        return None

    node_type = _normalize_graph_node_type(value.get("node_type"))
    resource_id = _clean_graph_value(value.get("resource_id"), 500)

    if not resource_id:
        return None

    return {
        "node_type": node_type,
        "resource_id": resource_id,
        "resource_name": _clean_graph_value(value.get("resource_name"), 500),
        "resource_arn": _clean_graph_value(value.get("resource_arn"), 2048),
        "service": _clean_graph_value(value.get("service"), 100),
        "signals": _normalize_graph_evidence(value.get("signals") or {}),
        "evidence": _normalize_graph_evidence(value.get("evidence") or {}),
    }


def _build_graph_metadata(data, now=None):
    """
    Build normalized relationship metadata for graph analysis.

    The scanner may place AWS-verified relationship data inside the
    ``security_graph`` object. That nested object is merged here so the
    data survives the finding model's persistence/upsert boundary.
    """
    now = now or datetime.utcnow()

    nested_graph = data.get("security_graph")
    if not isinstance(nested_graph, dict):
        nested_graph = {}

    # Nested graph fields are preferred because relationship enrichment
    # deliberately writes its normalized AWS resource identity there.
    graph_data = dict(data)
    graph_data.update(nested_graph)

    attack_path = graph_data.get("attack_path", [])
    if not isinstance(attack_path, list):
        attack_path = []

    attack_path = [
        _clean_graph_value(item, 500)
        for item in attack_path[:25]
    ]
    attack_path = [item for item in attack_path if item]

    try:
        attack_path_score = float(
            graph_data.get("attack_path_score", 0) or 0
        )
    except (TypeError, ValueError):
        attack_path_score = 0.0

    relationships = []
    raw_relationships = graph_data.get("relationships") or []
    if isinstance(raw_relationships, list):
        seen_relationships = set()
        for raw in raw_relationships[:500]:
            relationship = _normalize_graph_relationship(raw)
            if not relationship:
                continue
            key = (
                relationship["source_type"],
                relationship["source_id"],
                relationship["target_type"],
                relationship["target_id"],
                relationship["relationship_type"],
            )
            if key in seen_relationships:
                continue
            seen_relationships.add(key)
            relationships.append(relationship)

    related_resources = []
    raw_related = graph_data.get("related_resources") or []
    if isinstance(raw_related, list):
        seen_related = set()
        for raw in raw_related[:500]:
            related = _normalize_related_resource(raw)
            if not related:
                continue
            key = (
                related["node_type"],
                related["resource_id"],
            )
            if key in seen_related:
                continue
            seen_related.add(key)
            related_resources.append(related)

    graph_node_type = _normalize_graph_node_type(
        graph_data.get("graph_node_type")
        or graph_data.get("resource_type")
        or graph_data.get("node_type")
    )

    return {
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
        "resource_id": _clean_graph_value(
            graph_data.get("resource_id")
            or graph_data.get("resource")
            or graph_data.get("resource_identifier"),
            500,
        ),
        "resource_arn": _clean_graph_value(
            graph_data.get("resource_arn") or graph_data.get("arn"),
            2048,
        ),
        "resource_name": _clean_graph_value(
            graph_data.get("resource_name"),
            500,
        ),
        "graph_node_type": graph_node_type,
        "parent_resource_id": _clean_graph_value(
            graph_data.get("parent_resource_id"),
            500,
        ),
        "parent_resource_type": (
            _normalize_graph_node_type(graph_data.get("parent_resource_type"))
            if graph_data.get("parent_resource_type")
            else None
        ),
        "relationship_type": _normalize_relationship_type(
            graph_data.get("relationship_type")
        ),
        "related_resource_id": _clean_graph_value(
            graph_data.get("related_resource_id"),
            500,
        ),
        "related_resource_type": (
            _normalize_graph_node_type(graph_data.get("related_resource_type"))
            if graph_data.get("related_resource_type")
            else None
        ),
        "related_resource_arn": _clean_graph_value(
            graph_data.get("related_resource_arn"),
            2048,
        ),
        "relationships": relationships,
        "related_resources": related_resources,
        "internet_exposed": bool(
            graph_data.get("internet_exposed", False)
        ),
        "privilege_escalation": bool(
            graph_data.get("privilege_escalation", False)
        ),
        "lateral_movement": bool(
            graph_data.get("lateral_movement", False)
        ),
        "attack_path_score": max(
            0.0,
            min(100.0, attack_path_score),
        ),
        "attack_path": attack_path,
        "graph_updated_at": now,
    }


# ============================================================
# Workflow Status Calculation
# ============================================================

def _workflow_status_for_detection(
    detection_status,
    existing_status=None,
):
    """
    Determine customer workflow status.

    Protected controls:
        PROTECTED / PASS / PASSED
            -> NOT_APPLICABLE

    Existing actionable finding:
        Preserve customer workflow.

    New actionable finding:
        OPEN
    """

    detection_status = _normalize_detection_status(
        detection_status
    )

    if detection_status in PROTECTED_DETECTION_STATUSES:
        return WORKFLOW_NOT_APPLICABLE

    if existing_status in {
        WORKFLOW_OPEN,
        WORKFLOW_IN_PROGRESS,
        WORKFLOW_RESOLVED,
        WORKFLOW_IGNORED,
    }:
        return existing_status

    return WORKFLOW_OPEN


# ============================================================
# Organization Normalization
# ============================================================

def _normalize_organization_id(value):
    """Normalize an organization identifier for tenant-safe queries."""

    if value is None:
        return None

    value = str(value).strip()
    return value if value else None


# ============================================================
# Build Finding Query
# ============================================================

def _build_finding_query(
    finding_id,
    user_id,
    organization_id=None,
):
    """
    Build a tenant-safe finding query.

    The authenticated user is ALWAYS included.
    When organization_id is supplied, the organization is also
    included so a finding cannot cross SaaS tenant boundaries.
    """

    query = {
        "user_id": str(user_id)
    }

    organization_id = _normalize_organization_id(
        organization_id
    )

    if organization_id:
        query["organization_id"] = organization_id

    object_id = _to_object_id(finding_id)

    if object_id:
        query["_id"] = object_id
    else:
        query["finding_id"] = str(finding_id)

    return query


# ============================================================
# Create Finding
# ============================================================

def create_finding(data, user_id, organization_id=None):
    """
    Create a new finding.

    Every finding belongs to exactly one tenant/user.
    """

    now = datetime.utcnow()

    organization_id = _normalize_organization_id(
        organization_id or data.get("organization_id")
    )

    detection_status = _normalize_detection_status(
        data.get(
            "detection_status",
            data.get("status", "UNKNOWN"),
        )
    )

    workflow_status = _workflow_status_for_detection(
        detection_status
    )

    severity = _normalize_severity(
        data.get("severity", "LOW")
    )

    finding = {
        # ----------------------------------------------------
        # Tenant
        # ----------------------------------------------------

        "user_id": str(user_id),
        "organization_id": organization_id,

        # ----------------------------------------------------
        # Stable CloudGuardAI Identity
        # ----------------------------------------------------

        "finding_id": (
            str(data.get("finding_id"))
            if data.get("finding_id")
            else None
        ),

        # ----------------------------------------------------
        # AWS Account
        # ----------------------------------------------------

        "account_id": str(
            data.get("account_id", "")
        ),

        "aws_account_id": str(
            data.get("aws_account_id", "")
        ),

        "account_name": data.get(
            "account_name",
            "",
        ),

        # ----------------------------------------------------
        # AWS Resource
        # ----------------------------------------------------

        "service": data.get(
            "service",
            "AWS",
        ),

        "resource": data.get(
            "resource",
            "Unknown",
        ),

        "resource_type": data.get(
            "resource_type",
            "",
        ),

        # ----------------------------------------------------
        # Security Graph
        # ----------------------------------------------------

        "security_graph": _build_graph_metadata(
            data,
            now=now,
        ),

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        "severity": severity,

        # ----------------------------------------------------
        # Detection
        # ----------------------------------------------------

        "detection_status": detection_status,

        # ----------------------------------------------------
        # Customer Workflow
        # ----------------------------------------------------

        "status": workflow_status,

        "workflow_status": workflow_status,

        # ----------------------------------------------------
        # Finding Details
        # ----------------------------------------------------

        "issue": data.get(
            "issue",
            "",
        ),

        "description": data.get(
            "description",
            data.get(
                "issue",
                "",
            ),
        ),

        "evidence": data.get(
            "evidence",
            {},
        ),

        "impact": data.get(
            "impact",
            "",
        ),

        "recommendation": data.get(
            "recommendation",
            "",
        ),

        "remediation": data.get(
            "remediation",
            data.get(
                "recommendation",
                "",
            ),
        ),

        # ----------------------------------------------------
        # Compliance
        # ----------------------------------------------------

        "control_id": data.get(
            "control_id"
        ),

        "compliance": data.get(
            "compliance",
            [],
        ),

        # ----------------------------------------------------
        # Assignment
        # ----------------------------------------------------

        "assigned_to": data.get(
            "assigned_to"
        ),

        "notes": data.get(
            "notes",
            "",
        ),

        # ----------------------------------------------------
        # Resolution
        # ----------------------------------------------------

        "resolution": None,

        "resolved_at": None,

        # ----------------------------------------------------
        # Lifecycle
        # ----------------------------------------------------

        "first_seen": now,

        "last_seen": now,

        "created_at": now,

        "updated_at": now,
    }

    # Protected control
    if detection_status in PROTECTED_DETECTION_STATUSES:
        finding["status"] = WORKFLOW_NOT_APPLICABLE
        finding["workflow_status"] = WORKFLOW_NOT_APPLICABLE
        finding["resolution"] = "Control protected"
        finding["resolved_at"] = now

    result = findings_collection.insert_one(
        finding
    )

    finding["_id"] = str(
        result.inserted_id
    )

    return finding


# ============================================================
# Create OR Update Finding
# ============================================================

def upsert_finding(data, user_id, organization_id=None):
    """
    Create a new finding or update an existing finding.

    Stable finding_id allows the same security issue to
    persist across repeated scans.

    Customer workflow is preserved between scans.
    """

    now = datetime.utcnow()

    organization_id = _normalize_organization_id(
        organization_id or data.get("organization_id")
    )

    finding_id = data.get(
        "finding_id"
    )

    if not finding_id:
        raise ValueError(
            "finding_id is required"
        )

    user_id = str(user_id)

    query = {
        "user_id": user_id,
        "finding_id": str(finding_id),
    }

    if organization_id:
        query["organization_id"] = organization_id

    existing = findings_collection.find_one(
        query
    )

    # ========================================================
    # EXISTING FINDING
    # ========================================================

    if existing:

        detection_status = _normalize_detection_status(
            data.get(
                "detection_status",
                existing.get(
                    "detection_status",
                    "UNKNOWN",
                ),
            )
        )

        existing_status = existing.get(
            "status"
        )

        workflow_status = _workflow_status_for_detection(
            detection_status,
            existing_status,
        )

        severity = _normalize_severity(
            data.get(
                "severity",
                existing.get(
                    "severity",
                    "LOW",
                ),
            )
        )

        incoming_scan_time = data.get("scan_time") or data.get("last_seen") or now
        existing_last_seen = existing.get("last_seen")
        is_stale_scan = (
            isinstance(existing_last_seen, datetime)
            and isinstance(incoming_scan_time, datetime)
            and incoming_scan_time < existing_last_seen
        )

        update_fields = {
            # ------------------------------------------------
            # Scan lifecycle
            # ------------------------------------------------

            "last_seen": existing_last_seen if is_stale_scan else incoming_scan_time,
            "updated_at": now,

            # ------------------------------------------------
            # Detection
            # ------------------------------------------------

            "detection_status": detection_status,
            "severity": severity,

            # ------------------------------------------------
            # Workflow
            # ------------------------------------------------

            "status": workflow_status,
            "workflow_status": workflow_status,

            # ------------------------------------------------
            # Finding details
            # ------------------------------------------------

            "issue": data.get(
                "issue",
                existing.get(
                    "issue",
                    "",
                ),
            ),

            "description": data.get(
                "description",
                existing.get(
                    "description",
                    "",
                ),
            ),

            "evidence": data.get(
                "evidence",
                existing.get(
                    "evidence",
                    {},
                ),
            ),

            "impact": data.get(
                "impact",
                existing.get(
                    "impact",
                    "",
                ),
            ),

            "recommendation": data.get(
                "recommendation",
                existing.get(
                    "recommendation",
                    "",
                ),
            ),

            "remediation": data.get(
                "remediation",
                existing.get(
                    "remediation",
                    "",
                ),
            ),

            # ------------------------------------------------
            # Resource
            # ------------------------------------------------

            "service": data.get(
                "service",
                existing.get(
                    "service",
                    "AWS",
                ),
            ),

            "resource": data.get(
                "resource",
                existing.get(
                    "resource",
                    "Unknown",
                ),
            ),

            "resource_type": data.get(
                "resource_type",
                existing.get(
                    "resource_type",
                    "",
                ),
            ),

            # ------------------------------------------------
            # Security Graph
            # ------------------------------------------------

            # Scanner-supplied graph metadata is the authoritative
            # snapshot for this scan. Do not merge previous MongoDB
            # graph arrays into the current graph because that can
            # preserve stale rule-scoped evidence such as TCP/80 on
            # an SSH/TCP/22 finding. Workflow state is preserved
            # separately and is not affected by this replacement.
            "security_graph": _build_graph_metadata(
                data
                if isinstance(data.get("security_graph"), dict)
                else existing,
                now=now,
            ),

            # ------------------------------------------------
            # AWS Account
            # ------------------------------------------------

            "account_id": str(
                data.get(
                    "account_id",
                    existing.get(
                        "account_id",
                        "",
                    ),
                )
            ),

            "aws_account_id": str(
                data.get(
                    "aws_account_id",
                    existing.get(
                        "aws_account_id",
                        "",
                    ),
                )
            ),

            "account_name": data.get(
                "account_name",
                existing.get(
                    "account_name",
                    "",
                ),
            ),

            # ------------------------------------------------
            # Compliance
            # ------------------------------------------------

            "control_id": data.get(
                "control_id",
                existing.get(
                    "control_id"
                ),
            ),

            "compliance": data.get(
                "compliance",
                existing.get(
                    "compliance",
                    [],
                ),
            ),
        }

        # ====================================================
        # Scanner says protected
        # ====================================================

        if detection_status in PROTECTED_DETECTION_STATUSES:

            update_fields[
                "status"
            ] = WORKFLOW_NOT_APPLICABLE

            update_fields[
                "workflow_status"
            ] = WORKFLOW_NOT_APPLICABLE

            update_fields[
                "resolution"
            ] = "Control protected"

            update_fields[
                "resolved_at"
            ] = now

        # ====================================================
        # Previously protected, now vulnerable
        # ====================================================

        elif existing_status == WORKFLOW_NOT_APPLICABLE:

            update_fields[
                "status"
            ] = WORKFLOW_OPEN

            update_fields[
                "workflow_status"
            ] = WORKFLOW_OPEN

            update_fields[
                "resolution"
            ] = None

            update_fields[
                "resolved_at"
            ] = None

        findings_collection.update_one(
            query,
            {
                "$set": update_fields
            },
        )

        updated = findings_collection.find_one(
            query
        )

        return _serialize_finding(
            updated
        )

    # ========================================================
    # NEW FINDING
    # ========================================================

    return create_finding(
        data,
        user_id,
        organization_id=organization_id,
    )


# ============================================================
# Get User Findings
# ============================================================

def get_user_findings(
    user_id,
    status=None,
    severity=None,
    service=None,
    account_id=None,
    include_not_applicable=False,
    organization_id=None,
):
    """
    Return findings belonging only to the authenticated tenant.

    NOT_APPLICABLE findings are hidden by default.
    """

    query = {
        "user_id": str(user_id)
    }

    organization_id = _normalize_organization_id(
        organization_id
    )

    if organization_id:
        query["organization_id"] = organization_id

    if not include_not_applicable:
        query["status"] = {
            "$ne": WORKFLOW_NOT_APPLICABLE
        }

    if status:
        query["status"] = str(
            status
        ).strip().upper()

    if severity:
        query["severity"] = str(
            severity
        ).strip().upper()

    if service:
        query["service"] = str(
            service
        ).strip().upper()

    if account_id:
        query["account_id"] = str(
            account_id
        )

    findings = list(
        findings_collection
        .find(query)
        .sort(
            "created_at",
            -1,
        )
    )

    return [
        _serialize_finding(
            finding
        )
        for finding in findings
    ]


# ============================================================
# Get Single Finding
# ============================================================

def get_finding(
    finding_id,
    user_id,
    organization_id=None,
):
    """
    Get one finding while enforcing tenant ownership.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    finding = findings_collection.find_one(
        query
    )

    return _serialize_finding(
        finding
    )


# ============================================================
# Get Finding For Specific AWS Account
# ============================================================

def get_finding_for_account(
    finding_id,
    user_id,
    account_id,
    organization_id=None,
):
    """
    Security-critical helper.

    Verifies all three relationships:

        authenticated user
              ↓
        finding ownership
              ↓
        AWS account ownership

    The finding must belong to the specified account.

    This is intended for remediation and other
    security-sensitive workflows.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    query["account_id"] = str(
        account_id
    )

    finding = findings_collection.find_one(
        query
    )

    return _serialize_finding(
        finding
    )


# ============================================================
# Verify Finding Ownership
# ============================================================

def finding_belongs_to_user(
    finding_id,
    user_id,
    organization_id=None,
):
    """
    Return True when the finding belongs to the user.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    return (
        findings_collection.count_documents(
            query,
            limit=1,
        )
        > 0
    )


# ============================================================
# Verify Finding / Account Relationship
# ============================================================

def finding_belongs_to_account(
    finding_id,
    user_id,
    account_id,
    organization_id=None,
):
    """
    Return True when the finding belongs to the
    authenticated user and specified AWS account.
    """

    finding = get_finding_for_account(
        finding_id=finding_id,
        user_id=user_id,
        account_id=account_id,
        organization_id=organization_id,
    )

    return finding is not None


# ============================================================
# Check Finding Actionability
# ============================================================

def is_finding_actionable(finding):
    """
    Determine whether a finding is eligible for remediation.

    Protected / NOT_APPLICABLE findings cannot be remediated.
    """

    if not finding:
        return False

    workflow_status = str(
        finding.get(
            "status",
            "",
        )
    ).upper()

    detection_status = _normalize_detection_status(
        finding.get(
            "detection_status"
        )
    )

    if workflow_status == WORKFLOW_NOT_APPLICABLE:
        return False

    if detection_status in PROTECTED_DETECTION_STATUSES:
        return False

    return True


# ============================================================
# Update Finding Workflow Status
# ============================================================

def update_finding_status(
    finding_id,
    user_id,
    status,
    resolution=None,
    organization_id=None,
):
    """
    Update customer workflow status.

    Resolution is supported so the Findings API can safely
    provide a resolution message when closing a finding.
    """

    status = str(
        status
    ).strip().upper()

    if status not in ALLOWED_WORKFLOW_STATUSES:
        raise ValueError(
            f"Invalid finding status: {status}"
        )

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    existing = findings_collection.find_one(
        query
    )

    if not existing:
        return False

    now = datetime.utcnow()

    update_fields = {
        "status": status,
        "workflow_status": status,
        "updated_at": now,
    }

    # ========================================================
    # RESOLVED
    # ========================================================

    if status == WORKFLOW_RESOLVED:

        update_fields[
            "resolved_at"
        ] = now

        update_fields[
            "resolution"
        ] = (
            str(resolution).strip()
            if resolution
            else "Resolved"
        )

    # ========================================================
    # NOT APPLICABLE
    # ========================================================

    elif status == WORKFLOW_NOT_APPLICABLE:

        update_fields[
            "resolved_at"
        ] = now

        update_fields[
            "resolution"
        ] = (
            str(resolution).strip()
            if resolution
            else "Not applicable"
        )

    # ========================================================
    # REOPENED / OTHER WORKFLOW
    # ========================================================

    else:

        update_fields[
            "resolved_at"
        ] = None

        if resolution:
            update_fields[
                "resolution"
            ] = str(
                resolution
            ).strip()
        else:
            update_fields[
                "resolution"
            ] = None

    result = findings_collection.update_one(
        query,
        {
            "$set": update_fields
        },
    )

    return result.matched_count > 0


# ============================================================
# Assign Finding
# ============================================================

def assign_finding(
    finding_id,
    user_id,
    assigned_to,
    organization_id=None,
):
    """
    Assign a finding while enforcing tenant ownership.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    result = findings_collection.update_one(
        query,
        {
            "$set": {
                "assigned_to": assigned_to,
                "updated_at": datetime.utcnow(),
            }
        },
    )

    return result.matched_count > 0


# ============================================================
# Update Finding Notes
# ============================================================

def update_finding_notes(
    finding_id,
    user_id,
    notes,
    organization_id=None,
):
    """
    Update analyst notes while enforcing ownership.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    result = findings_collection.update_one(
        query,
        {
            "$set": {
                "notes": notes,
                "updated_at": datetime.utcnow(),
            }
        },
    )

    return result.matched_count > 0


# ============================================================
# Mark Finding As Seen
# ============================================================

def update_last_seen(
    finding_id,
    user_id,
    organization_id=None,
):
    """
    Update the last-seen timestamp.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    result = findings_collection.update_one(
        query,
        {
            "$set": {
                "last_seen": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
            }
        },
    )

    return result.matched_count > 0


# ============================================================
# Delete Finding
# ============================================================

def delete_finding(
    finding_id,
    user_id,
    organization_id=None,
):
    """
    Delete a finding belonging to the authenticated tenant.
    """

    query = _build_finding_query(
        finding_id,
        user_id,
        organization_id=organization_id,
    )

    result = findings_collection.delete_one(
        query
    )

    return result.deleted_count > 0


# ============================================================
# Security Graph Queries
# ============================================================

def get_graph_findings(
    user_id,
    account_id=None,
    service=None,
    include_resolved=False,
    organization_id=None,
):
    """
    Return graph-ready findings for one authenticated tenant.
    """
    query = {"user_id": str(user_id)}

    organization_id = _normalize_organization_id(organization_id)
    if organization_id:
        query["organization_id"] = organization_id

    if account_id:
        query["account_id"] = str(account_id)

    if service:
        query["service"] = str(service).strip().upper()

    if not include_resolved:
        query["status"] = {
            "$nin": [
                WORKFLOW_RESOLVED,
                WORKFLOW_IGNORED,
                WORKFLOW_NOT_APPLICABLE,
            ]
        }

    findings = list(
        findings_collection.find(query).sort("created_at", -1)
    )

    return [_serialize_finding(item) for item in findings]


def get_graph_findings_by_resource(
    user_id,
    resource_id,
    account_id=None,
    organization_id=None,
):
    """Return tenant-scoped findings attached to a graph resource."""
    query = {
        "user_id": str(user_id),
        "$or": [
            {"resource": str(resource_id)},
            {"security_graph.resource_id": str(resource_id)},
        ],
    }

    if organization_id:
        query["organization_id"] = organization_id

    if account_id:
        query["account_id"] = str(account_id)

    return [
        _serialize_finding(item)
        for item in findings_collection.find(query).sort("created_at", -1)
    ]


def get_graph_statistics(user_id, account_id=None, organization_id=None):
    """Return security-graph exposure statistics."""
    query = {
        "user_id": str(user_id),
        "status": {
            "$nin": [
                WORKFLOW_RESOLVED,
                WORKFLOW_IGNORED,
                WORKFLOW_NOT_APPLICABLE,
            ]
        },
    }

    organization_id = _normalize_organization_id(organization_id)
    if organization_id:
        query["organization_id"] = organization_id

    if account_id:
        query["account_id"] = str(account_id)

    return {
        "total_active_findings": findings_collection.count_documents(query),
        "internet_exposed": findings_collection.count_documents({
            **query,
            "security_graph.internet_exposed": True,
        }),
        "privilege_escalation": findings_collection.count_documents({
            **query,
            "security_graph.privilege_escalation": True,
        }),
        "lateral_movement": findings_collection.count_documents({
            **query,
            "security_graph.lateral_movement": True,
        }),
        "relationship_backed_findings": findings_collection.count_documents({
            **query,
            "security_graph.relationship_type": {
                "$in": list(ALLOWED_RELATIONSHIP_TYPES)
            },
        }),
        "graph_schema_version": GRAPH_SCHEMA_VERSION,
    }


# ============================================================
# Finding Statistics
# ============================================================

def get_finding_statistics(
    user_id,
    organization_id=None,
):
    """
    Return statistics for actionable findings.

    NOT_APPLICABLE findings are tracked separately.
    """

    user_id = str(user_id)

    base_query = {
        "user_id": user_id,
        "status": {
            "$ne": WORKFLOW_NOT_APPLICABLE
        },
    }

    organization_id = _normalize_organization_id(organization_id)
    if organization_id:
        base_query["organization_id"] = organization_id

    total = findings_collection.count_documents(
        base_query
    )

    open_count = findings_collection.count_documents(
        {
            **base_query,
            "status": WORKFLOW_OPEN,
        }
    )

    in_progress_count = findings_collection.count_documents(
        {
            **base_query,
            "status": WORKFLOW_IN_PROGRESS,
        }
    )

    resolved_count = findings_collection.count_documents(
        {
            **base_query,
            "status": WORKFLOW_RESOLVED,
        }
    )

    ignored_count = findings_collection.count_documents(
        {
            **base_query,
            "status": WORKFLOW_IGNORED,
        }
    )

    critical_count = findings_collection.count_documents(
        {
            **base_query,
            "severity": "CRITICAL",
        }
    )

    high_count = findings_collection.count_documents(
        {
            **base_query,
            "severity": "HIGH",
        }
    )

    medium_count = findings_collection.count_documents(
        {
            **base_query,
            "severity": "MEDIUM",
        }
    )

    low_count = findings_collection.count_documents(
        {
            **base_query,
            "severity": "LOW",
        }
    )

    protected_count = findings_collection.count_documents(
        {
            "user_id": user_id,
            "status": WORKFLOW_NOT_APPLICABLE,
        }
    )

    return {
        "total": total,

        "workflow": {
            "open": open_count,
            "in_progress": in_progress_count,
            "resolved": resolved_count,
            "ignored": ignored_count,
            "not_applicable": protected_count,
        },

        "severity": {
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
        },
    }


# ============================================================
# Finding Counts By Service
# ============================================================

def get_findings_by_service(
    user_id,
    organization_id=None,
):
    """
    Group actionable findings by AWS service.
    """

    organization_id = _normalize_organization_id(organization_id)

    match_query = {
        "user_id": str(user_id),
        "status": {
            "$ne": WORKFLOW_NOT_APPLICABLE
        },
    }

    if organization_id:
        match_query["organization_id"] = organization_id

    pipeline = [
        {
            "$match": match_query,
        },

        {
            "$group": {
                "_id": "$service",
                "count": {
                    "$sum": 1
                },
            }
        },

        {
            "$sort": {
                "count": -1
            }
        },
    ]

    results = list(
        findings_collection.aggregate(
            pipeline
        )
    )

    return [
        {
            "service": item.get(
                "_id",
                "AWS",
            ),
            "count": item.get(
                "count",
                0,
            ),
        }
        for item in results
    ]


# ============================================================
# Finding Counts By Severity
# ============================================================

def get_findings_by_severity(
    user_id,
    organization_id=None,
):
    """
    Group actionable findings by severity.
    """

    organization_id = _normalize_organization_id(organization_id)

    match_query = {
        "user_id": str(user_id),
        "status": {
            "$ne": WORKFLOW_NOT_APPLICABLE
        },
    }

    if organization_id:
        match_query["organization_id"] = organization_id

    pipeline = [
        {
            "$match": match_query,
        },

        {
            "$group": {
                "_id": "$severity",
                "count": {
                    "$sum": 1
                },
            }
        },
    ]

    results = list(
        findings_collection.aggregate(
            pipeline
        )
    )

    return {
        item.get(
            "_id",
            "LOW",
        ): item.get(
            "count",
            0,
        )
        for item in results
    }


# ============================================================
# MongoDB Indexes
# ============================================================

def create_finding_indexes():
    """
    Create production indexes for tenant-safe finding queries.
    """

    # --------------------------------------------------------
    # Unique finding identity per tenant
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("finding_id", 1),
        ],
        unique=True,
        sparse=True,
        name="user_finding_unique",
    )

    # --------------------------------------------------------
    # Tenant + workflow
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("status", 1),
        ],
        name="user_status_index",
    )

    # --------------------------------------------------------
    # Tenant + severity
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("severity", 1),
        ],
        name="user_severity_index",
    )

    # --------------------------------------------------------
    # Tenant + service
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("service", 1),
        ],
        name="user_service_index",
    )

    # --------------------------------------------------------
    # Tenant + AWS account
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
        ],
        name="user_account",
    )

    # --------------------------------------------------------
    # Tenant + account + finding
    #
    # Important for remediation ownership validation.
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("finding_id", 1),
        ],
        name="user_account_finding_index",
    )

    # --------------------------------------------------------
    # Recent findings
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("created_at", -1),
        ],
        name="user_created_index",
    )

    # --------------------------------------------------------
    # Last seen
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("last_seen", -1),
        ],
        name="user_last_seen_index",
    )

    # --------------------------------------------------------
    # Security graph indexes
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("security_graph.resource_id", 1),
        ],
        name="user_account_graph_resource_index",
    )

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("security_graph.relationship_type", 1),
        ],
        name="user_account_graph_relationship_index",
    )

    findings_collection.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("security_graph.internet_exposed", 1),
        ],
        name="user_account_graph_exposure_index",
    )

    # --------------------------------------------------------
    # SaaS organization indexes
    # --------------------------------------------------------

    findings_collection.create_index(
        [
            ("organization_id", 1),
            ("status", 1),
        ],
        name="organization_status_index",
    )

    findings_collection.create_index(
        [
            ("organization_id", 1),
            ("severity", 1),
        ],
        name="organization_severity_index",
    )

    findings_collection.create_index(
        [
            ("organization_id", 1),
            ("account_id", 1),
            ("finding_id", 1),
        ],
        name="organization_account_finding_index",
    )

    findings_collection.create_index(
        [
            ("organization_id", 1),
            ("created_at", -1),
        ],
        name="organization_created_index",
    )

    findings_collection.create_index(
        [
            ("organization_id", 1),
            ("last_seen", -1),
        ],
        name="organization_last_seen_index",
    )

    return True