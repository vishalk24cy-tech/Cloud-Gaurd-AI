# ============================================================
# CloudGuardAI - Compliance Model 2.1
# Production / Commercial SaaS
# ============================================================
# Purpose:
#   Versioned compliance evaluation snapshots with complete
#   tenant/account/scan/framework traceability.
#
# Tenant isolation:
#   user_id + account_id + scan_id + framework
#
# Persisted quality metadata:
#   - framework version
#   - mapping/catalog version
#   - engine version
#   - assessment state
#   - assessment coverage
#   - evidence confidence
#   - finding/control traceability
# ============================================================

from datetime import datetime
from typing import Optional

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


COLLECTION = db.compliance_history

FRAMEWORK_CIS = "CIS_AWS_Benchmark"
FRAMEWORK_NIST = "NIST_CSF"
FRAMEWORK_PCI = "PCI_DSS"

SUPPORTED_FRAMEWORKS = {
    FRAMEWORK_CIS,
    FRAMEWORK_NIST,
    FRAMEWORK_PCI,
}

STATUS_COMPLIANT = "COMPLIANT"
STATUS_AT_RISK = "AT_RISK"
STATUS_NON_COMPLIANT = "NON_COMPLIANT"
STATUS_REVIEW_REQUIRED = "REVIEW_REQUIRED"
STATUS_NOT_ASSESSED = "NOT_ASSESSED"

VALID_STATUSES = {
    STATUS_COMPLIANT,
    STATUS_AT_RISK,
    STATUS_NON_COMPLIANT,
    STATUS_REVIEW_REQUIRED,
    STATUS_NOT_ASSESSED,
}

DEFAULT_ENGINE_VERSION = "2.1"
DEFAULT_MAPPING_VERSION = "CloudGuardAI-MAP-1.0"

FRAMEWORK_METADATA = {
    FRAMEWORK_CIS: {
        "name": "CIS AWS Benchmark",
        "short_name": "CIS",
        "framework_version": "1.x",
        "mapping_version": DEFAULT_MAPPING_VERSION,
    },
    FRAMEWORK_NIST: {
        "name": "NIST Cybersecurity Framework",
        "short_name": "NIST",
        "framework_version": "CSF",
        "mapping_version": DEFAULT_MAPPING_VERSION,
    },
    FRAMEWORK_PCI: {
        "name": "PCI DSS",
        "short_name": "PCI DSS",
        "framework_version": "4.x",
        "mapping_version": DEFAULT_MAPPING_VERSION,
    },
}


def _safe_object_id(value):
    if isinstance(value, ObjectId):
        return value

    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError, ValueError):
        return None


def _clean(value):
    if value is None:
        return ""
    return str(value).strip()


def _normalize_framework(value):
    return _clean(value)


def _normalize_status(value):
    value = _clean(value).upper()
    return value if value in VALID_STATUSES else STATUS_NOT_ASSESSED


def _serialize(document):
    if not document:
        return None

    document = dict(document)

    if "_id" in document:
        document["_id"] = str(document["_id"])

    for key in ("created_at", "updated_at", "evaluated_at"):
        if isinstance(document.get(key), datetime):
            document[key] = document[key].isoformat()

    return document


def _framework_metadata(framework):
    return dict(FRAMEWORK_METADATA.get(framework, {}))


def _safe_dict(value):
    return value if isinstance(value, dict) else {}


def _extract_framework_result(compliance_result, framework):
    frameworks = _safe_dict(compliance_result.get("frameworks"))
    result = frameworks.get(framework, {})
    return result if isinstance(result, dict) else {}


def _extract_traceability(framework_result):
    control_results = framework_result.get("control_results", [])
    if not isinstance(control_results, list):
        control_results = []

    finding_ids = []
    control_ids = []

    for control in control_results:
        if not isinstance(control, dict):
            continue

        finding_id = _clean(control.get("finding_id"))
        control_id = _clean(
            control.get("control_id")
            or control.get("control_key")
        )

        if finding_id and finding_id not in finding_ids:
            finding_ids.append(finding_id)

        if control_id and control_id not in control_ids:
            control_ids.append(control_id)

    return {
        "finding_ids": finding_ids,
        "control_ids": control_ids,
    }


def _extract_versioned_metadata(compliance_result, framework, framework_result):
    fallback = _framework_metadata(framework)
    result_metadata = _safe_dict(framework_result.get("metadata"))
    engine_metadata = _safe_dict(compliance_result.get("engine_metadata"))

    framework_version = (
        result_metadata.get("version")
        or result_metadata.get("framework_version")
        or framework_result.get("framework_version")
        or fallback.get("framework_version")
    )

    mapping_version = (
        result_metadata.get("catalog_version")
        or framework_result.get("mapping_version")
        or engine_metadata.get("mapping_version")
        or fallback.get("mapping_version")
    )

    engine_version = (
        engine_metadata.get("engine_version")
        or framework_result.get("engine_version")
        or DEFAULT_ENGINE_VERSION
    )

    return {
        "framework_name": (
            result_metadata.get("name")
            or fallback.get("name")
            or framework
        ),
        "framework_short_name": (
            fallback.get("short_name")
            or framework
        ),
        "framework_version": _clean(framework_version),
        "mapping_version": _clean(mapping_version),
        "engine_version": _clean(engine_version),
        "catalog_version": _clean(
            result_metadata.get("catalog_version")
            or framework_result.get("catalog_version")
            or "1.0"
        ),
        "mapping_source": _clean(
            result_metadata.get("mapping_source")
            or "CloudGuardAI internal control mapping"
        ),
    }


def _extract_assessment_quality(compliance_result, framework_result):
    assessment = _safe_dict(compliance_result.get("assessment"))
    framework_assessment = _safe_dict(framework_result.get("assessment"))

    coverage = _safe_dict(framework_result.get("coverage"))
    top_coverage = _safe_dict(compliance_result.get("assessment_coverage"))

    evidence = _safe_dict(framework_result.get("evidence"))
    top_evidence = _safe_dict(compliance_result.get("evidence_confidence"))

    state = (
        framework_assessment.get("state")
        or framework_result.get("status")
        or assessment.get("state")
        or compliance_result.get("status")
        or STATUS_NOT_ASSESSED
    )

    has_controls = framework_assessment.get(
        "has_evaluated_controls",
        framework_result.get("controls", {}).get("total", 0) > 0,
    )

    evidence_sufficient = framework_assessment.get(
        "evidence_sufficient",
        assessment.get("evidence_sufficient", bool(has_controls)),
    )

    assessed_controls = coverage.get(
        "assessed_controls",
        top_coverage.get("assessed_controls", 0),
    )
    catalog_controls = coverage.get(
        "catalog_controls",
        top_coverage.get("catalog_controls", 0),
    )
    coverage_percent = coverage.get(
        "coverage_percent",
        top_coverage.get("coverage_percent", 0),
    )

    confidence = (
        evidence.get("confidence")
        or (
            top_evidence.get("overall")
            if isinstance(top_evidence, dict)
            else None
        )
        or "UNKNOWN"
    )

    return {
        "assessment_state": _normalize_status(state)
        if _clean(state).upper() in VALID_STATUSES
        else _clean(state).upper(),
        "has_evaluated_controls": bool(has_controls),
        "evidence_sufficient": bool(evidence_sufficient),
        "assessment_coverage": {
            "assessed_controls": int(assessed_controls or 0),
            "catalog_controls": int(catalog_controls or 0),
            "coverage_percent": float(coverage_percent or 0),
        },
        "evidence_confidence": _clean(confidence).upper() or "UNKNOWN",
        "evidence_counts": {
            "HIGH": int(evidence.get("HIGH", top_evidence.get("high", 0)) or 0),
            "MEDIUM": int(evidence.get("MEDIUM", top_evidence.get("medium", 0)) or 0),
            "LOW": int(evidence.get("LOW", top_evidence.get("low", 0)) or 0),
        },
    }


def _build_snapshot_document(
    user_id,
    account_id,
    aws_account_id,
    account_name,
    scan_id,
    framework,
    compliance_result,
):
    framework_result = _extract_framework_result(
        compliance_result,
        framework,
    )

    if not framework_result:
        framework_result = compliance_result

    metadata = _extract_versioned_metadata(
        compliance_result,
        framework,
        framework_result,
    )

    quality = _extract_assessment_quality(
        compliance_result,
        framework_result,
    )

    controls = _safe_dict(framework_result.get("controls"))
    control_results = framework_result.get("control_results", [])
    if not isinstance(control_results, list):
        control_results = []

    traceability = _extract_traceability(framework_result)

    score = framework_result.get(
        "score",
        compliance_result.get("compliance_score", 0),
    )

    try:
        score = float(score)
    except (TypeError, ValueError):
        score = 0.0

    score = max(0.0, min(score, 100.0))

    status = _normalize_status(
        framework_result.get(
            "status",
            compliance_result.get("status", STATUS_NOT_ASSESSED),
        )
    )

    now = datetime.utcnow()

    return {
        "user_id": _clean(user_id),

        "account_id": _clean(account_id),
        "aws_account_id": _clean(aws_account_id),
        "account_name": _clean(account_name),

        "scan_id": _clean(scan_id),

        "framework": framework,

        "framework_name": metadata["framework_name"],
        "framework_short_name": metadata["framework_short_name"],
        "framework_version": metadata["framework_version"],
        "catalog_version": metadata["catalog_version"],
        "mapping_version": metadata["mapping_version"],
        "mapping_source": metadata["mapping_source"],
        "engine_version": metadata["engine_version"],

        "score": round(score, 2),
        "compliance_score": round(score, 2),
        "status": status,

        "assessment_state": quality["assessment_state"],
        "has_evaluated_controls": quality["has_evaluated_controls"],
        "evidence_sufficient": quality["evidence_sufficient"],
        "assessment_coverage": quality["assessment_coverage"],
        "evidence_confidence": quality["evidence_confidence"],
        "evidence_counts": quality["evidence_counts"],

        "controls": {
            "total": int(controls.get("total", 0) or 0),
            "passed": int(controls.get("passed", 0) or 0),
            "failed": int(controls.get("failed", 0) or 0),
            "review": int(controls.get("review", 0) or 0),
        },

        "summary": _safe_dict(compliance_result.get("summary")),

        "control_results": control_results,

        "traceability": traceability,
        "finding_ids": traceability["finding_ids"],
        "control_ids": traceability["control_ids"],

        "passed_controls": [
            item for item in compliance_result.get("passed_controls", [])
            if isinstance(item, dict)
            and item.get("framework") == framework
        ],
        "failed_controls": [
            item for item in compliance_result.get("failed_controls", [])
            if isinstance(item, dict)
            and item.get("framework") == framework
        ],
        "review_controls": [
            item for item in compliance_result.get("review_controls", [])
            if isinstance(item, dict)
            and item.get("framework") == framework
        ],

        "evaluated_at": now,
        "created_at": now,
        "updated_at": now,
    }


def create_compliance_snapshot(
    user_id: str,
    account_id: Optional[str],
    aws_account_id: Optional[str],
    account_name: Optional[str],
    scan_id: str,
    framework: str,
    compliance_result: dict,
):
    """
    Upsert exactly one logical snapshot per:
        user + account + scan + framework

    Re-evaluating the same scan updates the same snapshot rather
    than creating duplicate history entries.
    """
    user_id = _clean(user_id)
    account_id = _clean(account_id)
    aws_account_id = _clean(aws_account_id)
    account_name = _clean(account_name)
    scan_id = _clean(scan_id)
    framework = _normalize_framework(framework)

    if not user_id:
        raise ValueError("user_id is required")
    if not scan_id:
        raise ValueError("scan_id is required")
    if framework not in SUPPORTED_FRAMEWORKS:
        raise ValueError(f"Unsupported compliance framework: {framework}")
    if not isinstance(compliance_result, dict):
        raise ValueError("compliance_result must be a dictionary")

    document = _build_snapshot_document(
        user_id=user_id,
        account_id=account_id,
        aws_account_id=aws_account_id,
        account_name=account_name,
        scan_id=scan_id,
        framework=framework,
        compliance_result=compliance_result,
    )

    identity = {
        "user_id": user_id,
        "scan_id": scan_id,
        "framework": framework,
    }

    # Account is part of logical tenancy when available.
    if account_id:
        identity["account_id"] = account_id

    result = COLLECTION.update_one(
        identity,
        {
            "$set": {
                key: value
                for key, value in document.items()
                if key not in {"created_at"}
            },
            "$setOnInsert": {
                "created_at": document["created_at"],
            },
        },
        upsert=True,
    )

    saved = COLLECTION.find_one(identity)

    if not saved:
        return None

    return _serialize(saved)


def get_compliance_snapshot(snapshot_id: str, user_id: str):
    user_id = _clean(user_id)
    object_id = _safe_object_id(snapshot_id)

    if not object_id or not user_id:
        return None

    document = COLLECTION.find_one({
        "_id": object_id,
        "user_id": user_id,
    })

    return _serialize(document)


def get_compliance_history(
    user_id: str,
    framework: Optional[str] = None,
    account_id: Optional[str] = None,
    limit: int = 50,
    skip: int = 0,
):
    user_id = _clean(user_id)

    query = {"user_id": user_id}

    if framework:
        framework = _normalize_framework(framework)
        if framework not in SUPPORTED_FRAMEWORKS:
            raise ValueError(f"Unsupported compliance framework: {framework}")
        query["framework"] = framework

    if account_id:
        query["account_id"] = _clean(account_id)

    limit = max(1, min(int(limit or 50), 200))
    skip = max(0, int(skip or 0))

    cursor = (
        COLLECTION.find(query)
        .sort([
            ("evaluated_at", -1),
            ("_id", -1),
        ])
        .skip(skip)
        .limit(limit)
    )

    return [_serialize(document) for document in cursor]


def get_latest_compliance_snapshot(
    user_id: str,
    account_id: Optional[str] = None,
    framework: Optional[str] = None,
):
    history = get_compliance_history(
        user_id=user_id,
        framework=framework,
        account_id=account_id,
        limit=1,
        skip=0,
    )
    return history[0] if history else None


# Backward-compatible alias.
def get_latest_compliance(
    user_id: str,
    framework: Optional[str] = None,
    account_id: Optional[str] = None,
):
    return get_latest_compliance_snapshot(
        user_id=user_id,
        framework=framework,
        account_id=account_id,
    )


def get_framework_history(
    user_id: str,
    framework: str,
    account_id: Optional[str] = None,
    limit: int = 50,
):
    return get_compliance_history(
        user_id=user_id,
        account_id=account_id,
        framework=framework,
        limit=limit,
    )


def get_compliance_trend(
    user_id: str,
    framework: Optional[str] = None,
    account_id: Optional[str] = None,
    limit: int = 30,
):
    history = get_compliance_history(
        user_id=user_id,
        framework=framework,
        account_id=account_id,
        limit=limit,
        skip=0,
    )

    history.reverse()

    return [
        {
            "date": item.get("evaluated_at"),
            "scan_id": item.get("scan_id"),
            "account_id": item.get("account_id"),
            "aws_account_id": item.get("aws_account_id"),
            "framework": item.get("framework"),
            "score": item.get("score", item.get("compliance_score", 0)),
            "status": item.get("status"),
            "framework_version": item.get("framework_version"),
            "mapping_version": item.get("mapping_version"),
            "engine_version": item.get("engine_version"),
            "assessment_coverage": item.get("assessment_coverage", {}),
            "evidence_confidence": item.get("evidence_confidence", "UNKNOWN"),
        }
        for item in history
    ]


def get_compliance_statistics(
    user_id: str,
    account_id: Optional[str] = None,
):
    user_id = _clean(user_id)

    query = {"user_id": user_id}
    if account_id:
        query["account_id"] = _clean(account_id)

    documents = list(COLLECTION.find(query))

    status_counts = {
        STATUS_COMPLIANT: 0,
        STATUS_AT_RISK: 0,
        STATUS_NON_COMPLIANT: 0,
        STATUS_REVIEW_REQUIRED: 0,
        STATUS_NOT_ASSESSED: 0,
    }

    framework_counts = {}
    scores = []

    for document in documents:
        status = _normalize_status(document.get("status"))
        status_counts[status] += 1

        framework = document.get("framework", "UNKNOWN")
        framework_counts[framework] = framework_counts.get(framework, 0) + 1

        if status != STATUS_NOT_ASSESSED:
            score = document.get("score", document.get("compliance_score"))
            if isinstance(score, (int, float)):
                scores.append(float(score))

    return {
        "total_snapshots": len(documents),
        "average_score": round(sum(scores) / len(scores), 2) if scores else None,
        "status_counts": status_counts,
        "framework_counts": framework_counts,
    }


def delete_compliance_snapshot(snapshot_id: str, user_id: str):
    user_id = _clean(user_id)
    object_id = _safe_object_id(snapshot_id)

    if not object_id or not user_id:
        return False

    result = COLLECTION.delete_one({
        "_id": object_id,
        "user_id": user_id,
    })

    return result.deleted_count > 0


def ensure_compliance_indexes():
    """
    Production indexes for tenant-safe retrieval and history.

    The unique logical identity is:
        user_id + account_id + scan_id + framework
    """
    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("evaluated_at", -1),
        ],
        name="user_evaluated_at",
    )

    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("framework", 1),
            ("evaluated_at", -1),
        ],
        name="user_account_framework_history",
    )

    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("account_id", 1),
            ("scan_id", 1),
            ("framework", 1),
        ],
        unique=True,
        name="user_account_scan_framework_unique",
    )

    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("framework", 1),
            ("framework_version", 1),
            ("mapping_version", 1),
            ("evaluated_at", -1),
        ],
        name="user_framework_version_history",
    )

    COLLECTION.create_index(
        [
            ("user_id", 1),
            ("finding_ids", 1),
        ],
        name="user_finding_traceability",
    )

    return True


try:
    ensure_compliance_indexes()
except Exception as exc:
    print(f"[WARNING] Compliance indexes initialization failed: {exc}")
