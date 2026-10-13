# ============================================================
# CloudGuardAI - Security Correlation Service
# Phase 2 / Step 3
# Finding <-> Graph <-> Remediation Correlation
#
# Production / Commercial SaaS
# ------------------------------------------------------------
# Design:
#   Tenant-scoped, account-scoped, read-only correlation.
#   No AWS mutation.
#   No client-supplied security facts are trusted.
#   Existing finding/remediation workflow remains authoritative.
# ============================================================

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db
from app.models.finding import (
    WORKFLOW_IGNORED,
    WORKFLOW_NOT_APPLICABLE,
    WORKFLOW_RESOLVED,
)

# Existing persisted collections.
findings_collection = db["findings"]
remediations_collection = db["remediations"]


CORRELATION_ENGINE_VERSION = "1.0"


ACTIVE_FINDING_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
}

NON_ACTIONABLE_REMEDIATION_STATUSES = {
    "COMPLETED",
    "FAILED",
    "EXECUTING",
    "REJECTED",
    "CANCELLED",
}


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _serialize(value: Any) -> Any:
    """Recursively make MongoDB values API-safe."""
    if isinstance(value, ObjectId):
        return str(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, dict):
        return {str(k): _serialize(v) for k, v in value.items()}

    if isinstance(value, list):
        return [_serialize(item) for item in value]

    if isinstance(value, tuple):
        return [_serialize(item) for item in value]

    return value


def _safe_object_id(value: Any) -> Optional[ObjectId]:
    try:
        return ObjectId(str(value))
    except (InvalidId, TypeError):
        return None


def _tenant_query(user_id: Any, account_id: Optional[Any] = None) -> Dict[str, Any]:
    query: Dict[str, Any] = {
        "user_id": str(user_id),
    }

    if account_id:
        query["account_id"] = str(account_id)

    return query


def _resource_candidates(resource_id: Any) -> Set[str]:
    """
    Build conservative identifiers for matching a graph node to a finding.

    Examples:
      SECURITY_GROUP:sg-123 -> SECURITY_GROUP:sg-123, sg-123
      arn:aws:...            -> full ARN
    """
    raw = _text(resource_id)
    if not raw:
        return set()

    candidates = {raw}

    # Graph node IDs commonly use TYPE:IDENTIFIER, and the scan-level
    # graph may use TYPE:AWS_ACCOUNT_ID:RESOURCE_ID. Add every useful
    # suffix so correlation can safely match the stable AWS resource ID.
    if ":" in raw:
        parts = [part for part in raw.split(":") if part]
        if len(parts) >= 2:
            candidates.add(":".join(parts[1:]))
            candidates.add(parts[-1])

    # Some graph builders may use slash-delimited resource IDs.
    if "/" in raw:
        suffix = raw.rsplit("/", 1)[-1]
        if suffix:
            candidates.add(suffix)

    return {item for item in candidates if item}


def _finding_matches_resource(
    finding: Dict[str, Any],
    resource_id: str,
) -> bool:
    candidates = _resource_candidates(resource_id)

    if not candidates:
        return False

    graph = finding.get("security_graph")
    if not isinstance(graph, dict):
        graph = {}

    values = [
        finding.get("resource"),
        finding.get("arn"),
        finding.get("resource_arn"),
        graph.get("resource_id"),
        graph.get("node_id"),
        graph.get("related_resource_id"),
        graph.get("related_resource"),
    ]

    # Also inspect common evidence identifiers without recursively
    # scanning arbitrary customer data.
    evidence = finding.get("evidence")
    if isinstance(evidence, dict):
        values.extend(
            [
                evidence.get("resource_id"),
                evidence.get("resource"),
                evidence.get("arn"),
                evidence.get("resource_arn"),
                evidence.get("security_group_id"),
                evidence.get("instance_id"),
                evidence.get("bucket"),
                evidence.get("bucket_name"),
                evidence.get("role_name"),
                evidence.get("role_arn"),
                evidence.get("user_name"),
                evidence.get("username"),
            ]
        )

    normalized_values = set()
    for value in values:
        if value is None:
            continue
        normalized_values.update(_resource_candidates(value))

    return bool(candidates.intersection(normalized_values))


def _node_matches_resource(
    node: Dict[str, Any],
    resource_id: str,
) -> bool:
    candidates = _resource_candidates(resource_id)

    if not candidates:
        return False

    values = [
        node.get("id"),
        node.get("resource_id"),
        node.get("resource"),
        node.get("arn"),
        node.get("resource_arn"),
        node.get("name"),
    ]

    normalized_values = set()
    for value in values:
        if value is None:
            continue
        normalized_values.update(_resource_candidates(value))

    return bool(candidates.intersection(normalized_values))


def _edge_endpoint_ids(edge: Dict[str, Any]) -> Set[str]:
    result = set()

    for key in ("source", "target"):
        value = _text(edge.get(key))
        if value:
            result.update(_resource_candidates(value))

    return result


def _edge_touches_resource(
    edge: Dict[str, Any],
    resource_id: str,
) -> bool:
    candidates = _resource_candidates(resource_id)
    return bool(candidates.intersection(_edge_endpoint_ids(edge)))


def _verified_edge(edge: Dict[str, Any]) -> bool:
    if not isinstance(edge, dict):
        return False

    evidence = edge.get("evidence")
    return (
        isinstance(evidence, dict)
        and evidence.get("verified") is True
    )


def _finding_actionability(finding: Dict[str, Any]) -> Dict[str, Any]:
    status = _upper(finding.get("status"))
    detection = _upper(finding.get("detection_status"))

    protected = status == WORKFLOW_NOT_APPLICABLE or detection in {
        "PROTECTED",
        "PASS",
        "PASSED",
    }

    resolved = status == WORKFLOW_RESOLVED
    ignored = status == WORKFLOW_IGNORED

    actionable = not protected and not resolved and not ignored

    return {
        "actionable": actionable,
        "workflow_status": status or "UNKNOWN",
        "detection_status": detection or "UNKNOWN",
        "protected": protected,
    }


def _finding_risk(finding: Dict[str, Any]) -> Dict[str, Any]:
    severity = _upper(finding.get("severity")) or "LOW"
    graph = finding.get("security_graph")
    if not isinstance(graph, dict):
        graph = {}

    return {
        "severity": severity,
        "internet_exposed": bool(graph.get("internet_exposed")),
        "privilege_escalation": bool(graph.get("privilege_escalation")),
        "lateral_movement": bool(graph.get("lateral_movement")),
    }


def _remediation_state(remediation: Dict[str, Any]) -> Dict[str, Any]:
    status = _upper(remediation.get("status")) or "UNKNOWN"

    return {
        "status": status,
        "active_proposal": status in {
            "PROPOSED",
            "PENDING_APPROVAL",
            "APPROVED",
        },
        "executing": status == "EXECUTING",
        "completed": status == "COMPLETED",
        "failed": status == "FAILED",
    }


def _build_recommended_actions(
    finding: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Return conservative action suggestions.

    These are recommendations only. They do not create a remediation
    proposal and do not execute AWS operations.
    """
    service = _upper(finding.get("service"))
    issue = (
        f"{_text(finding.get('issue'))} "
        f"{_text(finding.get('description'))}"
    ).lower()

    actions: List[Dict[str, Any]] = []

    def add(action_type: str, reason: str, automatic: bool) -> None:
        if action_type not in {
            item["action_type"] for item in actions
        }:
            actions.append(
                {
                    "action_type": action_type,
                    "reason": reason,
                    "supported_by_current_remediation_workflow": automatic,
                }
            )

    if service == "S3" and "public" in issue:
        add(
            "DISABLE_PUBLIC_ACCESS",
            "Reduce public exposure on the affected S3 resource.",
            True,
        )
        if "policy" in issue or "bucket policy" in issue:
            add(
                "REMOVE_PUBLIC_POLICY",
                "Remove a public S3 resource-policy condition when the finding supports it.",
                True,
            )

    if service in {"EC2", "VPC"} and any(
        term in issue
        for term in (
            "security group",
            "ssh",
            "rdp",
            "inbound",
            "internet",
            "0.0.0.0/0",
        )
    ):
        add(
            "RESTRICT_SECURITY_GROUP",
            "Restrict the exposed inbound security-group rule.",
            True,
        )

    if service == "IAM" and any(
        term in issue
        for term in (
            "policy",
            "permission",
            "privilege",
            "administrator",
        )
    ):
        add(
            "REVIEW_IAM_POLICY",
            "Review the affected IAM permissions for excessive privilege.",
            True,
        )

    if service == "IAM" and (
        "mfa" in issue or "multi-factor" in issue
    ):
        add(
            "ENABLE_MFA",
            "Require customer-controlled MFA enrollment for the IAM identity.",
            True,
        )

    if service == "RDS" and "public" in issue:
        add(
            "DISABLE_RDS_PUBLIC_ACCESS",
            "Remove public accessibility from the affected RDS instance.",
            True,
        )

    if service == "RDS" and "encrypt" in issue:
        add(
            "ENABLE_RDS_ENCRYPTION",
            "Enable encryption for the affected RDS resource where supported.",
            True,
        )

    if service == "RDS" and (
        "backup" in issue or "retention" in issue
    ):
        add(
            "ENABLE_RDS_BACKUPS",
            "Enable an appropriate automated backup/retention configuration.",
            True,
        )

    if service == "S3" and "encrypt" in issue:
        add(
            "ENABLE_S3_ENCRYPTION",
            "Enable server-side encryption for the affected S3 resource.",
            True,
        )

    if service == "CLOUDTRAIL" or "cloudtrail" in issue:
        add(
            "ENABLE_CLOUDTRAIL",
            "Enable CloudTrail logging for security visibility.",
            True,
        )

    # The finding recommendation remains the primary human-readable
    # recommendation even when no automated action is safely available.
    return actions


def _serialize_finding_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    actionability = _finding_actionability(finding)
    risk = _finding_risk(finding)

    return {
        "finding_id": finding.get("finding_id"),
        "database_id": finding.get("_id"),
        "account_id": finding.get("account_id"),
        "aws_account_id": finding.get("aws_account_id"),
        "service": finding.get("service"),
        "resource": finding.get("resource"),
        "resource_type": finding.get("resource_type"),
        "severity": risk["severity"],
        "status": actionability["workflow_status"],
        "workflow_status": actionability["workflow_status"],
        "detection_status": actionability["detection_status"],
        "actionable": actionability["actionable"],
        "issue": finding.get("issue"),
        "description": finding.get("description"),
        "recommendation": finding.get("recommendation") or finding.get("remediation"),
        "control_id": finding.get("control_id"),
        "risk": risk,
        "recommended_actions": _build_recommended_actions(finding),
        "last_seen": finding.get("last_seen"),
    }


def _serialize_remediation_summary(remediation: Dict[str, Any]) -> Dict[str, Any]:
    state = _remediation_state(remediation)

    return {
        "remediation_id": remediation.get("_id"),
        "finding_id": remediation.get("finding_id"),
        "account_id": remediation.get("account_id"),
        "aws_account_id": remediation.get("aws_account_id"),
        "service": remediation.get("service"),
        "resource": remediation.get("resource"),
        "severity": remediation.get("severity"),
        "action_type": remediation.get("action_type"),
        "title": remediation.get("title"),
        "description": remediation.get("description"),
        "reason": remediation.get("reason"),
        "recommendation": remediation.get("recommendation"),
        "status": state["status"],
        "active_proposal": state["active_proposal"],
        "executing": state["executing"],
        "completed": state["completed"],
        "failed": state["failed"],
        "created_at": remediation.get("created_at"),
        "updated_at": remediation.get("updated_at"),
    }


def _load_graph_snapshot(
    user_id: str,
    account_id: str,
) -> Dict[str, Any]:
    """
    Load the latest scan-level graph without changing the graph engine.

    The graph engine already enforces tenant/account scoping; this service
    consumes its persisted snapshot as read-only intelligence.
    """
    from app.services.security_graph_service import build_security_graph

    result = build_security_graph(
        user_id=str(user_id),
        account_id=str(account_id),
    )

    if not isinstance(result, dict):
        return {
            "graph": {},
            "nodes": [],
            "edges": [],
        }

    graph = result.get("graph")
    if not isinstance(graph, dict):
        graph = {}

    nodes = graph.get("nodes")
    if not isinstance(nodes, list):
        nodes = result.get("nodes", [])
        if not isinstance(nodes, list):
            nodes = []

    edges = graph.get("edges")
    if not isinstance(edges, list):
        edges = result.get("edges", [])
        if not isinstance(edges, list):
            edges = []

    return {
        "graph": graph,
        "nodes": nodes,
        "edges": edges,
        "attack_paths": result.get("attack_paths", [])
        if isinstance(result.get("attack_paths", []), list)
        else [],
        "summary": result.get("summary", {})
        if isinstance(result.get("summary", {}), dict)
        else {},
    }


def correlate_resource(
    user_id: str,
    account_id: str,
    resource_id: str,
) -> Dict[str, Any]:
    """
    Correlate one graph resource with:
      - verified graph relationships
      - active findings
      - remediation history/proposals

    This is read-only.
    """
    user_id = _text(user_id)
    account_id = _text(account_id)
    resource_id = _text(resource_id)

    if not user_id:
        raise ValueError("user_id is required")
    if not account_id:
        raise ValueError("account_id is required")
    if not resource_id:
        raise ValueError("resource_id is required")

    snapshot = _load_graph_snapshot(
        user_id=user_id,
        account_id=account_id,
    )

    nodes = snapshot["nodes"]
    edges = snapshot["edges"]

    matched_nodes = [
        node for node in nodes
        if isinstance(node, dict)
        and _node_matches_resource(node, resource_id)
    ]

    matched_node_ids = {
        _text(node.get("id"))
        for node in matched_nodes
        if _text(node.get("id"))
    }

    related_edges = [
        edge for edge in edges
        if isinstance(edge, dict)
        and _edge_touches_resource(edge, resource_id)
    ]

    verified_related_edges = [
        edge for edge in related_edges
        if _verified_edge(edge)
    ]

    finding_query = _tenant_query(
        user_id=user_id,
        account_id=account_id,
    )

    findings = [
        item
        for item in findings_collection.find(finding_query).sort(
            "created_at",
            -1,
        )
        if _finding_matches_resource(item, resource_id)
    ]

    remediation_query = _tenant_query(
        user_id=user_id,
        account_id=account_id,
    )

    remediations = [
        item
        for item in remediations_collection.find(remediation_query).sort(
            "created_at",
            -1,
        )
        if (
            _text(item.get("finding_id"))
            in {
                _text(finding.get("finding_id"))
                for finding in findings
                if _text(finding.get("finding_id"))
            }
            or _resource_candidates(item.get("resource"))
            & _resource_candidates(resource_id)
        )
    ]

    finding_summaries = [
        _serialize_finding_summary(item)
        for item in findings
    ]

    remediation_summaries = [
        _serialize_remediation_summary(item)
        for item in remediations
    ]

    active_findings = [
        item for item in finding_summaries
        if item["status"] in ACTIVE_FINDING_STATUSES
    ]

    active_remediations = [
        item for item in remediation_summaries
        if item["active_proposal"]
    ]

    severity_order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }

    highest_severity = "NONE"
    if finding_summaries:
        highest_severity = max(
            (
                item["severity"]
                for item in finding_summaries
                if item["severity"] in severity_order
            ),
            key=lambda value: severity_order[value],
            default="NONE",
        )

    risk_flags = {
        "internet_exposed": any(
            item["risk"]["internet_exposed"]
            for item in finding_summaries
        ),
        "privilege_escalation": any(
            item["risk"]["privilege_escalation"]
            for item in finding_summaries
        ),
        "lateral_movement": any(
            item["risk"]["lateral_movement"]
            for item in finding_summaries
        ),
    }

    return _serialize(
        {
            "status": "success",
            "engine_version": CORRELATION_ENGINE_VERSION,
            "account_id": account_id,
            "resource_id": resource_id,
            "resource": {
                "matched": bool(matched_nodes),
                "node_count": len(matched_nodes),
                "nodes": matched_nodes[:20],
            },
            "graph": {
                "related_edge_count": len(related_edges),
                "verified_related_edge_count": len(
                    verified_related_edges
                ),
                "verified_relationships": [
                    {
                        "id": edge.get("id"),
                        "source": edge.get("source"),
                        "target": edge.get("target"),
                        "relationship_type": edge.get(
                            "relationship_type"
                        ),
                        "evidence": edge.get("evidence", {}),
                    }
                    for edge in verified_related_edges[:50]
                ],
            },
            "findings": {
                "total": len(finding_summaries),
                "active": len(active_findings),
                "highest_severity": highest_severity,
                "risk_flags": risk_flags,
                "items": finding_summaries[:50],
            },
            "remediations": {
                "total": len(remediation_summaries),
                "active_proposals": len(active_remediations),
                "items": remediation_summaries[:50],
            },
            "correlation": {
                "resource_found_in_graph": bool(matched_nodes),
                "relationship_backed": bool(verified_related_edges),
                "finding_backed": bool(finding_summaries),
                "remediation_backed": bool(remediation_summaries),
                "needs_attention": bool(active_findings),
                "remediation_available": bool(
                    active_remediations
                    or any(
                        item["recommended_actions"]
                        for item in finding_summaries
                    )
                ),
            },
        }
    )


def correlate_finding(
    user_id: str,
    account_id: str,
    finding_id: str,
) -> Dict[str, Any]:
    """
    Correlate one finding with:
      - its graph resource/node
      - verified relationships touching that resource
      - remediation history/proposals
    """
    user_id = _text(user_id)
    account_id = _text(account_id)
    finding_id = _text(finding_id)

    if not finding_id:
        raise ValueError("finding_id is required")

    query = _tenant_query(
        user_id=user_id,
        account_id=account_id,
    )
    query["finding_id"] = finding_id

    finding = findings_collection.find_one(query)

    if not finding:
        return {
            "status": "not_found",
            "engine_version": CORRELATION_ENGINE_VERSION,
            "finding_id": finding_id,
        }

    resource_values = [
        finding.get("resource"),
        (finding.get("security_graph") or {}).get("resource_id")
        if isinstance(finding.get("security_graph"), dict)
        else None,
    ]

    resource_id = next(
        (
            _text(value)
            for value in resource_values
            if _text(value)
        ),
        "",
    )

    resource_result = (
        correlate_resource(
            user_id=user_id,
            account_id=account_id,
            resource_id=resource_id,
        )
        if resource_id
        else None
    )

    remediation_query = _tenant_query(
        user_id=user_id,
        account_id=account_id,
    )
    remediation_query["finding_id"] = finding_id

    remediation_items = list(
        remediations_collection.find(remediation_query).sort(
            "created_at",
            -1,
        )
    )

    return _serialize(
        {
            "status": "success",
            "engine_version": CORRELATION_ENGINE_VERSION,
            "account_id": account_id,
            "finding": _serialize_finding_summary(finding),
            "resource_id": resource_id or None,
            "resource_correlation": resource_result,
            "remediations": {
                "total": len(remediation_items),
                "items": [
                    _serialize_remediation_summary(item)
                    for item in remediation_items[:50]
                ],
            },
        }
    )
