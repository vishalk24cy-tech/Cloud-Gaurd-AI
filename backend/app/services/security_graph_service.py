# ============================================================
# CloudGuardAI - Security Graph Service
# Phase 2 / Step 2
# Production / Commercial SaaS
# ============================================================

from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.models.finding import get_graph_findings
from app.database.connection import db
from bson import ObjectId


GRAPH_ENGINE_VERSION = "2.2"
MAX_FINDINGS = 5000
MAX_NODES = 5000
MAX_EDGES = 10000
MAX_ATTACK_PATHS = 100

SEVERITY_WEIGHT = {
    "CRITICAL": 100.0,
    "HIGH": 75.0,
    "MEDIUM": 50.0,
    "LOW": 25.0,
}

# Relationship priority is intentionally bounded and deterministic.
RELATIONSHIP_WEIGHT = {
    "EXPOSES": 1.25,
    "ASSOCIATED_WITH": 1.10,
    "ATTACHED_TO": 1.10,
    "ASSUMES_ROLE": 1.25,
    "GRANTS": 1.30,
    "TRUSTS": 1.20,
    "ROUTES_TO": 1.15,
    "CONNECTED_TO": 1.10,
    "PROTECTS": 1.05,
    "CONTAINS": 1.00,
    "HOSTS": 1.00,
    "USES": 1.00,
    "DEPENDS_ON": 1.00,
    "TARGETS": 1.00,
    "MEMBER_OF": 1.00,
}

INTERNET_TYPES = {"INTERNET"}
PRIVILEGE_TYPES = {
    "IAM_ROLE",
    "IAM_USER",
    "IAM_POLICY",
}

EXPOSURE_KEYWORDS = {
    "PUBLIC",
    "INTERNET",
    "0.0.0.0/0",
    "::/0",
    "UNRESTRICTED",
    "EXPOSED",
}

PRIVILEGE_KEYWORDS = {
    "ADMINISTRATORACCESS",
    "ADMIN",
    "PRIVILEGE",
    "IAM",
    "ASSUME_ROLE",
    "ESCALATION",
}

LATERAL_KEYWORDS = {
    "SECURITY_GROUP",
    "NETWORK",
    "TRUST",
    "ROLE",
    "INSTANCE",
    "LATERAL",
}


# ============================================================
# Attack Path Intelligence 2.0
# ============================================================

ATTACK_PATH_VERSION = "2.2"

HIGH_VALUE_IDENTITY_TYPES = {
    "IAM_ROLE",
    "IAM_USER",
    "IAM_POLICY",
}

MAX_CORRELATION_BUCKETS = 2000
MAX_RESOURCES_PER_BUCKET = 100

# Only these verified relationship types may participate in an attack path.
# Administrative/account containment and finding-target edges are intentionally
# excluded so graph traversal cannot manufacture a security path.
ATTACK_PATH_RELATIONSHIPS = {
    "EXPOSES",
    "ASSUMES_ROLE",
    "GRANTS",
    "TRUSTS",
}


def _safe_object_id(value: Any):
    """Convert a MongoDB identifier safely without raising."""
    if isinstance(value, ObjectId):
        return value
    try:
        return ObjectId(str(value))
    except Exception:
        return None


def _load_latest_scan_security_graph(user_id: str, account_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Load the latest tenant-owned scan-level graph snapshot.

    Scan-level topology is authoritative for infrastructure relationships.
    Finding-level graph metadata remains a compatibility fallback for legacy
    scans that predate graph schema 2.0.
    """
    query: Dict[str, Any] = {"user_id": str(user_id)}
    if account_id:
        query["account_id"] = str(account_id)

    projection = {
        "security_graph": 1,
        "account_id": 1,
        "aws_account_id": 1,
        "region": 1,
        "scan_started_at": 1,
        "scan_completed_at": 1,
        "status": 1,
    }

    try:
        scan = db.scan_history.find_one(
            query,
            projection,
            sort=[
                ("scan_completed_at", -1),
                ("scan_started_at", -1),
                ("_id", -1),
            ],
        )
    except Exception:
        return None

    if not isinstance(scan, dict):
        return None

    graph = scan.get("security_graph")
    if not isinstance(graph, dict):
        return None

    if _text(graph.get("graph_schema_version")) != "2.0":
        return None

    return graph


def _seed_scan_level_graph(
    graph_snapshot: Dict[str, Any],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    account_id: Optional[str],
    max_nodes: int,
    max_edges: int,
) -> None:
    """Materialize verified scan-level graph topology into graph-engine form."""
    if not isinstance(graph_snapshot, dict):
        return

    snapshot_account = _text(graph_snapshot.get("account_id") or account_id)

    for raw_node in graph_snapshot.get("nodes") or []:
        if not isinstance(raw_node, dict):
            continue
        node_type = _upper(raw_node.get("node_type"), "RESOURCE").replace(" ", "_")
        resource_id = _text(raw_node.get("resource_id"))
        if not resource_id:
            continue
        node_id = _node_id(node_type, resource_id, snapshot_account)
        metadata = {
            "resource_id": resource_id,
            "resource_name": raw_node.get("resource_name") or resource_id,
            "resource_arn": raw_node.get("resource_arn"),
            "service": _upper(raw_node.get("service")) or None,
            "signals": raw_node.get("signals") or {},
            "evidence": raw_node.get("evidence") or {},
        }
        if len(nodes) < max_nodes or node_id in nodes:
            nodes.setdefault(node_id, _build_node(node_id, node_type, snapshot_account, **metadata))

    for raw_edge in graph_snapshot.get("relationships") or []:
        if not isinstance(raw_edge, dict):
            continue
        evidence = raw_edge.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("verified") is not True:
            continue

        source_type = _upper(raw_edge.get("source_type"), "RESOURCE").replace(" ", "_")
        source_id = _text(raw_edge.get("source_id"))
        target_type = _upper(raw_edge.get("target_type"), "RESOURCE").replace(" ", "_")
        target_id = _text(raw_edge.get("target_id"))
        relationship_type = _upper(raw_edge.get("relationship_type"), "ASSOCIATED_WITH").replace(" ", "_")
        if not all((source_id, target_id, relationship_type)):
            continue

        source = _node_id(source_type, source_id, snapshot_account)
        target = _node_id(target_type, target_id, snapshot_account)
        edge = _build_edge(source, target, relationship_type, snapshot_account, evidence)

        # Ensure verified relationship endpoints exist even when AWS returned
        # an edge whose node was not present in a discovery bucket.
        if len(nodes) < max_nodes:
            nodes.setdefault(source, _build_node(
                source, source_type, snapshot_account,
                resource_id=source_id,
                resource_name=source_id,
                relationship_evidence=evidence,
            ))
            if len(nodes) < max_nodes:
                nodes.setdefault(target, _build_node(
                    target, target_type, snapshot_account,
                    resource_id=target_id,
                    resource_name=target_id,
                    relationship_evidence=evidence,
                ))

        if len(edges) < max_edges or edge["id"] in edges:
            edges.setdefault(edge["id"], edge)


# ============================================================
# Safe Helpers
# ============================================================

def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _upper(value: Any, default: str = "") -> str:
    return _text(value, default).upper()


def _bounded_float(value: Any, minimum=0.0, maximum=100.0) -> float:
    try:
        return max(minimum, min(maximum, float(value)))
    except (TypeError, ValueError):
        return minimum


def _unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []

    for value in values:
        value = _text(value)
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)

    return result


def _safe_list(value: Any, limit: int = 100) -> List[Any]:
    if not isinstance(value, list):
        return []
    return value[:limit]


# ============================================================
# Stable Node Identity
# ============================================================

def _node_id(
    node_type: str,
    identifier: Any,
    account_id: Optional[str] = None,
) -> str:
    node_type = _upper(node_type, "RESOURCE").replace(" ", "_")
    identifier = _text(identifier, "unknown")

    # Account context prevents accidental cross-account collisions.
    account = _text(account_id, "unknown")

    return f"{node_type}:{account}:{identifier}"


def _finding_node_id(finding: Dict[str, Any]) -> str:
    stable_id = (
        finding.get("finding_id")
        or finding.get("_id")
        or finding.get("resource")
        or "unknown"
    )
    return _node_id("FINDING", stable_id, finding.get("account_id"))


# ============================================================
# Resource Type Detection
# ============================================================

def _infer_resource_type(finding: Dict[str, Any]) -> str:
    graph = finding.get("security_graph") or {}

    explicit = (
        graph.get("graph_node_type")
        or finding.get("resource_type")
    )

    if explicit:
        return _upper(explicit).replace("-", "_").replace(" ", "_")

    service = _upper(finding.get("service"))
    resource = _upper(finding.get("resource"))

    if service == "EC2":
        return "EC2"
    if service in {"S3", "S3_BUCKET"}:
        return "S3_BUCKET"
    if service == "RDS":
        return "RDS_INSTANCE"
    if service == "LAMBDA":
        return "LAMBDA_FUNCTION"
    if service == "IAM":
        if "ROLE" in resource:
            return "IAM_ROLE"
        if "POLICY" in resource:
            return "IAM_POLICY"
        return "IAM_USER"
    if service == "VPC":
        if "SECURITY" in resource or "SG-" in resource:
            return "SECURITY_GROUP"
        if "VPC" in resource:
            return "VPC"
        if "SUBNET" in resource:
            return "SUBNET"
    if service == "KMS":
        return "KMS_KEY"
    if service == "CLOUDTRAIL":
        return "CLOUDTRAIL"

    return "RESOURCE"


# ============================================================
# Node Builder
# ============================================================

def _build_node(
    node_id: str,
    node_type: str,
    account_id: Optional[str],
    **metadata,
) -> Dict[str, Any]:
    node = {
        "id": node_id,
        "type": _upper(node_type, "RESOURCE").replace(" ", "_"),
        "account_id": _text(account_id) or None,
    }

    for key, value in metadata.items():
        if value is not None and value != "":
            node[key] = value

    return node


# ============================================================
# Edge Builder
# ============================================================

def _build_edge(
    source: str,
    target: str,
    relationship_type: str,
    account_id: Optional[str],
    evidence: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    relationship_type = _upper(
        relationship_type,
        "ASSOCIATED_WITH",
    ).replace(" ", "_")

    return {
        "id": f"{source}|{relationship_type}|{target}",
        "source": source,
        "target": target,
        "relationship_type": relationship_type,
        "account_id": _text(account_id) or None,
        "evidence": evidence or {},
    }


# ============================================================
# Keyword Classification
# ============================================================

def _finding_signals(finding: Dict[str, Any]) -> Dict[str, bool]:
    graph = finding.get("security_graph") or {}

    haystack = " ".join(
        [
            _upper(finding.get("issue")),
            _upper(finding.get("description")),
            _upper(finding.get("detection_status")),
            _upper(finding.get("resource")),
            _upper(finding.get("service")),
            _upper(finding.get("control_id")),
        ]
    )

    return {
        "internet_exposed": bool(
            graph.get("internet_exposed")
            or any(keyword in haystack for keyword in EXPOSURE_KEYWORDS)
        ),
        "privilege_escalation": bool(
            graph.get("privilege_escalation")
            or any(keyword in haystack for keyword in PRIVILEGE_KEYWORDS)
        ),
        "lateral_movement": bool(
            graph.get("lateral_movement")
            or any(keyword in haystack for keyword in LATERAL_KEYWORDS)
        ),
    }


# ============================================================
# Evidence / Resource Correlation Helpers
# ============================================================

def _resource_identifiers(finding: Dict[str, Any]) -> List[str]:
    """Extract stable identifiers from common finding/evidence fields."""
    graph = finding.get("security_graph") or {}
    evidence = finding.get("evidence") or {}

    values = [
        graph.get("resource_id"),
        graph.get("resource_arn"),
        finding.get("resource"),
        finding.get("arn"),
        finding.get("resource_arn"),
        finding.get("instance_id"),
        finding.get("instanceId"),
        finding.get("security_group_id"),
        finding.get("security_group"),
        finding.get("securityGroupId"),
        finding.get("role_arn"),
        finding.get("roleArn"),
        finding.get("role_name"),
        finding.get("roleName"),
        finding.get("policy_arn"),
        finding.get("policyArn"),
        finding.get("policy_name"),
        finding.get("policyName"),
    ]

    if isinstance(evidence, dict):
        values.extend([
            evidence.get("resource_id"),
            evidence.get("resource_arn"),
            evidence.get("arn"),
            evidence.get("instance_id"),
            evidence.get("security_group_id"),
            evidence.get("role_arn"),
            evidence.get("policy_arn"),
            evidence.get("resource"),
        ])

    return _unique(str(value) for value in values if value)


def _severity_rank(value: Any) -> int:
    return {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }.get(_upper(value), 1)


def _identity_strength(node: Dict[str, Any]) -> float:
    text = " ".join([
        _upper(node.get("type")),
        _upper(node.get("resource_id")),
        _upper(node.get("resource_name")),
        _upper(node.get("issue")),
    ])

    if "ADMINISTRATORACCESS" in text or "ADMIN" in text:
        return 100.0
    if "POWERUSER" in text or "FULLACCESS" in text:
        return 85.0
    if node.get("privilege_escalation"):
        return 75.0
    return 50.0


# ============================================================
# Relationship Inference
# ============================================================

def _infer_relationships(
    finding: Dict[str, Any],
    resource_node_id: str,
    account_id: Optional[str],
) -> List[Dict[str, Any]]:
    graph = finding.get("security_graph") or {}
    edges = []

    # ------------------------------------------------------------
    # Explicit AWS-verified graph relationships
    # ------------------------------------------------------------
    #
    # Relationship enrichment is authoritative only when the scanner
    # supplies a verified relationship plus evidence. The graph engine
    # does not invent a relationship from severity or keywords.
    #
    explicit_relationships = graph.get("relationships") or []

    if isinstance(explicit_relationships, list):
        for relationship in explicit_relationships[:500]:
            if not isinstance(relationship, dict):
                continue

            source_type = _upper(
                relationship.get("source_type"),
                "RESOURCE",
            ).replace("-", "_").replace(" ", "_")

            target_type = _upper(
                relationship.get("target_type"),
                "RESOURCE",
            ).replace("-", "_").replace(" ", "_")

            source_id = _text(relationship.get("source_id"))
            target_id = _text(relationship.get("target_id"))

            if not source_id or not target_id:
                continue

            # Reuse the finding's existing resource node when the
            # relationship source represents that resource.
            inferred_type = _infer_resource_type(finding)
            finding_resource_id = _text(
                (graph or {}).get("resource_id")
                or finding.get("resource")
            )

            if (
                source_type == inferred_type
                and source_id == finding_resource_id
            ):
                source_node_id = resource_node_id
            else:
                source_node_id = _node_id(
                    source_type,
                    source_id,
                    account_id,
                )

            target_node_id = _node_id(
                target_type,
                target_id,
                account_id,
            )

            edges.append(
                _build_edge(
                    source_node_id,
                    target_node_id,
                    relationship.get("relationship_type")
                    or "ASSOCIATED_WITH",
                    account_id,
                    relationship.get("evidence")
                    or {
                        "source": "finding.security_graph",
                        "finding_id": finding.get("finding_id"),
                    },
                )
            )

    related_id = graph.get("related_resource_id")
    related_type = graph.get("related_resource_type")

    if related_id and related_type:
        related_node_id = _node_id(
            related_type,
            related_id,
            account_id,
        )

        edges.append(
            _build_edge(
                resource_node_id,
                related_node_id,
                graph.get("relationship_type") or "ASSOCIATED_WITH",
                account_id,
                {
                    "source": "finding.security_graph",
                    "finding_id": finding.get("finding_id"),
                },
            )
        )

    parent_id = graph.get("parent_resource_id")
    parent_type = graph.get("parent_resource_type")

    if parent_id and parent_type:
        parent_node_id = _node_id(
            parent_type,
            parent_id,
            account_id,
        )

        edges.append(
            _build_edge(
                parent_node_id,
                resource_node_id,
                "CONTAINS",
                account_id,
                {
                    "source": "finding.security_graph",
                    "finding_id": finding.get("finding_id"),
                },
            )
        )

    if _finding_signals(finding)["internet_exposed"]:
        internet_id = _node_id(
            "INTERNET",
            "PUBLIC_INTERNET",
            account_id,
        )

        edges.append(
            _build_edge(
                internet_id,
                resource_node_id,
                "EXPOSES",
                account_id,
                {
                    "source": "finding_detection",
                    "finding_id": finding.get("finding_id"),
                },
            )
        )

    return edges


def _infer_cross_finding_relationships(
    findings: List[Dict[str, Any]],
    nodes: Dict[str, Dict[str, Any]],
    edges: Dict[str, Dict[str, Any]],
    account_id: str,
):
    """
    Correlate findings only when identifiers or explicit evidence support it.
    This avoids inventing AWS relationships.
    """
    resources = [
        node for node in nodes.values()
        if node.get("type") not in {"FINDING", "AWS_ACCOUNT", "INTERNET"}
    ]

    identifier_map = defaultdict(set)

    for node in resources:
        for identifier in _resource_identifiers(node):
            identifier_map[identifier].add(node["id"])

    # Identifier-backed relationship inference.
    for identifier, node_ids in identifier_map.items():
        if len(node_ids) > MAX_RESOURCES_PER_BUCKET:
            continue

        related_nodes = [nodes[node_id] for node_id in node_ids]

        for source in related_nodes:
            for target in related_nodes:
                if source["id"] == target["id"]:
                    continue

                source_type = source.get("type")
                target_type = target.get("type")
                relationship = None

                if source_type == "EC2" and target_type == "IAM_ROLE":
                    relationship = "ASSUMES_ROLE"
                elif source_type == "LAMBDA_FUNCTION" and target_type == "IAM_ROLE":
                    relationship = "ASSUMES_ROLE"
                elif source_type == "IAM_ROLE" and target_type == "IAM_POLICY":
                    relationship = "GRANTS"
                elif source_type == "IAM_USER" and target_type == "IAM_POLICY":
                    relationship = "GRANTS"
                elif source_type == "SECURITY_GROUP" and target_type in {
                    "EC2",
                    "RDS_INSTANCE",
                }:
                    relationship = "EXPOSES"

                if relationship:
                    edge = _build_edge(
                        source["id"],
                        target["id"],
                        relationship,
                        account_id,
                        {
                            "source": "shared_resource_identifier",
                            "identifier": identifier,
                        },
                    )
                    edges.setdefault(edge["id"], edge)

    # Conservative privileged-policy inference from explicit finding text.
    for node in resources:
        if node.get("type") != "IAM_ROLE":
            continue

        for policy in resources:
            if policy.get("type") != "IAM_POLICY":
                continue

            policy_text = " ".join([
                _upper(policy.get("resource_id")),
                _upper(policy.get("resource_name")),
                _upper(policy.get("issue")),
            ])

            if any(
                token in policy_text
                for token in (
                    "ADMINISTRATORACCESS",
                    "POWERUSER",
                    "FULLACCESS",
                )
            ):
                edge = _build_edge(
                    node["id"],
                    policy["id"],
                    "GRANTS",
                    account_id,
                    {
                        "source": "privileged_policy_evidence",
                    },
                )
                edges.setdefault(edge["id"], edge)




# ============================================================
# Graph Construction
# ============================================================

def build_security_graph(
    user_id: str,
    account_id: Optional[str] = None,
    service: Optional[str] = None,
    include_resolved: bool = False,
) -> Dict[str, Any]:
    """
    Build a deterministic security graph for one tenant.

    All data originates from tenant-scoped findings.
    This function does not access another tenant's data.
    """
    findings = get_graph_findings(
        user_id=str(user_id),
        account_id=account_id,
        service=service,
        include_resolved=include_resolved,
    )

    findings = findings[:MAX_FINDINGS]

    nodes: Dict[str, Dict[str, Any]] = {}
    edges: Dict[str, Dict[str, Any]] = {}
    finding_ids = []

    # Prefer the authoritative scan-level graph for infrastructure topology.
    # This prevents relationship data from being duplicated or corrupted by
    # individual finding lifecycle updates.
    scan_graph = _load_latest_scan_security_graph(
        user_id=str(user_id),
        account_id=account_id,
    )
    if scan_graph:
        _seed_scan_level_graph(
            scan_graph,
            nodes,
            edges,
            account_id,
            MAX_NODES,
            MAX_EDGES,
        )

    def add_node(node: Dict[str, Any]):
        if len(nodes) >= MAX_NODES and node["id"] not in nodes:
            return
        nodes.setdefault(node["id"], node)

    def add_edge(edge: Dict[str, Any]):
        if len(edges) >= MAX_EDGES and edge["id"] not in edges:
            return

        # Explicit relationship enrichment can introduce a verified resource
        # that does not itself have a finding. Materialize a lightweight node
        # so graph traversal can use the relationship.
        account = _text(edge.get("account_id") or account_id)
        for endpoint in ("source", "target"):
            endpoint_id = _text(edge.get(endpoint))
            if not endpoint_id or endpoint_id in nodes:
                continue
            relationship_type = _upper(edge.get("relationship_type"))
            evidence = edge.get("evidence") or {}
            endpoint_type = "RESOURCE"
            if endpoint == "source":
                endpoint_type = _upper(
                    next((r.get("source_type") for r in [edge] if r.get("source_type")), "RESOURCE")
                ).replace(" ", "_")
            else:
                endpoint_type = _upper(
                    next((r.get("target_type") for r in [edge] if r.get("target_type")), "RESOURCE")
                ).replace(" ", "_")
            resource_id = endpoint_id.split(":", 3)[-1] if ":" in endpoint_id else endpoint_id
            add_node(
                _build_node(
                    endpoint_id,
                    endpoint_type,
                    account,
                    resource_id=resource_id,
                    resource_name=resource_id,
                    relationship_evidence=evidence,
                    relationship_type=relationship_type,
                )
            )

        edges.setdefault(edge["id"], edge)

    for finding in findings:
        account = _text(
            finding.get("account_id")
            or account_id
        )

        finding_id = _finding_node_id(finding)
        resource_identifier = (
            (finding.get("security_graph") or {}).get("resource_id")
            or finding.get("resource")
            or finding_id
        )

        resource_type = _infer_resource_type(finding)
        resource_node_id = _node_id(
            resource_type,
            resource_identifier,
            account,
        )

        add_node(
            _build_node(
                resource_node_id,
                resource_type,
                account,
                resource_id=resource_identifier,
                resource_arn=(
                    (finding.get("security_graph") or {}).get("resource_arn")
                    or finding.get("arn")
                ),
                resource_name=(
                    (finding.get("security_graph") or {}).get("resource_name")
                    or finding.get("resource")
                ),
                service=_upper(finding.get("service"), "AWS"),
            )
        )

        severity = _upper(finding.get("severity"), "LOW")
        signals = _finding_signals(finding)

        add_node(
            _build_node(
                finding_id,
                "FINDING",
                account,
                finding_id=finding.get("finding_id"),
                severity=severity,
                status=finding.get("status"),
                detection_status=finding.get("detection_status"),
                issue=finding.get("issue"),
                internet_exposed=signals["internet_exposed"],
                privilege_escalation=signals["privilege_escalation"],
                lateral_movement=signals["lateral_movement"],
            )
        )

        add_edge(
            _build_edge(
                resource_node_id,
                finding_id,
                "TARGETS",
                account,
                {
                    "source": "finding",
                    "finding_id": finding.get("finding_id"),
                },
            )
        )

        for edge in _infer_relationships(
            finding,
            resource_node_id,
            account,
        ):
            add_edge(edge)

        finding_ids.append(finding.get("finding_id") or finding_id)

    # Add account root node when account context exists.
    if account_id or findings:
        account = _text(
            account_id
            or (findings[0].get("account_id") if findings else "")
        )

        if account:
            account_node = _node_id(
                "AWS_ACCOUNT",
                account,
                account,
            )

            add_node(
                _build_node(
                    account_node,
                    "AWS_ACCOUNT",
                    account,
                    aws_account_id=(
                        findings[0].get("aws_account_id")
                        if findings
                        else None
                    ),
                    account_name=(
                        findings[0].get("account_name")
                        if findings
                        else None
                    ),
                )
            )

            for node in list(nodes.values()):
                if (
                    node["id"] != account_node
                    and node.get("account_id") == account
                    and node.get("type") != "AWS_ACCOUNT"
                ):
                    add_edge(
                        _build_edge(
                            account_node,
                            node["id"],
                            "CONTAINS",
                            account,
                            {"source": "CloudGuardAI_account_context"},
                        )
                    )

    graph_account = _text(
        account_id
        or (findings[0].get("account_id") if findings else "")
    )

    # Scan-level topology is authoritative. Legacy cross-finding inference is
    # used only when no schema-2.0 scan graph exists. This prevents lifecycle
    # records from introducing synthetic relationships into a fresh graph.
    if not scan_graph:
        _infer_cross_finding_relationships(
            findings=findings,
            nodes=nodes,
            edges=edges,
            account_id=graph_account,
        )

    attack_paths = analyze_attack_paths(
        nodes=list(nodes.values()),
        edges=list(edges.values()),
    )

    return {
        "status": "success",
        "graph": {
            "engine_version": GRAPH_ENGINE_VERSION,
            "attack_path_version": ATTACK_PATH_VERSION,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "account_id": _text(account_id) or None,
            "nodes": list(nodes.values()),
            "edges": list(edges.values()),
            "node_count": len(nodes),
            "edge_count": len(edges),
            "finding_count": len(finding_ids),
            "source": "scan_level_security_graph" if scan_graph else "finding_graph_legacy_fallback",
            "scan_graph_schema_version": (scan_graph or {}).get("graph_schema_version") if scan_graph else None,
            "scan_graph_discovery": (scan_graph or {}).get("discovery") if scan_graph else None,
        },
        "attack_paths": attack_paths,
        "summary": {
            "internet_exposed_nodes": sum(
                1 for n in nodes.values()
                if n.get("internet_exposed")
            ),
            "privilege_escalation_nodes": sum(
                1 for n in nodes.values()
                if n.get("privilege_escalation")
            ),
            "lateral_movement_nodes": sum(
                1 for n in nodes.values()
                if n.get("lateral_movement")
            ),
            "attack_path_count": len(attack_paths),
        },
    }


# ============================================================
# Attack Path Analysis
# ============================================================

def _adjacency(
    edges: List[Dict[str, Any]],
) -> Dict[str, List[Tuple[str, Dict[str, Any]]]]:
    graph = defaultdict(list)

    for edge in edges:
        source = edge.get("source")
        target = edge.get("target")

        if not source or not target:
            continue

        graph[source].append((target, edge))

    return graph


def _path_score(
    path_nodes: List[Dict[str, Any]],
    path_edges: List[Dict[str, Any]],
) -> float:
    """Bounded score for potential attack-path impact."""
    score = 0.0

    for node in path_nodes:
        score = max(
            score,
            SEVERITY_WEIGHT.get(
                _upper(node.get("severity"), "LOW"),
                25.0,
            ),
        )

        if node.get("internet_exposed"):
            score += 15.0
        if node.get("privilege_escalation"):
            score += 20.0
        if node.get("lateral_movement"):
            score += 10.0
        if node.get("type") in HIGH_VALUE_IDENTITY_TYPES:
            score += _identity_strength(node) * 0.15

    for edge in path_edges:
        score *= RELATIONSHIP_WEIGHT.get(
            edge.get("relationship_type"),
            1.0,
        )

    return round(min(100.0, score), 2)


def _path_has_valid_attack_edges(path_edges: List[Dict[str, Any]]) -> bool:
    """Validate the relationship semantics of a candidate path."""
    if not path_edges:
        return False
    if not all(_is_verified_attack_edge(edge) for edge in path_edges):
        return False

    relationships = [
        _upper(edge.get("relationship_type"))
        for edge in path_edges
    ]

    # Internet exposure must be the entry edge; downstream edges describe
    # verified movement/privilege relationships.
    if relationships[0] != "EXPOSES":
        return False
    return True


def _path_has_required_stages(path_nodes: List[Dict[str, Any]]) -> bool:
    types = {node.get("type") for node in path_nodes}

    return (
        "INTERNET" in types
        and bool(types.intersection({
            "EC2",
            "RDS_INSTANCE",
            "LAMBDA_FUNCTION",
            "SECURITY_GROUP",
            "VPC",
            "SUBNET",
        }))
        and bool(types.intersection(HIGH_VALUE_IDENTITY_TYPES))
    )


def _attack_path_category(path_nodes: List[Dict[str, Any]]) -> str:
    types = {node.get("type") for node in path_nodes}

    if (
        "INTERNET" in types
        and types.intersection(HIGH_VALUE_IDENTITY_TYPES)
    ):
        return "INTERNET_TO_PRIVILEGED_IDENTITY"

    if "SECURITY_GROUP" in types and "EC2" in types:
        return "NETWORK_TO_COMPUTE"

    return "CORRELATED_SECURITY_PATH"


def _path_explanation(path_nodes: List[Dict[str, Any]]) -> str:
    types = {node.get("type") for node in path_nodes}

    if (
        "INTERNET" in types
        and types.intersection(HIGH_VALUE_IDENTITY_TYPES)
    ):
        return (
            "Potential path from an internet-exposed entry point "
            "through cloud resources to a privileged identity or policy. "
            "This is risk correlation, not proof of exploitation."
        )

    return (
        "Multiple security findings form a correlated resource path. "
        "Validate the underlying AWS relationships before treating "
        "the path as exploitable."
    )


def _is_verified_attack_edge(edge: Dict[str, Any]) -> bool:
    """Return True only for evidence-backed attack-relevant edges."""
    if not isinstance(edge, dict):
        return False

    relationship = _upper(edge.get("relationship_type"))
    if relationship not in ATTACK_PATH_RELATIONSHIPS:
        return False

    evidence = edge.get("evidence")
    return isinstance(evidence, dict) and evidence.get("verified") is True


def analyze_attack_paths(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Detect short, explainable attack-path candidates.

    Graph construction is deterministic. AI may explain a path later,
    but an LLM cannot create or authorize a security path.
    """
    node_map = {
        node["id"]: node
        for node in nodes
        if node.get("id")
    }

    # Attack-path traversal is deliberately stricter than general graph
    # rendering: every traversed edge must be explicitly verified by AWS
    # evidence and belong to the approved attack relationship set.
    attack_edges = [
        edge for edge in edges
        if _is_verified_attack_edge(edge)
    ]
    adjacency = _adjacency(attack_edges)

    internet_nodes = [
        node["id"]
        for node in nodes
        if node.get("type") == "INTERNET"
    ]

    privileged_nodes = [
        node["id"]
        for node in nodes
        if (
            node.get("privilege_escalation")
            or node.get("type") in HIGH_VALUE_IDENTITY_TYPES
        )
    ]

    if not internet_nodes or not privileged_nodes:
        return []

    attack_paths = []
    seen_paths = set()

    for start in internet_nodes[:25]:
        queue = deque([(start, [start], [])])

        while queue and len(attack_paths) < MAX_ATTACK_PATHS:
            current, path, path_edges = queue.popleft()

            if len(path) > 8:
                continue

            for target, edge in adjacency.get(current, []):
                if target in path:
                    continue

                next_path = path + [target]
                next_edges = path_edges + [edge]

                path_nodes = [
                    node_map[node_id]
                    for node_id in next_path
                    if node_id in node_map
                ]

                if (
                    target in privileged_nodes
                    and len(next_path) >= 4
                    and _path_has_required_stages(path_nodes)
                    and _path_has_valid_attack_edges(next_edges)
                ):
                    signature = "|".join(next_path)

                    if signature not in seen_paths:
                        seen_paths.add(signature)

                        score = _path_score(
                            path_nodes,
                            next_edges,
                        )

                        attack_paths.append(
                            {
                                "path_id": f"AP-{len(attack_paths) + 1:04d}",
                                "attack_path_version": ATTACK_PATH_VERSION,
                                "score": score,
                                "severity": (
                                    "CRITICAL"
                                    if score >= 85
                                    else "HIGH"
                                    if score >= 65
                                    else "MEDIUM"
                                ),
                                "category": _attack_path_category(path_nodes),
                                "entry_point": start,
                                "target": target,
                                "nodes": next_path,
                                "node_types": [
                                    node.get("type")
                                    for node in path_nodes
                                ],
                                "relationships": [
                                    edge.get("relationship_type")
                                    for edge in next_edges
                                ],
                                "evidence": [
                                    edge.get("evidence", {})
                                    for edge in next_edges
                                ],
                                "confidence": "HIGH",
                                "explanation": _path_explanation(path_nodes),
                            }
                        )

                if len(next_path) < 8:
                    queue.append(
                        (target, next_path, next_edges)
                    )

    attack_paths.sort(
        key=lambda item: (
            item["score"],
            len(item["nodes"]),
        ),
        reverse=True,
    )

    return attack_paths[:MAX_ATTACK_PATHS]




# ============================================================
# Public Convenience Functions
# ============================================================

def get_attack_paths(
    user_id: str,
    account_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Return only attack paths for a tenant/account."""
    result = build_security_graph(
        user_id=user_id,
        account_id=account_id,
    )

    return result.get("attack_paths", [])


def get_security_graph_summary(
    user_id: str,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a lightweight graph summary for dashboards."""
    result = build_security_graph(
        user_id=user_id,
        account_id=account_id,
    )

    return {
        "engine_version": GRAPH_ENGINE_VERSION,
        "account_id": _text(account_id) or None,
        "summary": result.get("summary", {}),
        "attack_paths": result.get("attack_paths", [])[:10],
    }
