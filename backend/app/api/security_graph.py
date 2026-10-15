# ============================================================
# CloudGuardAI - Security Graph API
# Phase 2 / Step 2.2.3
# Production / Commercial SaaS
# ============================================================

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.middleware.auth_middleware import verify_token
from app.models.aws_account import get_account
from app.services.security_graph_service import (
    ATTACK_PATH_RELATIONSHIPS,
    GRAPH_ENGINE_VERSION,
    ATTACK_PATH_VERSION,
    build_security_graph,
)


router = APIRouter(
    prefix="/security-graph",
    tags=["Security Graph"],
)


# ============================================================
# Constants
# ============================================================

MAX_ACCOUNT_ID_LENGTH = 100
MAX_SERVICE_LENGTH = 100

ALLOWED_SERVICES = {
    "EC2",
    "S3",
    "IAM",
    "VPC",
    "RDS",
    "LAMBDA",
    "CLOUDTRAIL",
    "KMS",
}

VERIFIED_EDGE_RELATIONSHIPS = {
    str(value).strip().upper()
    for value in ATTACK_PATH_RELATIONSHIPS
}


# ============================================================
# Authentication / Tenant Helpers
# ============================================================

def _get_user_id(current_user: Optional[Dict[str, Any]]) -> str:
    """
    Return the authenticated tenant/user ID.

    This is a hard security boundary. No graph operation is
    allowed without a valid authenticated tenant.
    """
    if not current_user or not current_user.get("_id"):
        raise HTTPException(
            status_code=401,
            detail="Authenticated user not found",
        )

    return str(current_user["_id"])


def _normalize_account_id(
    value: Optional[str],
) -> Optional[str]:
    """
    Validate and normalize the internal CloudGuardAI account ID.
    """
    if value is None:
        return None

    value = str(value).strip()

    if not value:
        return None

    if len(value) > MAX_ACCOUNT_ID_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="Account ID is too long",
        )

    return value


def _normalize_service(
    value: Optional[str],
) -> Optional[str]:
    """
    Validate an optional AWS service filter.
    """
    if value is None:
        return None

    value = str(value).strip().upper()

    if not value:
        return None

    if len(value) > MAX_SERVICE_LENGTH:
        raise HTTPException(
            status_code=400,
            detail="Service filter is too long",
        )

    if value not in ALLOWED_SERVICES:
        raise HTTPException(
            status_code=400,
            detail="Unsupported AWS service filter",
        )

    return value


def _verify_account_ownership(
    account_id: Optional[str],
    user_id: str,
):
    """
    Verify that the requested AWS account belongs to the
    authenticated tenant.

    Never trust account IDs supplied by the client.
    """
    if not account_id:
        return None

    account = get_account(
        account_id,
        user_id,
    )

    if not account:
        raise HTTPException(
            status_code=404,
            detail="AWS account not found",
        )

    return account


# ============================================================
# Account Response Helpers
# ============================================================

def _account_payload(account: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Return safe account metadata.

    Never expose credentials, role secrets, tokens, or temporary
    AWS credentials through the graph API.
    """
    if not account:
        return None

    return {
        "id": str(account.get("_id")),
        "account_name": account.get("account_name", ""),
        "aws_account_id": account.get("aws_account_id", ""),
        "region": account.get("region", ""),
    }


# ============================================================
# Graph Diagnostic Helpers
# ============================================================

def _normalize_relationship_type(value: Any) -> str:
    """
    Normalize a graph relationship type.
    """
    return str(value or "").strip().upper().replace(" ", "_")


def _verified_edges(
    edges: Any,
) -> List[Dict[str, Any]]:
    """
    Return only edges backed by explicit verified evidence.

    The API does not treat inferred/unverified relationships as
    authoritative security relationships.
    """
    if not isinstance(edges, list):
        return []

    result = []

    for edge in edges:
        if not isinstance(edge, dict):
            continue

        evidence = edge.get("evidence")

        if not isinstance(evidence, dict):
            continue

        if evidence.get("verified") is not True:
            continue

        result.append(edge)

    return result


def _relationship_statistics(
    edges: Any,
) -> Dict[str, Any]:
    """
    Build bounded, deterministic relationship statistics.

    This metadata is useful for:
    - frontend graph dashboards
    - attack-path diagnostics
    - auditability
    - support/debugging
    """
    verified = _verified_edges(edges)

    counts: Dict[str, int] = {}

    for edge in verified:
        relationship = _normalize_relationship_type(
            edge.get("relationship_type")
        )

        if not relationship:
            continue

        counts[relationship] = counts.get(
            relationship,
            0,
        ) + 1

    attack_relationship_counts = {
        relationship: counts.get(relationship, 0)
        for relationship in sorted(VERIFIED_EDGE_RELATIONSHIPS)
    }

    return {
        "verified_edge_count": len(verified),
        "relationship_types": sorted(counts.keys()),
        "relationship_counts": dict(
            sorted(counts.items())
        ),
        "attack_relationship_types": sorted(
            VERIFIED_EDGE_RELATIONSHIPS
        ),
        "verified_attack_edge_count": sum(
            attack_relationship_counts.values()
        ),
        "verified_attack_relationship_counts": (
            attack_relationship_counts
        ),
    }


def _node_statistics(
    nodes: Any,
) -> Dict[str, Any]:
    """
    Build graph node statistics.
    """
    if not isinstance(nodes, list):
        nodes = []

    counts: Dict[str, int] = {}

    internet_exposed = 0
    privilege_escalation = 0
    lateral_movement = 0

    for node in nodes:
        if not isinstance(node, dict):
            continue

        node_type = str(
            node.get("type") or "RESOURCE"
        ).strip().upper()

        counts[node_type] = counts.get(
            node_type,
            0,
        ) + 1

        if node.get("internet_exposed") is True:
            internet_exposed += 1

        if node.get("privilege_escalation") is True:
            privilege_escalation += 1

        if node.get("lateral_movement") is True:
            lateral_movement += 1

    return {
        "node_count": len(nodes),
        "node_types": dict(
            sorted(counts.items())
        ),
        "internet_exposed_nodes": internet_exposed,
        "privilege_escalation_nodes": privilege_escalation,
        "lateral_movement_nodes": lateral_movement,
    }


def _build_graph_analysis(
    result: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Build commercial-grade diagnostic metadata.

    This does not invent attack paths.

    It explains the evidence available to the deterministic
    graph engine and makes a zero-path result understandable.
    """
    graph = result.get("graph") or {}

    if not isinstance(graph, dict):
        graph = {}

    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []

    node_stats = _node_statistics(nodes)
    relationship_stats = _relationship_statistics(edges)

    discovery = graph.get("scan_graph_discovery")

    if not isinstance(discovery, dict):
        discovery = {}

    discovery_complete = discovery.get("complete")

    if discovery_complete is None:
        discovery_complete = True

    warnings = discovery.get("warnings")

    if not isinstance(warnings, list):
        warnings = []

    source = (
        graph.get("source")
        or "unknown"
    )

    schema_version = (
        graph.get("scan_graph_schema_version")
    )

    attack_paths = result.get("attack_paths") or []

    if not isinstance(attack_paths, list):
        attack_paths = []

    has_internet_node = any(
        isinstance(node, dict)
        and str(node.get("type") or "").upper() == "INTERNET"
        for node in nodes
    )

    has_compute_or_network_node = any(
        isinstance(node, dict)
        and str(node.get("type") or "").upper()
        in {
            "EC2",
            "RDS_INSTANCE",
            "LAMBDA_FUNCTION",
            "SECURITY_GROUP",
            "VPC",
            "SUBNET",
        }
        for node in nodes
    )

    has_identity_node = any(
        isinstance(node, dict)
        and str(node.get("type") or "").upper()
        in {
            "IAM_ROLE",
            "IAM_USER",
            "IAM_POLICY",
        }
        for node in nodes
    )

    has_verified_exposes = any(
        isinstance(edge, dict)
        and _normalize_relationship_type(
            edge.get("relationship_type")
        ) == "EXPOSES"
        and isinstance(edge.get("evidence"), dict)
        and edge.get("evidence", {}).get("verified") is True
        for edge in edges
    )

    has_verified_identity_relationship = any(
        isinstance(edge, dict)
        and _normalize_relationship_type(
            edge.get("relationship_type")
        ) in {
            "ASSUMES_ROLE",
            "GRANTS",
            "TRUSTS",
        }
        and isinstance(edge.get("evidence"), dict)
        and edge.get("evidence", {}).get("verified") is True
        for edge in edges
    )

    # Diagnostic state is descriptive only.
    # It never changes attack-path detection.
    if attack_paths:
        analysis_state = "PATHS_DETECTED"
    elif not nodes:
        analysis_state = "NO_GRAPH_DATA"
    elif not has_internet_node:
        analysis_state = "NO_INTERNET_ENTRY_NODE"
    elif not has_compute_or_network_node:
        analysis_state = "NO_COMPUTE_OR_NETWORK_STAGE"
    elif not has_identity_node:
        analysis_state = "NO_IDENTITY_STAGE"
    elif not has_verified_exposes:
        analysis_state = "NO_VERIFIED_EXPOSURE_EDGE"
    elif not has_verified_identity_relationship:
        analysis_state = "NO_VERIFIED_IDENTITY_EDGE"
    elif not discovery_complete:
        analysis_state = "DISCOVERY_INCOMPLETE"
    else:
        analysis_state = "NO_COMPLETE_VERIFIED_ATTACK_PATH"

    return {
        "analysis_state": analysis_state,
        "graph_source": source,
        "scan_graph_schema_version": schema_version,
        "graph_engine_version": graph.get(
            "engine_version",
            GRAPH_ENGINE_VERSION,
        ),
        "attack_path_version": graph.get(
            "attack_path_version",
            ATTACK_PATH_VERSION,
        ),
        "deterministic": True,
        "verified_edges_only": True,
        "ai_decision_dependency": False,
        "discovery": {
            "complete": bool(discovery_complete),
            "warnings": warnings[:50],
        },
        "nodes": node_stats,
        "relationships": relationship_stats,
        "evidence_stages": {
            "internet_entry_present": has_internet_node,
            "compute_or_network_stage_present": (
                has_compute_or_network_node
            ),
            "identity_stage_present": has_identity_node,
            "verified_exposure_edge_present": (
                has_verified_exposes
            ),
            "verified_identity_relationship_present": (
                has_verified_identity_relationship
            ),
        },
        "attack_path_count": len(attack_paths),
    }


# ============================================================
# Graph Builder Wrapper
# ============================================================

def _build_graph_result(
    user_id: str,
    account_id: Optional[str],
    service: Optional[str] = None,
    include_resolved: bool = False,
) -> Dict[str, Any]:
    """
    Centralized graph-building operation.

    Keeping graph construction in one place ensures the API
    returns consistent graph, diagnostics, and attack-path data.
    """
    try:
        result = build_security_graph(
            user_id=user_id,
            account_id=account_id,
            service=service,
            include_resolved=include_resolved,
        )
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=500,
            detail="Unable to build security graph",
        )

    if not isinstance(result, dict):
        raise HTTPException(
            status_code=500,
            detail="Invalid security graph response",
        )

    return result


# ============================================================
# Full Security Graph
# ============================================================

@router.get("")
@router.get("/")
def security_graph(
    account_id: Optional[str] = Query(
        default=None,
        description="CloudGuardAI internal AWS account ID",
    ),
    service: Optional[str] = Query(
        default=None,
        description="Optional AWS service filter",
    ),
    include_resolved: bool = Query(
        default=False,
        description="Include resolved/ignored findings",
    ),
    current_user=Depends(verify_token),
):
    """
    Build the tenant-scoped security relationship graph.

    Returns:
    - graph topology
    - verified relationships
    - findings
    - attack paths
    - graph diagnostics
    """
    user_id = _get_user_id(current_user)

    normalized_account_id = _normalize_account_id(
        account_id
    )

    normalized_service = _normalize_service(
        service
    )

    account = _verify_account_ownership(
        normalized_account_id,
        user_id,
    )

    result = _build_graph_result(
        user_id=user_id,
        account_id=normalized_account_id,
        service=normalized_service,
        include_resolved=include_resolved,
    )

    result["account"] = _account_payload(
        account
    )

    result["analysis"] = _build_graph_analysis(
        result
    )

    return result


# ============================================================
# Attack Paths
# ============================================================

@router.get("/attack-paths")
def security_attack_paths(
    account_id: Optional[str] = Query(
        default=None,
        description="CloudGuardAI internal AWS account ID",
    ),
    current_user=Depends(verify_token),
):
    """
    Return deterministic, evidence-backed attack paths.

    The endpoint intentionally does not allow an AI model to
    create or authorize an attack path.
    """
    user_id = _get_user_id(current_user)

    normalized_account_id = _normalize_account_id(
        account_id
    )

    account = _verify_account_ownership(
        normalized_account_id,
        user_id,
    )

    result = _build_graph_result(
        user_id=user_id,
        account_id=normalized_account_id,
    )

    paths = result.get("attack_paths") or []

    if not isinstance(paths, list):
        paths = []

    analysis = _build_graph_analysis(
        result
    )

    return {
        "status": "success",
        "engine_version": GRAPH_ENGINE_VERSION,
        "attack_path_version": ATTACK_PATH_VERSION,
        "account": _account_payload(
            account
        ),
        "count": len(paths),
        "attack_paths": paths,
        "analysis": analysis,
    }


# ============================================================
# Lightweight Summary
# ============================================================

@router.get("/summary")
def security_graph_summary(
    account_id: Optional[str] = Query(
        default=None,
        description="CloudGuardAI internal AWS account ID",
    ),
    current_user=Depends(verify_token),
):
    """
    Return a lightweight graph summary suitable for dashboards.

    This endpoint exposes enough diagnostic information for the
    frontend to explain a zero-path result without loading the
    complete graph.
    """
    user_id = _get_user_id(current_user)

    normalized_account_id = _normalize_account_id(
        account_id
    )

    account = _verify_account_ownership(
        normalized_account_id,
        user_id,
    )

    result = _build_graph_result(
        user_id=user_id,
        account_id=normalized_account_id,
    )

    graph = result.get("graph") or {}

    if not isinstance(graph, dict):
        graph = {}

    summary = result.get("summary") or {}

    if not isinstance(summary, dict):
        summary = {}

    analysis = _build_graph_analysis(
        result
    )

    return {
        "status": "success",
        "engine_version": GRAPH_ENGINE_VERSION,
        "attack_path_version": ATTACK_PATH_VERSION,
        "account": _account_payload(
            account
        ),
        "account_id": normalized_account_id,
        "summary": {
            "internet_exposed_nodes": summary.get(
                "internet_exposed_nodes",
                0,
            ),
            "privilege_escalation_nodes": summary.get(
                "privilege_escalation_nodes",
                0,
            ),
            "lateral_movement_nodes": summary.get(
                "lateral_movement_nodes",
                0,
            ),
            "attack_path_count": len(
                result.get("attack_paths") or []
            ),
            "node_count": graph.get(
                "node_count",
                0,
            ),
            "edge_count": graph.get(
                "edge_count",
                0,
            ),
            "finding_count": graph.get(
                "finding_count",
                0,
            ),
        },
        "analysis": {
            "analysis_state": analysis.get(
                "analysis_state"
            ),
            "graph_source": analysis.get(
                "graph_source"
            ),
            "scan_graph_schema_version": analysis.get(
                "scan_graph_schema_version"
            ),
            "verified_edges_only": analysis.get(
                "verified_edges_only"
            ),
            "deterministic": analysis.get(
                "deterministic"
            ),
            "ai_decision_dependency": analysis.get(
                "ai_decision_dependency"
            ),
            "discovery": analysis.get(
                "discovery"
            ),
            "relationships": analysis.get(
                "relationships"
            ),
            "evidence_stages": analysis.get(
                "evidence_stages"
            ),
        },
        "attack_paths": (
            result.get("attack_paths") or []
        )[:10],
    }


# ============================================================
# Health / Capability
# ============================================================

@router.get("/health")
def security_graph_health(
    current_user=Depends(verify_token),
):
    """
    Authenticated capability endpoint.

    This endpoint does not inspect AWS and does not access graph
    data. It is safe for frontend service health checks.
    """
    _get_user_id(current_user)

    return {
        "status": "success",
        "service": "security-graph",
        "engine_version": GRAPH_ENGINE_VERSION,
        "attack_path_version": ATTACK_PATH_VERSION,
        "capabilities": {
            "relationship_graph": True,
            "scan_level_graph": True,
            "attack_path_analysis": True,
            "evidence_backed_relationships": True,
            "verified_edges_only_for_attack_paths": True,
            "tenant_isolation": True,
            "deterministic_analysis": True,
            "ai_decision_dependency": False,
        },
        "limits": {
            "allowed_services": sorted(
                ALLOWED_SERVICES
            ),
        },
    }