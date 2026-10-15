# ============================================================
# CloudGuardAI - AWS Cloud Security API
# Production / Commercial SaaS Foundation
# ============================================================

from datetime import datetime
import hashlib
import logging
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from botocore.exceptions import BotoCoreError, ClientError

from app.services.aws_analyzer import analyze

from app.services.s3_checker import check_s3, inspect_s3_inventory
from app.services.ec2_checker import check_ec2
from app.services.iam_checker import check_iam
from app.services.cloudtrail_checker import check_cloudtrail
from app.services.vpc_checker import check_vpc
from app.services.rds_checker import check_rds
from app.services.lambda_checker import check_lambda
from app.services.kms_checker import check_kms

from app.services.policy_generator import generate_policies
from app.services.ai_explainer import explain

from app.ai.gemini import ask_gemini

from app.services.scan_service import (
    save_scan,
    get_all_scans,
    get_scan,
    delete_scan,
    search_scans,
    filter_scans,
)

from app.services.quota_service import reserve_quota
from app.services.organization_usage_service import release_usage

from app.services.notification_service import create_alert

from app.services.aws_connection import (
    assume_aws_role,
    get_aws_clients,
    verify_aws_account,
)

from pydantic import BaseModel

from app.services.ec2_inventory_service import (
    fetch_ec2_instances_inventory,
    validate_aws_region,
)

from app.services.ec2_control_service import (
    execute_ec2_instance_action,
    EC2ControlExecutionError,
)

from app.services.s3_control_service import (
    fetch_s3_buckets_inventory,
    execute_s3_bucket_action,
    S3ControlExecutionError,
    validate_aws_region as validate_s3_region,
)

from app.services.rds_control_service import (
    fetch_rds_instances_inventory,
    fetch_rds_clusters_inventory,
    execute_rds_instance_action,
    RDSControlExecutionError,
    validate_aws_region as validate_rds_region,
)

from app.services.network_control_service import (
    query_vpcs,
    query_subnets,
    query_security_groups,
    query_route_tables,
    query_gateways,
    query_vpc_endpoints,
    execute_security_group_control,
    NetworkControlExecutionError,
    validate_aws_region as validate_network_region,
    is_valid_vpc_id,
    is_valid_security_group_id,
)

class SecurityGroupActionPayload(BaseModel):
    action: str
    region: Optional[str] = None
    rule_spec: Optional[dict] = None
    confirmed: bool = True

from app.models.aws_account import (
    get_account,
)

from app.models.finding import (
    upsert_finding,
)

from app.middleware.auth_middleware import verify_token
from app.services.tenant_context import (
    TenantContext,
    resolve_tenant_context,
)

from app.services.audit_log_service import (
    record_failure as record_audit_failure,
    record_info as record_audit_info,
    record_success as record_audit_success,
)
from app.models.audit_log import (
    EVENT_SCAN_STARTED,
    EVENT_SCAN_COMPLETED,
    EVENT_SCAN_FAILED,
)


logger = logging.getLogger("cloudguardai.audit")


router = APIRouter()


def _record_scan_audit(
    *,
    user_id,
    event_type,
    action,
    result,
    account_id=None,
    aws_account_id=None,
    resource_id=None,
    message=None,
    metadata=None,
):
    """
    Record scan lifecycle audit events.

    Audit persistence is fail-safe: an audit failure must never break a
    successful customer security scan. Failures are logged server-side so
    the integration can be diagnosed without exposing internal details.
    """
    try:
        kwargs = {
            "user_id": user_id,
            "event_type": event_type,
            "action": action,
            "account_id": account_id,
            "aws_account_id": aws_account_id,
            "resource_id": resource_id,
            "message": message,
            "metadata": metadata or {},
        }

        if result == "SUCCESS":
            audit_result = record_audit_success(**kwargs)
        elif result == "FAILURE":
            audit_result = record_audit_failure(**kwargs)
        else:
            audit_result = record_audit_info(**kwargs)

        logger.info(
            "AUDIT_EVENT_RECORDED event_type=%s user_id=%s account_id=%s",
            event_type,
            user_id,
            account_id,
        )
        return audit_result

    except Exception as exc:
        logger.exception(
            "AUDIT_EVENT_FAILED event_type=%s user_id=%s account_id=%s error=%s",
            event_type,
            user_id,
            account_id,
            exc,
        )

        # Audit failure must never break the customer's scan.
        return None


# ============================================================
# HELPERS
# ============================================================

def _safe_string(value):
    """
    Safely convert a value into a clean string.
    """

    if value is None:
        return ""

    return str(value).strip()


def _coerce_cloud_tenant_context(
    current_user: Any,
    required_role: Optional[str] = None,
) -> TenantContext:
    """
    Validates authenticated user identity, active tenant membership, and role authorization
    for cloud control operations using shared tenant context and RBAC.

    Guarantees:
    - User identity and organization are resolved strictly from verified server-side identity (current_user).
    - Ignores client request headers, query params, or body fields for organization override (request=None).
    - Enforces active membership via db.organization_members.
    - Rejects restricted or non-active statuses (inactive, revoked, suspended, removed) fail-closed.
    - Rejects missing, invalid, or unsupported roles fail-closed.
    - If required_role == 'owner_or_admin', requires role in ('owner', 'admin') with a safe 403.
    """
    if isinstance(current_user, TenantContext):
        ctx = current_user
    elif isinstance(current_user, dict):
        user_id = _safe_string(
            current_user.get("_id")
            or current_user.get("user_id")
            or current_user.get("id")
        )
        if not user_id:
            raise HTTPException(status_code=401, detail="Authentication required.")

        trusted_org = _safe_string(
            current_user.get("organization") or current_user.get("organization_id")
        )
        if not trusted_org:
            raise HTTPException(status_code=403, detail="Organization context is required.")

        try:
            ctx = resolve_tenant_context(
                target_organization_id=trusted_org,
                current_user=current_user,
                request=None,
            )
        except HTTPException as exc:
            if exc.status_code == 500:
                raise HTTPException(
                    status_code=500,
                    detail="Internal error resolving organization membership.",
                ) from exc
            raise
    else:
        raise HTTPException(status_code=401, detail="Authentication required.")

    if not ctx.organization_id:
        raise HTTPException(status_code=403, detail="Organization context is required.")

    role = str(ctx.role or "").strip().lower()
    if not role or role not in ("owner", "admin", "analyst", "viewer"):
        raise HTTPException(
            status_code=403,
            detail="Invalid or unsupported organization role. Access denied.",
        )

    if required_role == "owner_or_admin":
        if role not in ("owner", "admin"):
            raise HTTPException(
                status_code=403,
                detail="You must have an Admin or Owner role to perform this action.",
            )

    return ctx


def _get_service(finding):
    """
    Determine the AWS service associated with a finding.
    """

    if not isinstance(finding, dict):
        return "AWS"

    service = finding.get("service")

    if service:
        return _safe_string(service).upper()

    resource_type = finding.get("resource_type")

    if resource_type:
        return _safe_string(resource_type).upper()

    if finding.get("bucket"):
        return "S3"

    if finding.get("security_group"):
        return "EC2"

    if finding.get("user"):
        return "IAM"

    return "AWS"


def _get_resource(finding):
    """
    Determine the affected resource.
    """

    if not isinstance(finding, dict):
        return "AWS Resource"

    candidates = [
        finding.get("resource"),
        finding.get("resource_arn"),
        finding.get("bucket"),
        finding.get("security_group"),
        finding.get("security_group_id"),
        finding.get("user"),
        finding.get("function_name"),
        finding.get("db_identifier"),
        finding.get("key_id"),
        finding.get("trail_name"),
        finding.get("service"),
    ]

    for value in candidates:

        if value:
            return _safe_string(value)

    return "AWS Resource"


def _create_finding_id(
    finding,
    account_id
):
    """
    Create a stable deterministic finding ID.

    The same underlying issue on the same AWS account
    should receive the same ID across scans.
    """

    service = _get_service(finding)

    resource = _get_resource(finding)

    issue = _safe_string(
        finding.get(
            "issue",
            "Security Finding"
        )
    )

    severity = _safe_string(
        finding.get(
            "severity",
            "LOW"
        )
    ).upper()

    control_id = _safe_string(
        finding.get(
            "control_id",
            ""
        )
    )

    raw = "|".join(
        [
            _safe_string(account_id),
            service,
            resource,
            issue,
            severity,
            control_id,
        ]
    )

    digest = hashlib.sha256(
        raw.encode("utf-8")
    ).hexdigest()[:16].upper()

    return f"CG-{digest}"


def _normalize_finding(
    finding,
    account_id,
    scan_time
):
    """
    Normalize checker output into a commercial
    CloudGuardAI finding structure.
    """

    if not isinstance(finding, dict):
        return None

    normalized = dict(finding)

    severity = _safe_string(
        normalized.get(
            "severity",
            "LOW"
        )
    ).upper()

    if severity not in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
    ]:
        severity = "LOW"

    original_status = _safe_string(
        normalized.get(
            "status",
            ""
        )
    ).upper()

    # --------------------------------------------------------
    # Stable identity
    # --------------------------------------------------------

    finding_id = _create_finding_id(
        normalized,
        account_id
    )

    # --------------------------------------------------------
    # Service / resource
    # --------------------------------------------------------

    service = _get_service(
        normalized
    )

    resource = _get_resource(
        normalized
    )

    # --------------------------------------------------------
    # Workflow status
    #
    # Detection status and workflow status are separate.
    #
    # IMPORTANT:
    # The dedicated findings collection controls the
    # actual customer workflow state.
    # --------------------------------------------------------

    protected_statuses = {
        "PROTECTED",
        "PASS",
        "PASSED",
    }

    review_statuses = {
        "REVIEW",
        "WARNING",
    }

    unknown_statuses = {
        "UNKNOWN",
    }

    if original_status in protected_statuses:

        workflow_status = "PROTECTED"

    elif original_status in review_statuses:

        workflow_status = "REVIEW"

    elif original_status in unknown_statuses:

        workflow_status = "UNKNOWN"

    else:

        workflow_status = "OPEN"

    # --------------------------------------------------------
    # Commercial metadata
    # --------------------------------------------------------

    normalized["finding_id"] = finding_id

    normalized["service"] = service

    normalized["resource"] = resource

    normalized["severity"] = severity

    normalized["detection_status"] = (
        original_status
        if original_status
        else "DETECTED"
    )

    normalized["status"] = workflow_status

    normalized["workflow_status"] = workflow_status

    normalized["account_id"] = _safe_string(
        account_id
    )

    normalized["first_seen"] = scan_time

    normalized["last_seen"] = scan_time

    # --------------------------------------------------------
    # Finding lifecycle defaults
    # --------------------------------------------------------

    normalized.setdefault(
        "resolution",
        None
    )

    normalized.setdefault(
        "resolved_at",
        None
    )

    normalized.setdefault(
        "assigned_to",
        None
    )

    normalized.setdefault(
        "notes",
        ""
    )

    return normalized


def _normalize_findings(
    findings,
    account_id,
    scan_time
):
    """
    Normalize and deduplicate findings.
    """

    if not isinstance(findings, list):
        return []

    normalized = []

    seen = set()

    for finding in findings:

        item = _normalize_finding(
            finding,
            account_id,
            scan_time
        )

        if not item:
            continue

        finding_id = item.get(
            "finding_id"
        )

        if not finding_id:
            continue

        if finding_id in seen:
            continue

        seen.add(
            finding_id
        )

        normalized.append(
            item
        )

    return normalized


def _persist_findings(
    findings,
    user_id,
    aws_account,
    aws_account_id
):
    """
    Persist normalized findings into the dedicated
    findings collection.

    Existing findings are updated using stable
    finding_id.

    IMPORTANT:
    Customer workflow state is preserved by
    upsert_finding().
    """

    persisted_findings = []

    if not isinstance(findings, list):
        return persisted_findings

    for finding in findings:

        if not isinstance(
            finding,
            dict
        ):
            continue

        finding_data = dict(
            finding
        )

        # ----------------------------------------------------
        # Connected account
        # ----------------------------------------------------

        connected_account_id = str(
            aws_account.get(
                "_id",
                ""
            )
        )

        finding_data[
            "account_id"
        ] = connected_account_id

        finding_data[
            "aws_account_id"
        ] = str(
            aws_account_id
        )

        finding_data[
            "account_name"
        ] = aws_account.get(
            "account_name",
            ""
        )

        # ----------------------------------------------------
        # Stable finding ID
        # ----------------------------------------------------

        if not finding_data.get(
            "finding_id"
        ):

            finding_data[
                "finding_id"
            ] = _create_finding_id(
                finding_data,
                aws_account_id
            )

        # ----------------------------------------------------
        # Ensure useful fields exist
        # ----------------------------------------------------

        finding_data.setdefault(
            "service",
            _get_service(
                finding_data
            )
        )

        finding_data.setdefault(
            "resource",
            _get_resource(
                finding_data
            )
        )

        finding_data.setdefault(
            "description",
            finding_data.get(
                "issue",
                ""
            )
        )

        finding_data.setdefault(
            "remediation",
            finding_data.get(
                "recommendation",
                ""
            )
        )

        # ----------------------------------------------------
        # Persist / Update
        # ----------------------------------------------------

        try:

            persisted = upsert_finding(
                finding_data,
                user_id
            )

            if persisted:

                persisted_findings.append(
                    persisted
                )

        except Exception as error:

            # Do not silently break the complete AWS scan
            # if one finding persistence operation fails.
            #
            # The error is raised after adding context so
            # production logs can identify the problem.

            raise RuntimeError(
                "Failed to persist finding "
                f"{finding_data.get('finding_id')}: "
                f"{error}"
            ) from error

    return persisted_findings



# ============================================================
# AWS RELATIONSHIP ENRICHMENT
# ============================================================

def _aws_name(value):
    return _safe_string(value)


def _extract_role_name(role_arn):
    role_arn = _safe_string(role_arn)
    if not role_arn:
        return ""
    return role_arn.rsplit("/", 1)[-1]


def _build_relationship_evidence(source, **extra):
    evidence = {
        "source": "AWS_API_RELATIONSHIP_ENRICHMENT",
        "verified": True,
        "retrieved_at": datetime.utcnow().isoformat() + "Z",
        "source_api": source,
    }
    evidence.update({
        key: value
        for key, value in extra.items()
        if value is not None and value != ""
    })
    return evidence


def _safe_aws_call(callable_obj, default):
    try:
        return callable_obj()
    except Exception:
        return default


def _collect_aws_relationship_inventory(ec2, iam, rds, lambda_client, account_id, region):
    from app.services.aws_relationship_service import collect_relationship_inventory
    return collect_relationship_inventory(ec2, iam, rds, lambda_client, account_id, region)


def _apply_aws_relationship_enrichment(findings, relationship_inventory):
    from app.services.aws_relationship_service import enrich_findings_with_relationships
    return enrich_findings_with_relationships(findings, relationship_inventory)



def _build_scan_security_graph(relationship_inventory, findings=None):
    """Build the authoritative scan-level AWS security graph snapshot."""
    inventory = relationship_inventory if isinstance(relationship_inventory, dict) else {}
    findings = findings if isinstance(findings, list) else []
    node_maps = ("instances", "security_groups", "roles", "policies", "users", "lambdas", "rds", "vpcs", "subnets", "internet_gateways", "route_tables", "s3_buckets")
    nodes = {}
    for bucket in node_maps:
        values = inventory.get(bucket) or {}
        if not isinstance(values, dict):
            continue
        for key, node in values.items():
            if not isinstance(node, dict):
                continue
            node_type = _safe_string(node.get("node_type") or "RESOURCE").upper()
            resource_id = _safe_string(node.get("resource_id") or key)
            if not resource_id:
                continue
            normalized = dict(node)
            normalized["node_type"] = node_type
            normalized["resource_id"] = resource_id
            normalized.setdefault("resource_name", resource_id)
            nodes[f"{node_type}:{resource_id}"] = normalized

    relationships = []
    seen = set()
    for edge in inventory.get("relationships") or []:
        if not isinstance(edge, dict):
            continue
        evidence = edge.get("evidence")
        if not isinstance(evidence, dict) or evidence.get("verified") is not True:
            continue
        source_type = _safe_string(edge.get("source_type")).upper()
        source_id = _safe_string(edge.get("source_id"))
        target_type = _safe_string(edge.get("target_type")).upper()
        target_id = _safe_string(edge.get("target_id"))
        relation_type = _safe_string(edge.get("relationship_type")).upper()
        if not all((source_type, source_id, target_type, target_id, relation_type)):
            continue
        key = (source_type, source_id, target_type, target_id, relation_type)
        if key in seen:
            continue
        seen.add(key)
        relationships.append({
            "source_type": source_type,
            "source_id": source_id,
            "target_type": target_type,
            "target_id": target_id,
            "relationship_type": relation_type,
            "evidence": evidence,
        })
        for node_type, resource_id in ((source_type, source_id), (target_type, target_id)):
            node_key = f"{node_type}:{resource_id}"
            if node_key not in nodes:
                nodes[node_key] = {
                    "node_type": node_type,
                    "resource_id": resource_id,
                    "resource_name": resource_id,
                    "resource_arn": None,
                    "service": None,
                    "signals": {},
                    "materialized_from_relationship": True,
                }

    finding_refs = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        graph = finding.get("security_graph")
        if not isinstance(graph, dict):
            continue
        resource_id = _safe_string(graph.get("resource_id"))
        node_type = _safe_string(graph.get("graph_node_type") or "RESOURCE").upper()
        if resource_id:
            finding_refs.append({
                "finding_id": _safe_string(finding.get("finding_id")),
                "node_type": node_type,
                "resource_id": resource_id,
            })

    discovery = inventory.get("discovery")
    if not isinstance(discovery, dict):
        discovery = {"complete": True, "warnings": []}
    return {
        "graph_schema_version": "2.0",
        "inventory_version": _safe_string(inventory.get("version") or "unknown"),
        "source": _safe_string(inventory.get("source") or "AWS_API_RELATIONSHIP_ENRICHMENT"),
        "account_id": _safe_string(inventory.get("account_id")),
        "region": _safe_string(inventory.get("region")),
        "retrieved_at": inventory.get("retrieved_at"),
        "nodes": list(nodes.values()),
        "relationships": relationships,
        "finding_refs": finding_refs,
        "discovery": {
            "complete": bool(discovery.get("complete", False)),
            "warnings": list(discovery.get("warnings") or []),
        },
        "node_count": len(nodes),
        "relationship_count": len(relationships),
        "attack_paths": [],
        "attack_path_count": 0,
        "generated_at": datetime.utcnow(),
    }


# ============================================================
# EC2 RESOURCE INVENTORY (READ-ONLY)
# ============================================================

@router.get("/aws/ec2/{account_id}/instances")
def list_ec2_instances(
    account_id: str,
    region: Optional[str] = None,
    max_results: Optional[int] = None,
    next_token: Optional[str] = None,
    all_pages: bool = False,
    current_user=Depends(verify_token),
):
    """
    Secure, read-only EC2 instance inventory for the connected AWS account.

    Enforces:
    - JWT authentication
    - Organization tenant isolation
    - Connected AWS account ownership
    - AWS STS identity verification
    - Read-only DescribeInstances execution
    """
    # Unpack potential Query object defaults if called directly in unit tests
    if hasattr(region, "default"):
        region = region.default
    if hasattr(max_results, "default"):
        max_results = max_results.default
    if hasattr(next_token, "default"):
        next_token = next_token.default
    if hasattr(all_pages, "default"):
        all_pages = bool(all_pages.default)

    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(
            status_code=400,
            detail="AWS Account ID is required.",
        )

    # Validate region parameter upfront if explicitly provided
    if region is not None:
        target_region = str(region).strip()
        if not validate_aws_region(target_region):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid AWS region '{region}'. Region must match standard format like 'us-east-1', 'ap-south-1'.",
            )
    else:
        target_region = None

    # Tenant-scoped account lookup
    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found.",
        )

    # Fall back to account's configured region if not explicitly specified
    if target_region is None:
        target_region = str(aws_account.get("region") or "ap-south-1").strip()
        if not validate_aws_region(target_region):
            target_region = "ap-south-1"

    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(
            status_code=400,
            detail="AWS account is missing configured role_arn.",
        )

    # Assume AWS IAM role with temporary credentials
    try:
        session = assume_aws_role(
            role_arn,
            region=target_region,
            external_id=aws_account.get("external_id"),
        )
    except Exception as assume_err:
        logger.warning(
            "EC2 inventory role assumption failed account_id=%s: %s",
            clean_account_id,
            assume_err,
        )
        raise HTTPException(
            status_code=403,
            detail="Failed to assume AWS role for the connected account. Verify IAM trust relationship.",
        )

    # Verify assumed role matches expected AWS account
    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(
            status_code=403,
            detail=str(perm_err),
        )
    except Exception:
        raise HTTPException(
            status_code=403,
            detail="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    ec2_client = clients.get("ec2")
    if not ec2_client:
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize EC2 service client.",
        )

    try:
        inventory_result = fetch_ec2_instances_inventory(
            ec2_client=ec2_client,
            region=target_region,
            max_results=max_results,
            next_token=next_token,
            all_pages=all_pages,
        )
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise HTTPException(
                status_code=403,
                detail=f"AWS AccessDenied: The IAM role lacks ec2:DescribeInstances permission in {target_region}.",
            )
        elif code in ("RequestLimitExceeded", "Throttling"):
            raise HTTPException(
                status_code=429,
                detail="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            )
        else:
            raise HTTPException(
                status_code=502,
                detail=f"AWS EC2 service error ({code}).",
            )
    except BotoCoreError:
        raise HTTPException(
            status_code=502,
            detail="Network or connection failure communicating with AWS EC2 service.",
        )

    return {
        "status": "success",
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "account_name": aws_account.get("account_name"),
        "region": target_region,
        "regional_scope": f"Single-region inventory for {target_region}. Pass ?region=<region> to inspect other regions.",
        "total_count": inventory_result["total_count"],
        "instances": inventory_result["instances"],
        "next_token": inventory_result.get("next_token"),
    }


class EC2ActionRequest(BaseModel):
    action: str
    region: Optional[str] = None
    confirmed: bool = False


@router.post("/aws/ec2/{account_id}/instances/{instance_id}/action")
def control_ec2_instance(
    account_id: str,
    instance_id: str,
    payload: EC2ActionRequest,
    request: Request = None,
    current_user=Depends(verify_token),
):
    """
    Securely execute Start, Stop, or Reboot on a connected AWS EC2 instance.

    Enforces:
    - Authentication & tenant organization isolation
    - Strict Owner/Admin role authorization
    - Explicit user confirmation
    - AWS STS account verification
    - Pre-state and post-state transition validation
    - Comprehensive audit logging
    """
    request_id = ""
    if request:
        request_id = (
            request.headers.get("x-request-id")
            or request.headers.get("x-correlation-id")
            or getattr(request.state, "request_id", "")
            or ""
        )

    ctx = _coerce_cloud_tenant_context(current_user)

    try:
        result = execute_ec2_instance_action(
            account_id=account_id,
            instance_id=instance_id,
            action=payload.action,
            region=payload.region,
            confirmed=payload.confirmed,
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            role=ctx.role,
            request_id=request_id or None,
        )
        return result
    except EC2ControlExecutionError as err:
        logger.warning(
            "[REQ:%s] EC2 control execution error [%s - %s]: %s (user_id=%s, org_id=%s)",
            request_id or "N/A",
            err.status_code,
            err.code,
            err.public_message,
            ctx.user_id,
            ctx.organization_id,
        )
        raise HTTPException(
            status_code=err.status_code,
            detail=err.public_message,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(
            "[REQ:%s] Unexpected error controlling EC2 instance: %s",
            request_id or "N/A",
            exc,
        )
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while executing the EC2 control action.",
        )


# ============================================================
# S3 RESOURCE INVENTORY & CONTROLS
# Phase 3: Secure AWS S3 Resource Management
# ============================================================

@router.get("/aws/s3/{account_id}/buckets")
def list_s3_buckets(
    account_id: str,
    region: Optional[str] = None,
    page_size: Optional[int] = 50,
    next_token: Optional[str] = None,
    all_pages: bool = False,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """
    Secure, read-only S3 bucket inventory & security posture inspection for the connected AWS account.

    Enforces:
    - JWT authentication
    - Organization tenant isolation
    - Connected AWS account ownership
    - AWS STS identity verification
    - Read-only S3 configuration & posture inspection
    """
    if hasattr(region, "default"):
        region = region.default
    if hasattr(page_size, "default"):
        page_size = page_size.default
    if hasattr(next_token, "default"):
        next_token = next_token.default
    if hasattr(all_pages, "default"):
        all_pages = bool(all_pages.default)
    if hasattr(search, "default"):
        search = search.default

    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(
            status_code=400,
            detail="AWS Account ID is required.",
        )

    if region is not None:
        target_region = str(region).strip()
        if not validate_s3_region(target_region):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid AWS region '{region}'. Region must match standard format like 'us-east-1', 'ap-south-1'.",
            )
    else:
        target_region = None

    # Tenant-scoped account lookup
    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found.",
        )

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(
            status_code=400,
            detail="AWS account is missing configured role_arn.",
        )

    # Assume AWS IAM role with temporary credentials
    try:
        session = assume_aws_role(
            role_arn,
            region=target_region or "us-east-1",
            external_id=aws_account.get("external_id"),
        )
    except Exception as assume_err:
        logger.warning(
            "S3 inventory role assumption failed account_id=%s: %s",
            clean_account_id,
            assume_err,
        )
        raise HTTPException(
            status_code=403,
            detail="Failed to assume AWS role for the connected account. Verify IAM trust relationship.",
        )

    # Verify assumed role matches expected AWS account
    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(
            status_code=403,
            detail=str(perm_err),
        )
    except Exception:
        raise HTTPException(
            status_code=403,
            detail="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    s3_client = clients.get("s3")
    if not s3_client:
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize S3 service client.",
        )

    try:
        inventory_result = fetch_s3_buckets_inventory(
            s3_client=s3_client,
            session=session,
            account_id=stored_aws_account_id,
            region_filter=target_region,
            page_size=page_size,
            next_token=next_token,
            all_pages=all_pages,
            search=search,
        )
    except S3ControlExecutionError as s3_err:
        raise HTTPException(
            status_code=s3_err.status_code,
            detail=s3_err.public_message,
        )
    except Exception as exc:
        logger.error("Unexpected error fetching S3 inventory: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while inspecting S3 bucket inventory.",
        )

    return {
        "status": "success",
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "account_name": aws_account.get("account_name"),
        "region_filter": target_region,
        "total_count": inventory_result["total_count"],
        "summary": inventory_result["summary"],
        "coverage": inventory_result["coverage"],
        "buckets": inventory_result["buckets"],
        "next_token": inventory_result.get("next_token"),
    }


class S3ActionRequest(BaseModel):
    action: str
    region: Optional[str] = None
    confirmed: bool = False


@router.post("/aws/s3/{account_id}/buckets/{bucket_name}/action")
def control_s3_bucket(
    account_id: str,
    bucket_name: str,
    payload: S3ActionRequest,
    current_user=Depends(verify_token),
):
    """
    Securely execute supported S3 security controls on a connected AWS bucket.

    Supported Actions:
    - enable_block_public_access
    - enable_encryption
    - enable_versioning

    Enforces:
    - Authentication & tenant organization isolation
    - Strict Owner/Admin role authorization
    - Explicit user confirmation
    - AWS STS account verification
    - Pre-state and post-state transition validation
    - Tamper-evident audit logging
    """
    ctx = _coerce_cloud_tenant_context(current_user)

    try:
        result = execute_s3_bucket_action(
            account_id=account_id,
            bucket_name=bucket_name,
            action=payload.action,
            region=payload.region,
            confirmed=payload.confirmed,
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            role=ctx.role,
        )
        return result
    except S3ControlExecutionError as err:
        raise HTTPException(
            status_code=err.status_code,
            detail=err.public_message,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error controlling S3 bucket: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while executing the S3 control action.",
        )



# ============================================================
# RDS RESOURCE INVENTORY & CONTROLS
# Phase 4: AWS RDS Resource Management & Database Security
# ============================================================

@router.get("/aws/rds/{account_id}/instances")
def list_rds_instances(
    account_id: str,
    region: Optional[str] = None,
    max_records: Optional[int] = 50,
    marker: Optional[str] = None,
    all_pages: bool = False,
    search: Optional[str] = None,
    engine: Optional[str] = None,
    status: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """
    Secure, read-only RDS DB instance inventory for the connected AWS account.

    Enforces:
    - JWT authentication
    - Organization tenant isolation
    - Connected AWS account ownership
    - AWS STS identity verification
    - Read-only RDS DescribeDBInstances execution
    """
    if hasattr(region, "default"):
        region = region.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(marker, "default"):
        marker = marker.default
    if hasattr(all_pages, "default"):
        all_pages = bool(all_pages.default)
    if hasattr(search, "default"):
        search = search.default
    if hasattr(engine, "default"):
        engine = engine.default
    if hasattr(status, "default"):
        status = status.default

    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(
            status_code=400,
            detail="AWS Account ID is required.",
        )

    # Tenant-scoped account lookup
    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found.",
        )

    if region is not None:
        target_region = str(region).strip()
        if not validate_rds_region(target_region):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid AWS region '{region}'. Region must match standard format like 'us-east-1', 'ap-south-1'.",
            )
    else:
        target_region = str(aws_account.get("region") or "us-east-1").strip()
        if not validate_rds_region(target_region):
            target_region = "us-east-1"

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(
            status_code=400,
            detail="AWS account is missing configured role_arn.",
        )

    # Assume AWS IAM role with temporary credentials
    try:
        session = assume_aws_role(
            role_arn,
            region=target_region,
            external_id=aws_account.get("external_id"),
        )
    except Exception as assume_err:
        logger.warning(
            "RDS inventory role assumption failed account_id=%s: %s",
            clean_account_id,
            assume_err,
        )
        raise HTTPException(
            status_code=403,
            detail="Failed to assume AWS role for the connected account. Verify IAM trust relationship.",
        )

    # Verify assumed role matches expected AWS account
    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(
            status_code=403,
            detail=str(perm_err),
        )
    except Exception:
        raise HTTPException(
            status_code=403,
            detail="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    rds_client = clients.get("rds")
    if not rds_client:
        raise HTTPException(
            status_code=500,
            detail="Failed to initialize RDS service client.",
        )

    try:
        inventory_result = fetch_rds_instances_inventory(
            rds_client=rds_client,
            region=target_region,
            max_records=max_records,
            marker=marker,
            all_pages=all_pages,
            search=search,
            engine_filter=engine,
            status_filter=status,
        )
    except RDSControlExecutionError as rds_err:
        raise HTTPException(
            status_code=rds_err.status_code,
            detail=rds_err.public_message,
        )
    except Exception as exc:
        logger.error("Unexpected error fetching RDS inventory: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while inspecting RDS database inventory.",
        )

    return {
        "status": "success",
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "account_name": aws_account.get("account_name"),
        "region": target_region,
        "regional_scope": f"RDS inventory for {target_region}. Pass ?region=<region> to inspect other regions.",
        "total_count": inventory_result["total_count"],
        "summary": inventory_result["summary"],
        "coverage": inventory_result["coverage"],
        "instances": inventory_result["instances"],
        "next_token": inventory_result.get("next_token"),
    }


@router.get("/aws/rds/{account_id}/clusters")
def list_rds_clusters(
    account_id: str,
    region: Optional[str] = None,
    max_records: Optional[int] = 50,
    marker: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """
    Secure, read-only RDS DB cluster inventory for the connected AWS account.
    """
    if hasattr(region, "default"):
        region = region.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(marker, "default"):
        marker = marker.default

    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(
            status_code=400,
            detail="AWS Account ID is required.",
        )

    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found.",
        )

    if region is not None:
        target_region = str(region).strip()
        if not validate_rds_region(target_region):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid AWS region '{region}'.",
            )
    else:
        target_region = str(aws_account.get("region") or "us-east-1").strip()
        if not validate_rds_region(target_region):
            target_region = "us-east-1"

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(
            status_code=400,
            detail="AWS account is missing configured role_arn.",
        )

    try:
        session = assume_aws_role(
            role_arn,
            region=target_region,
            external_id=aws_account.get("external_id"),
        )
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(status_code=403, detail=str(perm_err))
    except Exception as err:
        raise HTTPException(status_code=403, detail="Unable to verify AWS account identity.")

    clients = get_aws_clients(session)
    rds_client = clients.get("rds")
    if not rds_client:
        raise HTTPException(status_code=500, detail="Failed to initialize RDS client.")

    try:
        cluster_result = fetch_rds_clusters_inventory(
            rds_client=rds_client,
            region=target_region,
            max_records=max_records,
            marker=marker,
        )
    except RDSControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Failed to inspect RDS DB clusters.")

    return {
        "status": "success",
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "region": target_region,
        "total_count": cluster_result["total_count"],
        "clusters": cluster_result["clusters"],
        "next_token": cluster_result.get("next_token"),
    }


class RDSActionRequest(BaseModel):
    action: str
    region: Optional[str] = None
    confirmed: bool = False


@router.post("/aws/rds/{account_id}/instances/{instance_id}/action")
def control_rds_instance(
    account_id: str,
    instance_id: str,
    payload: RDSActionRequest,
    current_user=Depends(verify_token),
):
    """
    Securely execute supported operational or security actions on an RDS instance.

    Supported Actions:
    - start
    - stop
    - reboot
    - disable_public_access
    - enable_deletion_protection

    Enforces:
    - Authentication & tenant organization isolation
    - Strict Owner/Admin role authorization
    - Explicit user confirmation
    - AWS STS account verification
    - Server-side pre-state and post-state transition validation
    - Tamper-evident audit logging
    """
    ctx = _coerce_cloud_tenant_context(current_user)

    try:
        result = execute_rds_instance_action(
            account_id=account_id,
            instance_id=instance_id,
            action=payload.action,
            region=payload.region,
            confirmed=payload.confirmed,
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            role=ctx.role,
        )
        return result
    except RDSControlExecutionError as err:
        raise HTTPException(
            status_code=err.status_code,
            detail=err.public_message,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error controlling RDS instance: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while executing the RDS control action.",
        )

# ============================================================
# AWS VPC & NETWORK RESOURCE INVENTORY & CONTROLS (PHASE 5)
# ============================================================

def _resolve_network_account_and_client(
    account_id: str,
    region: Optional[str],
    current_user: dict,
):
    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required.",
        )

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(
            status_code=400,
            detail="AWS Account ID is required.",
        )

    aws_account = get_account(
        clean_account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise HTTPException(
            status_code=404,
            detail="AWS Account not found.",
        )

    if region is not None:
        target_region = str(region).strip()
        if not validate_network_region(target_region):
            raise HTTPException(
                status_code=400,
                detail=f"Invalid AWS region '{region}'. Region must match standard format like 'us-east-1', 'ap-south-1'.",
            )
    else:
        target_region = str(aws_account.get("region") or "us-east-1").strip()
        if not validate_network_region(target_region):
            target_region = "us-east-1"

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(
            status_code=400,
            detail="AWS account is missing configured role_arn.",
        )

    try:
        session = assume_aws_role(
            role_arn,
            region=target_region,
            external_id=aws_account.get("external_id"),
        )
    except Exception as assume_err:
        logger.warning("Network role assumption failed account_id=%s: %s", clean_account_id, assume_err)
        raise HTTPException(
            status_code=403,
            detail="Failed to assume AWS role for the connected account. Verify IAM trust relationship.",
        )

    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(status_code=403, detail=str(perm_err))
    except Exception:
        raise HTTPException(status_code=403, detail="Unable to verify AWS account identity.")

    clients = get_aws_clients(session)
    ec2_client = clients.get("ec2")
    if not ec2_client:
        raise HTTPException(status_code=500, detail="Failed to initialize AWS EC2 service client.")

    return {
        "user_id": user_id,
        "organization_id": organization_id,
        "aws_account": aws_account,
        "stored_aws_account_id": stored_aws_account_id,
        "target_region": target_region,
        "ec2_client": ec2_client,
    }


@router.get("/aws/network/{account_id}/vpcs")
def list_vpcs(
    account_id: str,
    region: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only VPC inventory for the connected AWS account."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_vpcs(
            ctx["ec2_client"],
            region=ctx["target_region"],
            max_records=max_records,
            search=search,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying VPC inventory: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting VPC inventory.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "vpcs": result["vpcs"],
    }


@router.get("/aws/network/{account_id}/subnets")
def list_subnets(
    account_id: str,
    region: Optional[str] = None,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only Subnet inventory for the connected AWS account."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(vpc_id, "default"):
        vpc_id = vpc_id.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_subnets(
            ctx["ec2_client"],
            region=ctx["target_region"],
            vpc_id=vpc_id,
            max_records=max_records,
            search=search,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying Subnet inventory: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting Subnet inventory.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "subnets": result["subnets"],
    }


@router.get("/aws/network/{account_id}/security-groups")
def list_security_groups(
    account_id: str,
    region: Optional[str] = None,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    posture: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only Security Group inventory with security posture analysis."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(vpc_id, "default"):
        vpc_id = vpc_id.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default
    if hasattr(posture, "default"):
        posture = posture.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_security_groups(
            ctx["ec2_client"],
            region=ctx["target_region"],
            vpc_id=vpc_id,
            max_records=max_records,
            search=search,
            posture_filter=posture,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying Security Group inventory: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting Security Groups.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "security_groups": result["security_groups"],
    }


@router.get("/aws/network/{account_id}/route-tables")
def list_route_tables(
    account_id: str,
    region: Optional[str] = None,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only Route Tables inventory."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(vpc_id, "default"):
        vpc_id = vpc_id.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_route_tables(
            ctx["ec2_client"],
            region=ctx["target_region"],
            vpc_id=vpc_id,
            max_records=max_records,
            search=search,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying Route Tables: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting Route Tables.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "route_tables": result["route_tables"],
    }


@router.get("/aws/network/{account_id}/gateways")
def list_gateways(
    account_id: str,
    region: Optional[str] = None,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only Internet Gateways and NAT Gateways inventory."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(vpc_id, "default"):
        vpc_id = vpc_id.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_gateways(
            ctx["ec2_client"],
            region=ctx["target_region"],
            vpc_id=vpc_id,
            max_records=max_records,
            search=search,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying Gateways: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting Gateways.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "gateways": result["gateways"],
    }


@router.get("/aws/network/{account_id}/endpoints")
def list_vpc_endpoints(
    account_id: str,
    region: Optional[str] = None,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """Secure, read-only VPC Endpoints inventory."""
    if hasattr(region, "default"):
        region = region.default
    if hasattr(vpc_id, "default"):
        vpc_id = vpc_id.default
    if hasattr(max_records, "default"):
        max_records = max_records.default
    if hasattr(search, "default"):
        search = search.default

    ctx = _resolve_network_account_and_client(account_id, region, current_user)
    try:
        result = query_vpc_endpoints(
            ctx["ec2_client"],
            region=ctx["target_region"],
            vpc_id=vpc_id,
            max_records=max_records,
            search=search,
        )
    except NetworkControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except Exception as exc:
        logger.error("Error querying VPC Endpoints: %s", exc)
        raise HTTPException(status_code=500, detail="An error occurred while inspecting VPC Endpoints.")

    return {
        "status": "success",
        "account_id": str(ctx["aws_account"].get("_id", account_id)),
        "aws_account_id": ctx["stored_aws_account_id"],
        "account_name": ctx["aws_account"].get("account_name"),
        "region": ctx["target_region"],
        "total_count": result["total_count"],
        "summary": result["summary"],
        "endpoints": result["endpoints"],
    }


@router.post("/aws/network/{account_id}/security-groups/{group_id}/action")
def control_security_group(
    account_id: str,
    group_id: str,
    payload: SecurityGroupActionPayload,
    current_user=Depends(verify_token),
):
    """
    Execute audited, post-verified, safety-checked security group rule mutations.
    Requires Owner or Admin role, explicit confirmation, and valid rule target.
    """
    ctx = _coerce_cloud_tenant_context(current_user)

    try:
        result = execute_security_group_control(
            account_id=account_id,
            group_id=group_id,
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            user_role=ctx.role,
            action=payload.action,
            region=payload.region,
            rule_spec=payload.rule_spec,
            confirmed=payload.confirmed,
        )
        return result
    except NetworkControlExecutionError as err:
        raise HTTPException(
            status_code=err.status_code,
            detail=err.public_message,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error controlling security group: %s", exc)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while executing the security group action.",
        )


@router.get("/aws/scan/{account_id}")
def scan_aws(
    account_id: str,
    current_user=Depends(verify_token)
):

    scan_started_at = datetime.utcnow()

    try:

        # ====================================================
        # CURRENT USER
        # ====================================================

        user_id = str(
            current_user["_id"]
        )

        # ====================================================
        # ORGANIZATION CONTEXT
        # ====================================================

        organization_id = _safe_string(
            current_user.get("organization")
        )

        if not organization_id:

            raise HTTPException(
                status_code=403,
                detail="Organization context is required for scanning."
            )

        # ====================================================
        # GET AWS ACCOUNT
        #
        # Tenant scoped: the AWS account MUST belong to the
        # authenticated user's organization.
        # This prevents a legacy/same-user account from another
        # organization from being scanned.
        # ====================================================

        aws_account = get_account(
            account_id,
            organization_id=organization_id
        )

        if not aws_account:

            raise HTTPException(
                status_code=404,
                detail="AWS Account not found"
            )

        # ====================================================
        # SAAS QUOTA: RESERVE ONE SCAN
        #
        # The AWS account has already been verified and scoped
        # to the current tenant. Reserve quota before any AWS
        # API call so an over-limit scan never starts.
        # ====================================================

        scan_quota_reserved = False

        try:

            reserve_quota(
                organization_id=organization_id,
                quota_type="scans",
                amount=1
            )

            scan_quota_reserved = True

        except ValueError as quota_error:

            raise HTTPException(
                status_code=403,
                detail=str(quota_error)
            ) from quota_error

        # ====================================================
        # AUDIT: SCAN STARTED
        # ====================================================

        _record_scan_audit(
            user_id=user_id,
            event_type=EVENT_SCAN_STARTED,
            action="AWS_SECURITY_SCAN",
            result="INFO",
            account_id=str(aws_account.get("_id", account_id)),
            aws_account_id=_safe_string(
                aws_account.get("aws_account_id") or ""
            ),
            message="AWS security scan started",
            metadata={
                "region": aws_account.get("region"),
                "account_name": aws_account.get("account_name"),
            },
        )

        # ====================================================
        # ASSUME AWS ROLE
        # ====================================================

        session = assume_aws_role(
            aws_account["role_arn"],
            aws_account["region"],
            external_id=aws_account.get("external_id"),
        )

        # ====================================================
        # CREATE AWS CLIENTS
        # ====================================================

        clients = get_aws_clients(
            session
        )

        sts = clients["sts"]

        ec2 = clients["ec2"]

        s3 = clients["s3"]

        iam = clients["iam"]

        cloudtrail = clients["cloudtrail"]

        rds = clients["rds"]

        lambda_client = clients["lambda"]

        kms = clients["kms"]

        # ====================================================
        # VERIFIED AWS RELATIONSHIP INVENTORY
        # ====================================================

        relationship_inventory = _collect_aws_relationship_inventory(
            ec2=ec2,
            iam=iam,
            rds=rds,
            lambda_client=lambda_client,
            account_id=_safe_string(aws_account.get("aws_account_id") or aws_account.get("account") or ""),
            region=_safe_string(aws_account.get("region") or ""),
        )

        # ====================================================
        # AWS ACCOUNT IDENTITY
        # ====================================================

        identity = sts.get_caller_identity()

        aws_identity_account = _safe_string(
            identity.get(
                "Account",
                ""
            )
        )

        aws_identity_arn = _safe_string(
            identity.get(
                "Arn",
                ""
            )
        )

        # ====================================================
        # SECURITY CHECK:
        # Connected AWS account must match
        # the assumed-role account.
        # ====================================================

        stored_aws_account_id = _safe_string(
            aws_account.get(
                "aws_account_id",
                ""
            )
        )

        if (
            stored_aws_account_id
            and aws_identity_account
            and stored_aws_account_id
            != aws_identity_account
        ):

            raise HTTPException(
                status_code=403,
                detail=(
                    "AWS account identity mismatch. "
                    "The assumed role belongs to a "
                    "different AWS account."
                )
            )

        # ====================================================
        # EC2
        # ====================================================

        reservations = ec2.describe_instances()[
            "Reservations"
        ]

        ec2_count = 0

        for reservation in reservations:

            ec2_count += len(
                reservation.get(
                    "Instances",
                    []
                )
            )

        ec2_security = check_ec2(
            ec2
        )

        # ====================================================
        # S3
        # ====================================================

        s3_evaluated = False
        uninspected_s3_resources = set()
        s3_coverage_status = "UNKNOWN"
        s3_scan_error = None
        try:
            s3_security = check_s3(
                s3,
                session=session,
                account_id=aws_identity_account,
            )
            s3_inventory = inspect_s3_inventory(
                s3,
                session=session,
                account_id=aws_identity_account,
                raise_on_error=True,
            )
            s3_count = len(s3_inventory)

            # Check for uninspected or partial buckets
            for bucket_item in s3_inventory:
                if (
                    bucket_item.get("coverage") == "PARTIAL"
                    or bucket_item.get("security_posture") in ("UNKNOWN", "UNVERIFIED")
                ):
                    b_name = bucket_item.get("bucket_name")
                    if b_name:
                        uninspected_s3_resources.add(b_name)

            # S3 is evaluated authoritatively only if discovery succeeded and there are no global discovery failures
            has_discovery_failure = any(
                f.get("status") == "Unknown" and f.get("resource") == "s3"
                for f in s3_security
            )
            if has_discovery_failure:
                s3_coverage_status = "FAILED"
                s3_evaluated = False
            elif s3_count == 0:
                s3_coverage_status = "ZERO_DISCOVERED"
                s3_evaluated = True
            elif uninspected_s3_resources:
                s3_coverage_status = "PARTIAL"
                s3_evaluated = False
            else:
                s3_coverage_status = "COMPLETE"
                s3_evaluated = True

            if not s3_evaluated:
                logger.warning(
                    "S3 scan completed with partial coverage (discovery_failure=%s, uninspected_buckets=%s); marking s3_evaluated=False",
                    has_discovery_failure,
                    list(uninspected_s3_resources),
                )

            # Register S3 buckets into relationship inventory for security graph
            if s3_inventory and isinstance(relationship_inventory, dict):
                relationship_inventory.setdefault("s3_buckets", {})
                for bucket_item in s3_inventory:
                    bname = bucket_item.get("bucket_name")
                    if bname:
                        relationship_inventory["s3_buckets"][bname] = {
                            "node_type": "S3_BUCKET",
                            "resource_id": bname,
                            "resource_name": bname,
                            "resource_arn": bucket_item.get("resource_arn") or f"arn:aws:s3:::{bname}",
                            "service": "S3",
                            "region": bucket_item.get("region"),
                            "signals": {"posture": bucket_item.get("security_posture", "SECURE")},
                        }
        except Exception as s3_err:
            logger.warning("S3 scan inspection failed: %s", s3_err)
            s3_count = 0
            s3_evaluated = False
            s3_coverage_status = "FAILED"
            s3_scan_error = str(s3_err)
            s3_security = [{
                "resource_type": "S3 Service",
                "resource": "s3",
                "service": "S3",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": "CloudGuardAI could not inspect S3 resources due to an error.",
                "recommendation": "Verify scanner permissions for Amazon S3.",
                "account_id": aws_identity_account,
                "evidence": {"error": str(s3_err)},
            }]
            s3_inventory = []

        # ====================================================
        # IAM
        # ====================================================

        iam_users = iam.list_users()[
            "Users"
        ]

        iam_count = len(
            iam_users
        )

        iam_security = check_iam(
            iam
        )

        # ====================================================
        # CLOUDTRAIL
        # ====================================================

        cloudtrail_security = check_cloudtrail(
            cloudtrail
        )

        # ====================================================
        # VPC
        # ====================================================

        vpc_security = check_vpc(
            ec2
        )

        # ====================================================
        # RDS
        # ====================================================

        rds_security = check_rds(
            rds
        )

        # ====================================================
        # LAMBDA
        # ====================================================

        lambda_security = check_lambda(
            lambda_client
        )

        # ====================================================
        # KMS
        # ====================================================

        kms_security = check_kms(
            kms
        )

        # ====================================================
        # RESOURCE SUMMARY
        #
        # Only actual resource inventory counts belong here.
        # Finding counts are NOT resources.
        # ====================================================

        resources = {

            "ec2": ec2_count,

            "s3": s3_count,

            "iam": iam_count,

            "cloudtrail": 0,

            "vpc": 0,

            "rds": 0,

            "lambda": 0,

            "kms": 0,

        }

        # ====================================================
        # SECURITY RISK ANALYSIS
        # ====================================================

        ai_result = analyze(

            resources,

            s3_security,

            ec2_security,

            iam_security,

            cloudtrail_security,

            vpc_security,

            rds_security,

            lambda_security,

            kms_security

        )

        # ====================================================
        # SCAN TIME
        # ====================================================

        scan_time = datetime.utcnow()

        # ====================================================
        # FINDINGS
        # ====================================================

        raw_findings = ai_result.get(
            "findings",
            []
        )

        findings = _normalize_findings(
            raw_findings,
            str(aws_account.get("_id", account_id)),
            scan_time
        )

        # ====================================================
        # VERIFIED AWS RELATIONSHIP ENRICHMENT
        # ====================================================

        findings = _apply_aws_relationship_enrichment(
            findings,
            relationship_inventory,
        )

        # ====================================================
        # PERSIST FINDINGS
        #
        # This creates a dedicated findings collection.
        #
        # Existing findings are updated rather than duplicated.
        # Customer workflow status is preserved.
        # ====================================================

        findings = _persist_findings(
            findings,
            user_id,
            aws_account,
            aws_identity_account
        )

        # ====================================================
        # GENERATE SECURITY POLICIES
        # ====================================================

        generated_policies = generate_policies(
            findings
        )

        # ====================================================
        # AI EXPLANATIONS
        # ====================================================

        ai_explanations = explain(
            findings
        )

        # ====================================================
        # GEMINI AI ANALYSIS
        # ====================================================

        gemini_analysis = ask_gemini(
            findings
        )

        # ====================================================
        # SCAN COMPLETION TIME
        # ====================================================

        scan_completed_at = datetime.utcnow()

        # ====================================================
        # SCAN-LEVEL SECURITY GRAPH SNAPSHOT
        # ====================================================

        scan_security_graph = _build_scan_security_graph(
            relationship_inventory,
            findings,
        )

        # ====================================================
        # FINAL SCAN DATA
        # ====================================================

        scan = {

            # ------------------------------------------------
            # Ownership / tenant information
            # ------------------------------------------------

            "user_id": user_id,

            # CloudGuardAI organization / tenant ID.
            # Every scan is explicitly linked to its SaaS organization.
            "organization_id": organization_id,

            # CloudGuardAI internal AWS-account document ID.
            "account_id": str(
                aws_account.get(
                    "_id",
                    account_id
                )
            ),

            # Real AWS 12-digit account ID.
            "aws_account_id": aws_identity_account,

            # Backward-compatible alias.
            "connected_account_id": str(
                aws_account.get(
                    "_id",
                    account_id
                )
            ),

            # ------------------------------------------------
            # AWS identity
            # ------------------------------------------------

            "account": aws_identity_account,

            "arn": aws_identity_arn,

            "region": aws_account.get(
                "region",
                "ap-south-1"
            ),

            # ------------------------------------------------
            # Risk
            # ------------------------------------------------

            "risk_score":
                ai_result.get(
                    "risk_score",
                    0
                ),

            "security_level":
                ai_result.get(
                    "security_level",
                    "Unknown"
                ),

            "security_posture":
                ai_result.get(
                    "security_posture",
                    "Unknown"
                ),

            "risk_points":
                ai_result.get(
                    "risk_points",
                    0
                ),

            "severity_summary":
                ai_result.get(
                    "severity_summary",
                    {}
                ),

            "finding_summary":
                ai_result.get(
                    "finding_summary",
                    {}
                ),

            # ------------------------------------------------
            # Resources
            # ------------------------------------------------

            "resources":
                resources,

            # ------------------------------------------------
            # Findings
            # ------------------------------------------------

            "findings":
                findings,

            # ------------------------------------------------
            # AI / remediation
            # ------------------------------------------------

            "generated_policies":
                generated_policies,

            "ai_explanations":
                ai_explanations,

            "gemini_analysis":
                gemini_analysis,

            # ------------------------------------------------
            # Raw checker results
            # ------------------------------------------------

            "ec2_security":
                ec2_security,

            "s3_security":
                s3_security,

            "s3_inventory":
                s3_inventory,

            "s3_coverage": {
                "status": s3_coverage_status,
                "total_buckets": s3_count,
                "evaluated": s3_evaluated,
                "error": s3_scan_error,
                "uninspected_buckets": list(uninspected_s3_resources),
            },

            "iam_security":
                iam_security,

            "cloudtrail_security":
                cloudtrail_security,

            "vpc_security":
                vpc_security,

            "rds_security":
                rds_security,

            "lambda_security":
                lambda_security,

            "kms_security":
                kms_security,

            # ------------------------------------------------
            # Scan-level Security Graph
            # ------------------------------------------------

            "security_graph":
                scan_security_graph,

            # ------------------------------------------------
            # Scan metadata
            # ------------------------------------------------

            "scan_started_at":
                scan_started_at,

            "scan_completed_at":
                scan_completed_at,

            "status":
                "completed",

        }

        # ====================================================
        # SAVE USER SCAN
        # ====================================================

        scan_id = save_scan(
            scan,
            user_id,
            account_id=str(
                aws_account.get(
                    "_id",
                    account_id
                )
            )
        )

        scan["_id"] = scan_id

        # ====================================================
        # SAAS QUOTA: SCAN CONSUMED
        #
        # The scan has now been successfully persisted.
        # The reserved quota is therefore consumed.
        # Any later non-critical failure must NOT release it.
        # ====================================================

        scan_quota_reserved = False

        # ====================================================
        # AUDIT: SCAN COMPLETED
        # ====================================================

        _record_scan_audit(
            user_id=user_id,
            event_type=EVENT_SCAN_COMPLETED,
            action="AWS_SECURITY_SCAN",
            result="SUCCESS",
            account_id=str(aws_account.get("_id", account_id)),
            aws_account_id=aws_identity_account,
            resource_id=scan_id,
            message="AWS security scan completed successfully",
            metadata={
                "finding_count": len(findings),
                "risk_score": scan.get("risk_score", 0),
                "security_level": scan.get("security_level"),
                "status": scan.get("status"),
                "region": scan.get("region"),
                "scan_started_at": scan_started_at.isoformat(),
                "scan_completed_at": scan_completed_at.isoformat(),
            },
        )

        # ====================================================
        # UPDATE AWS ACCOUNT LAST SCAN
        # ====================================================

        try:

            from app.models.aws_account import (
                update_last_scan
            )

            update_last_scan(
                account_id,
                user_id
            )

        except Exception:
            # Updating metadata should not cause a
            # successful security scan to fail.
            pass

        # ====================================================
        # AUTHORITATIVE REMEDIATION RECONCILIATION
        # ====================================================

        try:

            from app.services.scan_remediation_reconciler import (
                reconcile_scan_remediations,
            )

            evaluated_services = {
                "EC2",
                "IAM",
                "CLOUDTRAIL",
                "VPC",
                "RDS",
                "LAMBDA",
                "KMS",
            }
            if s3_evaluated:
                evaluated_services.add("S3")

            detected_ids = {
                str(f.get("finding_id")).strip()
                for f in findings
                if isinstance(f, dict) and f.get("finding_id")
            }

            reconcile_scan_remediations(
                account_id=str(
                    aws_account.get(
                        "_id",
                        account_id,
                    )
                ),
                user_id=user_id,
                organization_id=organization_id,
                aws_account_id=aws_identity_account,
                scan_id=scan_id,
                scan_started_at=scan_started_at,
                scan_completed_at=scan_completed_at,
                detected_finding_ids=detected_ids,
                evaluated_services=evaluated_services,
                uninspected_resources=uninspected_s3_resources,
            )

        except Exception as reconciler_error:
            # Reconciler failures must never break a successful scan response
            logger.exception(
                "SCAN_REMEDIATION_RECONCILER_FAILED account_id=%s scan_id=%s error=%s",
                account_id,
                scan_id,
                reconciler_error,
            )

        # ====================================================
        # SECURITY NOTIFICATIONS
        # ====================================================

        for finding in findings:

            severity = _safe_string(
                finding.get(
                    "severity",
                    ""
                )
            ).upper()

            detection_status = _safe_string(
                finding.get(
                    "detection_status",
                    ""
                )
            ).upper()

            workflow_status = _safe_string(
                finding.get(
                    "status",
                    ""
                )
            ).upper()

            # ------------------------------------------------
            # Only active high-impact findings
            # should generate alerts.
            #
            # Detection status is used to determine whether
            # the scanner actually detected a problem.
            # ------------------------------------------------

            protected_detection_states = {
                "PROTECTED",
                "PASS",
                "PASSED",
            }

            if (
                severity in [
                    "HIGH",
                    "CRITICAL"
                ]
                and detection_status
                not in protected_detection_states
                and workflow_status
                not in {
                    "RESOLVED",
                    "IGNORED",
                }
            ):

                issue = _safe_string(
                    finding.get(
                        "issue",
                        "Security risk detected"
                    )
                )

                recommendation = _safe_string(
                    finding.get(
                        "recommendation",
                        ""
                    )
                )

                message = issue

                if recommendation:

                    message += (
                        " | "
                        + recommendation
                    )

                create_alert(

                    title="Security Risk Detected",

                    message=message,

                    severity=severity,

                    # Tenant context
                    user_id=user_id,

                    # Stable finding identity
                    finding_id=finding.get("finding_id"),

                    # CloudGuardAI internal account ID
                    account_id=str(
                        aws_account.get(
                            "_id",
                            account_id
                        )
                    ),

                    # Real AWS account ID
                    aws_account_id=aws_identity_account,

                    # Account metadata
                    account_name=aws_account.get(
                        "account_name",
                        ""
                    ),

                    # Security context
                    service=finding.get(
                        "service"
                    ),

                    resource=finding.get(
                        "resource"
                    ),

                    detection_status=detection_status,

                )

        # ====================================================
        # RESPONSE
        # ====================================================

        return {

            "status":
                "success",

            "scan":
                scan,

            "finding_count":
                len(findings),

        }

    except HTTPException as e:

        # ----------------------------------------------------
        # Release reserved scan quota when the scan fails.
        # Successful scans never reach this block.
        # ----------------------------------------------------

        if locals().get("scan_quota_reserved"):

            try:

                release_usage(
                    organization_id=locals().get("organization_id"),
                    usage_field="scans_used",
                    amount=1
                )

            except Exception as quota_release_error:

                logger.exception(
                    "SCAN_QUOTA_RELEASE_FAILED organization_id=%s error=%s",
                    locals().get("organization_id"),
                    quota_release_error,
                )

        # Record expected/controlled scan failures without exposing
        # implementation details to the customer.
        try:
            _record_scan_audit(
                user_id=locals().get("user_id"),
                event_type=EVENT_SCAN_FAILED,
                action="AWS_SECURITY_SCAN",
                result="FAILURE",
                account_id=locals().get("account_id"),
                aws_account_id=locals().get("aws_identity_account"),
                message="AWS security scan failed",
                metadata={
                    "http_status": e.status_code,
                    "error_type": type(e).__name__,
                },
            )
        except Exception:
            pass

        raise

    except Exception as e:

        # ----------------------------------------------------
        # Release reserved scan quota when an unexpected scan
        # failure occurs.
        # ----------------------------------------------------

        if locals().get("scan_quota_reserved"):

            try:

                release_usage(
                    organization_id=locals().get("organization_id"),
                    usage_field="scans_used",
                    amount=1
                )

            except Exception as quota_release_error:

                logger.exception(
                    "SCAN_QUOTA_RELEASE_FAILED organization_id=%s error=%s",
                    locals().get("organization_id"),
                    quota_release_error,
                )

        try:
            _record_scan_audit(
                user_id=locals().get("user_id"),
                event_type=EVENT_SCAN_FAILED,
                action="AWS_SECURITY_SCAN",
                result="FAILURE",
                account_id=locals().get("account_id"),
                aws_account_id=locals().get("aws_identity_account"),
                message="AWS security scan failed",
                metadata={
                    "http_status": 500,
                    "error_type": type(e).__name__,
                },
            )
        except Exception:
            pass

        # Do not expose internal exception text through the API.
        raise HTTPException(
            status_code=500,
            detail="AWS security scan failed. Please try again or contact support.",
        )


# ============================================================
# IAM RESOURCE INVENTORY & CONTROLS
# Phase 6: AWS IAM Identity & Access Management
# ============================================================

from app.services.iam_control_service import fetch_iam_inventory, execute_iam_action, IAMControlExecutionError

@router.get("/aws/iam/{account_id}/inventory")
def list_iam_inventory(
    account_id: str,
    max_items: Optional[int] = 100,
    marker: Optional[str] = None,
    current_user=Depends(verify_token),
):
    """
    Secure, read-only IAM inventory for the connected AWS account.
    """
    if hasattr(max_items, "default"):
        max_items = max_items.default
    if hasattr(marker, "default"):
        marker = marker.default

    user_id = str(current_user["_id"])
    organization_id = _safe_string(current_user.get("organization"))
    if not organization_id:
        raise HTTPException(status_code=403, detail="Organization context is required.")

    clean_account_id = str(account_id or "").strip()
    if not clean_account_id:
        raise HTTPException(status_code=400, detail="AWS Account ID is required.")

    aws_account = get_account(clean_account_id, organization_id=organization_id)
    if not aws_account:
        raise HTTPException(status_code=404, detail="AWS Account not found.")

    stored_aws_account_id = _safe_string(aws_account.get("aws_account_id") or aws_account.get("account") or "")
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise HTTPException(status_code=400, detail="AWS account is missing configured role_arn.")

    try:
        session = assume_aws_role(
            role_arn,
            region="us-east-1",
            external_id=aws_account.get("external_id"),
        )
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise HTTPException(status_code=403, detail=str(perm_err))
    except Exception:
        raise HTTPException(status_code=403, detail="Unable to verify AWS account identity.")

    clients = get_aws_clients(session)
    iam_client = clients.get("iam")
    if not iam_client:
        raise HTTPException(status_code=500, detail="Failed to initialize IAM service client.")

    try:
        inventory_result = fetch_iam_inventory(iam_client, max_items=max_items, marker=marker)
    except Exception as exc:
        logger.error("Unexpected error fetching IAM inventory: %s", exc)
        raise HTTPException(status_code=500, detail="An unexpected error occurred while inspecting IAM inventory.")

    return {
        "status": "success",
        "account_id": str(aws_account.get("_id", clean_account_id)),
        "aws_account_id": stored_aws_account_id,
        "account_name": aws_account.get("account_name"),
        "inventory": inventory_result,
    }

class IAMActionRequest(BaseModel):
    action: str
    resource_type: str
    parameters: Optional[dict] = None
    confirmed: bool = False

@router.post("/aws/iam/{account_id}/resources/{resource_id}/action")
def control_iam_resource(
    account_id: str,
    resource_id: str,
    payload: IAMActionRequest,
    current_user=Depends(verify_token),
):
    """
    Securely execute IAM security controls on a connected AWS account.
    """
    ctx = _coerce_cloud_tenant_context(current_user)

    try:
        result = execute_iam_action(
            account_id=account_id,
            resource_id=resource_id,
            resource_type=payload.resource_type,
            action=payload.action,
            parameters=payload.parameters,
            confirmed=payload.confirmed,
            user_id=ctx.user_id,
            organization_id=ctx.organization_id,
            role=ctx.role,
        )
        return result
    except IAMControlExecutionError as err:
        raise HTTPException(status_code=err.status_code, detail=err.public_message)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Unexpected error controlling IAM resource: %s", exc)
        raise HTTPException(status_code=500, detail="An unexpected error occurred while executing the IAM control action.")


# ============================================================
# HISTORY APIs
# ============================================================


@router.get("/history")
def history(
    current_user=Depends(verify_token)
):
    """
    Return lightweight scan history for the authenticated user.

    SaaS tenant isolation:
    - Requires organization context.
    - Returns scans belonging only to the user's organization.
    - Keeps the existing lightweight projection for performance.
    - Detailed scan data remains available through
      GET /history/{scan_id}.
    """

    user_id = str(
        current_user["_id"]
    )

    organization_id = _safe_string(
        current_user.get("organization")
    )

    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required"
        )

    # Lightweight tenant-scoped history fields
    scans = get_all_scans(
        user_id,
        projection={
            "_id": 1,
            "user_id": 1,
            "organization_id": 1,
            "account": 1,
            "account_id": 1,
            "aws_account_id": 1,
            "connected_account_id": 1,
            "account_name": 1,
            "arn": 1,
            "region": 1,
            "risk_score": 1,
            "security_level": 1,
            "security_posture": 1,
            "risk_points": 1,
            "severity_summary": 1,
            "finding_summary": 1,
            "scan_started_at": 1,
            "scan_completed_at": 1,
            "scan_time": 1,
            "status": 1,
            "resources": 1,
            "s3_coverage": 1,
            "s3_inventory": 1,
        },
        limit=20,
        organization_id=organization_id
    )

    # Normalize s3_coverage and s3_inventory for backward compatibility on historical scans
    for s in scans:
        if "s3_coverage" not in s:
            if s.get("s3_inventory") is not None:
                inv = s.get("s3_inventory") or []
                s["s3_coverage"] = {
                    "status": "ZERO_DISCOVERED" if len(inv) == 0 else "COMPLETE",
                    "total_buckets": len(inv),
                    "evaluated": True,
                    "error": None,
                    "uninspected_buckets": [],
                }
            else:
                s["s3_inventory"] = None
                s["s3_coverage"] = {
                    "status": "UNAVAILABLE",
                    "total_buckets": s.get("resources", {}).get("s3", 0),
                    "evaluated": False,
                    "error": None,
                    "uninspected_buckets": [],
                    "message": "S3 bucket inventory details were not captured in this historical scan.",
                }

    # Dashboard currently needs findings + Gemini analysis
    # from the latest scan only.
    if scans:

        latest_scan = get_scan(
            scans[0]["_id"],
            user_id
        )

        if latest_scan:

            scans[0]["findings"] = (
                latest_scan.get("findings", [])
            )

            scans[0]["gemini_analysis"] = (
                latest_scan.get("gemini_analysis")
            )

    return scans

# Backward-compatible alias for history endpoint
history_list = history

# ============================================================
# GET SINGLE SCAN
# ============================================================


@router.get("/history/{scan_id}")
def history_details(

    scan_id: str,

    current_user=Depends(verify_token)

):

    user_id = str(
        current_user["_id"]
    )

    organization_id = _safe_string(
        current_user.get("organization")
    )

    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required."
        )

    scan = get_scan(

        scan_id,

        user_id,

        organization_id=organization_id

    )

    if scan is None:

        raise HTTPException(

            status_code=404,

            detail="Scan not found"

        )

    # Ensure s3_coverage and s3_inventory are backward-compatible for historical scans
    if "s3_coverage" not in scan:
        if scan.get("s3_inventory") is not None:
            inv = scan.get("s3_inventory") or []
            scan["s3_coverage"] = {
                "status": "ZERO_DISCOVERED" if len(inv) == 0 else "COMPLETE",
                "total_buckets": len(inv),
                "evaluated": True,
                "error": None,
                "uninspected_buckets": [],
            }
        else:
            scan["s3_inventory"] = None
            scan["s3_coverage"] = {
                "status": "UNAVAILABLE",
                "total_buckets": scan.get("resources", {}).get("s3", 0),
                "evaluated": False,
                "error": None,
                "uninspected_buckets": [],
                "message": "S3 bucket inventory details were not captured in this historical scan.",
            }

    return scan


# ============================================================
# DELETE SCAN
# ============================================================


@router.delete("/history/{scan_id}")
def remove_scan(

    scan_id: str,

    current_user=Depends(verify_token)

):
    """
    Delete the authenticated user's scan.

    SaaS tenant isolation:
    - Requires organization context.
    - Verifies the scan belongs to the user's organization.
    - Deletes only the authenticated user's scan.
    """

    user_id = str(
        current_user["_id"]
    )

    organization_id = _safe_string(
        current_user.get("organization")
    )

    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required"
        )

    scan = get_scan(
        scan_id,
        user_id,
        organization_id=organization_id
    )

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    deleted = delete_scan(
        scan_id,
        user_id,
        organization_id=organization_id
    )

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    return {
        "message": "Scan deleted successfully",
        "organization_id": organization_id,
        "scan_id": str(scan_id)
    }


# ============================================================
# SEARCH SCANS
# ============================================================


@router.get("/history/search/{keyword}")
def search(

    keyword: str,

    current_user=Depends(verify_token)

):

    return search_scans(

        keyword,

        str(
            current_user["_id"]
        )

    )


# ============================================================
# FILTER SCANS
# ============================================================


@router.get("/history/filter/{level}")
def filter_history(

    level: str,

    current_user=Depends(verify_token)

):

    organization_id = _safe_string(
        current_user.get("organization")
    )

    if not organization_id:
        raise HTTPException(
            status_code=403,
            detail="Organization context is required"
        )

    return filter_scans(

        level,

        str(
            current_user["_id"]
        ),
        organization_id=organization_id

    )
