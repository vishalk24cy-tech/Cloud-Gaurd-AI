# ============================================================
# CloudGuardAI - Secure RDS Resource Control & Inventory Service
# Phase 4: AWS RDS Resource Management & Database Security
# ============================================================

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

from botocore.exceptions import BotoCoreError, ClientError

from app.models.audit_log import (
    ACTOR_USER,
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_RESOURCE_CONTROL_COMPLETED,
    EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
    EVENT_RESOURCE_CONTROL_FAILED,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
)
from app.models.aws_account import get_account
from app.services.audit_log_service import record_event
from app.services.aws_connection import (
    assume_aws_role,
    get_aws_clients,
    verify_aws_account,
)

logger = logging.getLogger("cloudguardai.rds_controls")

# AWS RDS Identifier naming rules: 1-63 chars, letters, numbers, hyphens, no trailing hyphen, no consecutive hyphens
RDS_IDENTIFIER_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9-]{0,62}$")
AWS_REGION_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

ALLOWED_RDS_ACTIONS = {
    "start",
    "stop",
    "reboot",
    "disable_public_access",
    "enable_deletion_protection",
}

MUTATION_ALLOWED_ROLES = {"owner", "admin"}


class RDSControlExecutionError(Exception):
    """Safe public error details for RDS control workflows."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        category: str,
        message: str,
        audit_recorded: bool = False,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.category = category
        self.public_message = message
        self.audit_recorded = audit_recorded


def is_valid_rds_identifier(identifier: str) -> bool:
    """Validate that an RDS DB instance or cluster identifier conforms to AWS naming rules."""
    if not isinstance(identifier, str):
        return False
    name = identifier.strip()
    return bool(
        RDS_IDENTIFIER_PATTERN.fullmatch(name)
        and not name.endswith("-")
        and "--" not in name
    )


def validate_aws_region(region: Optional[str]) -> bool:
    """Validate that the region string conforms to standard AWS region naming."""
    if not region or not isinstance(region, str):
        return False
    return bool(AWS_REGION_REGEX.match(region.strip()))


def _safe_string(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


def _safe_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(code))[:100] or "AWS_ERROR"


def normalize_rds_instance(db: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """
    Extract and normalize read-only RDS DB instance attributes into an API-safe dictionary.
    Calculates security posture (SECURE, RISK, CRITICAL, UNKNOWN) and compliance metrics.
    """
    if not isinstance(db, dict):
        return {}

    identifier = _safe_string(db.get("DBInstanceIdentifier"))
    arn = _safe_string(db.get("DBInstanceArn"))
    engine = _safe_string(db.get("Engine") or "unknown")
    engine_version = _safe_string(db.get("EngineVersion"))
    instance_class = _safe_string(db.get("DBInstanceClass"))
    status = _safe_string(db.get("DBInstanceStatus") or "unknown").lower()
    az = _safe_string(db.get("AvailabilityZone"))
    
    # Infer region from AZ or fallback
    region = az[:-1] if az and az[-1].isalpha() and az[:-1] else fallback_region

    publicly_accessible = bool(db.get("PubliclyAccessible", False))
    storage_encrypted = bool(db.get("StorageEncrypted", False))
    kms_key_id = _safe_string(db.get("KmsKeyId"))
    backup_retention = int(db.get("BackupRetentionPeriod") or 0)
    deletion_protection = bool(db.get("DeletionProtection", False))
    multi_az = bool(db.get("MultiAZ", False))
    auto_minor_version_upgrade = bool(db.get("AutoMinorVersionUpgrade", False))
    
    cluster_id = db.get("DBClusterIdentifier")
    cluster_identifier = _safe_string(cluster_id) if cluster_id else None

    # Endpoint metadata (safe connection info)
    endpoint_obj = db.get("Endpoint") or {}
    endpoint = (
        {
            "address": endpoint_obj.get("Address"),
            "port": endpoint_obj.get("Port"),
            "hosted_zone_id": endpoint_obj.get("HostedZoneId"),
        }
        if endpoint_obj.get("Address")
        else None
    )

    # Subnet & VPC info
    subnet_group = db.get("DBSubnetGroup") or {}
    vpc_id = subnet_group.get("VpcId")
    subnet_group_name = subnet_group.get("DBSubnetGroupName")

    # Security Groups
    vpc_security_groups = [
        {
            "group_id": sg.get("VpcSecurityGroupId"),
            "status": sg.get("Status"),
        }
        for sg in (db.get("VpcSecurityGroups") or [])
        if isinstance(sg, dict) and sg.get("VpcSecurityGroupId")
    ]

    # Creation time
    create_time = db.get("InstanceCreateTime")
    create_time_str = (
        create_time.isoformat()
        if hasattr(create_time, "isoformat")
        else str(create_time)
        if create_time
        else None
    )

    # Latest restorable time
    restorable_time = db.get("LatestRestorableTime")
    restorable_time_str = (
        restorable_time.isoformat()
        if hasattr(restorable_time, "isoformat")
        else str(restorable_time)
        if restorable_time
        else None
    )

    # Posture evaluation
    has_critical = publicly_accessible
    has_risk = not storage_encrypted or backup_retention <= 0

    if has_critical:
        security_posture = "CRITICAL"
    elif has_risk:
        security_posture = "RISK"
    elif storage_encrypted and backup_retention > 0 and not publicly_accessible and deletion_protection:
        security_posture = "SECURE"
    else:
        security_posture = "EVALUATED"

    return {
        "db_instance_identifier": identifier,
        "resource": identifier,
        "resource_id": identifier,
        "resource_arn": arn,
        "resource_type": "RDS_INSTANCE",
        "engine": engine,
        "engine_version": engine_version,
        "instance_class": instance_class,
        "status": status,
        "region": region,
        "availability_zone": az or None,
        "multi_az": multi_az,
        "publicly_accessible": publicly_accessible,
        "storage_encrypted": storage_encrypted,
        "kms_key_id": kms_key_id or None,
        "backup_retention_period": backup_retention,
        "deletion_protection": deletion_protection,
        "auto_minor_version_upgrade": auto_minor_version_upgrade,
        "cluster_identifier": cluster_identifier,
        "is_cluster_member": bool(cluster_identifier),
        "endpoint": endpoint,
        "vpc_id": vpc_id,
        "subnet_group_name": subnet_group_name,
        "vpc_security_groups": vpc_security_groups,
        "storage_type": db.get("StorageType"),
        "allocated_storage": db.get("AllocatedStorage"),
        "performance_insights_enabled": bool(db.get("PerformanceInsightsEnabled", False)),
        "enhanced_monitoring_enabled": bool(db.get("EnhancedMonitoringResourceArn")),
        "create_time": create_time_str,
        "latest_restorable_time": restorable_time_str,
        "security_posture": security_posture,
        "coverage": "COMPLETE",
    }


def normalize_rds_cluster(cluster: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize read-only RDS DB cluster attributes (Aurora/Multi-AZ clusters)."""
    if not isinstance(cluster, dict):
        return {}

    identifier = _safe_string(cluster.get("DBClusterIdentifier"))
    arn = _safe_string(cluster.get("DBClusterArn"))
    engine = _safe_string(cluster.get("Engine") or "unknown")
    engine_version = _safe_string(cluster.get("EngineVersion"))
    status = _safe_string(cluster.get("Status") or "unknown").lower()
    
    azs = cluster.get("AvailabilityZones") or []
    region = fallback_region
    if azs and isinstance(azs[0], str) and azs[0][:-1]:
        region = azs[0][:-1]

    storage_encrypted = bool(cluster.get("StorageEncrypted", False))
    kms_key_id = _safe_string(cluster.get("KmsKeyId"))
    backup_retention = int(cluster.get("BackupRetentionPeriod") or 0)
    deletion_protection = bool(cluster.get("DeletionProtection", False))
    multi_az = bool(cluster.get("MultiAZ", False))

    members = [
        {
            "instance_identifier": m.get("DBInstanceIdentifier"),
            "is_cluster_writer": bool(m.get("IsClusterWriter", False)),
        }
        for m in (cluster.get("DBClusterMembers") or [])
        if isinstance(m, dict) and m.get("DBInstanceIdentifier")
    ]

    create_time = cluster.get("ClusterCreateTime")
    create_time_str = (
        create_time.isoformat()
        if hasattr(create_time, "isoformat")
        else str(create_time)
        if create_time
        else None
    )

    has_risk = not storage_encrypted or backup_retention <= 0
    security_posture = "RISK" if has_risk else ("SECURE" if deletion_protection else "EVALUATED")

    return {
        "db_cluster_identifier": identifier,
        "resource": identifier,
        "resource_id": identifier,
        "resource_arn": arn,
        "resource_type": "RDS_CLUSTER",
        "engine": engine,
        "engine_version": engine_version,
        "status": status,
        "region": region,
        "availability_zones": azs,
        "multi_az": multi_az,
        "storage_encrypted": storage_encrypted,
        "kms_key_id": kms_key_id or None,
        "backup_retention_period": backup_retention,
        "deletion_protection": deletion_protection,
        "cluster_members": members,
        "endpoint": cluster.get("Endpoint"),
        "reader_endpoint": cluster.get("ReaderEndpoint"),
        "port": cluster.get("Port"),
        "create_time": create_time_str,
        "security_posture": security_posture,
        "coverage": "COMPLETE",
    }


def fetch_rds_instances_inventory(
    rds_client: Any,
    region: str,
    max_records: Optional[int] = 50,
    marker: Optional[str] = None,
    all_pages: bool = False,
    search: Optional[str] = None,
    engine_filter: Optional[str] = None,
    status_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query RDS DescribeDBInstances in a strictly read-only manner, handling pagination and filtering.
    """
    normalized_instances: List[Dict[str, Any]] = []
    current_marker = marker
    limit = max(20, min(max_records or 50, 100))

    while True:
        kwargs: Dict[str, Any] = {"MaxRecords": limit}
        if current_marker:
            kwargs["Marker"] = current_marker

        try:
            response = rds_client.describe_db_instances(**kwargs)
        except ClientError as client_err:
            code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
            msg = client_err.response.get("Error", {}).get("Message", str(client_err))
            if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
                raise RDSControlExecutionError(
                    status_code=403,
                    code="AWS_ACCESS_DENIED",
                    category="PERMISSION_DENIED",
                    message=f"AWS AccessDenied: The IAM role lacks rds:DescribeDBInstances permission in {region}.",
                ) from client_err
            elif code in ("Throttling", "RequestLimitExceeded"):
                raise RDSControlExecutionError(
                    status_code=429,
                    code="AWS_THROTTLED",
                    category="RATE_LIMIT",
                    message="AWS RDS request rate limit exceeded. Please retry after a brief pause.",
                ) from client_err
            else:
                raise RDSControlExecutionError(
                    status_code=502,
                    code=code,
                    category="AWS_SERVICE_ERROR",
                    message=f"AWS RDS service error in {region}: [{code}] {msg}",
                ) from client_err
        except Exception as exc:
            raise RDSControlExecutionError(
                status_code=502,
                code="RDS_CONNECTION_ERROR",
                category="NETWORK_ERROR",
                message=f"Failed to communicate with AWS RDS service: {str(exc)}",
            ) from exc

        raw_instances = response.get("DBInstances", [])
        for inst in raw_instances:
            item = normalize_rds_instance(inst, fallback_region=region)
            if not item.get("db_instance_identifier"):
                continue

            # Search filter
            if search:
                s = search.strip().lower()
                name_match = s in item["db_instance_identifier"].lower()
                engine_match = s in item["engine"].lower()
                if not name_match and not engine_match:
                    continue

            # Engine filter
            if engine_filter and engine_filter.lower() != "all":
                if engine_filter.lower() not in item["engine"].lower():
                    continue

            # Status filter
            if status_filter and status_filter.lower() != "all":
                if item["status"] != status_filter.lower():
                    continue

            normalized_instances.append(item)

        current_marker = response.get("Marker")
        if not all_pages or not current_marker:
            break

    # Calculate summary metrics
    total_count = len(normalized_instances)
    available_count = sum(1 for i in normalized_instances if i["status"] == "available")
    stopped_count = sum(1 for i in normalized_instances if i["status"] == "stopped")
    public_count = sum(1 for i in normalized_instances if i["publicly_accessible"])
    encrypted_count = sum(1 for i in normalized_instances if i["storage_encrypted"])
    critical_count = sum(1 for i in normalized_instances if i["security_posture"] == "CRITICAL")
    risk_count = sum(1 for i in normalized_instances if i["security_posture"] == "RISK")
    secure_count = sum(1 for i in normalized_instances if i["security_posture"] == "SECURE")

    return {
        "total_count": total_count,
        "instances": normalized_instances,
        "next_token": current_marker,
        "summary": {
            "total_instances": total_count,
            "available_instances": available_count,
            "stopped_instances": stopped_count,
            "publicly_accessible": public_count,
            "encrypted_instances": encrypted_count,
            "critical_posture": critical_count,
            "risk_posture": risk_count,
            "secure_posture": secure_count,
        },
        "coverage": "COMPLETE",
    }


def fetch_rds_clusters_inventory(
    rds_client: Any,
    region: str,
    max_records: Optional[int] = 50,
    marker: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Query RDS DescribeDBClusters in a strictly read-only manner.
    """
    kwargs: Dict[str, Any] = {"MaxRecords": max(20, min(max_records or 50, 100))}
    if marker:
        kwargs["Marker"] = marker

    try:
        response = rds_client.describe_db_clusters(**kwargs)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        if code in ("AccessDenied", "UnauthorizedOperation"):
            raise RDSControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks rds:DescribeDBClusters permission in {region}.",
            ) from client_err
        raise RDSControlExecutionError(
            status_code=502,
            code=code,
            category="AWS_SERVICE_ERROR",
            message=f"AWS RDS clusters query error in {region}: {str(client_err)}",
        ) from client_err

    clusters = [
        normalize_rds_cluster(c, fallback_region=region)
        for c in response.get("DBClusters", [])
        if isinstance(c, dict) and c.get("DBClusterIdentifier")
    ]

    return {
        "total_count": len(clusters),
        "clusters": clusters,
        "next_token": response.get("Marker"),
    }


def execute_rds_instance_action(
    *,
    account_id: str,
    instance_id: str,
    action: str,
    region: Optional[str] = None,
    confirmed: bool = False,
    user_id: str,
    organization_id: str,
    role: str = "viewer",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a secure, verified action on an RDS DB Instance.

    Supported Actions:
    1. start -> Start a stopped DB instance.
    2. stop -> Stop an available DB instance.
    3. reboot -> Reboot a DB instance.
    4. disable_public_access -> Modify DB instance to set PubliclyAccessible=False.
    5. enable_deletion_protection -> Modify DB instance to set DeletionProtection=True.

    Enforces:
    - Action whitelist validation (destructive actions strictly rejected).
    - Explicit user confirmation required (confirmed: True).
    - Strict Owner/Admin role authorization.
    - Tenant organization isolation.
    - AWS role assumption and STS identity verification.
    - Server-side pre-state verification (invalid transitions rejected).
    - Post-state verification and tamper-evident audit logging.
    """
    clean_action = _safe_string(action).lower()
    clean_instance = _safe_string(instance_id).strip()
    clean_account_id = _safe_string(account_id).strip()
    clean_role = _safe_string(role).lower()

    # 1. Action whitelist validation
    if clean_action not in ALLOWED_RDS_ACTIONS:
        raise RDSControlExecutionError(
            status_code=400,
            code="UNSUPPORTED_ACTION",
            category="VALIDATION_ERROR",
            message=f"Action '{action}' is not supported. Supported actions: {sorted(list(ALLOWED_RDS_ACTIONS))}.",
        )

    # 2. Explicit confirmation check
    if not confirmed:
        raise RDSControlExecutionError(
            status_code=400,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_ERROR",
            message="Explicit user confirmation is required to execute RDS control actions.",
        )

    # 3. Instance identifier validation
    if not is_valid_rds_identifier(clean_instance):
        raise RDSControlExecutionError(
            status_code=400,
            code="INVALID_INSTANCE_ID",
            category="VALIDATION_ERROR",
            message=f"Invalid RDS DB instance identifier '{instance_id}'. Must conform to AWS naming rules.",
        )

    # 4. Strict Role Authorization (Owner / Admin only)
    if clean_role not in MUTATION_ALLOWED_ROLES:
        audit_event = record_event(
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"rds:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_instance,
            result=RESULT_DENIED,
            details={
                "reason": "INSUFFICIENT_ROLE",
                "role": clean_role,
                "required_roles": sorted(list(MUTATION_ALLOWED_ROLES)),
                "action": clean_action,
                "service": "RDS",
            },
        )
        raise RDSControlExecutionError(
            status_code=403,
            code="PERMISSION_DENIED",
            category="AUTHORIZATION_ERROR",
            message=f"User role '{clean_role}' is not authorized to execute RDS controls. Required roles: {sorted(list(MUTATION_ALLOWED_ROLES))}.",
            audit_recorded=bool(audit_event),
        )

    # 5. Tenant-scoped account lookup
    aws_account = get_account(clean_account_id, organization_id=organization_id)
    if not aws_account:
        raise RDSControlExecutionError(
            status_code=404,
            code="ACCOUNT_NOT_FOUND",
            category="NOT_FOUND",
            message="AWS Account not found in current organization context.",
        )

    account_status = _safe_string(aws_account.get("status")).lower()
    if account_status != "connected":
        raise RDSControlExecutionError(
            status_code=400,
            code="ACCOUNT_NOT_CONNECTED",
            category="ACCOUNT_VALIDATION",
            message=f"AWS account is not connected (status: '{account_status or 'unknown'}'). Action rejected.",
        )

    # 5b. Verify organization remediation setting for RDS
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, clean_account_id, "rds"):
        record_event(
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"rds:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_instance,
            result=RESULT_DENIED,
            details={
                "reason": "REMEDIATION_SETTING_DISABLED",
                "action": clean_action,
                "service": "RDS",
            },
        )
        raise RDSControlExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="AUTHORIZATION_ERROR",
            message="Remediation is disabled for RDS for this account.",
            audit_recorded=True,
        )

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise RDSControlExecutionError(
            status_code=400,
            code="MISSING_ROLE_ARN",
            category="CONFIGURATION_ERROR",
            message="AWS account is missing configured role_arn.",
        )

    target_region = str(region or aws_account.get("region") or "us-east-1").strip()
    if not validate_aws_region(target_region):
        target_region = "us-east-1"

    # 6. Assume IAM role & Verify Account Identity
    try:
        session = assume_aws_role(role_arn, region=target_region)
    except Exception as assume_err:
        logger.warning(
            "RDS control role assumption failed account_id=%s: %s",
            clean_account_id,
            assume_err,
        )
        raise RDSControlExecutionError(
            status_code=403,
            code="ROLE_ASSUMPTION_FAILED",
            category="AUTHENTICATION_ERROR",
            message="Failed to assume AWS role for the connected account. Verify IAM trust policy.",
        )

    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise RDSControlExecutionError(
            status_code=403,
            code="ACCOUNT_IDENTITY_MISMATCH",
            category="AUTHORIZATION_ERROR",
            message=str(perm_err),
        )
    except Exception:
        raise RDSControlExecutionError(
            status_code=403,
            code="ACCOUNT_VERIFICATION_FAILED",
            category="AUTHORIZATION_ERROR",
            message="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    rds_client = clients.get("rds")
    if not rds_client:
        raise RDSControlExecutionError(
            status_code=500,
            code="CLIENT_INIT_FAILED",
            category="INTERNAL_ERROR",
            message="Failed to initialize RDS service client.",
        )

    # 7. Pre-State Inspection & Validation
    try:
        desc_resp = rds_client.describe_db_instances(DBInstanceIdentifier=clean_instance)
        instances_list = desc_resp.get("DBInstances", [])
        if not instances_list:
            raise RDSControlExecutionError(
                status_code=404,
                code="INSTANCE_NOT_FOUND",
                category="NOT_FOUND",
                message=f"RDS DB instance '{clean_instance}' not found in region '{target_region}'.",
            )
        pre_instance = instances_list[0]
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        if code == "DBInstanceNotFound":
            raise RDSControlExecutionError(
                status_code=404,
                code="INSTANCE_NOT_FOUND",
                category="NOT_FOUND",
                message=f"RDS DB instance '{clean_instance}' not found in region '{target_region}'.",
            ) from client_err
        elif code in ("AccessDenied", "UnauthorizedOperation"):
            raise RDSControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks rds:DescribeDBInstances permission in {target_region}.",
            ) from client_err
        raise RDSControlExecutionError(
            status_code=502,
            code=code,
            category="AWS_SERVICE_ERROR",
            message=f"AWS RDS error describing instance '{clean_instance}': {str(client_err)}",
        ) from client_err

    current_status = _safe_string(pre_instance.get("DBInstanceStatus")).lower()
    is_cluster_member = bool(pre_instance.get("DBClusterIdentifier"))

    # State transition validation
    if clean_action == "start":
        if is_cluster_member:
            raise RDSControlExecutionError(
                status_code=400,
                code="CLUSTER_MEMBER_NOT_SUPPORTED",
                category="VALIDATION_ERROR",
                message=f"Instance '{clean_instance}' is part of a DB cluster. Individual cluster instances cannot be started directly; control the cluster instead.",
            )
        if current_status != "stopped":
            raise RDSControlExecutionError(
                status_code=400,
                code="INVALID_STATE_TRANSITION",
                category="STATE_ERROR",
                message=f"Cannot start RDS instance '{clean_instance}' because it is in '{current_status}' state (must be 'stopped').",
            )
    elif clean_action == "stop":
        if is_cluster_member:
            raise RDSControlExecutionError(
                status_code=400,
                code="CLUSTER_MEMBER_NOT_SUPPORTED",
                category="VALIDATION_ERROR",
                message=f"Instance '{clean_instance}' is part of a DB cluster. Individual cluster instances cannot be stopped directly; control the cluster instead.",
            )
        if current_status != "available":
            raise RDSControlExecutionError(
                status_code=400,
                code="INVALID_STATE_TRANSITION",
                category="STATE_ERROR",
                message=f"Cannot stop RDS instance '{clean_instance}' because it is in '{current_status}' state (must be 'available').",
            )
    elif clean_action == "reboot":
        if current_status != "available":
            raise RDSControlExecutionError(
                status_code=400,
                code="INVALID_STATE_TRANSITION",
                category="STATE_ERROR",
                message=f"Cannot reboot RDS instance '{clean_instance}' because it is in '{current_status}' state (must be 'available').",
            )
    elif clean_action == "disable_public_access":
        if not pre_instance.get("PubliclyAccessible", False):
            return {
                "status": "success",
                "action": clean_action,
                "instance_id": clean_instance,
                "region": target_region,
                "verification_status": "ALREADY_COMPLIANT",
                "message": f"RDS instance '{clean_instance}' is already not publicly accessible.",
            }
    elif clean_action == "enable_deletion_protection":
        if pre_instance.get("DeletionProtection", False):
            return {
                "status": "success",
                "action": clean_action,
                "instance_id": clean_instance,
                "region": target_region,
                "verification_status": "ALREADY_COMPLIANT",
                "message": f"Deletion protection is already enabled on RDS instance '{clean_instance}'.",
            }

    # 8. Record Execution Started Audit Event
    record_event(
        event_type=EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
        action=f"rds:{clean_action}",
        actor_id=user_id,
        actor_type=ACTOR_USER,
        organization_id=organization_id,
        account_id=clean_account_id,
        resource_id=clean_instance,
        result=RESULT_SUCCESS,
        details={
            "service": "RDS",
            "action": clean_action,
            "instance_id": clean_instance,
            "pre_status": current_status,
            "region": target_region,
            "aws_account_id": stored_aws_account_id,
            "role": clean_role,
        },
    )

    # 9. Execute the AWS Action
    try:
        if clean_action == "start":
            rds_client.start_db_instance(DBInstanceIdentifier=clean_instance)
        elif clean_action == "stop":
            rds_client.stop_db_instance(DBInstanceIdentifier=clean_instance)
        elif clean_action == "reboot":
            rds_client.reboot_db_instance(DBInstanceIdentifier=clean_instance)
        elif clean_action == "disable_public_access":
            rds_client.modify_db_instance(
                DBInstanceIdentifier=clean_instance,
                PubliclyAccessible=False,
                ApplyImmediately=True,
            )
        elif clean_action == "enable_deletion_protection":
            rds_client.modify_db_instance(
                DBInstanceIdentifier=clean_instance,
                DeletionProtection=True,
                ApplyImmediately=True,
            )
    except ClientError as client_err:
        err_code = _safe_error_code(client_err)
        err_msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        record_event(
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"rds:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_instance,
            result=RESULT_FAILURE,
            details={
                "service": "RDS",
                "action": clean_action,
                "error_code": err_code,
                "error_message": err_msg,
                "region": target_region,
            },
        )
        if err_code in ("AccessDenied", "UnauthorizedOperation"):
            raise RDSControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks permission to execute rds:{clean_action} on '{clean_instance}'.",
                audit_recorded=True,
            ) from client_err
        elif err_code == "InvalidDBInstanceState":
            raise RDSControlExecutionError(
                status_code=400,
                code="INVALID_DB_STATE",
                category="STATE_ERROR",
                message=f"AWS rejected '{clean_action}': {err_msg}",
                audit_recorded=True,
            ) from client_err
        else:
            raise RDSControlExecutionError(
                status_code=502,
                code=err_code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS RDS error executing '{clean_action}': [{err_code}] {err_msg}",
                audit_recorded=True,
            ) from client_err
    except Exception as exc:
        record_event(
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"rds:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_instance,
            result=RESULT_FAILURE,
            details={
                "service": "RDS",
                "action": clean_action,
                "error": str(exc),
                "region": target_region,
            },
        )
        raise RDSControlExecutionError(
            status_code=500,
            code="EXECUTION_FAILED",
            category="INTERNAL_ERROR",
            message=f"Unexpected error executing '{clean_action}' on RDS instance: {str(exc)}",
            audit_recorded=True,
        ) from exc

    # 10. Post-action verification
    post_instance = {}
    try:
        post_resp = rds_client.describe_db_instances(DBInstanceIdentifier=clean_instance)
        post_list = post_resp.get("DBInstances", [])
        if post_list:
            post_instance = normalize_rds_instance(post_list[0], fallback_region=target_region)
    except Exception as verify_err:
        logger.warning("Failed to describe post-action RDS state: %s", verify_err)

    post_status = post_instance.get("status", "unknown")
    verified = True
    verification_status = "INITIATED"

    if clean_action == "start":
        if post_status in ("starting", "available"):
            verification_status = "VERIFIED"
    elif clean_action == "stop":
        if post_status in ("stopping", "stopped"):
            verification_status = "VERIFIED"
    elif clean_action == "reboot":
        if post_status in ("rebooting", "available"):
            verification_status = "VERIFIED"
    elif clean_action == "disable_public_access":
        if not post_instance.get("publicly_accessible", True) or post_status == "modifying":
            verification_status = "VERIFIED"
    elif clean_action == "enable_deletion_protection":
        if post_instance.get("deletion_protection", False) or post_status == "modifying":
            verification_status = "VERIFIED"

    # 11. Record Completion Audit Event
    record_event(
        event_type=EVENT_RESOURCE_CONTROL_COMPLETED,
        action=f"rds:{clean_action}",
        actor_id=user_id,
        actor_type=ACTOR_USER,
        organization_id=organization_id,
        account_id=clean_account_id,
        resource_id=clean_instance,
        result=RESULT_SUCCESS,
        details={
            "service": "RDS",
            "action": clean_action,
            "instance_id": clean_instance,
            "post_status": post_status,
            "region": target_region,
            "verification_status": verification_status,
        },
    )

    return {
        "status": "success",
        "action": clean_action,
        "instance_id": clean_instance,
        "region": target_region,
        "account_id": clean_account_id,
        "aws_account_id": stored_aws_account_id,
        "verification_status": verification_status,
        "post_state": post_instance,
        "message": f"Successfully executed '{clean_action}' on RDS instance '{clean_instance}'. Status: {post_status} ({verification_status}).",
    }
