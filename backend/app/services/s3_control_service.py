# ============================================================
# CloudGuardAI - Secure S3 Resource Control & Inventory Service
# Phase 3: Secure AWS S3 Resource Management
# ============================================================

from __future__ import annotations

import ipaddress
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
    AWS_CONFIG,
    assume_aws_role,
    get_aws_clients,
    verify_aws_account,
)
from app.services.s3_checker import (
    S3RegionResolutionError,
    get_regional_s3_client,
    resolve_bucket_region,
)

logger = logging.getLogger("cloudguardai.s3_controls")

# S3 Bucket naming rules according to AWS specifications
S3_BUCKET_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
AWS_REGION_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

ALLOWED_S3_ACTIONS = {
    "enable_block_public_access",
    "enable_bpa",
    "enable_encryption",
    "enable_versioning",
}

MUTATION_ALLOWED_ROLES = {"owner", "admin"}


class S3ControlExecutionError(Exception):
    """Safe public error details for S3 control workflows."""

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


def is_valid_bucket_name(bucket_name: str) -> bool:
    """
    Validate that an S3 bucket name conforms strictly to AWS bucket naming conventions.
    Rejects IP-like formats, path traversals, special suffixes, and invalid lengths.
    """
    if not isinstance(bucket_name, str):
        return False
    name = bucket_name.strip()
    if (
        not S3_BUCKET_NAME_PATTERN.fullmatch(name)
        or ".." in name
        or ".-" in name
        or "-." in name
        or name.startswith(("xn--", "sthree-", "amzn-s3-demo-"))
        or name.endswith(("-s3alias", "--ol-s3", "--x-s3", "--table-s3"))
    ):
        return False
    try:
        ipaddress.ip_address(name)
        return False
    except ValueError:
        return True


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


def inspect_single_bucket_posture(
    regional_client: Any,
    bucket_name: str,
    bucket_region: str,
    account_id: Optional[str] = None,
    created_str: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Inspect all supported security controls for a single S3 bucket using a regional client.
    Captures Block Public Access, Bucket Policy, ACL, Encryption, Versioning, and Logging.
    """
    owner_kwargs = {"ExpectedBucketOwner": account_id} if account_id else {}

    # 1. Block Public Access (BPA)
    bpa_record = {
        "configured": False,
        "BlockPublicAcls": False,
        "IgnorePublicAcls": False,
        "BlockPublicPolicy": False,
        "RestrictPublicBuckets": False,
        "all_protected": False,
        "status": "UNCONFIGURED",
        "verified": False,
    }
    try:
        bpa_resp = regional_client.get_public_access_block(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        cfg = bpa_resp.get("PublicAccessBlockConfiguration", {})
        bpa_protected = bool(
            cfg.get("BlockPublicAcls")
            and cfg.get("IgnorePublicAcls")
            and cfg.get("BlockPublicPolicy")
            and cfg.get("RestrictPublicBuckets")
        )
        bpa_record = {
            "configured": True,
            "BlockPublicAcls": bool(cfg.get("BlockPublicAcls")),
            "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls")),
            "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy")),
            "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets")),
            "all_protected": bpa_protected,
            "status": "PROTECTED" if bpa_protected else "PARTIAL",
            "verified": True,
        }
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code == "NoSuchPublicAccessBlockConfiguration":
            bpa_record["status"] = "NOT_CONFIGURED"
            bpa_record["configured"] = False
            bpa_record["verified"] = True
            bpa_record["all_protected"] = False
        elif err_code in ("AccessDenied", "Forbidden"):
            bpa_record["status"] = "ACCESS_DENIED"
            bpa_record["verified"] = False
        else:
            bpa_record["status"] = "ERROR"
            bpa_record["verified"] = False
            bpa_record["error"] = err_code
    except Exception as err:
        bpa_record["status"] = "ERROR"
        bpa_record["verified"] = False
        bpa_record["error"] = str(err)

    # 2. Bucket Policy
    policy_record = {"exists": False, "is_public": False, "status": "NONE", "verified": False}
    try:
        pol_resp = regional_client.get_bucket_policy_status(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        is_pub = bool(pol_resp.get("PolicyStatus", {}).get("IsPublic", False))
        policy_record = {
            "exists": True,
            "is_public": is_pub,
            "status": "PUBLIC" if is_pub else "RESTRICTED",
            "verified": True,
        }
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
            policy_record = {"exists": False, "is_public": False, "status": "NO_POLICY", "verified": True}
        elif err_code in ("AccessDenied", "Forbidden"):
            policy_record["status"] = "ACCESS_DENIED"
            policy_record["verified"] = False
        else:
            policy_record["status"] = "ERROR"
            policy_record["verified"] = False
            policy_record["error"] = err_code
    except Exception as err:
        policy_record["status"] = "ERROR"
        policy_record["verified"] = False
        policy_record["error"] = str(err)

    # 3. Bucket ACL
    acl_record = {"public": False, "grants_count": 0, "status": "PRIVATE", "verified": False}
    try:
        acl_resp = regional_client.get_bucket_acl(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        grants = acl_resp.get("Grants", [])
        acl_record["grants_count"] = len(grants)
        is_public_acl = False
        for g in grants:
            uri = g.get("Grantee", {}).get("URI", "")
            if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                is_public_acl = True
                break
        acl_record["public"] = is_public_acl
        acl_record["status"] = "PUBLIC" if is_public_acl else "PRIVATE"
        acl_record["verified"] = True
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code in ("AccessDenied", "Forbidden"):
            acl_record["status"] = "ACCESS_DENIED"
            acl_record["verified"] = False
        else:
            acl_record["status"] = "ERROR"
            acl_record["verified"] = False
            acl_record["error"] = err_code
    except Exception as err:
        acl_record["status"] = "ERROR"
        acl_record["verified"] = False
        acl_record["error"] = str(err)

    # 4. Encryption
    enc_record = {"enabled": False, "algorithm": None, "status": "DISABLED", "verified": False}
    try:
        enc_resp = regional_client.get_bucket_encryption(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            algo = (
                rules[0]
                .get("ApplyServerSideEncryptionByDefault", {})
                .get("SSEAlgorithm")
            )
            enc_record = {"enabled": True, "algorithm": algo, "status": "ENABLED", "verified": True}
        else:
            enc_record = {"enabled": False, "algorithm": None, "status": "DISABLED", "verified": True}
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket") or "not found" in str(err).lower():
            enc_record = {"enabled": False, "algorithm": None, "status": "NOT_CONFIGURED", "verified": True}
        elif err_code in ("AccessDenied", "Forbidden"):
            enc_record["status"] = "ACCESS_DENIED"
            enc_record["verified"] = False
        else:
            enc_record["status"] = "ERROR"
            enc_record["verified"] = False
            enc_record["error"] = err_code
    except Exception as err:
        enc_record["status"] = "ERROR"
        enc_record["verified"] = False
        enc_record["error"] = str(err)

    # 5. Versioning
    ver_record = {"status": "DISABLED", "mfa_delete": "Disabled", "enabled": False, "verified": False}
    try:
        ver_resp = regional_client.get_bucket_versioning(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        ver_status = ver_resp.get("Status") or "Disabled"
        mfa_status = ver_resp.get("MFADelete") or "Disabled"
        ver_record = {
            "status": ver_status.upper(),
            "mfa_delete": mfa_status,
            "enabled": ver_status.lower() == "enabled",
            "verified": True,
        }
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code in ("AccessDenied", "Forbidden"):
            ver_record["status"] = "ACCESS_DENIED"
            ver_record["verified"] = False
        else:
            ver_record["status"] = "ERROR"
            ver_record["verified"] = False
            ver_record["error"] = err_code
    except Exception as err:
        ver_record["status"] = "ERROR"
        ver_record["verified"] = False
        ver_record["error"] = str(err)

    # 6. Server Access Logging
    log_record = {"enabled": False, "target_bucket": None, "target_prefix": None, "status": "DISABLED", "verified": False}
    try:
        log_resp = regional_client.get_bucket_logging(
            Bucket=bucket_name,
            **owner_kwargs,
        )
        logging_enabled = log_resp.get("LoggingEnabled")
        if logging_enabled:
            log_record = {
                "enabled": True,
                "target_bucket": logging_enabled.get("TargetBucket"),
                "target_prefix": logging_enabled.get("TargetPrefix"),
                "status": "ENABLED",
                "verified": True,
            }
        else:
            log_record = {
                "enabled": False,
                "target_bucket": None,
                "target_prefix": None,
                "status": "DISABLED",
                "verified": True,
            }
    except ClientError as err:
        err_code = err.response.get("Error", {}).get("Code", "")
        if err_code in ("AccessDenied", "Forbidden"):
            log_record["status"] = "ACCESS_DENIED"
            log_record["verified"] = False
        else:
            log_record["status"] = "ERROR"
            log_record["verified"] = False
            log_record["error"] = err_code
    except Exception as err:
        log_record["status"] = "ERROR"
        log_record["verified"] = False
        log_record["error"] = str(err)

    # Overall bucket posture classification
    all_checks_verified = (
        bpa_record.get("verified", False)
        and policy_record.get("verified", False)
        and acl_record.get("verified", False)
        and enc_record.get("verified", False)
        and ver_record.get("verified", False)
        and log_record.get("verified", False)
    )

    has_critical = (
        policy_record.get("is_public", False)
        or acl_record.get("public", False)
    )

    has_risk = (
        not bpa_record.get("all_protected", False)
        or not enc_record.get("enabled", False)
    )

    if not all_checks_verified:
        if has_critical:
            overall_posture = "CRITICAL"
        elif has_risk:
            overall_posture = "RISK"
        else:
            overall_posture = "UNKNOWN"
        coverage_status = "PARTIAL"
    else:
        coverage_status = "COMPLETE"
        if bpa_record["all_protected"] and not policy_record["is_public"] and not acl_record["public"] and enc_record["enabled"]:
            overall_posture = "SECURE"
        elif has_critical:
            overall_posture = "CRITICAL"
        elif has_risk:
            overall_posture = "RISK"
        else:
            overall_posture = "EVALUATED"

    return {
        "bucket_name": bucket_name,
        "resource": bucket_name,
        "resource_id": bucket_name,
        "resource_arn": f"arn:aws:s3:::{bucket_name}",
        "resource_type": "S3 Bucket",
        "service": "S3",
        "region": bucket_region,
        "account_id": account_id or "",
        "creation_date": created_str,
        "block_public_access": bpa_record,
        "bucket_policy": policy_record,
        "acl": acl_record,
        "encryption": enc_record,
        "versioning": ver_record,
        "logging": log_record,
        "security_posture": overall_posture,
        "coverage": coverage_status,
    }


def fetch_s3_buckets_inventory(
    s3_client: Any,
    session: Optional[Any] = None,
    account_id: Optional[str] = None,
    region_filter: Optional[str] = None,
    page_size: Optional[int] = 50,
    next_token: Optional[str] = None,
    all_pages: bool = False,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Fetch S3 bucket inventory and evaluate security posture in a strictly read-only manner.
    Supports filtering by region and search keyword, and bounded pagination.
    """
    try:
        response = s3_client.list_buckets()
        raw_buckets = response.get("Buckets", [])
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = error.response.get("Error", {}).get("Message", str(error))
        if code in ("AccessDenied", "UnauthorizedOperation", "Forbidden"):
            raise S3ControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message="AWS AccessDenied: The IAM role lacks s3:ListAllMyBuckets permission.",
            ) from error
        elif code in ("RequestLimitExceeded", "Throttling", "SlowDown"):
            raise S3ControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS S3 request rate limit exceeded. Please retry after a brief pause.",
            ) from error
        else:
            raise S3ControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS S3 service error during discovery: [{code}] {msg}",
            ) from error
    except Exception as exc:
        raise S3ControlExecutionError(
            status_code=502,
            code="S3_DISCOVERY_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS S3: {str(exc)}",
        ) from exc

    processed_buckets: List[Dict[str, Any]] = []

    for bucket in raw_buckets:
        bucket_name = _safe_string(bucket.get("Name"))
        if not bucket_name:
            continue

        created = bucket.get("CreationDate")
        created_str = (
            created.isoformat()
            if hasattr(created, "isoformat")
            else str(created)
            if created
            else None
        )

        try:
            bucket_region = resolve_bucket_region(s3_client, bucket_name)
        except S3RegionResolutionError as reg_err:
            item = {
                "bucket_name": bucket_name,
                "resource": bucket_name,
                "resource_id": bucket_name,
                "resource_arn": f"arn:aws:s3:::{bucket_name}",
                "resource_type": "S3 Bucket",
                "service": "S3",
                "region": "UNKNOWN",
                "account_id": account_id or "",
                "creation_date": created_str,
                "block_public_access": {"status": "UNVERIFIED", "all_protected": False, "verified": False},
                "bucket_policy": {"status": "UNVERIFIED", "exists": False, "is_public": False, "verified": False},
                "acl": {"status": "UNVERIFIED", "public": False, "verified": False},
                "encryption": {"status": "UNVERIFIED", "enabled": False, "verified": False},
                "versioning": {"status": "UNVERIFIED", "enabled": False, "verified": False},
                "logging": {"status": "UNVERIFIED", "enabled": False, "verified": False},
                "security_posture": "UNKNOWN",
                "coverage": "PARTIAL",
                "inspection_error": {
                    "stage": "REGION_RESOLUTION",
                    "error_code": reg_err.error_code,
                    "message": reg_err.message,
                },
            }
            processed_buckets.append(item)
            continue

        # Check region filter if provided
        if region_filter and bucket_region.lower() != region_filter.strip().lower():
            continue

        # Check search filter if provided
        if search and search.strip().lower() not in bucket_name.lower():
            continue

        regional_client = get_regional_s3_client(s3_client, bucket_region, session=session)
        posture = inspect_single_bucket_posture(
            regional_client=regional_client,
            bucket_name=bucket_name,
            bucket_region=bucket_region,
            account_id=account_id,
            created_str=created_str,
        )
        processed_buckets.append(posture)

    # Calculate summary metrics
    total_count = len(processed_buckets)
    secure_count = sum(1 for b in processed_buckets if b.get("security_posture") == "SECURE")
    risk_count = sum(1 for b in processed_buckets if b.get("security_posture") == "RISK")
    critical_count = sum(1 for b in processed_buckets if b.get("security_posture") == "CRITICAL")
    unverified_count = sum(1 for b in processed_buckets if b.get("security_posture") in ("UNKNOWN", "EVALUATED") or b.get("coverage") == "PARTIAL")

    # Pagination logic
    limit = max(1, min(page_size or 50, 200))
    start_idx = 0
    if next_token and next_token.isdigit():
        start_idx = int(next_token)

    if all_pages:
        paginated_buckets = processed_buckets
        out_token = None
    else:
        paginated_buckets = processed_buckets[start_idx : start_idx + limit]
        next_idx = start_idx + limit
        out_token = str(next_idx) if next_idx < total_count else None

    return {
        "total_count": total_count,
        "buckets": paginated_buckets,
        "next_token": out_token,
        "summary": {
            "total_buckets": total_count,
            "secure_buckets": secure_count,
            "risk_buckets": risk_count,
            "critical_buckets": critical_count,
            "unverified_buckets": unverified_count,
            "protected_bpa_buckets": sum(1 for b in processed_buckets if b.get("block_public_access", {}).get("all_protected")),
            "encrypted_buckets": sum(1 for b in processed_buckets if b.get("encryption", {}).get("enabled")),
        },
        "coverage": "COMPLETE" if unverified_count == 0 else "PARTIAL",
    }


def execute_s3_bucket_action(
    *,
    account_id: str,
    bucket_name: str,
    action: str,
    region: Optional[str] = None,
    confirmed: bool = False,
    user_id: str,
    organization_id: str,
    role: str = "viewer",
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Executes a secure S3 control/remediation action on a connected AWS account.

    Supported Actions:
    1. enable_block_public_access (or enable_bpa) -> Configures all 4 Block Public Access flags to True.
    2. enable_encryption -> Applies default AES-256 Server-Side Encryption.
    3. enable_versioning -> Enables S3 Bucket Versioning.

    Enforces:
    - Action validation (only supported actions allowed; destructive actions strictly rejected).
    - Explicit confirmation required (confirmed: True).
    - Strict Owner/Admin role authorization.
    - Tenant organization isolation.
    - AWS role assumption and STS identity verification.
    - Authoritative bucket region resolution.
    - Pre-state and post-state transition validation.
    - Structured, tamper-evident audit logging.
    """
    clean_action = _safe_string(action).lower()
    clean_bucket = _safe_string(bucket_name).strip()
    clean_account_id = _safe_string(account_id).strip()
    clean_role = _safe_string(role).lower()

    # 1. Action validation
    if clean_action == "enable_bpa":
        clean_action = "enable_block_public_access"

    if clean_action not in ALLOWED_S3_ACTIONS:
        raise S3ControlExecutionError(
            status_code=400,
            code="UNSUPPORTED_ACTION",
            category="VALIDATION_ERROR",
            message=f"Action '{action}' is not supported. Supported actions are: {sorted(list(ALLOWED_S3_ACTIONS))}.",
        )

    # 2. Explicit confirmation check
    if not confirmed:
        raise S3ControlExecutionError(
            status_code=400,
            code="CONFIRMATION_REQUIRED",
            category="CONFIRMATION_ERROR",
            message="Explicit user confirmation is required to execute S3 control actions.",
        )

    # 3. Bucket name validation
    if not is_valid_bucket_name(clean_bucket):
        raise S3ControlExecutionError(
            status_code=400,
            code="INVALID_BUCKET_NAME",
            category="VALIDATION_ERROR",
            message=f"Invalid S3 bucket name '{bucket_name}'. Bucket name must comply with AWS naming rules.",
        )

    # 4. Strict Role Authorization
    if clean_role not in MUTATION_ALLOWED_ROLES:
        audit_event = record_event(
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"s3:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_bucket,
            result=RESULT_DENIED,
            details={
                "reason": "INSUFFICIENT_ROLE",
                "role": clean_role,
                "required_roles": sorted(list(MUTATION_ALLOWED_ROLES)),
                "action": clean_action,
                "service": "S3",
            },
        )
        raise S3ControlExecutionError(
            status_code=403,
            code="PERMISSION_DENIED",
            category="AUTHORIZATION_ERROR",
            message=f"User role '{clean_role}' is not authorized to execute S3 controls. Required roles: {sorted(list(MUTATION_ALLOWED_ROLES))}.",
            audit_recorded=bool(audit_event),
        )

    # 5. Tenant-scoped account lookup
    aws_account = get_account(clean_account_id, organization_id=organization_id)
    if not aws_account:
        raise S3ControlExecutionError(
            status_code=404,
            code="ACCOUNT_NOT_FOUND",
            category="NOT_FOUND",
            message="AWS Account not found in current organization context.",
        )

    account_status = _safe_string(aws_account.get("status")).lower()
    if account_status != "connected":
        raise S3ControlExecutionError(
            status_code=400,
            code="ACCOUNT_NOT_CONNECTED",
            category="ACCOUNT_VALIDATION",
            message=f"AWS account is not connected (status: '{account_status or 'unknown'}'). Action rejected.",
        )

    # 5b. Verify organization remediation setting for S3
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, clean_account_id, "s3"):
        record_event(
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"s3:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_bucket,
            result=RESULT_DENIED,
            details={
                "reason": "REMEDIATION_SETTING_DISABLED",
                "action": clean_action,
                "service": "S3",
            },
        )
        raise S3ControlExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="AUTHORIZATION_ERROR",
            message="Remediation is disabled for S3 for this account.",
            audit_recorded=True,
        )

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise S3ControlExecutionError(
            status_code=400,
            code="MISSING_ROLE_ARN",
            category="CONFIGURATION_ERROR",
            message="AWS account is missing configured role_arn.",
        )

    # 6. Assume IAM role & Verify Account Identity
    try:
        session = assume_aws_role(role_arn, region=region or "us-east-1")
    except Exception as assume_err:
        logger.warning(
            "S3 control role assumption failed account_id=%s: %s",
            clean_account_id,
            assume_err,
        )
        raise S3ControlExecutionError(
            status_code=403,
            code="ROLE_ASSUMPTION_FAILED",
            category="AUTHENTICATION_ERROR",
            message="Failed to assume AWS role for the connected account. Verify IAM trust policy.",
        )

    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise S3ControlExecutionError(
            status_code=403,
            code="ACCOUNT_IDENTITY_MISMATCH",
            category="AUTHORIZATION_ERROR",
            message=str(perm_err),
        )
    except Exception:
        raise S3ControlExecutionError(
            status_code=403,
            code="ACCOUNT_VERIFICATION_FAILED",
            category="AUTHORIZATION_ERROR",
            message="Unable to verify AWS account identity.",
        )

    clients = get_aws_clients(session)
    s3_client = clients.get("s3")
    if not s3_client:
        raise S3ControlExecutionError(
            status_code=500,
            code="CLIENT_INIT_FAILED",
            category="INTERNAL_ERROR",
            message="Failed to initialize S3 service client.",
        )

    # 7. Authoritatively resolve bucket region
    try:
        bucket_region = resolve_bucket_region(s3_client, clean_bucket)
    except S3RegionResolutionError as reg_err:
        raise S3ControlExecutionError(
            status_code=404 if "NoSuchBucket" in reg_err.error_code else 502,
            code=reg_err.error_code,
            category="REGION_RESOLUTION_ERROR",
            message=f"Cannot perform S3 control: {reg_err.message}",
        )

    regional_client = get_regional_s3_client(s3_client, bucket_region, session=session)
    owner_kwargs = {"ExpectedBucketOwner": stored_aws_account_id} if stored_aws_account_id else {}

    # 8. Record Execution Started Audit Event
    start_audit = record_event(
        event_type=EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
        action=f"s3:{clean_action}",
        actor_id=user_id,
        actor_type=ACTOR_USER,
        organization_id=organization_id,
        account_id=clean_account_id,
        resource_id=clean_bucket,
        result=RESULT_SUCCESS,
        details={
            "service": "S3",
            "action": clean_action,
            "bucket_name": clean_bucket,
            "bucket_region": bucket_region,
            "aws_account_id": stored_aws_account_id,
            "role": clean_role,
        },
    )

    # 9. Execute the specific action
    try:
        if clean_action == "enable_block_public_access":
            regional_client.put_public_access_block(
                Bucket=clean_bucket,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
                **owner_kwargs,
            )
        elif clean_action == "enable_encryption":
            regional_client.put_bucket_encryption(
                Bucket=clean_bucket,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256",
                            }
                        }
                    ]
                },
                **owner_kwargs,
            )
        elif clean_action == "enable_versioning":
            regional_client.put_bucket_versioning(
                Bucket=clean_bucket,
                VersioningConfiguration={
                    "Status": "Enabled",
                },
                **owner_kwargs,
            )
    except ClientError as client_err:
        err_code = _safe_error_code(client_err)
        err_msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        record_event(
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"s3:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_bucket,
            result=RESULT_FAILURE,
            details={
                "service": "S3",
                "action": clean_action,
                "error_code": err_code,
                "error_message": err_msg,
                "bucket_region": bucket_region,
            },
        )
        if err_code in ("AccessDenied", "UnauthorizedOperation"):
            raise S3ControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks permission to execute s3:{clean_action} on '{clean_bucket}'.",
                audit_recorded=True,
            ) from client_err
        else:
            raise S3ControlExecutionError(
                status_code=502,
                code=err_code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS S3 error executing '{clean_action}': [{err_code}] {err_msg}",
                audit_recorded=True,
            ) from client_err
    except Exception as exc:
        record_event(
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"s3:{clean_action}",
            actor_id=user_id,
            actor_type=ACTOR_USER,
            organization_id=organization_id,
            account_id=clean_account_id,
            resource_id=clean_bucket,
            result=RESULT_FAILURE,
            details={
                "service": "S3",
                "action": clean_action,
                "error": str(exc),
                "bucket_region": bucket_region,
            },
        )
        raise S3ControlExecutionError(
            status_code=500,
            code="EXECUTION_FAILED",
            category="INTERNAL_ERROR",
            message=f"Unexpected error executing '{clean_action}' on S3 bucket: {str(exc)}",
            audit_recorded=True,
        ) from exc

    # 10. Post-action verification
    post_state = inspect_single_bucket_posture(
        regional_client=regional_client,
        bucket_name=clean_bucket,
        bucket_region=bucket_region,
        account_id=stored_aws_account_id,
    )

    verified = False
    if clean_action == "enable_block_public_access":
        verified = post_state.get("block_public_access", {}).get("all_protected", False)
    elif clean_action == "enable_encryption":
        verified = post_state.get("encryption", {}).get("enabled", False)
    elif clean_action == "enable_versioning":
        verified = post_state.get("versioning", {}).get("enabled", False)

    verification_status = "VERIFIED" if verified else "UNVERIFIED"

    # 11. Record Completion Audit Event
    record_event(
        event_type=EVENT_RESOURCE_CONTROL_COMPLETED,
        action=f"s3:{clean_action}",
        actor_id=user_id,
        actor_type=ACTOR_USER,
        organization_id=organization_id,
        account_id=clean_account_id,
        resource_id=clean_bucket,
        result=RESULT_SUCCESS if verified else RESULT_FAILURE,
        details={
            "service": "S3",
            "action": clean_action,
            "bucket_name": clean_bucket,
            "bucket_region": bucket_region,
            "verification_status": verification_status,
            "post_posture": post_state.get("security_posture"),
        },
    )

    return {
        "status": "success" if verified else "partial_success",
        "action": clean_action,
        "bucket_name": clean_bucket,
        "region": bucket_region,
        "account_id": clean_account_id,
        "aws_account_id": stored_aws_account_id,
        "verification_status": verification_status,
        "post_state": post_state,
        "message": f"Successfully executed '{clean_action}' on bucket '{clean_bucket}'. Post-state verification: {verification_status}.",
    }
