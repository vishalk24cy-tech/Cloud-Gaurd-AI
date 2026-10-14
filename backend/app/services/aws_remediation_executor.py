"""
CloudGuardAI - AWS Remediation Executor

Production-oriented AWS remediation execution layer.

Flow:

    APPROVED remediation
            ↓
    Verify ownership
            ↓
    Verify AWS account
            ↓
    Assume temporary IAM role
            ↓
    Validate allowlisted action
            ↓
    Execute ONE remediation action
            ↓
    Verify AWS state
            ↓
    COMPLETED / FAILED
            ↓
    Update remediation record
            ↓
    Resolve finding only after successful verification

IMPORTANT:
- This service NEVER accepts raw boto3 operation names from the client.
- Only explicitly allowlisted actions can execute.
- AWS credentials are temporary STS credentials.
- Account ownership is checked before execution.
- AWS account identity is verified after AssumeRole.
- Verification is mandatory for successful completion.
"""

from __future__ import annotations

import json
import logging
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Optional

from botocore.exceptions import BotoCoreError, ClientError

from app.models.aws_account import get_account
from app.models.finding import (
    get_finding_for_account,
    is_finding_actionable,
)
from app.models.remediation import (
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_EXECUTING,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_REJECTED,
    ACTION_DISABLE_PUBLIC_ACCESS,
    ACTION_ENABLE_ENCRYPTION,
    ACTION_RESTRICT_SECURITY_GROUP,
    ACTION_ENABLE_MFA,
    ACTION_ENABLE_CLOUDTRAIL,
    ACTION_ENABLE_RDS_ENCRYPTION,
    ACTION_DISABLE_RDS_PUBLIC_ACCESS,
    ACTION_ENABLE_RDS_BACKUPS,
    ACTION_ENABLE_S3_ENCRYPTION,
    ACTION_REVIEW_IAM_POLICY,
    ACTION_REMOVE_PUBLIC_POLICY,
    get_remediation,
    update_execution_result,
    transition_to_executing,
    transition_to_completed,
    transition_to_failed,
)
from app.services.aws_connection import (
    assume_aws_role,
    get_aws_clients,
    verify_aws_account,
)


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger("cloudguardai.remediation")


# ============================================================
# CONSTANTS
# ============================================================

EXECUTOR_NAME = "CloudGuardAI-RemediationExecutor"
EXECUTOR_VERSION = "1.1.0"

MAX_EXECUTION_DURATION_SECONDS = 3600


# ============================================================
# ALLOWLIST
# ============================================================

ALLOWED_ACTIONS = {
    ACTION_DISABLE_PUBLIC_ACCESS,
    ACTION_ENABLE_ENCRYPTION,
    ACTION_RESTRICT_SECURITY_GROUP,
    ACTION_ENABLE_MFA,
    ACTION_ENABLE_CLOUDTRAIL,
    ACTION_ENABLE_RDS_ENCRYPTION,
    ACTION_DISABLE_RDS_PUBLIC_ACCESS,
    ACTION_ENABLE_RDS_BACKUPS,
    ACTION_ENABLE_S3_ENCRYPTION,
    ACTION_REVIEW_IAM_POLICY,
    ACTION_REMOVE_PUBLIC_POLICY,
}


# Actions which are intentionally NOT executable automatically.
#
# REVIEW_IAM_POLICY is a proposal/review action rather than a
# destructive AWS operation.
NON_EXECUTABLE_ACTIONS = {
    ACTION_REVIEW_IAM_POLICY,
}


# ============================================================
# CUSTOM EXCEPTIONS
# ============================================================

class RemediationExecutionError(Exception):
    """Base remediation execution error."""


class RemediationSecurityError(RemediationExecutionError):
    """Security boundary violation."""


class RemediationValidationError(RemediationExecutionError):
    """Invalid remediation request."""


class RemediationVerificationError(RemediationExecutionError):
    """AWS state verification failed."""


# ============================================================
# BASIC HELPERS
# ============================================================

def _now() -> datetime:
    return datetime.utcnow()


def _safe_string(value: Any) -> str:
    if value is None:
        return ""

    return str(value).strip()


def _normalize_action(action_type: Any) -> str:
    return _safe_string(action_type).upper()


def _normalize_status(status: Any) -> str:
    return _safe_string(status).upper()


def _is_successful_status(status: Any) -> bool:
    return _normalize_status(status) == STATUS_COMPLETED


def _get_operation(remediation: Dict[str, Any]) -> Dict[str, Any]:
    operation = remediation.get("operation")

    if operation is None:
        return {}

    if isinstance(operation, dict):
        return deepcopy(operation)

    if isinstance(operation, str):
        try:
            parsed = json.loads(operation)

            if isinstance(parsed, dict):
                return parsed

        except (TypeError, ValueError, json.JSONDecodeError):
            return {}

    return {}


def _get_resource(remediation: Dict[str, Any]) -> str:
    return _safe_string(
        remediation.get("resource")
        or _get_operation(remediation).get("resource")
    )


def _normalize_service(value: Any) -> str:
    """Normalize CloudGuardAI service labels to executor service names."""
    service = _safe_string(value).lower().replace("-", "_").replace(" ", "_")

    aliases = {
        "s3_bucket": "s3",
        "aws_s3": "s3",
        "amazon_s3": "s3",
        "ec2_instance": "ec2",
        "ec2_security_group": "ec2",
        "securitygroup": "security_group",
        "security_group": "security_group",
        "aws_rds": "rds",
        "amazon_rds": "rds",
        "aws_iam": "iam",
        "aws_cloudtrail": "cloudtrail",
    }

    return aliases.get(service, service)


def _get_service(remediation: Dict[str, Any]) -> str:
    return _normalize_service(
        remediation.get("service")
        or _get_operation(remediation).get("service")
    )


def _get_region(
    remediation: Dict[str, Any],
    account: Dict[str, Any],
) -> str:
    operation = _get_operation(remediation)

    return (
        _safe_string(operation.get("region"))
        or _safe_string(account.get("region"))
        or "ap-south-1"
    )


def _get_aws_account_id(
    remediation: Dict[str, Any],
    account: Dict[str, Any],
) -> str:
    return (
        _safe_string(account.get("aws_account_id"))
        or _safe_string(remediation.get("aws_account_id"))
    )


# ============================================================
# EXECUTION RESULT HELPERS
# ============================================================

def _result(
    *,
    action_type: str,
    service: str,
    resource: str,
    message: str,
    before_state: Optional[Dict[str, Any]] = None,
    after_state: Optional[Dict[str, Any]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return {
        "success": True,
        "action_type": action_type,
        "service": service,
        "resource": resource,
        "message": message,
        "before_state": before_state or {},
        "after_state": after_state or {},
        "verification": verification or {},
        "executed_at": _now(),
        "executor": EXECUTOR_NAME,
        "executor_version": EXECUTOR_VERSION,
    }


# ============================================================
# VALIDATION
# ============================================================

def validate_remediation(
    remediation: Dict[str, Any],
    account: Dict[str, Any],
    finding: Dict[str, Any],
) -> None:
    """
    Validate all security boundaries before touching AWS.
    """

    if not remediation:
        raise RemediationValidationError(
            "Remediation proposal was not found."
        )

    if not account:
        raise RemediationSecurityError(
            "AWS account was not found."
        )

    if not finding:
        raise RemediationSecurityError(
            "Associated finding was not found."
        )

    status = _normalize_status(
        remediation.get("status")
    )

    if status != STATUS_APPROVED:
        raise RemediationValidationError(
            f"Remediation must be APPROVED before execution. "
            f"Current status: {status or 'UNKNOWN'}."
        )

    action_type = _normalize_action(
        remediation.get("action_type")
    )

    if action_type not in ALLOWED_ACTIONS:
        raise RemediationSecurityError(
            f"Remediation action is not allowlisted: {action_type}"
        )

    if action_type in NON_EXECUTABLE_ACTIONS:
        raise RemediationValidationError(
            f"{action_type} is a review action and cannot be "
            "executed automatically."
        )

    if not is_finding_actionable(finding):
        raise RemediationValidationError(
            "The associated finding is no longer actionable."
        )

    finding_status = _normalize_status(
        finding.get("status")
        or finding.get("workflow_status")
    )

    blocked_finding_statuses = {
        STATUS_COMPLETED,
        "RESOLVED",
        "IGNORED",
        "NOT_APPLICABLE",
    }

    if finding_status in blocked_finding_statuses:
        raise RemediationValidationError(
            f"Finding is not eligible for remediation. "
            f"Current status: {finding_status}."
        )

    resource = _get_resource(remediation)

    if not resource:
        raise RemediationValidationError(
            "Remediation resource is missing."
        )

    aws_account_id = _get_aws_account_id(
        remediation,
        account,
    )

    if not aws_account_id:
        raise RemediationSecurityError(
            "AWS account ID is missing."
        )

    account_id_from_record = _safe_string(
        remediation.get("aws_account_id")
    )

    canonical_account_id = _safe_string(
        account.get("aws_account_id")
    )

    if (
        account_id_from_record
        and canonical_account_id
        and account_id_from_record != canonical_account_id
    ):
        raise RemediationSecurityError(
            "Remediation AWS account ID does not match "
            "the connected AWS account."
        )


# ============================================================
# S3 - PUBLIC ACCESS BLOCK
# ============================================================

def _execute_s3_disable_public_access(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    s3 = clients["s3"]

    bucket = _get_resource(remediation)

    if not bucket:
        raise RemediationValidationError(
            "S3 bucket name is required."
        )

    before_state: Dict[str, Any] = {}

    try:
        existing = s3.get_public_access_block(
            Bucket=bucket
        )

        before_state = {
            "public_access_block": existing.get(
                "PublicAccessBlockConfiguration",
                {},
            )
        }

    except ClientError as exc:

        code = exc.response.get(
            "Error",
            {},
        ).get(
            "Code",
            "",
        )

        if code not in {
            "NoSuchPublicAccessBlockConfiguration",
            "NoSuchPublicAccessBlockConfigurationException",
        }:
            raise

    # --------------------------------------------------------
    # Apply secure configuration
    # --------------------------------------------------------

    secure_configuration = {
        "BlockPublicAcls": True,
        "IgnorePublicAcls": True,
        "BlockPublicPolicy": True,
        "RestrictPublicBuckets": True,
    }

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration=secure_configuration,
    )

    # --------------------------------------------------------
    # Verify
    # --------------------------------------------------------

    verified = s3.get_public_access_block(
        Bucket=bucket
    )

    actual = verified.get(
        "PublicAccessBlockConfiguration",
        {},
    )

    verification_passed = all(
        actual.get(key) is True
        for key in secure_configuration
    )

    if not verification_passed:
        raise RemediationVerificationError(
            "S3 Public Access Block verification failed."
        )

    return _result(
        action_type=ACTION_DISABLE_PUBLIC_ACCESS,
        service="s3",
        resource=bucket,
        message="S3 public access protection enabled.",
        before_state=before_state,
        after_state={
            "public_access_block": actual
        },
        verification={
            "verified": True,
            "all_public_access_block_settings": True,
        },
    )


# ============================================================
# S3 - ENCRYPTION
# ============================================================

def _execute_s3_enable_encryption(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    s3 = clients["s3"]

    bucket = _get_resource(remediation)

    if not bucket:
        raise RemediationValidationError(
            "S3 bucket name is required."
        )

    before_state: Dict[str, Any] = {}

    try:
        current = s3.get_bucket_encryption(
            Bucket=bucket
        )

        before_state = {
            "server_side_encryption_configuration":
                current.get(
                    "ServerSideEncryptionConfiguration",
                    {},
                )
        }

    except ClientError as exc:

        code = exc.response.get(
            "Error",
            {},
        ).get(
            "Code",
            "",
        )

        if code not in {
            "ServerSideEncryptionConfigurationNotFoundError",
            "NoSuchBucket",
        }:
            raise

    # --------------------------------------------------------
    # AES256 is the safest generic automated remediation.
    # --------------------------------------------------------

    encryption_configuration = {
        "Rules": [
            {
                "ApplyServerSideEncryptionByDefault": {
                    "SSEAlgorithm": "AES256"
                }
            }
        ]
    }

    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration=
            encryption_configuration,
    )

    # --------------------------------------------------------
    # Verify
    # --------------------------------------------------------

    verified = s3.get_bucket_encryption(
        Bucket=bucket
    )

    actual = verified.get(
        "ServerSideEncryptionConfiguration",
        {},
    )

    rules = actual.get(
        "Rules",
        [],
    )

    verified_algorithms = []

    for rule in rules:

        default = rule.get(
            "ApplyServerSideEncryptionByDefault",
            {},
        )

        algorithm = default.get(
            "SSEAlgorithm"
        )

        if algorithm:
            verified_algorithms.append(
                algorithm
            )

    if "AES256" not in verified_algorithms:
        raise RemediationVerificationError(
            "S3 encryption verification failed."
        )

    return _result(
        action_type=ACTION_ENABLE_S3_ENCRYPTION,
        service="s3",
        resource=bucket,
        message="S3 server-side encryption enabled.",
        before_state=before_state,
        after_state={
            "encryption": actual
        },
        verification={
            "verified": True,
            "algorithm": "AES256",
        },
    )


# ============================================================
# S3 - REMOVE PUBLIC POLICY
# ============================================================

def _statement_is_public(
    statement: Dict[str, Any],
) -> bool:
    """
    Conservative public-policy detector.

    We only remove statements that clearly contain:
        Effect: Allow
        Principal: *
    """

    effect = _safe_string(
        statement.get("Effect")
    ).lower()

    if effect != "allow":
        return False

    principal = statement.get(
        "Principal"
    )

    if principal == "*":
        return True

    if isinstance(principal, dict):

        aws_principal = principal.get(
            "AWS"
        )

        if aws_principal == "*":
            return True

        if isinstance(
            aws_principal,
            list,
        ) and "*" in aws_principal:
            return True

    return False


def _execute_s3_remove_public_policy(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    s3 = clients["s3"]

    bucket = _get_resource(remediation)

    if not bucket:
        raise RemediationValidationError(
            "S3 bucket name is required."
        )

    try:
        response = s3.get_bucket_policy(
            Bucket=bucket
        )

    except ClientError as exc:

        code = exc.response.get(
            "Error",
            {},
        ).get(
            "Code",
            "",
        )

        if code in {
            "NoSuchBucketPolicy",
            "NoSuchBucket",
        }:
            return _result(
                action_type=ACTION_REMOVE_PUBLIC_POLICY,
                service="s3",
                resource=bucket,
                message="No S3 bucket policy was present.",
                before_state={
                    "policy_present": False
                },
                after_state={
                    "policy_present": False
                },
                verification={
                    "verified": True
                },
            )

        raise

    raw_policy = response.get(
        "Policy"
    )

    if not raw_policy:
        return _result(
            action_type=ACTION_REMOVE_PUBLIC_POLICY,
            service="s3",
            resource=bucket,
            message="S3 bucket policy was empty.",
            before_state={
                "policy_present": False
            },
            after_state={
                "policy_present": False
            },
            verification={
                "verified": True
            },
        )

    try:
        policy = json.loads(raw_policy)

    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise RemediationValidationError(
            "S3 bucket policy could not be safely parsed."
        ) from exc

    statements = policy.get(
        "Statement",
        [],
    )

    if isinstance(
        statements,
        dict,
    ):
        statements = [
            statements
        ]

    if not isinstance(
        statements,
        list,
    ):
        raise RemediationValidationError(
            "S3 bucket policy has an unsupported format."
        )

    public_statements = [
        statement
        for statement in statements
        if isinstance(statement, dict)
        and _statement_is_public(statement)
    ]

    if not public_statements:
        return _result(
            action_type=ACTION_REMOVE_PUBLIC_POLICY,
            service="s3",
            resource=bucket,
            message="No clearly public S3 policy statement was found.",
            before_state={
                "policy_present": True,
                "public_statement_count": 0,
            },
            after_state={
                "policy_present": True,
                "public_statement_count": 0,
            },
            verification={
                "verified": True
            },
        )

    remaining_statements = [
        statement
        for statement in statements
        if not (
            isinstance(statement, dict)
            and _statement_is_public(statement)
        )
    ]

    # --------------------------------------------------------
    # If the policy contains ONLY public statements, remove
    # the policy completely.
    # --------------------------------------------------------

    if not remaining_statements:

        s3.delete_bucket_policy(
            Bucket=bucket
        )

        try:
            s3.get_bucket_policy(
                Bucket=bucket
            )

            raise RemediationVerificationError(
                "S3 public policy deletion could not be verified."
            )

        except ClientError as exc:

            code = exc.response.get(
                "Error",
                {},
            ).get(
                "Code",
                "",
            )

            if code != "NoSuchBucketPolicy":
                raise

        return _result(
            action_type=ACTION_REMOVE_PUBLIC_POLICY,
            service="s3",
            resource=bucket,
            message="Public S3 bucket policy removed.",
            before_state={
                "policy_present": True,
                "public_statement_count":
                    len(public_statements),
            },
            after_state={
                "policy_present": False,
            },
            verification={
                "verified": True,
                "public_statements_removed": True,
            },
        )

    # --------------------------------------------------------
    # Preserve non-public policy statements.
    # --------------------------------------------------------

    updated_policy = deepcopy(policy)

    updated_policy["Statement"] = remaining_statements

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            updated_policy
        ),
    )

    # --------------------------------------------------------
    # Verify.
    # --------------------------------------------------------

    verified_response = s3.get_bucket_policy(
        Bucket=bucket
    )

    verified_policy = json.loads(
        verified_response["Policy"]
    )

    verified_statements = verified_policy.get(
        "Statement",
        [],
    )

    if isinstance(
        verified_statements,
        dict,
    ):
        verified_statements = [
            verified_statements
        ]

    remaining_public = [
        statement
        for statement in verified_statements
        if isinstance(statement, dict)
        and _statement_is_public(statement)
    ]

    if remaining_public:
        raise RemediationVerificationError(
            "Public S3 policy statements still exist after remediation."
        )

    return _result(
        action_type=ACTION_REMOVE_PUBLIC_POLICY,
        service="s3",
        resource=bucket,
        message="Public S3 policy statements removed.",
        before_state={
            "policy_present": True,
            "public_statement_count":
                len(public_statements),
        },
        after_state={
            "policy_present": True,
            "public_statement_count": 0,
        },
        verification={
            "verified": True
        },
    )


# ============================================================
# RDS - DISABLE PUBLIC ACCESS
# ============================================================

def _execute_rds_disable_public_access(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    rds = clients["rds"]

    db_identifier = _get_resource(
        remediation
    )

    if not db_identifier:
        raise RemediationValidationError(
            "RDS DB identifier is required."
        )

    response = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )

    instances = response.get(
        "DBInstances",
        []
    )

    if not instances:
        raise RemediationValidationError(
            "RDS DB instance was not found."
        )

    db = instances[0]

    before_state = {
        "publicly_accessible":
            db.get("PubliclyAccessible")
    }

    if before_state["publicly_accessible"] is False:
        return _result(
            action_type=ACTION_DISABLE_RDS_PUBLIC_ACCESS,
            service="rds",
            resource=db_identifier,
            message="RDS instance is already private.",
            before_state=before_state,
            after_state=before_state,
            verification={
                "verified": True
            },
        )

    rds.modify_db_instance(
        DBInstanceIdentifier=db_identifier,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )

    # --------------------------------------------------------
    # Verification immediately after request.
    #
    # AWS may temporarily report a modifying state, therefore
    # we verify that the requested state has been accepted.
    # --------------------------------------------------------

    verified_response = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )

    verified_db = verified_response[
        "DBInstances"
    ][0]

    actual_public = verified_db.get(
        "PubliclyAccessible"
    )

    if actual_public is not False:
        raise RemediationVerificationError(
            "RDS public-access remediation could not be verified."
        )

    return _result(
        action_type=ACTION_DISABLE_RDS_PUBLIC_ACCESS,
        service="rds",
        resource=db_identifier,
        message="RDS public accessibility disabled.",
        before_state=before_state,
        after_state={
            "publicly_accessible":
                actual_public
        },
        verification={
            "verified": True
        },
    )


# ============================================================
# RDS - ENABLE ENCRYPTION
# ============================================================

def _execute_rds_enable_encryption(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    rds = clients["rds"]

    db_identifier = _get_resource(
        remediation
    )

    if not db_identifier:
        raise RemediationValidationError(
            "RDS DB identifier is required."
        )

    response = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )

    instances = response.get(
        "DBInstances",
        []
    )

    if not instances:
        raise RemediationValidationError(
            "RDS DB instance was not found."
        )

    db = instances[0]

    before_state = {
        "storage_encrypted":
            db.get("StorageEncrypted"),
        "kms_key_id":
            db.get("KmsKeyId"),
    }

    if before_state["storage_encrypted"] is True:
        return _result(
            action_type=ACTION_ENABLE_RDS_ENCRYPTION,
            service="rds",
            resource=db_identifier,
            message="RDS storage encryption is already enabled.",
            before_state=before_state,
            after_state=before_state,
            verification={
                "verified": True
            },
        )

    # --------------------------------------------------------
    # AWS does not support enabling storage encryption on an
    # existing unencrypted RDS instance in-place.
    #
    # Fail closed instead of attempting destructive migration.
    # --------------------------------------------------------

    raise RemediationValidationError(
        "RDS encryption cannot be safely enabled in-place on "
        "an existing unencrypted DB instance. "
        "Use an approved snapshot/copy migration workflow."
    )


# ============================================================
# RDS - ENABLE BACKUPS
# ============================================================

def _execute_rds_enable_backups(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    rds = clients["rds"]

    db_identifier = _get_resource(
        remediation
    )

    if not db_identifier:
        raise RemediationValidationError(
            "RDS DB identifier is required."
        )

    response = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )

    instances = response.get(
        "DBInstances",
        []
    )

    if not instances:
        raise RemediationValidationError(
            "RDS DB instance was not found."
        )

    db = instances[0]

    before_state = {
        "backup_retention_period":
            db.get("BackupRetentionPeriod")
    }

    retention = before_state[
        "backup_retention_period"
    ]

    if retention and retention > 0:
        return _result(
            action_type=ACTION_ENABLE_RDS_BACKUPS,
            service="rds",
            resource=db_identifier,
            message="RDS automated backups are already enabled.",
            before_state=before_state,
            after_state=before_state,
            verification={
                "verified": True
            },
        )

    rds.modify_db_instance(
        DBInstanceIdentifier=db_identifier,
        BackupRetentionPeriod=7,
        ApplyImmediately=True,
    )

    verified_response = rds.describe_db_instances(
        DBInstanceIdentifier=db_identifier
    )

    verified_db = verified_response[
        "DBInstances"
    ][0]

    actual_retention = verified_db.get(
        "BackupRetentionPeriod"
    )

    if not actual_retention or actual_retention <= 0:
        raise RemediationVerificationError(
            "RDS backup configuration could not be verified."
        )

    return _result(
        action_type=ACTION_ENABLE_RDS_BACKUPS,
        service="rds",
        resource=db_identifier,
        message="RDS automated backups enabled.",
        before_state=before_state,
        after_state={
            "backup_retention_period":
                actual_retention
        },
        verification={
            "verified": True,
            "retention_days":
                actual_retention,
        },
    )


# ============================================================
# EC2 - SECURITY GROUP RESTRICTION
# ============================================================

def _execute_restrict_security_group(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    ec2 = clients["ec2"]

    security_group_id = _get_resource(
        remediation
    )

    if not security_group_id.startswith(
        "sg-"
    ):
        raise RemediationValidationError(
            "A valid security group ID is required."
        )

    response = ec2.describe_security_groups(
        GroupIds=[
            security_group_id
        ]
    )

    groups = response.get(
        "SecurityGroups",
        []
    )

    if not groups:
        raise RemediationValidationError(
            "Security group was not found."
        )

    group = groups[0]

    operation = _get_operation(
        remediation
    )

    # --------------------------------------------------------
    # IMPORTANT:
    # The executor will NOT guess a replacement source.
    #
    # Proposal must explicitly provide:
    #
    # {
    #     "protocol": "tcp",
    #     "from_port": 22,
    #     "to_port": 22,
    #     "cidr": "0.0.0.0/0"
    # }
    #
    # This prevents CloudGuardAI from accidentally changing
    # unrelated firewall rules.
    # --------------------------------------------------------

    protocol = operation.get(
        "protocol"
    )

    from_port = operation.get(
        "from_port"
    )

    to_port = operation.get(
        "to_port"
    )

    # --------------------------------------------------------
    # Normalize the trusted operation schema.
    #
    # CloudGuardAI proposals use the canonical fields:
    #     source
    #     source_type
    #
    # Older remediation records may use:
    #     cidr
    #     ipv6_cidr
    #
    # The executor accepts both formats, but NEVER accepts the
    # source from the HTTP client directly. It only reads the
    # persisted, server-generated remediation operation.
    # --------------------------------------------------------

    source = operation.get("source")
    source_type = _safe_string(
        operation.get("source_type")
    ).upper()

    cidr = operation.get("cidr")
    ipv6_cidr = operation.get("ipv6_cidr")

    if source is not None:
        source = _safe_string(source)

    if cidr is not None:
        cidr = _safe_string(cidr)

    if ipv6_cidr is not None:
        ipv6_cidr = _safe_string(ipv6_cidr)

    if protocol is None:
        raise RemediationValidationError(
            "Security group protocol is required."
        )

    protocol = _safe_string(protocol)

    if source:
        if source_type == "IPV6_CIDR":
            ipv6_cidr = source
            cidr = None
        elif source_type in {"", "IPV4_CIDR"}:
            cidr = source
            ipv6_cidr = None
        else:
            raise RemediationValidationError(
                f"Unsupported security-group source type: {source_type}"
            )

    if cidr is None and ipv6_cidr is None:
        raise RemediationValidationError(
            "Security group CIDR is required. "
            "Expected operation.source with source_type "
            "IPV4_CIDR/IPV6_CIDR, or legacy cidr/ipv6_cidr."
        )

    if cidr is not None and ipv6_cidr is not None:
        raise RemediationValidationError(
            "Security group remediation must target exactly one "
            "IPv4 or IPv6 CIDR."
        )

    before_rules = []

    for permission in group.get(
        "IpPermissions",
        []
    ):

        if permission.get(
            "IpProtocol"
        ) != protocol:
            continue

        if (
            from_port is not None
            and permission.get("FromPort")
            != from_port
        ):
            continue

        if (
            to_port is not None
            and permission.get("ToPort")
            != to_port
        ):
            continue

        before_rules.append(
            deepcopy(permission)
        )

    if not before_rules:
        return _result(
            action_type=ACTION_RESTRICT_SECURITY_GROUP,
            service="ec2",
            resource=security_group_id,
            message="Target security-group rule was not found.",
            before_state={
                "matching_rules": []
            },
            after_state={
                "matching_rules": []
            },
            verification={
                "verified": True,
                "already_remediated": True,
            },
        )

    # --------------------------------------------------------
    # Build ONE precise revoke permission.
    # --------------------------------------------------------

    permission = {
        "IpProtocol": protocol,
    }

    if from_port is not None:
        permission["FromPort"] = int(
            from_port
        )

    if to_port is not None:
        permission["ToPort"] = int(
            to_port
        )

    if cidr:
        permission["IpRanges"] = [
            {
                "CidrIp": cidr
            }
        ]

    if ipv6_cidr:
        permission["Ipv6Ranges"] = [
            {
                "CidrIpv6": ipv6_cidr
            }
        ]

    ec2.revoke_security_group_ingress(
        GroupId=security_group_id,
        IpPermissions=[
            permission
        ],
    )

    # --------------------------------------------------------
    # Verify target exposure is gone.
    # --------------------------------------------------------

    verified_response = ec2.describe_security_groups(
        GroupIds=[
            security_group_id
        ]
    )

    verified_group = verified_response[
        "SecurityGroups"
    ][0]

    remaining_matches = []

    for current_permission in verified_group.get(
        "IpPermissions",
        []
    ):

        if current_permission.get(
            "IpProtocol"
        ) != protocol:
            continue

        if (
            from_port is not None
            and current_permission.get("FromPort")
            != from_port
        ):
            continue

        if (
            to_port is not None
            and current_permission.get("ToPort")
            != to_port
        ):
            continue

        remaining_matches.append(
            current_permission
        )

    # We specifically check the normalized requested CIDR.
    # Only the exact trusted target is considered.
    target_still_exists = False

    for permission_item in remaining_matches:

        for ip_range in permission_item.get(
            "IpRanges",
            []
        ):

            if cidr and ip_range.get(
                "CidrIp"
            ) == cidr:
                target_still_exists = True

        for ipv6_range in permission_item.get(
            "Ipv6Ranges",
            []
        ):

            if ipv6_cidr and ipv6_range.get(
                "CidrIpv6"
            ) == ipv6_cidr:
                target_still_exists = True

    if target_still_exists:
        raise RemediationVerificationError(
            "Security-group rule still exists after remediation."
        )

    return _result(
        action_type=ACTION_RESTRICT_SECURITY_GROUP,
        service="ec2",
        resource=security_group_id,
        message="Specified security-group ingress exposure removed.",
        before_state={
            "matching_rules":
                before_rules
        },
        after_state={
            "target_rule_removed": True
        },
        verification={
            "verified": True
        },
    )


# ============================================================
# IAM - ENABLE MFA
# ============================================================

def _execute_enable_mfa(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    iam = clients["iam"]

    username = _get_resource(
        remediation
    )

    if not username:
        raise RemediationValidationError(
            "IAM username is required."
        )

    # --------------------------------------------------------
    # MFA cannot safely be "enabled" automatically because
    # virtual MFA setup requires a device secret/QR workflow.
    #
    # Never attempt to create or assign MFA without explicit
    # customer-controlled enrollment.
    # --------------------------------------------------------

    response = iam.list_mfa_devices(
        UserName=username
    )

    devices = response.get(
        "MFADevices",
        []
    )

    if devices:
        return _result(
            action_type=ACTION_ENABLE_MFA,
            service="iam",
            resource=username,
            message="IAM user already has an MFA device.",
            before_state={
                "mfa_enabled": True
            },
            after_state={
                "mfa_enabled": True
            },
            verification={
                "verified": True
            },
        )

    raise RemediationValidationError(
        "IAM MFA enrollment requires an interactive/customer-controlled "
        "device enrollment workflow and cannot be completed safely "
        "by the automatic executor."
    )


# ============================================================
# CLOUDTRAIL - ENABLE LOGGING
# ============================================================

def _execute_enable_cloudtrail(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:

    cloudtrail = clients["cloudtrail"]

    operation = _get_operation(
        remediation
    )

    trail_name = (
        _safe_string(
            operation.get("trail_name")
        )
        or _get_resource(remediation)
    )

    if not trail_name:
        raise RemediationValidationError(
            "CloudTrail trail name is required."
        )

    response = cloudtrail.get_trail_status(
        Name=trail_name
    )

    before_state = {
        "is_logging":
            response.get("IsLogging", False)
    }

    if before_state["is_logging"] is True:
        return _result(
            action_type=ACTION_ENABLE_CLOUDTRAIL,
            service="cloudtrail",
            resource=trail_name,
            message="CloudTrail trail is already logging.",
            before_state=before_state,
            after_state=before_state,
            verification={
                "verified": True
            },
        )

    cloudtrail.start_logging(
        Name=trail_name
    )

    verified = cloudtrail.get_trail_status(
        Name=trail_name
    )

    if verified.get(
        "IsLogging"
    ) is not True:
        raise RemediationVerificationError(
            "CloudTrail logging could not be verified."
        )

    return _result(
        action_type=ACTION_ENABLE_CLOUDTRAIL,
        service="cloudtrail",
        resource=trail_name,
        message="CloudTrail logging enabled.",
        before_state=before_state,
        after_state={
            "is_logging": True
        },
        verification={
            "verified": True
        },
    )


# ============================================================
# DISPATCHER
# ============================================================

def execute_action(
    clients: Dict[str, Any],
    remediation: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Execute exactly one allowlisted remediation action.
    """

    action_type = _normalize_action(
        remediation.get("action_type")
    )

    if action_type not in ALLOWED_ACTIONS:
        raise RemediationSecurityError(
            f"Blocked non-allowlisted remediation action: "
            f"{action_type}"
        )

    service = _get_service(
        remediation
    )

    # --------------------------------------------------------
    # S3
    # --------------------------------------------------------

    if action_type == ACTION_DISABLE_PUBLIC_ACCESS:

        if service not in {
            "",
            "s3",
        }:
            raise RemediationValidationError(
                "DISABLE_PUBLIC_ACCESS is only valid for S3."
            )

        return _execute_s3_disable_public_access(
            clients,
            remediation,
        )

    if action_type == ACTION_REMOVE_PUBLIC_POLICY:

        if service not in {
            "",
            "s3",
        }:
            raise RemediationValidationError(
                "REMOVE_PUBLIC_POLICY is only valid for S3."
            )

        return _execute_s3_remove_public_policy(
            clients,
            remediation,
        )

    if action_type == ACTION_ENABLE_S3_ENCRYPTION:

        if service not in {
            "",
            "s3",
        }:
            raise RemediationValidationError(
                "ENABLE_S3_ENCRYPTION is only valid for S3."
            )

        return _execute_s3_enable_encryption(
            clients,
            remediation,
        )

    # --------------------------------------------------------
    # EC2
    # --------------------------------------------------------

    if action_type == ACTION_RESTRICT_SECURITY_GROUP:

        if service not in {
            "",
            "ec2",
            "vpc",
            "security_group",
        }:
            raise RemediationValidationError(
                "RESTRICT_SECURITY_GROUP is only valid for "
                "EC2/VPC security groups."
            )

        return _execute_restrict_security_group(
            clients,
            remediation,
        )

    # --------------------------------------------------------
    # RDS
    # --------------------------------------------------------

    if action_type == ACTION_DISABLE_RDS_PUBLIC_ACCESS:

        if service not in {
            "",
            "rds",
        }:
            raise RemediationValidationError(
                "DISABLE_RDS_PUBLIC_ACCESS is only valid for RDS."
            )

        return _execute_rds_disable_public_access(
            clients,
            remediation,
        )

    if action_type == ACTION_ENABLE_RDS_ENCRYPTION:

        if service not in {
            "",
            "rds",
        }:
            raise RemediationValidationError(
                "ENABLE_RDS_ENCRYPTION is only valid for RDS."
            )

        return _execute_rds_enable_encryption(
            clients,
            remediation,
        )

    if action_type == ACTION_ENABLE_RDS_BACKUPS:

        if service not in {
            "",
            "rds",
        }:
            raise RemediationValidationError(
                "ENABLE_RDS_BACKUPS is only valid for RDS."
            )

        return _execute_rds_enable_backups(
            clients,
            remediation,
        )

    # --------------------------------------------------------
    # IAM
    # --------------------------------------------------------

    if action_type == ACTION_ENABLE_MFA:

        if service not in {
            "",
            "iam",
        }:
            raise RemediationValidationError(
                "ENABLE_MFA is only valid for IAM."
            )

        return _execute_enable_mfa(
            clients,
            remediation,
        )

    # --------------------------------------------------------
    # CloudTrail
    # --------------------------------------------------------

    if action_type == ACTION_ENABLE_CLOUDTRAIL:

        if service not in {
            "",
            "cloudtrail",
        }:
            raise RemediationValidationError(
                "ENABLE_CLOUDTRAIL is only valid for CloudTrail."
            )

        return _execute_enable_cloudtrail(
            clients,
            remediation,
        )

    raise RemediationValidationError(
        f"No executor implementation exists for action: "
        f"{action_type}"
    )


# ============================================================
# MAIN EXECUTION FUNCTION
# ============================================================

def execute_approved_remediation(
    remediation_id: str,
    user_id: str,
    organization_id: Optional[str] = None,
    role: Optional[str] = None,
    confirmed: bool = True,
) -> Dict[str, Any]:
    """
    Main entry point used by the remediation API/service.

    Security flow:

        remediation_id
              ↓
        user / organization ownership
              ↓
        account ownership
              ↓
        finding ownership
              ↓
        APPROVED status
              ↓
        temporary AWS role
              ↓
        account verification
              ↓
        allowlisted action
              ↓
        AWS execution
              ↓
        AWS verification
              ↓
        database result
    """

    if not remediation_id:
        raise RemediationValidationError(
            "Remediation ID is required."
        )

    if not user_id:
        raise RemediationSecurityError(
            "Authenticated user ID is required."
        )

    if role and str(role).strip().lower() not in {"owner", "admin"}:
        raise RemediationSecurityError(
            "Owner or admin role is required to execute remediation."
        )

    if confirmed is not True:
        raise RemediationSecurityError(
            "Explicit execution confirmation is required."
        )

    # --------------------------------------------------------
    # Load remediation using tenant-scoped model access.
    # --------------------------------------------------------

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
        organization_id=organization_id,
    )

    if not remediation:
        raise RemediationSecurityError(
            "Remediation proposal was not found."
        )

    if organization_id:
        rem_org = str(remediation.get("organization_id") or "").strip()
        if rem_org and rem_org != str(organization_id).strip():
            raise RemediationSecurityError(
                "Remediation does not belong to the active organization."
            )

    # --------------------------------------------------------
    # Prevent duplicate execution and enforce approval.
    # --------------------------------------------------------

    current_status = _normalize_status(
        remediation.get("status")
    )

    if current_status != STATUS_APPROVED:
        raise RemediationValidationError(
            f"Remediation is not approved. "
            f"Current status: {current_status or 'UNKNOWN'}."
        )

    if "approved_by" in remediation and not remediation.get("approved_by"):
        raise RemediationSecurityError(
            "Remediation must be approved by an authorized actor before execution."
        )

    # --------------------------------------------------------
    # Account ownership.
    # --------------------------------------------------------

    account_id = _safe_string(
        remediation.get("account_id")
    )

    if not account_id:
        raise RemediationSecurityError(
            "Remediation does not contain an AWS account reference."
        )

    account = get_account(
        account_id,
        user_id=user_id,
        organization_id=organization_id,
    )

    if not account:
        raise RemediationSecurityError(
            "AWS account does not belong to the authenticated organization/user."
        )

    if account.get("status") != "connected":
        raise RemediationSecurityError(
            "Connected AWS account is required for execution."
        )

    # --------------------------------------------------------
    # Finding ownership.
    # --------------------------------------------------------

    finding_id = _safe_string(
        remediation.get("finding_id")
    )

    if not finding_id:
        raise RemediationValidationError(
            "Remediation is not associated with a finding."
        )

    finding = get_finding_for_account(
        finding_id,
        user_id=user_id,
        account_id=account_id,
        organization_id=organization_id,
    )

    if not finding:
        raise RemediationSecurityError(
            "Associated finding does not belong to this AWS account."
        )

    # --------------------------------------------------------
    # Validate before AWS access.
    # --------------------------------------------------------

    validate_remediation(
        remediation,
        account,
        finding,
    )

    action_type = _normalize_action(
        remediation.get("action_type")
    )

    region = _get_region(
        remediation,
        account,
    )

    expected_aws_account_id = _get_aws_account_id(
        remediation,
        account,
    )

    role_arn = _safe_string(
        account.get("role_arn")
    )

    if not role_arn:
        raise RemediationSecurityError(
            "AWS account does not contain an IAM role ARN."
        )

    # --------------------------------------------------------
    # Enforce organization remediation settings governance.
    # --------------------------------------------------------

    service_name = _get_service(remediation)
    if service_name in ("security_group", "vpc"):
        service_key = "vpc"
    elif service_name in ("s3", "ec2", "rds", "iam", "cloudtrail"):
        service_key = service_name
    else:
        _action_to_service = {
            ACTION_DISABLE_PUBLIC_ACCESS: "s3",
            ACTION_ENABLE_ENCRYPTION: "s3",
            ACTION_ENABLE_S3_ENCRYPTION: "s3",
            ACTION_REMOVE_PUBLIC_POLICY: "s3",
            ACTION_RESTRICT_SECURITY_GROUP: "vpc",
            ACTION_ENABLE_MFA: "iam",
            ACTION_REVIEW_IAM_POLICY: "iam",
            ACTION_ENABLE_CLOUDTRAIL: "cloudtrail",
            ACTION_ENABLE_RDS_ENCRYPTION: "rds",
            ACTION_DISABLE_RDS_PUBLIC_ACCESS: "rds",
            ACTION_ENABLE_RDS_BACKUPS: "rds",
        }
        service_key = _action_to_service.get(action_type, service_name)

    organization_id = _safe_string(
        organization_id
        or account.get("organization_id")
        or remediation.get("organization_id")
    )

    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, account_id, service_key):
        raise RemediationSecurityError(
            f"Remediation setting is disabled for {service_key} for this account."
        )

    # --------------------------------------------------------
    # Mark execution as EXECUTING before touching AWS.
    # --------------------------------------------------------

    execution_status_updated = transition_to_executing(
        remediation_id=remediation_id,
        user_id=user_id,
        organization_id=organization_id,
    )

    if not execution_status_updated:
        raise RemediationExecutionError(
            "Unable to transition remediation to EXECUTING."
        )

    execution_started = _now()

    try:

        # ----------------------------------------------------
        # Assume temporary role.
        # ----------------------------------------------------

        session = assume_aws_role(
            role_arn=role_arn,
            region=region,
            session_name=(
                f"CloudGuardAI-Remediation-{remediation_id}"
            ),
        )

        # ----------------------------------------------------
        # Verify account identity.
        # ----------------------------------------------------

        identity = verify_aws_account(
            session,
            expected_aws_account_id,
        )

        # ----------------------------------------------------
        # Create service clients.
        # ----------------------------------------------------

        clients = get_aws_clients(
            session
        )

        # ----------------------------------------------------
        # Execute exactly one allowlisted action.
        # ----------------------------------------------------

        result = execute_action(
            clients,
            remediation,
        )

        execution_completed = _now()

        # ----------------------------------------------------
        # Attach execution metadata.
        # ----------------------------------------------------

        result["aws_identity"] = {
            "account": identity.get(
                "Account"
            ),
            "arn": identity.get(
                "Arn"
            ),
            "user_id": identity.get(
                "UserId"
            ),
        }

        result["execution_started_at"] = (
            execution_started
        )

        result["execution_completed_at"] = (
            execution_completed
        )

        result["duration_seconds"] = (
            execution_completed
            - execution_started
        ).total_seconds()

        if result["duration_seconds"] > MAX_EXECUTION_DURATION_SECONDS:
            result["execution_duration_warning"] = (
                "Execution exceeded the configured duration threshold."
            )

        # ----------------------------------------------------
        # Persist execution result.
        # ----------------------------------------------------

        update_execution_result(
            remediation_id,
            user_id,
            result,
            organization_id=organization_id,
        )

        completed_status_updated = transition_to_completed(
            remediation_id=remediation_id,
            user_id=user_id,
            organization_id=organization_id,
        )

        if not completed_status_updated:
            raise RemediationExecutionError(
                "AWS remediation succeeded, but the remediation "
                "record could not be transitioned to COMPLETED."
            )


        logger.info(
            "AWS remediation completed: remediation_id=%s "
            "action=%s account=%s",
            remediation_id,
            action_type,
            expected_aws_account_id,
        )

        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "remediation_id": remediation_id,
            "finding_id": finding_id,
            "action_type": action_type,
            "result": result,
        }

    except Exception as exc:

        execution_failed = _now()

        error_message = str(exc)

        # Never store credentials, tokens, or sensitive AWS
        # response bodies in the error message.
        if len(error_message) > 1000:
            error_message = (
                error_message[:1000]
                + "..."
            )

        failure_result = {
            "success": False,
            "action_type": action_type,
            "error": error_message,
            "executor": EXECUTOR_NAME,
            "execution_started_at":
                execution_started,
            "execution_failed_at":
                execution_failed,
            "duration_seconds": (
                execution_failed
                - execution_started
            ).total_seconds(),
        }

        try:

            update_execution_result(
                remediation_id,
                user_id,
                failure_result,
                organization_id=organization_id,
            )

            transition_to_failed(
                remediation_id=remediation_id,
                user_id=user_id,
                execution_error=error_message,
                organization_id=organization_id,
            )

        except Exception as persistence_exc:

            logger.error(
                "Failed to persist remediation failure: %s",
                str(persistence_exc),
            )

        logger.exception(
            "AWS remediation failed: remediation_id=%s "
            "action=%s",
            remediation_id,
            action_type,
        )

        return {
            "success": False,
            "status": STATUS_FAILED,
            "remediation_id": remediation_id,
            "finding_id": finding_id,
            "action_type": action_type,
            "error": error_message,
        }


# ============================================================
# SAFE EXECUTION CHECK
# ============================================================

def is_remediation_action_allowed(
    action_type: str,
) -> bool:
    """
    Public helper for APIs/services that want to check whether
    an action is executable before calling the executor.
    """

    normalized = _normalize_action(
        action_type
    )

    return (
        normalized in ALLOWED_ACTIONS
        and normalized not in NON_EXECUTABLE_ACTIONS
    )


# ============================================================
# EXECUTOR HEALTH INFORMATION
# ============================================================

def get_executor_capabilities() -> Dict[str, Any]:
    """
    Return executor capabilities for UI/admin diagnostics.
    """

    return {
        "executor": EXECUTOR_NAME,
        "version": EXECUTOR_VERSION,
        "allowlisted_actions": sorted(
            ALLOWED_ACTIONS
        ),
        "automatically_executable": sorted(
            ALLOWED_ACTIONS
            - NON_EXECUTABLE_ACTIONS
        ),
        "manual_review_actions": sorted(
            NON_EXECUTABLE_ACTIONS
        ),
        "temporary_credentials": True,
        "account_verification": True,
        "post_execution_verification": True,
    }