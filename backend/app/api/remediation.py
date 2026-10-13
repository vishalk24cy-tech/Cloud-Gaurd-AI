# ============================================================
# CloudGuardAI - Remediation Management API
# Production / Commercial SaaS
# Secure Proposal Workflow
# ============================================================

from typing import Optional
import re

from fastapi.responses import JSONResponse

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Request,
    Query,
    status,
)

from app.database.connection import db

from pydantic import BaseModel, Field

from app.middleware.auth_middleware import verify_token

from app.models.finding import (
    get_finding_for_account,
    is_finding_actionable,
)

from app.models.aws_account import (
    get_account,
)

from app.models.remediation import (
    ACTION_EC2_STOP_INSTANCE,
    ACTION_CLOUDTRAIL_ENABLE_LOGGING,
    ACTION_IAM_DISABLE_ACCESS_KEY,
    ACTION_RDS_DISABLE_PUBLIC_ACCESS,
    ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
    ACTION_VPC_REMOVE_INSECURE_INGRESS,
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_PENDING_APPROVAL,
    STATUS_REJECTED,
    cancel_remediation,
    create_remediation,
    delete_remediation,
    get_remediation,
    get_active_remediation,
    get_remediation_statistics,
    get_user_remediations,
    reconcile_successful_execution,
    update_remediation_status,
)

from app.models.audit_log import (
    EVENT_REMEDIATION_APPROVED,
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_REMEDIATION_CREATED,
    EVENT_REMEDIATION_FAILED,
    EVENT_REMEDIATION_VERIFICATION_REQUESTED,
)
from app.services.audit_log_service import record_remediation_event
from app.services.scan_job_service import create_scan_job

from app.services.aws_remediation_executor import (
    execute_approved_remediation,
    is_remediation_action_allowed,
)
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.ec2_execution import (
    EC2StopExecutionError,
    INSTANCE_ID_PATTERN,
    execute_ec2_stop,
)
from app.services.remediation.s3_execution import (
    S3BlockPublicAccessError,
    execute_s3_block_public_access,
    is_valid_bucket_name,
)
from app.services.remediation.iam_execution import (
    IAMAccessKeyExecutionError,
    execute_iam_disable_access_key,
    is_valid_iam_access_key_id,
    is_valid_iam_username,
    mask_iam_access_key_id,
)
from app.services.remediation.vpc_execution import (
    VPCIngressExecutionError,
    execute_vpc_remove_ssh_ingress,
)
from app.services.remediation.rds_execution import (
    RDSDisablePublicAccessError,
    execute_rds_disable_public_access,
    is_valid_rds_instance_identifier,
)
from app.services.remediation.cloudtrail_execution import (
    CloudTrailEnableLoggingError,
    execute_cloudtrail_enable_logging,
    is_valid_trail_name,
)


# ============================================================
# Router
# ============================================================

router = APIRouter(
    prefix="/remediation",
    tags=["Remediation"],
)


# ============================================================
# Constants
# ============================================================

ALLOWED_SEVERITIES = {
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW",
}


# ------------------------------------------------------------
# Supported remediation actions
#
# IMPORTANT:
# These are proposal types only.
# The actual AWS executor will be implemented separately.
# ------------------------------------------------------------

ALLOWED_ACTION_TYPES = {
    ACTION_EC2_STOP_INSTANCE,
    "DISABLE_PUBLIC_ACCESS",
    "RESTRICT_SECURITY_GROUP",
    "ENABLE_MFA",
    "ENABLE_CLOUDTRAIL",
    "ENABLE_RDS_ENCRYPTION",
    "DISABLE_RDS_PUBLIC_ACCESS",
    "ENABLE_RDS_BACKUPS",
    "ENABLE_S3_ENCRYPTION",
    "REVIEW_IAM_POLICY",
    "REMOVE_PUBLIC_POLICY",
}


# ============================================================
# Request Models
# ============================================================

class CreateRemediationRequest(BaseModel):
    """
    Secure remediation proposal request.

    The client supplies only identifiers and the requested
    supported remediation action.

    Security-sensitive finding details are NOT trusted from
    the client. They are loaded from MongoDB server-side.
    """

    finding_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )

    account_id: str = Field(
        ...,
        min_length=1,
        max_length=200,
    )

    action_type: str = Field(
        ...,
        min_length=1,
        max_length=100,
    )


class RejectRemediationRequest(BaseModel):
    reason: str = Field(
        ...,
        min_length=1,
        max_length=2000,
    )


class ApproveRemediationRequest(BaseModel):
    comment: Optional[str] = Field(
        default=None,
        max_length=2000,
    )


class CreateRemediationActionRequest(BaseModel):
    account_id: str = Field(..., min_length=1, max_length=200)
    resource_id: Optional[str] = Field(default=None, min_length=1, max_length=500)
    username: Optional[str] = Field(default=None, min_length=1, max_length=64)
    finding_id: Optional[str] = Field(default=None, min_length=1, max_length=200)


class ExecuteRemediationRequest(BaseModel):
    confirmed: bool = False


# ============================================================
# Helpers
# ============================================================

def _get_user_id(current_user):
    """
    Safely extract authenticated user ID.
    """

    if isinstance(current_user, dict):

        user_id = (
            current_user.get("_id")
            or current_user.get("id")
            or current_user.get("user_id")
        )

    else:

        user_id = (
            getattr(current_user, "_id", None)
            or getattr(current_user, "id", None)
            or getattr(current_user, "user_id", None)
        )

    if not user_id:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user not found",
        )

    return str(user_id)


def _clean_text(value):
    """
    Normalize text values.
    """

    if value is None:
        return ""

    return str(value).strip()


def _normalize_action_type(value):
    """
    Normalize and validate remediation action.
    """

    action_type = _clean_text(value).upper()

    if action_type not in ALLOWED_ACTION_TYPES:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Unsupported remediation action. "
                "Allowed actions: "
                + ", ".join(
                    sorted(ALLOWED_ACTION_TYPES)
                )
            ),
        )

    return action_type


def _get_organization_context_from_user(current_user) -> tuple[str, str]:
    """Resolve active tenant membership and role from the JWT-backed identity."""

    if isinstance(current_user, dict):
        user_id = (
            current_user.get("_id")
            or current_user.get("id")
            or current_user.get("user_id")
        )
        organization_id = current_user.get("organization")
    else:
        user_id = (
            getattr(current_user, "_id", None)
            or getattr(current_user, "id", None)
            or getattr(current_user, "user_id", None)
        )
        organization_id = getattr(current_user, "organization", None)

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user not found",
        )

    if not organization_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is not associated with an organization",
        )

    organization_id = str(organization_id).strip()

    membership = db.organization_members.find_one(
        {
            "organization_id": organization_id,
            "user_id": str(user_id),
            "status": "active",
        }
    )

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not have access to this organization",
        )

    role = _clean_text(membership.get("role") or "viewer").lower()
    return organization_id, role


def _role_can_access_action(role: str, allowed_roles) -> bool:
    normalized_role = _clean_text(role).lower()
    return normalized_role in {
        _clean_text(allowed_role).lower()
        for allowed_role in (allowed_roles or ())
    }


def _record_remediation_audit_event(**kwargs):
    try:
        return record_remediation_event(**kwargs)
    except Exception:
        print("[ERROR] Remediation audit event could not be recorded")
        return None


def _safe_remediation_response(remediation):
    """Redact IAM access-key identifiers from every remediation response."""

    if not isinstance(remediation, dict):
        return remediation

    action_id = str(remediation.get("action_type") or "").upper()
    if action_id != ACTION_IAM_DISABLE_ACCESS_KEY:
        return remediation

    credential_fields = {
        "accesskeyid",
        "awsaccesskeyid",
        "secretaccesskey",
        "awssecretaccesskey",
        "sessiontoken",
        "awssessiontoken",
        "credentials",
    }

    def redact(value):
        if isinstance(value, str) and is_valid_iam_access_key_id(value):
            return mask_iam_access_key_id(value)
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                normalized_key = str(key).lower().replace("_", "").replace("-", "")
                if normalized_key in credential_fields:
                    continue
                result[key] = redact(item)
            return result
        return value

    return redact(remediation)


def _vpc_ssh_rule_from_finding(finding):
    if not isinstance(finding, dict):
        return None
    service = _clean_text(finding.get("service")).upper()
    resource_type = _clean_text(finding.get("resource_type")).upper().replace(" ", "_")
    issue = _clean_text(finding.get("issue"))
    group_id = _clean_text(finding.get("security_group_id") or finding.get("resource"))
    if service != "VPC" or resource_type != "SECURITY_GROUP" or not re.fullmatch(r"sg-[0-9a-fA-F]{8,17}", group_id):
        return None
    if issue == "SSH port 22 is open to the Internet.":
        source, source_type = "0.0.0.0/0", "IPV4_CIDR"
    elif issue == "SSH port 22 is open to the Internet over IPv6.":
        source, source_type = "::/0", "IPV6_CIDR"
    else:
        return None
    return {
        "security_group_id": group_id,
        "protocol": "tcp",
        "from_port": 22,
        "to_port": 22,
        "source": source,
        "source_type": source_type,
        "rule_scope": "INGRESS",
    }


def _rds_public_access_resource_from_finding(finding):
    if not isinstance(finding, dict):
        return None
    service = _clean_text(finding.get("service")).upper()
    resource_type = _clean_text(finding.get("resource_type")).upper().replace(" ", "_")
    identifier = _clean_text(finding.get("resource"))
    if (
        service != "RDS"
        or resource_type != "RDS_DATABASE"
        or _clean_text(finding.get("issue")) != "RDS database is publicly accessible."
        or not is_valid_rds_instance_identifier(identifier)
    ):
        return None
    return identifier


def _cloudtrail_disabled_trail_from_finding(finding):
    if not isinstance(finding, dict):
        return None
    service = _clean_text(finding.get("service")).upper()
    resource_type = _clean_text(finding.get("resource_type")).upper().replace(" ", "_")
    trail_name = _clean_text(finding.get("resource"))
    if (
        service != "CLOUDTRAIL"
        or resource_type != "CLOUDTRAIL"
        or not is_valid_trail_name(trail_name)
        or _clean_text(finding.get("issue")) != f"CloudTrail logging is disabled ({trail_name})."
    ):
        return None
    return trail_name


def _validate_severity(severity):
    """
    Validate canonical finding severity.
    """

    severity = _clean_text(
        severity
    ).upper()

    if severity not in ALLOWED_SEVERITIES:

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Stored finding contains invalid severity",
        )

    return severity


# ============================================================
# Action Compatibility
# ============================================================

def _is_action_compatible(
    action_type,
    finding,
):
    """
    Verify that the requested remediation action makes sense
    for the actual finding.

    This prevents a client from taking a legitimate action type
    and attaching it to an unrelated security finding.

    This is intentionally conservative.

    If CloudGuardAI does not yet have enough evidence to safely
    determine compatibility, the proposal is rejected instead
    of guessing.
    """

    action_type = str(
        action_type
    ).strip().upper()

    service = str(
        finding.get(
            "service",
            "",
        )
    ).strip().upper()

    resource_type = str(
        finding.get(
            "resource_type",
            "",
        )
    ).strip().upper()

    issue = str(
        finding.get(
            "issue",
            "",
        )
    ).strip().lower()

    description = str(
        finding.get(
            "description",
            "",
        )
    ).strip().lower()

    combined = (
        issue
        + " "
        + description
    )

    # --------------------------------------------------------
    # S3 public policy
    # --------------------------------------------------------

    if action_type == "REMOVE_PUBLIC_POLICY":

        return (
            "S3" in service
            and (
                "public" in combined
                or "bucket policy" in combined
                or "policy allows" in combined
            )
        )

    # --------------------------------------------------------
    # S3 public access
    # --------------------------------------------------------

    if action_type == "DISABLE_PUBLIC_ACCESS":

        return (
            "S3" in service
            and (
                "public" in combined
                or "access" in combined
            )
        )

    # --------------------------------------------------------
    # S3 encryption
    # --------------------------------------------------------

    if action_type == "ENABLE_S3_ENCRYPTION":

        return (
            "S3" in service
            and (
                "encrypt" in combined
                or "encryption" in combined
            )
        )

    # --------------------------------------------------------
    # RDS encryption
    # --------------------------------------------------------

    if action_type == "ENABLE_RDS_ENCRYPTION":

        return (
            "RDS" in service
            and (
                "encrypt" in combined
                or "encryption" in combined
            )
        )

    # --------------------------------------------------------
    # RDS public accessibility
    # --------------------------------------------------------

    if action_type == "DISABLE_RDS_PUBLIC_ACCESS":

        return (
            "RDS" in service
            and (
                "public" in combined
                or "accessible" in combined
            )
        )

    # --------------------------------------------------------
    # RDS backups
    # --------------------------------------------------------

    if action_type == "ENABLE_RDS_BACKUPS":

        return (
            "RDS" in service
            and (
                "backup" in combined
                or "retention" in combined
            )
        )

    # --------------------------------------------------------
    # Security group restriction
    # --------------------------------------------------------

    if action_type == "RESTRICT_SECURITY_GROUP":

        return (
            (
                "EC2" in service
                or "VPC" in service
            )
            and (
                "security group" in combined
                or "ssh" in combined
                or "rdp" in combined
                or "inbound" in combined
                or "internet" in combined
                or "0.0.0.0/0" in combined
            )
        )

    # --------------------------------------------------------
    # MFA
    # --------------------------------------------------------

    if action_type == "ENABLE_MFA":

        return (
            "IAM" in service
            and (
                "mfa" in combined
                or "multi-factor" in combined
            )
        )

    # --------------------------------------------------------
    # CloudTrail
    # --------------------------------------------------------

    if action_type == "ENABLE_CLOUDTRAIL":

        return (
            "CLOUDTRAIL" in service
            or "cloudtrail" in combined
        )

    # --------------------------------------------------------
    # IAM policy review
    # --------------------------------------------------------

    if action_type == "REVIEW_IAM_POLICY":

        return (
            "IAM" in service
            and (
                "policy" in combined
                or "permission" in combined
                or "privilege" in combined
                or "administrator" in combined
            )
        )

    return False


# ============================================================
# Server Generated Remediation Metadata
# ============================================================

def _build_remediation_metadata(
    action_type,
    finding,
    aws_account,
):
    """
    Generate remediation proposal content from trusted
    server-side data.

    The client does not control these values.
    """

    service = _clean_text(
        finding.get(
            "service",
            "AWS",
        )
    )

    resource = _clean_text(
        finding.get(
            "resource",
            "Unknown",
        )
    )

    severity = _validate_severity(
        finding.get(
            "severity",
            "LOW",
        )
    )

    issue = _clean_text(
        finding.get(
            "issue",
            "",
        )
    )

    description = _clean_text(
        finding.get(
            "description",
            issue,
        )
    )

    recommendation = _clean_text(
        finding.get(
            "recommendation",
            finding.get(
                "remediation",
                "",
            ),
        )
    )

    # --------------------------------------------------------
    # Action-specific titles
    # --------------------------------------------------------

    titles = {
        "REMOVE_PUBLIC_POLICY":
            "Remove public resource policy",

        "DISABLE_PUBLIC_ACCESS":
            "Disable public access",

        "ENABLE_ENCRYPTION":
            "Enable encryption",

        "ENABLE_S3_ENCRYPTION":
            "Enable S3 encryption",

        "RESTRICT_SECURITY_GROUP":
            "Restrict security group access",

        "ENABLE_MFA":
            "Enable IAM MFA",

        "ENABLE_CLOUDTRAIL":
            "Enable CloudTrail logging",

        "ENABLE_RDS_ENCRYPTION":
            "Enable RDS encryption",

        "DISABLE_RDS_PUBLIC_ACCESS":
            "Disable RDS public accessibility",

        "ENABLE_RDS_BACKUPS":
            "Enable RDS automated backups",

        "REVIEW_IAM_POLICY":
            "Review IAM permissions",
    }

    title = titles.get(
        action_type,
        "Cloud security remediation",
    )

    # --------------------------------------------------------
    # Reason
    # --------------------------------------------------------

    reason = (
        f"CloudGuardAI detected a {severity} severity "
        f"security issue on {service} resource "
        f"{resource}."
    )

    # --------------------------------------------------------
    # Proposal description
    # --------------------------------------------------------

    proposal_description = (
        description
        or issue
        or (
            "CloudGuardAI recommends remediation "
            "for this security finding."
        )
    )

    # --------------------------------------------------------
    # Server-side operation placeholder
    #
    # IMPORTANT:
    # This is NOT an AWS API instruction.
    #
    # The future executor will translate action_type into
    # a hard-coded, reviewed AWS operation.
    # --------------------------------------------------------

    operation = {
        "action_type": action_type,
        "executor_version": "v1",
        "execution_mode": "SERVER_SIDE_ONLY",
    }

    # --------------------------------------------------------
    # Security-group remediation contract
    # --------------------------------------------------------
    # Exact network-rule values are copied only from trusted
    # scanner evidence. The client cannot supply or override them.
    # Fail closed when required evidence is missing or invalid.
    # --------------------------------------------------------

    if action_type == "RESTRICT_SECURITY_GROUP":
        evidence = finding.get("evidence") or {}

        if not isinstance(evidence, dict):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation requires valid finding evidence",
            )

        security_group_id = _clean_text(
            evidence.get("security_group_id")
            or finding.get("security_group_id")
            or resource
        )
        protocol = _clean_text(evidence.get("protocol")).lower()
        source = _clean_text(evidence.get("source"))
        source_type = _clean_text(evidence.get("source_type")).upper()
        from_port = evidence.get("from_port")
        to_port = evidence.get("to_port")

        rule_match = evidence.get("rule_match")
        if isinstance(rule_match, dict):
            protocol = _clean_text(rule_match.get("protocol") or protocol).lower()
            source = _clean_text(rule_match.get("source") or source)
            source_type = _clean_text(rule_match.get("source_type") or source_type).upper()
            if rule_match.get("from_port") is not None:
                from_port = rule_match.get("from_port")
            if rule_match.get("to_port") is not None:
                to_port = rule_match.get("to_port")

        if not security_group_id or not protocol or not source:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation cannot be created because required network evidence is missing",
            )

        if from_port is None or to_port is None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation cannot be created because the observed port range is missing",
            )

        try:
            from_port = int(from_port)
            to_port = int(to_port)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation cannot be created because the observed port range is invalid",
            )

        if not (0 <= from_port <= 65535 and 0 <= to_port <= 65535 and from_port <= to_port):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation cannot be created because the observed port range is invalid",
            )

        if source_type not in {"IPV4_CIDR", "IPV6_CIDR"}:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Security-group remediation cannot be created because the observed source type is unsupported",
            )

        if source_type == "IPV4_CIDR" and ":" in source:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="IPv4 source evidence is invalid")
        if source_type == "IPV6_CIDR" and ":" not in source:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="IPv6 source evidence is invalid")

        operation.update({
            "security_group_id": security_group_id,
            "protocol": protocol,
            "from_port": from_port,
            "to_port": to_port,
            "source": source,
            "source_type": source_type,
            "rule_scope": "INGRESS",
        })

    # --------------------------------------------------------
    # Before state
    #
    # Captured from the finding evidence, not client input.
    # --------------------------------------------------------

    before_state = {
        "finding_id": finding.get(
            "finding_id"
        ),
        "service": service,
        "resource": resource,
        "severity": severity,
        "detection_status": finding.get(
            "detection_status"
        ),
        "evidence": finding.get(
            "evidence",
            {},
        ),
    }

    if action_type == "RESTRICT_SECURITY_GROUP":
        before_state["operation_snapshot"] = {
            "security_group_id": operation["security_group_id"],
            "protocol": operation["protocol"],
            "from_port": operation["from_port"],
            "to_port": operation["to_port"],
            "source": operation["source"],
            "source_type": operation["source_type"],
            "rule_scope": operation["rule_scope"],
        }

    return {
        "service": service,
        "resource": resource,
        "severity": severity,
        "title": title,
        "description": proposal_description,
        "reason": reason,
        "recommendation": recommendation,
        "operation": operation,
        "before_state": before_state,
    }


# ============================================================
# CREATE REMEDIATION
# ============================================================

@router.post(
    "/",
    status_code=status.HTTP_201_CREATED,
)
def create_remediation_proposal(
    payload: CreateRemediationRequest,
    current_user=Depends(verify_token),
):
    """
    Create a secure remediation proposal.

    IMPORTANT:

    This endpoint ONLY creates a proposal.

    It does NOT execute AWS changes.

    Security guarantees:

    1. Authenticated user required.
    2. Finding ownership verified.
    3. AWS account ownership verified.
    4. Finding/account relationship verified.
    5. Finding must be actionable.
    6. Action type must be allowlisted.
    7. Action must match the finding.
    8. Finding details come from the server.
    9. Arbitrary AWS operation payloads are rejected.
    """

    user_id = _get_user_id(
        current_user
    )

    finding_id = _clean_text(
        payload.finding_id
    )

    account_id = _clean_text(
        payload.account_id
    )

    if not finding_id:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Finding ID is required",
        )

    if not account_id:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account ID is required",
        )

    action_type = _normalize_action_type(
        payload.action_type
    )

    # ========================================================
    # STEP 1
    # Verify AWS account ownership
    # ========================================================

    aws_account = get_account(
        account_id,
        user_id=user_id,
    )

    if not aws_account:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="AWS account not found",
        )

    # ========================================================
    # STEP 2
    # Verify finding belongs to the user AND account
    # ========================================================

    finding = get_finding_for_account(
        finding_id=finding_id,
        user_id=user_id,
        account_id=account_id,
    )

    if not finding:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                "Finding not found for the specified "
                "AWS account"
            ),
        )

    # ========================================================
    # STEP 3
    # Finding must be actionable
    # ========================================================

    if not is_finding_actionable(
        finding
    ):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "This finding is not actionable and "
                "cannot receive a remediation proposal"
            ),
        )

    # ========================================================
    # STEP 4
    # Prevent remediation of already resolved findings
    # ========================================================

    finding_status = str(
        finding.get(
            "status",
            "",
        )
    ).upper()

    if finding_status in {
        "RESOLVED",
        "IGNORED",
        "NOT_APPLICABLE",
    }:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Finding cannot be remediated while "
                f"workflow status is {finding_status}"
            ),
        )

    # ========================================================
    # STEP 5
    # Verify action is compatible with finding
    # ========================================================

    if not _is_action_compatible(
        action_type,
        finding,
    ):

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "The requested remediation action is not "
                "compatible with this finding"
            ),
        )

    # ========================================================
    # STEP 6
    # Verify AWS identity
    #
    # The canonical AWS account ID comes from the connected
    # account record, NOT the client request.
    # ========================================================

    canonical_aws_account_id = _clean_text(
        aws_account.get(
            "aws_account_id"
        )
    )

    finding_aws_account_id = _clean_text(
        finding.get(
            "aws_account_id"
        )
    )

    if (
        finding_aws_account_id
        and canonical_aws_account_id
        and finding_aws_account_id
        != canonical_aws_account_id
    ):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Finding AWS account identity does not "
                "match the connected AWS account"
            ),
        )

    # ========================================================
    # STEP 7
    # Build proposal entirely from trusted server data
    # ========================================================

    metadata = _build_remediation_metadata(
        action_type=action_type,
        finding=finding,
        aws_account=aws_account,
    )

    data = {
        # ----------------------------------------------------
        # Tenant
        # ----------------------------------------------------

        "user_id": user_id,

        # ----------------------------------------------------
        # Finding
        # ----------------------------------------------------

        "finding_id": finding.get(
            "finding_id"
        ),

        # ----------------------------------------------------
        # CloudGuardAI account
        # ----------------------------------------------------

        "account_id": str(
            aws_account.get(
                "_id"
            )
        ),

        # ----------------------------------------------------
        # Real AWS account
        # ----------------------------------------------------

        "aws_account_id": canonical_aws_account_id,

        # ----------------------------------------------------
        # Trusted finding metadata
        # ----------------------------------------------------

        "service": metadata[
            "service"
        ],

        "resource": metadata[
            "resource"
        ],

        "severity": metadata[
            "severity"
        ],

        # ----------------------------------------------------
        # Approved action
        # ----------------------------------------------------

        "action_type": action_type,

        # ----------------------------------------------------
        # Server-generated proposal
        # ----------------------------------------------------

        "title": metadata[
            "title"
        ],

        "description": metadata[
            "description"
        ],

        "reason": metadata[
            "reason"
        ],

        "recommendation": metadata[
            "recommendation"
        ],

        # ----------------------------------------------------
        # No client-controlled AWS instructions
        # ----------------------------------------------------

        "operation": metadata[
            "operation"
        ],

        "before_state": metadata[
            "before_state"
        ],
    }

    # ========================================================
    # STEP 8
    # Active-proposal deduplication
    # ========================================================
    # Only one active proposal is allowed for the same:
    #   tenant + CloudGuardAI account + finding + action
    #
    # Historical COMPLETED / FAILED / REJECTED / CANCELLED
    # records remain available for audit and future remediation
    # cycles.
    # ========================================================

    try:

        existing_remediation = get_active_remediation(
            user_id=user_id,
            finding_id=finding.get("finding_id"),
            account_id=str(aws_account.get("_id")),
            action_type=action_type,
        )

    except Exception as exc:

        print(
            "[ERROR] Failed to check for an existing active "
            f"remediation proposal: {exc}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to validate existing remediation proposals",
        )

    if existing_remediation:

        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "status": "success",
                "message": "Existing active remediation proposal returned",
                "created": False,
                "deduplicated": True,
                "remediation": existing_remediation,
            },
        )

    # ========================================================
    # STEP 9
    # Persist proposal
    # ========================================================

    try:

        remediation = create_remediation(
            data
        )

    except Exception as exc:

        print(
            "[ERROR] Failed to create remediation: "
            f"{exc}"
        )

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=(
                "Unable to create remediation proposal"
            ),
        )

    return {
        "status": "success",
        "message": (
            "Secure remediation proposal created"
        ),
        "created": True,
        "deduplicated": False,
        "remediation": remediation,
    }


# ============================================================
# LIST REMEDIATIONS
# ============================================================

@router.get("/")
def list_remediations(
    status_filter: Optional[str] = Query(
        default=None,
        alias="status",
    ),

    finding_id: Optional[str] = Query(
        default=None,
    ),

    account_id: Optional[str] = Query(
        default=None,
    ),

    severity: Optional[str] = Query(
        default=None,
    ),

    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),

    current_user=Depends(verify_token),
):
    """
    Return remediation records belonging only to
    the authenticated tenant.
    """

    user_id = _get_user_id(
        current_user
    )

    clean_status = (
        _clean_text(
            status_filter
        ).upper()
        if status_filter
        else None
    )

    clean_finding_id = (
        _clean_text(
            finding_id
        )
        if finding_id
        else None
    )

    clean_account_id = (
        _clean_text(
            account_id
        )
        if account_id
        else None
    )

    clean_severity = (
        _clean_text(
            severity
        ).upper()
        if severity
        else None
    )

    try:

        remediations = get_user_remediations(
            user_id=user_id,
            status=clean_status,
            finding_id=clean_finding_id,
            account_id=clean_account_id,
            severity=clean_severity,
            limit=limit,
        )

    except Exception as exc:

        print(
            "[ERROR] Failed to list remediations: "
            f"{exc}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve remediations"
            ),
        )

    return {
        "status": "success",
        "count": len(
            remediations
        ),
        "remediations": [
            _safe_remediation_response(item)
            for item in remediations
        ],
    }


# ============================================================
# REMEDIATION STATISTICS
# ============================================================

@router.get("/statistics")
def remediation_statistics(
    current_user=Depends(verify_token),
):
    """
    Return customer-specific remediation statistics.
    """

    user_id = _get_user_id(
        current_user
    )

    try:

        statistics = get_remediation_statistics(
            user_id
        )

    except Exception as exc:

        print(
            "[ERROR] Failed to retrieve remediation "
            f"statistics: {exc}"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to retrieve remediation statistics"
            ),
        )

    return {
        "status": "success",
        "statistics": statistics,
    }


# ============================================================
# REGISTRY ACTIONS
# ============================================================

@router.post("/actions/{action_id}/proposals", status_code=status.HTTP_201_CREATED)
def create_remediation_action_proposal(
    action_id: str,
    payload: CreateRemediationActionRequest,
    request: Request,
    current_user=Depends(verify_token),
):
    """Create a tenant-scoped proposal for an explicitly enabled registry action."""

    user_id = _get_user_id(current_user)
    organization_id, role = _get_organization_context_from_user(current_user)
    action_id = _clean_text(action_id)
    action = get_default_engine().get_action(action_id)

    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation action not found in the registry",
        )

    if action_id not in {
        ACTION_EC2_STOP_INSTANCE,
        ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
        ACTION_IAM_DISABLE_ACCESS_KEY,
        ACTION_VPC_REMOVE_INSECURE_INGRESS,
        ACTION_RDS_DISABLE_PUBLIC_ACCESS,
        ACTION_CLOUDTRAIL_ENABLE_LOGGING,
    }:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This remediation action is not enabled for execution",
        )

    if not _role_can_access_action(role, action.allowed_roles):
        _record_remediation_audit_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"{action.service} remediation proposal authorization denied",
            action_id=action_id,
            authorization_result="DENIED",
            confirmation_state="NOT_CONFIRMED",
            approval_state="NOT_APPROVED",
            execution_state="NOT_STARTED",
            request_id=getattr(request.state, "request_id", None),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to propose this remediation action",
        )

    if (
        action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="The remediation action does not satisfy the required approval policy",
        )

    finding_based_action = action_id in {
        ACTION_VPC_REMOVE_INSECURE_INGRESS,
        ACTION_RDS_DISABLE_PUBLIC_ACCESS,
        ACTION_CLOUDTRAIL_ENABLE_LOGGING,
    }
    resource_id = _clean_text(payload.resource_id)
    finding_id = _clean_text(payload.finding_id) if finding_based_action else None
    operation = {"execution_mode": "SERVER_SIDE_ONLY"}

    if finding_based_action:
        if not finding_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="A finding ID is required for this remediation action",
            )
    else:
        if action_id == ACTION_EC2_STOP_INSTANCE:
            resource_is_valid = bool(INSTANCE_ID_PATTERN.fullmatch(resource_id))
            resource_error = "A valid EC2 instance ID is required"
        elif action_id == ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS:
            resource_is_valid = is_valid_bucket_name(resource_id)
            resource_error = "A valid S3 bucket name is required"
        else:
            resource_is_valid = is_valid_iam_access_key_id(resource_id)
            resource_error = "A valid IAM access-key identifier is required"
        if not resource_is_valid:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=resource_error,
            )

    if (
        action_id == ACTION_IAM_DISABLE_ACCESS_KEY
        and not is_valid_iam_username(_clean_text(payload.username))
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A valid IAM username is required",
        )

    try:
        account = get_account(
            _clean_text(payload.account_id),
            user_id=user_id,
            organization_id=organization_id,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Connected AWS account could not be validated",
        ) from None
    if not account or account.get("status") != "connected":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connected AWS account not found for this organization",
        )

    aws_account_id = _clean_text(account.get("aws_account_id"))
    if not aws_account_id.isdigit() or len(aws_account_id) != 12:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Connected AWS account identity is invalid",
        )

    account_id = str(account.get("_id"))

    if finding_based_action:
        finding = get_finding_for_account(
            finding_id=finding_id,
            user_id=user_id,
            account_id=account_id,
            organization_id=organization_id,
        )
        if not finding:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found for the selected AWS account",
            )
        if not is_finding_actionable(finding):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The source finding is no longer actionable",
            )

        if action_id == ACTION_VPC_REMOVE_INSECURE_INGRESS:
            operation.update(_vpc_ssh_rule_from_finding(finding) or {})
            if not operation.get("security_group_id"):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The finding does not identify a supported public SSH ingress rule",
                )
            resource_id = operation["security_group_id"]
        elif action_id == ACTION_RDS_DISABLE_PUBLIC_ACCESS:
            derived_identifier = _rds_public_access_resource_from_finding(finding)
            if not derived_identifier:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The finding does not identify a publicly accessible RDS instance",
                )
            resource_id = derived_identifier
            operation["db_instance_identifier"] = resource_id
        else:
            trail_name = _cloudtrail_disabled_trail_from_finding(finding)
            if not trail_name:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="The finding does not identify an existing disabled CloudTrail trail",
                )
            resource_id = trail_name
            operation["trail_name"] = trail_name

        if payload.resource_id and _clean_text(payload.resource_id) != resource_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The requested resource does not match the selected finding",
            )

    try:
        existing = get_active_remediation(
            user_id=user_id,
            finding_id=finding_id,
            account_id=account_id,
            action_type=action_id,
            resource_id=resource_id,
        )
        if existing:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "status": "success",
                    "created": False,
                    "deduplicated": True,
                    "remediation": _safe_remediation_response(existing),
                },
            )

        if action_id == ACTION_IAM_DISABLE_ACCESS_KEY:
            operation["username"] = _clean_text(payload.username)
        elif action_id in {ACTION_EC2_STOP_INSTANCE, ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS}:
            operation.update({
                "action_type": action_id,
                "resource_id": resource_id,
            })

        remediation = create_remediation({
            "user_id": user_id,
            "organization_id": organization_id,
            "finding_id": finding_id or None,
            "account_id": account_id,
            "aws_account_id": aws_account_id,
            "service": action.service,
            "resource": resource_id,
            "resource_type": action.resource_type,
            "action_type": action_id,
            "title": action.action_name,
            "description": action.description,
            "reason": f"Explicit {action.service} remediation proposal created by an authorized organization member.",
            "recommendation": action.notes,
            "operation": operation,
            "before_state": {},
        })
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Unable to create remediation proposal",
        ) from None

    audit_record = _record_remediation_audit_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=EVENT_REMEDIATION_CREATED,
        action=f"{action.service} remediation proposal created",
        action_id=action_id,
        authorization_result="AUTHORIZED",
        confirmation_state="NOT_CONFIRMED",
        approval_state="PENDING_APPROVAL",
        execution_state="NOT_STARTED",
        request_id=getattr(request.state, "request_id", None),
        account_id=account_id,
        aws_account_id=aws_account_id,
        remediation_id=remediation.get("_id"),
        resource_id=(
            mask_iam_access_key_id(resource_id)
            if action_id == ACTION_IAM_DISABLE_ACCESS_KEY
            else resource_id
        ),
    )

    return {
        "status": "success",
        "created": True,
        "deduplicated": False,
        "audit_recorded": bool(audit_record),
        "remediation": _safe_remediation_response(remediation),
    }

@router.get("/actions")
def list_remediation_actions(
    current_user=Depends(verify_token),
):
    """
    Return the centralized remediation registry metadata for the current tenant.

    This endpoint is read-only and does not execute any AWS action.
    """

    organization_id, role = _get_organization_context_from_user(current_user)
    engine = get_default_engine()
    actions = [
        action
        for action in engine.list_actions()
        if _role_can_access_action(role, action.get("allowed_roles"))
    ]

    return {
        "status": "success",
        "organization_id": organization_id,
        "count": len(actions),
        "actions": actions,
    }


@router.get("/actions/{action_id}")
def get_remediation_action(
    action_id: str,
    current_user=Depends(verify_token),
):
    """
    Return a single remediation action definition from the centralized registry.

    This is metadata only; no AWS or IAM state is modified.
    """

    action_id = _clean_text(action_id)
    if not action_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Action ID is required",
        )

    organization_id, role = _get_organization_context_from_user(current_user)
    engine = get_default_engine()
    action = engine.get_action(action_id)

    if action is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation action not found in the registry",
        )

    if not _role_can_access_action(role, action.allowed_roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to access this remediation action",
        )

    return {
        "status": "success",
        "organization_id": organization_id,
        "action": action.as_dict(),
    }


# ============================================================
# GET SINGLE REMEDIATION
# ============================================================

@router.get("/{remediation_id}")
def get_single_remediation(
    remediation_id: str,
    current_user=Depends(verify_token),
):
    """
    Retrieve one remediation belonging to the
    authenticated customer.
    """

    user_id = _get_user_id(
        current_user
    )

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    return {
        "status": "success",
        "remediation": _safe_remediation_response(remediation),
    }


# ============================================================
# APPROVE REMEDIATION
# ============================================================

@router.patch(
    "/{remediation_id}/approve"
)
def approve_remediation(
    remediation_id: str,

    payload: ApproveRemediationRequest,

    request: Request,

    current_user=Depends(verify_token),
):
    """
    Approve a remediation proposal.

    IMPORTANT:

    Approval still DOES NOT execute AWS changes.

    It only moves the proposal into APPROVED state.

    A future AWS executor must consume approved proposals.
    """

    user_id = _get_user_id(
        current_user
    )

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    current_status = str(
        remediation.get(
            "status",
            "",
        )
    ).upper()

    if current_status not in {
        "PROPOSED",
        STATUS_PENDING_APPROVAL,
    }:

        raise HTTPException(
            status_code=409,
            detail=(
                "Remediation cannot be approved "
                f"from status {current_status}"
            ),
        )

    action_id = _clean_text(remediation.get("action_type"))
    resource_action = action_id in {
        ACTION_EC2_STOP_INSTANCE,
        ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
        ACTION_IAM_DISABLE_ACCESS_KEY,
        ACTION_VPC_REMOVE_INSECURE_INGRESS,
        ACTION_RDS_DISABLE_PUBLIC_ACCESS,
    }
    organization_id = None
    role = None

    if resource_action:
        organization_id, role = _get_organization_context_from_user(current_user)
        action = get_default_engine().get_action(action_id)
        if action is None or not _role_can_access_action(role, action.allowed_roles):
            _record_remediation_audit_event(
                user_id=user_id,
                organization_id=organization_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action=f"{action.service if action else 'Remediation'} approval authorization denied",
                action_id=action_id,
                authorization_result="DENIED",
                approval_state="PENDING_APPROVAL",
                execution_state="NOT_STARTED",
                request_id=getattr(request.state, "request_id", None),
                remediation_id=remediation_id,
                resource_id=(
                    mask_iam_access_key_id(remediation.get("resource"))
                    if action_id == ACTION_IAM_DISABLE_ACCESS_KEY
                    else remediation.get("resource")
                ),
                success=False,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to approve this remediation action",
            )

        if str(remediation.get("organization_id") or "") != organization_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Remediation does not belong to the active organization",
            )

        account = get_account(
            remediation.get("account_id"),
            user_id=user_id,
            organization_id=organization_id,
        )
        if not account or account.get("status") != "connected":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Connected AWS account not found for this organization",
            )

        resource_id = _clean_text(remediation.get("resource"))
        if action_id == ACTION_EC2_STOP_INSTANCE:
            valid_resource = bool(INSTANCE_ID_PATTERN.fullmatch(resource_id))
        elif action_id == ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS:
            valid_resource = is_valid_bucket_name(resource_id)
        elif action_id == ACTION_IAM_DISABLE_ACCESS_KEY:
            valid_resource = is_valid_iam_access_key_id(resource_id)
            operation = remediation.get("operation") or {}
            username = operation.get("username") if isinstance(operation, dict) else None
            valid_resource = valid_resource and is_valid_iam_username(_clean_text(username))
        elif action_id == ACTION_VPC_REMOVE_INSECURE_INGRESS:
            source_finding = get_finding_for_account(
                finding_id=remediation.get("finding_id"),
                user_id=user_id,
                account_id=remediation.get("account_id"),
                organization_id=organization_id,
            )
            expected_rule = _vpc_ssh_rule_from_finding(source_finding)
            operation = remediation.get("operation") or {}
            valid_resource = (
                source_finding is not None
                and is_finding_actionable(source_finding)
                and expected_rule is not None
                and isinstance(operation, dict)
                and all(operation.get(key) == value for key, value in expected_rule.items())
                and resource_id == expected_rule["security_group_id"]
            )
        elif action_id == ACTION_RDS_DISABLE_PUBLIC_ACCESS:
            source_finding = get_finding_for_account(
                finding_id=remediation.get("finding_id"),
                user_id=user_id,
                account_id=remediation.get("account_id"),
                organization_id=organization_id,
            )
            expected_identifier = _rds_public_access_resource_from_finding(source_finding)
            operation = remediation.get("operation") or {}
            valid_resource = (
                source_finding is not None
                and is_finding_actionable(source_finding)
                and expected_identifier is not None
                and resource_id == expected_identifier
                and isinstance(operation, dict)
                and operation.get("db_instance_identifier") == expected_identifier
            )
        elif action_id == ACTION_CLOUDTRAIL_ENABLE_LOGGING:
            source_finding = get_finding_for_account(
                finding_id=remediation.get("finding_id"),
                user_id=user_id,
                account_id=remediation.get("account_id"),
                organization_id=organization_id,
            )
            expected_trail_name = _cloudtrail_disabled_trail_from_finding(source_finding)
            operation = remediation.get("operation") or {}
            valid_resource = (
                source_finding is not None
                and is_finding_actionable(source_finding)
                and expected_trail_name is not None
                and resource_id == expected_trail_name
                and isinstance(operation, dict)
                and operation.get("trail_name") == expected_trail_name
            )
        else:
            valid_resource = False
        if not valid_resource:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="The remediation target is invalid for this action",
            )

        if (
            action_id in {
                ACTION_IAM_DISABLE_ACCESS_KEY,
                ACTION_VPC_REMOVE_INSECURE_INGRESS,
                ACTION_RDS_DISABLE_PUBLIC_ACCESS,
                ACTION_CLOUDTRAIL_ENABLE_LOGGING,
            }
            and _clean_text(remediation.get("aws_account_id"))
            != _clean_text(account.get("aws_account_id"))
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Remediation AWS account does not match the connected account",
            )
    else:
        # Recheck the source finding before approval. It may have changed
        # since the proposal was created.
        account_id = remediation.get("account_id")
        finding_id = remediation.get("finding_id")
        finding = get_finding_for_account(
            finding_id=finding_id,
            user_id=user_id,
            account_id=account_id,
        )

        if not finding:
            raise HTTPException(
                status_code=409,
                detail="The source finding is no longer available for this remediation",
            )

        if not is_finding_actionable(finding):
            raise HTTPException(
                status_code=409,
                detail="The source finding is no longer actionable",
            )

    updated = update_remediation_status(
        remediation_id=remediation_id,

        status=STATUS_APPROVED,

        user_id=user_id,

        approved_by=user_id,

        approval_comment=(
            _clean_text(
                payload.comment
            )
            or None
        ),
    )

    if not updated:

        raise HTTPException(
            status_code=409,
            detail="Remediation approval failed",
        )

    updated_remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if resource_action:
        action = get_default_engine().get_action(action_id)
        _record_remediation_audit_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=EVENT_REMEDIATION_APPROVED,
            action=f"{action.service} remediation proposal approved",
            action_id=action_id,
            authorization_result="AUTHORIZED",
            confirmation_state="AWAITING_EXECUTION_CONFIRMATION",
            approval_state=STATUS_APPROVED,
            execution_state="NOT_STARTED",
            account_id=remediation.get("account_id"),
            aws_account_id=remediation.get("aws_account_id"),
            remediation_id=remediation_id,
            resource_id=(
                mask_iam_access_key_id(remediation.get("resource"))
                if action_id == ACTION_IAM_DISABLE_ACCESS_KEY
                else remediation.get("resource")
            ),
            request_id=getattr(request.state, "request_id", None),
        )

    return {
        "status": "success",

        "message": (
            "Remediation approved. "
            "No AWS changes have been executed yet."
        ),

        "remediation": _safe_remediation_response(updated_remediation),
    }


# ============================================================
# REJECT REMEDIATION
# ============================================================

@router.patch(
    "/{remediation_id}/reject"
)
def reject_remediation(
    remediation_id: str,

    payload: RejectRemediationRequest,

    current_user=Depends(verify_token),
):
    """
    Reject a remediation proposal.
    """

    user_id = _get_user_id(
        current_user
    )

    reason = _clean_text(
        payload.reason
    )

    if not reason:

        raise HTTPException(
            status_code=400,
            detail="Rejection reason is required",
        )

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    current_status = str(
        remediation.get(
            "status",
            "",
        )
    ).upper()

    if current_status not in {
        "PROPOSED",
        STATUS_PENDING_APPROVAL,
    }:

        raise HTTPException(
            status_code=409,
            detail=(
                "Remediation cannot be rejected "
                f"from status {current_status}"
            ),
        )

    updated = update_remediation_status(
        remediation_id=remediation_id,

        status=STATUS_REJECTED,

        user_id=user_id,

        rejected_by=user_id,

        rejection_reason=reason,
    )

    if not updated:

        raise HTTPException(
            status_code=409,
            detail="Remediation rejection failed",
        )

    updated_remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    return {
        "status": "success",
        "message": "Remediation rejected",
        "remediation": _safe_remediation_response(updated_remediation),
    }


# ============================================================
# CANCEL REMEDIATION
# ============================================================

@router.patch(
    "/{remediation_id}/cancel"
)
def cancel_remediation_proposal(
    remediation_id: str,

    current_user=Depends(verify_token),
):
    """
    Cancel a remediation before execution.
    """

    user_id = _get_user_id(
        current_user
    )

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    updated = cancel_remediation(
        remediation_id,
        user_id,
    )

    if not updated:

        raise HTTPException(
            status_code=409,
            detail=(
                "Remediation cannot be cancelled"
            ),
        )

    updated_remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    return {
        "status": "success",
        "message": "Remediation cancelled",
        "remediation": _safe_remediation_response(updated_remediation),
    }


# ============================================================
# EXECUTE APPROVED REMEDIATION
# ============================================================

@router.post(
    "/{remediation_id}/execute"
)
def execute_remediation(
    remediation_id: str,
    request: Request,
    payload: Optional[ExecuteRemediationRequest] = None,
    current_user=Depends(verify_token),
):
    """
    Execute an APPROVED remediation proposal.

    IMPORTANT SECURITY BOUNDARY:

    This endpoint does NOT accept arbitrary AWS commands,
    boto3 operation names, IAM policies, or AWS parameters
    from the client.

    The executor loads the trusted remediation record and
    associated AWS account/finding, then:

        1. Verifies tenant ownership.
        2. Verifies the remediation is APPROVED.
        3. Verifies the associated finding.
        4. Assumes the customer's temporary AWS role.
        5. Verifies the real AWS account identity.
        6. Executes only an allowlisted action.
        7. Verifies the resulting AWS state.
        8. Marks the remediation COMPLETED or FAILED.
        9. Resolves the finding only after successful verification.

    Approval and execution remain separate workflow steps.
    """

    user_id = _get_user_id(
        current_user
    )

    remediation_id = _clean_text(
        remediation_id
    )

    if not remediation_id:

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remediation ID is required",
        )

    # --------------------------------------------------------
    # Load the proposal using tenant-scoped access.
    # --------------------------------------------------------

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation not found",
        )

    current_status = str(
        remediation.get(
            "status",
            "",
        )
    ).strip().upper()

    action_id = _clean_text(remediation.get("action_type", "")).upper()
    registered_action = get_default_engine().get_action(action_id)
    if registered_action is not None:
        if action_id not in {
            ACTION_EC2_STOP_INSTANCE,
            ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
            ACTION_IAM_DISABLE_ACCESS_KEY,
            ACTION_VPC_REMOVE_INSECURE_INGRESS,
            ACTION_RDS_DISABLE_PUBLIC_ACCESS,
            ACTION_CLOUDTRAIL_ENABLE_LOGGING,
        }:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="This registry action is not enabled for execution",
            )

        organization_id, role = _get_organization_context_from_user(current_user)
        if not _role_can_access_action(role, registered_action.allowed_roles):
            _record_remediation_audit_event(
                user_id=user_id,
                organization_id=organization_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action=f"{registered_action.service} remediation execution authorization denied",
                action_id=action_id,
                authorization_result="DENIED",
                confirmation_state="NOT_CONFIRMED",
                approval_state=current_status,
                execution_state="NOT_STARTED",
                request_id=getattr(request.state, "request_id", None),
                account_id=remediation.get("account_id"),
                aws_account_id=remediation.get("aws_account_id"),
                remediation_id=remediation_id,
                resource_id=(
                    mask_iam_access_key_id(remediation.get("resource"))
                    if action_id == ACTION_IAM_DISABLE_ACCESS_KEY
                    else remediation.get("resource")
                ),
                success=False,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to execute this remediation action",
            )

        if action_id == ACTION_EC2_STOP_INSTANCE:
            try:
                result = execute_ec2_stop(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    confirmed=bool(payload and payload.confirmed),
                    request_id=getattr(request.state, "request_id", None),
                )
            except EC2StopExecutionError as error:
                if not error.audit_recorded:
                    _record_remediation_audit_event(
                        user_id=user_id,
                        organization_id=organization_id,
                        event_type=EVENT_REMEDIATION_FAILED,
                        action="EC2 stop attempt rejected before AWS mutation",
                        action_id=action_id,
                        authorization_result="AUTHORIZED",
                        confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                        approval_state=current_status,
                        execution_state="NOT_STARTED",
                        account_id=remediation.get("account_id"),
                        aws_account_id=remediation.get("aws_account_id"),
                        remediation_id=remediation_id,
                        resource_id=remediation.get("resource"),
                        request_id=getattr(request.state, "request_id", None),
                        success=False,
                        error_code=error.code,
                        error_category=error.category,
                        verification_result="NOT_RUN",
                    )
                raise HTTPException(
                    status_code=error.status_code,
                    detail={
                        "code": error.code,
                        "category": error.category,
                        "message": error.public_message,
                    },
                ) from None
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="The EC2 remediation could not be completed",
                ) from None

            return {
                "status": "success",
                "message": "EC2 state was verified as stopped.",
                "remediation": result,
            }

        if action_id == ACTION_IAM_DISABLE_ACCESS_KEY:
            try:
                result = execute_iam_disable_access_key(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    confirmed=bool(payload and payload.confirmed),
                    request_id=getattr(request.state, "request_id", None),
                )
            except IAMAccessKeyExecutionError as error:
                if not error.audit_recorded:
                    _record_remediation_audit_event(
                        user_id=user_id,
                        organization_id=organization_id,
                        event_type=EVENT_REMEDIATION_FAILED,
                        action="IAM access-key attempt rejected before mutation",
                        action_id=action_id,
                        authorization_result="AUTHORIZED",
                        confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                        approval_state=current_status,
                        execution_state="NOT_STARTED",
                        account_id=remediation.get("account_id"),
                        aws_account_id=remediation.get("aws_account_id"),
                        remediation_id=remediation_id,
                        resource_id=mask_iam_access_key_id(remediation.get("resource")),
                        request_id=getattr(request.state, "request_id", None),
                        success=False,
                        error_code=error.code,
                        error_category=error.category,
                        verification_result="NOT_RUN",
                    )
                raise HTTPException(
                    status_code=error.status_code,
                    detail={
                        "code": error.code,
                        "category": error.category,
                        "message": error.public_message,
                    },
                ) from None
            except Exception:
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="The IAM remediation could not be completed",
                ) from None

            return {
                "status": "success",
                "message": "The IAM access key was disabled and verified inactive.",
                "remediation": result,
            }

        if action_id == ACTION_VPC_REMOVE_INSECURE_INGRESS:
            try:
                result = execute_vpc_remove_ssh_ingress(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    confirmed=bool(payload and payload.confirmed),
                    request_id=getattr(request.state, "request_id", None),
                )
            except VPCIngressExecutionError as error:
                if not error.audit_recorded:
                    _record_remediation_audit_event(
                        user_id=user_id,
                        organization_id=organization_id,
                        event_type=EVENT_REMEDIATION_FAILED,
                        action="VPC ingress attempt rejected before mutation",
                        action_id=action_id,
                        authorization_result="AUTHORIZED",
                        confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                        approval_state=current_status,
                        execution_state="NOT_STARTED",
                        account_id=remediation.get("account_id"),
                        aws_account_id=remediation.get("aws_account_id"),
                        finding_id=remediation.get("finding_id"),
                        remediation_id=remediation_id,
                        resource_id=remediation.get("resource"),
                        request_id=getattr(request.state, "request_id", None),
                        success=False,
                        error_code=error.code,
                        error_category=error.category,
                        verification_result="NOT_RUN",
                    )
                raise HTTPException(
                    status_code=error.status_code,
                    detail={"code": error.code, "category": error.category, "message": error.public_message},
                ) from None
            except Exception:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The VPC remediation could not be completed") from None
            return {"status": "success", "message": "The identified SSH ingress rule was removed and verified.", "remediation": result}

        if action_id == ACTION_RDS_DISABLE_PUBLIC_ACCESS:
            try:
                result = execute_rds_disable_public_access(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    confirmed=bool(payload and payload.confirmed),
                    request_id=getattr(request.state, "request_id", None),
                )
            except RDSDisablePublicAccessError as error:
                if not error.audit_recorded:
                    _record_remediation_audit_event(
                        user_id=user_id,
                        organization_id=organization_id,
                        event_type=EVENT_REMEDIATION_FAILED,
                        action="RDS public-access attempt rejected before mutation",
                        action_id=action_id,
                        authorization_result="AUTHORIZED",
                        confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                        approval_state=current_status,
                        execution_state="NOT_STARTED",
                        account_id=remediation.get("account_id"),
                        aws_account_id=remediation.get("aws_account_id"),
                        finding_id=remediation.get("finding_id"),
                        remediation_id=remediation_id,
                        resource_id=remediation.get("resource"),
                        request_id=getattr(request.state, "request_id", None),
                        success=False,
                        error_code=error.code,
                        error_category=error.category,
                        verification_result="NOT_RUN",
                    )
                raise HTTPException(
                    status_code=error.status_code,
                    detail={"code": error.code, "category": error.category, "message": error.public_message},
                ) from None
            except Exception:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The RDS remediation could not be completed") from None
            return {"status": "success", "message": "RDS public accessibility was disabled and verified.", "remediation": result}

        if action_id == ACTION_CLOUDTRAIL_ENABLE_LOGGING:
            try:
                result = execute_cloudtrail_enable_logging(
                    remediation=remediation,
                    user_id=user_id,
                    organization_id=organization_id,
                    role=role,
                    confirmed=bool(payload and payload.confirmed),
                    request_id=getattr(request.state, "request_id", None),
                )
            except CloudTrailEnableLoggingError as error:
                if not error.audit_recorded:
                    _record_remediation_audit_event(
                        user_id=user_id,
                        organization_id=organization_id,
                        event_type=EVENT_REMEDIATION_FAILED,
                        action="CloudTrail logging attempt rejected before mutation",
                        action_id=action_id,
                        authorization_result="AUTHORIZED",
                        confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                        approval_state=current_status,
                        execution_state="NOT_STARTED",
                        account_id=remediation.get("account_id"),
                        aws_account_id=remediation.get("aws_account_id"),
                        finding_id=remediation.get("finding_id"),
                        remediation_id=remediation_id,
                        resource_id=remediation.get("resource"),
                        request_id=getattr(request.state, "request_id", None),
                        success=False,
                        error_code=error.code,
                        error_category=error.category,
                        verification_result="NOT_RUN",
                    )
                raise HTTPException(
                    status_code=error.status_code,
                    detail={"code": error.code, "category": error.category, "message": error.public_message},
                ) from None
            except Exception:
                raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail="The CloudTrail remediation could not be completed") from None
            return {"status": "success", "message": "CloudTrail logging was enabled and verified.", "remediation": result}

        try:
            result = execute_s3_block_public_access(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                role=role,
                confirmed=bool(payload and payload.confirmed),
                request_id=getattr(request.state, "request_id", None),
            )
        except S3BlockPublicAccessError as error:
            if not error.audit_recorded:
                _record_remediation_audit_event(
                    user_id=user_id,
                    organization_id=organization_id,
                    event_type=EVENT_REMEDIATION_FAILED,
                    action="S3 Block Public Access attempt rejected before AWS mutation",
                    action_id=action_id,
                    authorization_result="AUTHORIZED",
                    confirmation_state=("CONFIRMED" if payload and payload.confirmed else "NOT_CONFIRMED"),
                    approval_state=current_status,
                    execution_state="NOT_STARTED",
                    account_id=remediation.get("account_id"),
                    aws_account_id=remediation.get("aws_account_id"),
                    remediation_id=remediation_id,
                    resource_id=remediation.get("resource"),
                    request_id=getattr(request.state, "request_id", None),
                    success=False,
                    error_code=error.code,
                    error_category=error.category,
                    verification_result="NOT_RUN",
                )
            raise HTTPException(
                status_code=error.status_code,
                detail={
                    "code": error.code,
                    "category": error.category,
                    "message": error.public_message,
                },
            ) from None
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="The S3 remediation could not be completed",
            ) from None

        return {
            "status": "success",
            "message": "S3 Block Public Access was enabled and verified.",
            "remediation": result,
        }

    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="This remediation action is not enabled for execution",
    )

    # --------------------------------------------------------
    # SAFE EXECUTION RECONCILIATION
    # --------------------------------------------------------
    # A previous executor run may have successfully changed AWS
    # and verified the result, while the workflow status remained
    # APPROVED because the process was interrupted before the final
    # database transition.
    #
    # Reconcile ONLY from trusted persisted execution evidence.
    # This function does NOT call AWS and therefore cannot repeat
    # the customer's cloud change.
    # --------------------------------------------------------

    if current_status == STATUS_APPROVED:
        try:
            # The executor stores verification inside after_state in
            # successful historical records. Support both the newer
            # nested shape and the older top-level shape.
            after_state = remediation.get("after_state") or {}
            stored_verification = (
                after_state.get("verification")
                if isinstance(after_state, dict)
                else None
            ) or remediation.get("verification") or {}

            already_verified = (
                isinstance(after_state, dict)
                and after_state.get("success") is True
                and isinstance(stored_verification, dict)
                and stored_verification.get("verified") is True
            )

            if already_verified:
                # First try the model's dedicated reconciliation helper.
                # This performs a tenant-scoped database-only transition.
                reconcile_successful_execution(
                    remediation_id=remediation_id,
                    user_id=user_id,
                )

                # If an older model implementation does not recognize the
                # nested verification shape, safely complete the record here.
                # No AWS call is made in this fallback.
                reconciled = get_remediation(
                    remediation_id,
                    user_id=user_id,
                )

                if reconciled:
                    reconciled_status = str(
                        reconciled.get("status", "")
                    ).strip().upper()

                    if reconciled_status == STATUS_APPROVED:
                        updated = update_remediation_status(
                            remediation_id=remediation_id,
                            status=STATUS_COMPLETED,
                            user_id=user_id,
                        )

                        if not updated:
                            raise RuntimeError(
                                "Unable to reconcile verified remediation state"
                            )

            # Reload after reconciliation so the response reflects
            # the authoritative database state.
            reconciled = get_remediation(
                remediation_id,
                user_id=user_id,
            )

            if reconciled:
                reconciled_status = str(
                    reconciled.get(
                        "status",
                        "",
                    )
                ).strip().upper()

                if reconciled_status == STATUS_COMPLETED:
                    return {
                        "status": "success",
                        "message": (
                            "Remediation execution was already "
                            "successfully verified. The workflow "
                            "record has been safely reconciled to COMPLETED. "
                            "No AWS changes were executed."
                        ),
                        "remediation": reconciled,
                    }

                # Continue with the original approved workflow only
                # when reconciliation did not establish a verified
                # completed state.
                remediation = reconciled
                current_status = reconciled_status

        except Exception as exc:
            print(
                "[WARNING] Remediation reconciliation skipped: "
                f"{exc}"
            )

    # --------------------------------------------------------
    # Execution is allowed ONLY after approval.
    # --------------------------------------------------------

    if current_status != STATUS_APPROVED:

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                "Remediation must be APPROVED before "
                f"execution. Current status: {current_status or 'UNKNOWN'}"
            ),
        )

    # --------------------------------------------------------
    # Defense in depth:
    # verify that this action is still executable.
    # --------------------------------------------------------

    action_type = _normalize_action_type(
        remediation.get(
            "action_type",
            "",
        )
    )

    if not is_remediation_action_allowed(
        action_type
    ):

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Remediation action {action_type} "
                "is not automatically executable."
            ),
        )

    # --------------------------------------------------------
    # Delegate ALL AWS interaction to the executor.
    #
    # No boto3 calls belong in this API layer.
    # --------------------------------------------------------

    result = execute_approved_remediation(
        remediation_id=remediation_id,
        user_id=user_id,
    )

    # --------------------------------------------------------
    # Return the workflow result.
    #
    # A failed AWS remediation is a business/workflow result,
    # not a malformed HTTP request, so return the executor
    # result rather than exposing internal AWS details.
    # --------------------------------------------------------

    if not result.get(
        "success",
        False,
    ):

        return {
            "status": "failed",
            "message": (
                "Remediation execution failed. "
                "The AWS environment was not marked as remediated."
            ),
            "remediation": result,
        }

    return {
        "status": "success",
        "message": (
            "Remediation executed and AWS state "
            "was successfully verified."
        ),
        "remediation": result,
    }


# ============================================================
# VERIFY REMEDIATION (PHASE 8)
# ============================================================

@router.post(
    "/{remediation_id}/verify"
)
def verify_remediation(
    remediation_id: str,
    current_user=Depends(verify_token),
):
    """
    Request a re-evaluation scan for a completed remediation.
    """
    user_id = str(current_user.get("user_id", ""))
    organization_id = str(current_user.get("organization_id", ""))
    
    if not user_id or not organization_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid authentication is required."
        )
    
    remediation = get_remediation(remediation_id, user_id)
    if not remediation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Remediation proposal not found."
        )
    
    if remediation.get("status") != STATUS_COMPLETED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only COMPLETED remediations can be verified."
        )
    
    account_id = remediation.get("account_id")
    if not account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Remediation missing account_id."
        )
        
    finding_id = remediation.get("finding_id")
    finding = get_finding_for_account(finding_id, user_id, account_id) if finding_id else None
    aws_account_id = finding.get("aws_account_id") if finding else None
    
    try:
        scan_job = create_scan_job(
            organization_id=organization_id,
            user_id=user_id,
            account_id=account_id,
            aws_account_id=aws_account_id,
        )
    except ValueError as e:
        if "already active" in str(e):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="A scan is already active for this AWS account. Please wait for it to finish."
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
        
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    
    from app.models.remediation import remediations_collection
    remediations_collection.update_one(
        {"_id": remediation["_id"]},
        {
            "$set": {
                "verification.status": "pending",
                "verification.job_id": str(scan_job.get("_id") or scan_job.get("id")),
                "verification.requested_at": now,
                "updated_at": now,
            }
        }
    )
    
    record_remediation_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=EVENT_REMEDIATION_VERIFICATION_REQUESTED,
        result="SUCCESS",
        account_id=account_id,
        remediation_id=remediation_id,
        message="Requested post-remediation verification scan.",
        metadata={
            "scan_job_id": str(scan_job.get("_id") or scan_job.get("id")),
        }
    )
    
    return {
        "status": "success",
        "message": "Verification scan requested.",
        "job": scan_job,
    }


# ============================================================
# DELETE REMEDIATION
# ============================================================

@router.delete(
    "/{remediation_id}"
)
def remove_remediation(
    remediation_id: str,

    current_user=Depends(verify_token),
):
    """
    Delete an unused remediation proposal.

    Completed and failed execution records should remain
    available for auditability.
    """

    user_id = _get_user_id(
        current_user
    )

    remediation = get_remediation(
        remediation_id,
        user_id=user_id,
    )

    if not remediation:

        raise HTTPException(
            status_code=404,
            detail="Remediation not found",
        )

    deleted = delete_remediation(
        remediation_id,
        user_id,
    )

    if not deleted:

        raise HTTPException(
            status_code=409,
            detail=(
                "Only proposed, rejected, or cancelled "
                "remediations can be deleted"
            ),
        )

    return {
        "status": "success",
        "message": "Remediation deleted",
    }