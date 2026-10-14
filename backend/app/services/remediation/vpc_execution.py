from __future__ import annotations

import re
from typing import Any, Dict, Optional

from botocore.exceptions import BotoCoreError, ClientError

from app.models.aws_account import get_account
from app.models.audit_log import (
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_REMEDIATION_COMPLETED,
    EVENT_REMEDIATION_EXECUTION_STARTED,
    EVENT_REMEDIATION_FAILED,
)
from app.models.remediation import (
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_EXECUTING,
    STATUS_FAILED,
    transition_to_completed,
    transition_to_executing,
    transition_to_failed,
    update_execution_result,
)
from app.services.audit_log_service import record_remediation_event
from app.services.aws_connection import AWS_CONFIG, assume_aws_role, verify_aws_account
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.remediation_models import VPC_REMOVE_INSECURE_INGRESS_ACTION_ID


VPC_REMOVE_INGRESS_ACTION = VPC_REMOVE_INSECURE_INGRESS_ACTION_ID
SECURITY_GROUP_ID_PATTERN = re.compile(r"^sg-[0-9a-fA-F]{8,17}$")
ALLOWED_SSH_CIDRS = {"0.0.0.0/0", "::/0"}


class VPCIngressExecutionError(Exception):
    """Safe public error details for the VPC ingress remediation."""

    def __init__(self, *, status_code: int, code: str, category: str, message: str, audit_recorded: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.category = category
        self.public_message = message
        self.audit_recorded = audit_recorded


def _aws_error_code(error: Exception) -> str:
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
    elif isinstance(error, BotoCoreError):
        code = type(error).__name__
    else:
        code = type(error).__name__
    return re.sub(r"[^A-Za-z0-9_.-]", "_", str(code))[:100] or "AWS_ERROR"


def _aws_request_id(response: Optional[Dict[str, Any]]) -> Optional[str]:
    if not isinstance(response, dict):
        return None
    metadata = response.get("ResponseMetadata") or {}
    value = metadata.get("RequestId") or metadata.get("RequestID")
    return str(value)[:128] if value else None


def _record_event(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    request_id: Optional[str],
    event_type: str,
    action: str,
    execution_state: str,
    authorization_result: str = "AUTHORIZED",
    approval_state: Optional[str] = None,
    confirmation_state: str = "CONFIRMED",
    success: Optional[bool] = None,
    error_code: Optional[str] = None,
    error_category: Optional[str] = None,
    verification_result: Optional[str] = None,
    aws_request_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    return record_remediation_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=event_type,
        action_id=VPC_REMOVE_INGRESS_ACTION,
        action=action,
        authorization_result=authorization_result,
        approval_state=approval_state or remediation.get("status"),
        confirmation_state=confirmation_state,
        execution_state=execution_state,
        success=success,
        error_code=error_code,
        error_category=error_category,
        verification_result=verification_result,
        account_id=remediation.get("account_id"),
        aws_account_id=remediation.get("aws_account_id"),
        finding_id=remediation.get("finding_id"),
        remediation_id=remediation.get("_id"),
        resource_id=remediation.get("resource"),
        request_id=request_id,
        aws_request_id=aws_request_id,
    )


def _operation_rule(remediation: Dict[str, Any]) -> Dict[str, Any]:
    operation = remediation.get("operation") or {}
    if not isinstance(operation, dict):
        raise VPCIngressExecutionError(
            status_code=400,
            code="INVALID_RULE_EVIDENCE",
            category="RESOURCE_VALIDATION",
            message="The security-group rule evidence is invalid.",
        )
    group_id = str(operation.get("security_group_id") or remediation.get("resource") or "").strip()
    protocol = str(operation.get("protocol") or "").strip().lower()
    source = str(operation.get("source") or "").strip()
    source_type = str(operation.get("source_type") or "").strip().upper()
    from_port = operation.get("from_port")
    to_port = operation.get("to_port")

    if (
        not SECURITY_GROUP_ID_PATTERN.fullmatch(group_id)
        or protocol != "tcp"
        or from_port != 22
        or to_port != 22
        or source not in ALLOWED_SSH_CIDRS
        or (source_type == "IPV4_CIDR" and source != "0.0.0.0/0")
        or (source_type == "IPV6_CIDR" and source != "::/0")
        or source_type not in {"IPV4_CIDR", "IPV6_CIDR"}
        or operation.get("rule_scope") != "INGRESS"
    ):
        raise VPCIngressExecutionError(
            status_code=400,
            code="UNSUPPORTED_RULE_TARGET",
            category="RESOURCE_VALIDATION",
            message="Only the explicitly identified public SSH port 22 ingress rule can be removed.",
        )
    return {
        "security_group_id": group_id,
        "protocol": protocol,
        "from_port": 22,
        "to_port": 22,
        "source": source,
        "source_type": source_type,
    }


def _matching_permissions(group: Dict[str, Any], rule: Dict[str, Any]) -> list[Dict[str, Any]]:
    matches = []
    source_key = "IpRanges" if rule["source_type"] == "IPV4_CIDR" else "Ipv6Ranges"
    cidr_key = "CidrIp" if rule["source_type"] == "IPV4_CIDR" else "CidrIpv6"
    for permission in group.get("IpPermissions", []) or []:
        if (
            str(permission.get("IpProtocol", "")).lower() != "tcp"
            or permission.get("FromPort") != 22
            or permission.get("ToPort") != 22
        ):
            continue
        if any(item.get(cidr_key) == rule["source"] for item in permission.get(source_key, []) or []):
            matches.append(permission)
    return matches


def execute_vpc_remove_ssh_ingress(
    *,
    remediation: Dict[str, Any],
    user_id: str,
    organization_id: str,
    role: str,
    confirmed: bool,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    action = get_default_engine().get_action(VPC_REMOVE_INGRESS_ACTION)
    if action is None or action.service != "VPC" or action.resource_type != "SECURITY_GROUP":
        raise VPCIngressExecutionError(status_code=503, code="ACTION_DEFINITION_UNAVAILABLE", category="REGISTRY_VALIDATION", message="The VPC remediation action is unavailable.")

    if not action.allowed_roles or role.strip().lower() not in {item.strip().lower() for item in action.allowed_roles}:
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_AUTHORIZATION, action="VPC ingress authorization denied", authorization_result="DENIED", confirmation_state="NOT_CONFIRMED", execution_state="NOT_STARTED", success=False, error_code="ROLE_NOT_ALLOWED", error_category="AUTHORIZATION")
        raise VPCIngressExecutionError(status_code=403, code="ROLE_NOT_ALLOWED", category="AUTHORIZATION", message="You are not authorized to execute this remediation action.", audit_recorded=True)

    if (
        remediation.get("action_type") != VPC_REMOVE_INGRESS_ACTION
        or action.classification.value != "APPROVAL_REQUIRED"
        or not action.requires_confirmation
        or not action.requires_approval
    ):
        raise VPCIngressExecutionError(status_code=409, code="ACTION_POLICY_MISMATCH", category="ACTION_VALIDATION", message="The remediation action does not satisfy the required approval policy.")
    rem_org = str(remediation.get("organization_id") or "").strip()
    if not rem_org or rem_org != str(organization_id).strip():
        raise VPCIngressExecutionError(status_code=403, code="ORGANIZATION_MISMATCH", category="TENANT_VALIDATION", message="Remediation does not belong to the active organization.")
    if not remediation.get("user_id"):
        raise VPCIngressExecutionError(status_code=404, code="REMEDIATION_NOT_FOUND", category="TENANT_VALIDATION", message="Remediation proposer not found.")
    if str(remediation.get("status", "")).upper() != STATUS_APPROVED or not remediation.get("approved_by") or not remediation.get("approved_at"):
        raise VPCIngressExecutionError(status_code=409, code="APPROVAL_REQUIRED", category="APPROVAL_VALIDATION", message="Remediation must be approved before execution.")
    if confirmed is not True:
        raise VPCIngressExecutionError(status_code=409, code="CONFIRMATION_REQUIRED", category="CONFIRMATION_VALIDATION", message="Explicit confirmation is required before execution.")

    rule = _operation_rule(remediation)
    if str(remediation.get("resource") or "").strip() != rule["security_group_id"]:
        raise VPCIngressExecutionError(status_code=409, code="RESOURCE_MISMATCH", category="RESOURCE_VALIDATION", message="The stored security-group target does not match the rule evidence.")

    execution_started = False
    aws_request_id = None
    try:
        account = get_account(str(remediation.get("account_id") or ""), user_id=user_id, organization_id=organization_id)
        if not account or account.get("status") != "connected":
            raise VPCIngressExecutionError(status_code=404, code="AWS_ACCOUNT_NOT_FOUND", category="ACCOUNT_VALIDATION", message="Connected AWS account not found for this organization.")
        expected_account_id = str(account.get("aws_account_id") or "").strip()
        if not re.fullmatch(r"[0-9]{12}", expected_account_id) or str(remediation.get("aws_account_id") or "") != expected_account_id:
            raise VPCIngressExecutionError(status_code=409, code="AWS_ACCOUNT_MISMATCH", category="ACCOUNT_VALIDATION", message="Remediation AWS account does not match the connected account.")
        role_arn = str(account.get("role_arn") or "").strip()
        region = str(account.get("region") or "ap-south-1").strip()
        if not role_arn or not region:
            raise VPCIngressExecutionError(status_code=409, code="AWS_CONNECTION_INCOMPLETE", category="ACCOUNT_VALIDATION", message="The connected AWS account is missing execution configuration.")

        # Verify organization remediation setting for VPC
        from app.models.remediation_settings import is_remediation_enabled
        if not is_remediation_enabled(organization_id, str(remediation.get("account_id") or ""), "vpc"):
            _record_event(
                remediation=remediation,
                user_id=user_id,
                organization_id=organization_id,
                request_id=request_id,
                event_type=EVENT_REMEDIATION_AUTHORIZATION,
                action="VPC Ingress remediation authorization denied (setting disabled)",
                authorization_result="DENIED",
                confirmation_state="CONFIRMED",
                execution_state="NOT_STARTED",
                success=False,
                error_code="REMEDIATION_SETTING_DISABLED",
                error_category="GOVERNANCE",
            )
            raise VPCIngressExecutionError(
                status_code=403,
                code="REMEDIATION_SETTING_DISABLED",
                category="GOVERNANCE",
                message="Remediation setting is disabled for VPC for this account.",
                audit_recorded=True,
            )

        session = assume_aws_role(role_arn=role_arn, region=region, session_name=f"CloudGuardAI-VPCIngress-{str(remediation.get('_id', ''))[:24]}")
        verify_aws_account(session, expected_account_id)
        ec2 = session.client("ec2", region_name=region, config=AWS_CONFIG)
        response = ec2.describe_security_groups(GroupIds=[rule["security_group_id"]])
        groups = response.get("SecurityGroups") or []
        aws_request_id = _aws_request_id(response)
        if len(groups) != 1 or groups[0].get("GroupId") != rule["security_group_id"]:
            raise VPCIngressExecutionError(status_code=404, code="SECURITY_GROUP_NOT_FOUND", category="RESOURCE_VALIDATION", message="The security group was not found in the connected account.")
        if str(groups[0].get("OwnerId") or "") != expected_account_id:
            raise VPCIngressExecutionError(status_code=403, code="SECURITY_GROUP_ACCOUNT_MISMATCH", category="RESOURCE_VALIDATION", message="The security group does not belong to the connected AWS account.")
        if not _matching_permissions(groups[0], rule):
            raise VPCIngressExecutionError(status_code=409, code="TARGET_RULE_NOT_FOUND", category="RESOURCE_VALIDATION", message="The exact public SSH ingress rule was not found; no rule was changed.")

        if not transition_to_executing(remediation["_id"], user_id, organization_id=organization_id):
            raise VPCIngressExecutionError(status_code=409, code="EXECUTION_ALREADY_CLAIMED", category="WORKFLOW_VALIDATION", message="This remediation is already being processed or is no longer approved.")
        execution_started = True
        start_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_EXECUTION_STARTED, action="VPC SSH ingress removal started", execution_state=STATUS_EXECUTING, verification_result="PENDING", aws_request_id=aws_request_id)
        if not start_audit:
            raise VPCIngressExecutionError(status_code=503, code="AUDIT_UNAVAILABLE", category="AUDIT_FAILURE", message="Execution could not start because the audit event could not be recorded.")

        permission = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
        if rule["source_type"] == "IPV4_CIDR":
            permission["IpRanges"] = [{"CidrIp": rule["source"]}]
        else:
            permission["Ipv6Ranges"] = [{"CidrIpv6": rule["source"]}]
        mutation = ec2.revoke_security_group_ingress(GroupId=rule["security_group_id"], IpPermissions=[permission])
        aws_request_id = _aws_request_id(mutation) or aws_request_id

        verified_response = ec2.describe_security_groups(GroupIds=[rule["security_group_id"]])
        aws_request_id = _aws_request_id(verified_response) or aws_request_id
        verified_groups = verified_response.get("SecurityGroups") or []
        if len(verified_groups) != 1 or verified_groups[0].get("OwnerId") != expected_account_id:
            raise VPCIngressExecutionError(status_code=502, code="SECURITY_GROUP_VERIFICATION_FAILED", category="AWS_STATE_VERIFICATION", message="The security-group state could not be verified.")
        if _matching_permissions(verified_groups[0], rule):
            raise VPCIngressExecutionError(status_code=502, code="INGRESS_RULE_VERIFICATION_FAILED", category="AWS_STATE_VERIFICATION", message="The targeted public SSH ingress rule is still present.")

        after_state = {"success": True, "resource_id": rule["security_group_id"], "removed_rule": {"protocol": "tcp", "from_port": 22, "to_port": 22, "source": rule["source"]}}
        verification = {"verified": True, "rule_absent": True, "protocol": "tcp", "from_port": 22, "to_port": 22, "source": rule["source"]}
        if not update_execution_result(remediation["_id"], user_id, after_state=after_state, verification=verification, organization_id=organization_id):
            raise VPCIngressExecutionError(status_code=500, code="RESULT_PERSISTENCE_FAILED", category="WORKFLOW_PERSISTENCE", message="AWS state was verified but the remediation result could not be saved.")
        if not transition_to_completed(remediation["_id"], user_id, organization_id=organization_id):
            raise VPCIngressExecutionError(status_code=500, code="COMPLETION_TRANSITION_FAILED", category="WORKFLOW_PERSISTENCE", message="AWS state was verified but the remediation could not be completed.")
        completion_audit = _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_COMPLETED, action="VPC SSH ingress removal completed", execution_state=STATUS_COMPLETED, success=True, verification_result="VERIFIED_RULE_REMOVED", aws_request_id=aws_request_id)
        return {"success": True, "status": STATUS_COMPLETED, "remediation_id": remediation["_id"], "action_id": VPC_REMOVE_INGRESS_ACTION, "service": "VPC", "resource_type": "SECURITY_GROUP", "resource_id": rule["security_group_id"], "aws_account_id": expected_account_id, "verification": verification, "audit_recorded": bool(completion_audit)}
    except VPCIngressExecutionError as error:
        if not getattr(error, "audit_recorded", False):
            if execution_started:
                transition_to_failed(remediation["_id"], user_id, execution_error=f"{error.code}:{error.category}", organization_id=organization_id)
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="VPC SSH ingress removal failed", execution_state=STATUS_FAILED, success=False, error_code=error.code, error_category=error.category, verification_result="FAILED", aws_request_id=aws_request_id)
            else:
                _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="VPC ingress attempt failed before mutation", execution_state="NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error.code, error_category=error.category, verification_result="NOT_RUN", aws_request_id=aws_request_id)
            error.audit_recorded = True
        raise
    except Exception as error:
        error_code = _aws_error_code(error)
        if isinstance(error, ClientError):
            aws_request_id = _aws_request_id(error.response) or aws_request_id
            if error_code in {"AccessDenied", "UnauthorizedOperation", "403"}:
                category, status_code, message = "AWS_AUTHORIZATION", 403, "The assumed role cannot inspect or modify this security group."
            elif error_code in {"InvalidGroup.NotFound", "InvalidGroupId.Malformed"}:
                category, status_code, message = "RESOURCE_VALIDATION", 404, "The security group was not found in the connected account."
            else:
                category, status_code, message = "AWS_API", 502, "The VPC remediation could not be completed."
        elif isinstance(error, PermissionError):
            error_code, category, status_code, message = "AWS_ACCOUNT_MISMATCH", "ACCOUNT_VALIDATION", 403, "The assumed AWS role does not belong to the connected account."
        else:
            category, status_code, message = "AWS_API", 502 if execution_started else 503, "The VPC remediation could not be completed."
        if execution_started:
            transition_to_failed(remediation["_id"], user_id, execution_error=f"{error_code}:{category}", organization_id=organization_id)
        _record_event(remediation=remediation, user_id=user_id, organization_id=organization_id, request_id=request_id, event_type=EVENT_REMEDIATION_FAILED, action="VPC ingress removal failed" if execution_started else "VPC ingress validation failed", execution_state=STATUS_FAILED if execution_started else "NOT_STARTED", confirmation_state="CONFIRMED" if confirmed else "NOT_CONFIRMED", success=False, error_code=error_code, error_category=category, verification_result="FAILED" if execution_started else "NOT_RUN", aws_request_id=aws_request_id)
        raise VPCIngressExecutionError(status_code=status_code, code=error_code, category=category, message=message, audit_recorded=True) from None
