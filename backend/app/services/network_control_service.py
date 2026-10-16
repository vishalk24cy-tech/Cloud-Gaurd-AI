# ============================================================
# CloudGuardAI - Secure VPC & Network Resource Control Service
# Phase 5: AWS VPC, Network Inventory, Security Groups & Remediation
# ============================================================

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import logging
import re
import threading
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

logger = logging.getLogger("cloudguardai.network_controls")

STANDARD_AWS_REGIONS = [
    "ap-south-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "sa-east-1",
]

# AWS Resource Identifier patterns
VPC_ID_PATTERN = re.compile(r"^vpc-[0-9a-fA-F]{8,17}$")
SUBNET_ID_PATTERN = re.compile(r"^subnet-[0-9a-fA-F]{8,17}$")
SECURITY_GROUP_ID_PATTERN = re.compile(r"^sg-[0-9a-fA-F]{8,17}$")
ROUTE_TABLE_ID_PATTERN = re.compile(r"^rtb-[0-9a-fA-F]{8,17}$")
GATEWAY_ID_PATTERN = re.compile(r"^(igw|nat)-[0-9a-fA-F]{8,17}$")
VPC_ENDPOINT_ID_PATTERN = re.compile(r"^vpce-[0-9a-fA-F]{8,17}$")
AWS_REGION_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

ALLOWED_NETWORK_MUTATION_ACTIONS = {
    "revoke_ingress_rule",
    "revoke_egress_rule",
    "revoke_ssh_ingress",
    "revoke_rdp_ingress",
    "revoke_all_traffic_ingress",
}

MUTATION_ALLOWED_ROLES = {"owner", "admin"}


class NetworkControlExecutionError(Exception):
    """Safe public error details for VPC and Network control workflows."""

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


def is_valid_vpc_id(vpc_id: str) -> bool:
    if not isinstance(vpc_id, str):
        return False
    return bool(VPC_ID_PATTERN.fullmatch(vpc_id.strip()))


def is_valid_subnet_id(subnet_id: str) -> bool:
    if not isinstance(subnet_id, str):
        return False
    return bool(SUBNET_ID_PATTERN.fullmatch(subnet_id.strip()))


def is_valid_security_group_id(sg_id: str) -> bool:
    if not isinstance(sg_id, str):
        return False
    return bool(SECURITY_GROUP_ID_PATTERN.fullmatch(sg_id.strip()))


def is_valid_route_table_id(rt_id: str) -> bool:
    if not isinstance(rt_id, str):
        return False
    return bool(ROUTE_TABLE_ID_PATTERN.fullmatch(rt_id.strip()))


def is_valid_gateway_id(gw_id: str) -> bool:
    if not isinstance(gw_id, str):
        return False
    return bool(GATEWAY_ID_PATTERN.fullmatch(gw_id.strip()))


def is_valid_vpc_endpoint_id(vpce_id: str) -> bool:
    if not isinstance(vpce_id, str):
        return False
    return bool(VPC_ENDPOINT_ID_PATTERN.fullmatch(vpce_id.strip()))


def validate_aws_region(region: Optional[str], allow_all: bool = False) -> bool:
    if not region or not isinstance(region, str):
        return False
    reg = region.strip().lower()
    if allow_all and reg == "all":
        return True
    return bool(AWS_REGION_REGEX.match(reg))


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


# ============================================================
# NORMALIZERS
# ============================================================

def normalize_vpc(vpc: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS VPC dictionary into clean, safe API model."""
    if not isinstance(vpc, dict):
        return {}

    vpc_id = _safe_string(vpc.get("VpcId"))
    state = _safe_string(vpc.get("State") or "unknown").lower()
    cidr_block = _safe_string(vpc.get("CidrBlock"))
    dhcp_options_id = _safe_string(vpc.get("DhcpOptionsId"))
    is_default = bool(vpc.get("IsDefault", False))
    instance_tenancy = _safe_string(vpc.get("InstanceTenancy") or "default")

    # Extract secondary CIDR blocks
    cidr_block_association_set = vpc.get("CidrBlockAssociationSet") or []
    secondary_cidrs = [
        _safe_string(c.get("CidrBlock"))
        for c in cidr_block_association_set
        if isinstance(c, dict) and c.get("CidrBlock") and c.get("CidrBlock") != cidr_block
    ]

    # Extract tags
    raw_tags = vpc.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }
    name = tags.get("Name") or vpc_id

    return {
        "vpc_id": vpc_id,
        "resource": vpc_id,
        "resource_id": vpc_id,
        "resource_type": "VPC",
        "name": name,
        "state": state,
        "cidr_block": cidr_block,
        "secondary_cidrs": secondary_cidrs,
        "dhcp_options_id": dhcp_options_id,
        "is_default": is_default,
        "instance_tenancy": instance_tenancy,
        "tags": tags,
        "region": fallback_region,
        "security_posture": "SECURE" if not is_default else "EVALUATED",
    }


def normalize_subnet(subnet: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS Subnet dictionary into clean, safe API model."""
    if not isinstance(subnet, dict):
        return {}

    subnet_id = _safe_string(subnet.get("SubnetId"))
    vpc_id = _safe_string(subnet.get("VpcId"))
    state = _safe_string(subnet.get("State") or "unknown").lower()
    cidr_block = _safe_string(subnet.get("CidrBlock"))
    az = _safe_string(subnet.get("AvailabilityZone"))
    az_id = _safe_string(subnet.get("AvailabilityZoneId"))
    available_ip_count = int(subnet.get("AvailableIpAddressCount") or 0)
    map_public_ip = bool(subnet.get("MapPublicIpOnLaunch", False))
    default_for_az = bool(subnet.get("DefaultForAz", False))

    region = az[:-1] if az and az[-1].isalpha() and az[:-1] else fallback_region

    raw_tags = subnet.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }
    name = tags.get("Name") or subnet_id

    # Security posture: Auto-assign public IP is higher risk for backend subnets
    security_posture = "RISK" if map_public_ip else "SECURE"

    return {
        "subnet_id": subnet_id,
        "resource": subnet_id,
        "resource_id": subnet_id,
        "resource_type": "SUBNET",
        "name": name,
        "vpc_id": vpc_id,
        "state": state,
        "cidr_block": cidr_block,
        "availability_zone": az,
        "availability_zone_id": az_id,
        "available_ip_address_count": available_ip_count,
        "map_public_ip_on_launch": map_public_ip,
        "default_for_az": default_for_az,
        "tags": tags,
        "region": region,
        "security_posture": security_posture,
    }


def _analyze_rule_security(
    permission: Dict[str, Any], is_egress: bool = False
) -> Dict[str, Any]:
    """Analyze a single IP permission rule for dangerous exposure."""
    protocol = str(permission.get("IpProtocol", "")).lower()
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")

    ip_ranges = [
        _safe_string(r.get("CidrIp"))
        for r in (permission.get("IpRanges") or [])
        if isinstance(r, dict) and r.get("CidrIp")
    ]
    ipv6_ranges = [
        _safe_string(r.get("CidrIpv6"))
        for r in (permission.get("Ipv6Ranges") or [])
        if isinstance(r, dict) and r.get("CidrIpv6")
    ]
    user_id_group_pairs = [
        {
            "group_id": _safe_string(g.get("GroupId")),
            "group_name": _safe_string(g.get("GroupName")),
            "user_id": _safe_string(g.get("UserId")),
            "vpc_id": _safe_string(g.get("VpcId")),
        }
        for g in (permission.get("UserIdGroupPairs") or [])
        if isinstance(g, dict) and g.get("GroupId")
    ]
    prefix_lists = [
        _safe_string(p.get("PrefixListId"))
        for p in (permission.get("PrefixListIds") or [])
        if isinstance(p, dict) and p.get("PrefixListId")
    ]

    has_unrestricted_ipv4 = "0.0.0.0/0" in ip_ranges
    has_unrestricted_ipv6 = "::/0" in ipv6_ranges
    is_unrestricted = has_unrestricted_ipv4 or has_unrestricted_ipv6

    risk_level = "LOW"
    risk_description = ""

    if not is_egress:
        # Ingress analysis
        if is_unrestricted:
            if protocol == "-1":
                risk_level = "CRITICAL"
                risk_description = "Unrestricted all-traffic ingress from Internet (0.0.0.0/0 or ::/0)"
            elif from_port == 22 and to_port == 22:
                risk_level = "HIGH"
                risk_description = "Unrestricted SSH (port 22) exposed to Internet"
            elif from_port == 3389 and to_port == 3389:
                risk_level = "HIGH"
                risk_description = "Unrestricted RDP (port 3389) exposed to Internet"
            elif from_port == 0 and to_port == 65535:
                risk_level = "CRITICAL"
                risk_description = f"Unrestricted full port range (0-65535) exposed for {protocol.upper()}"
            else:
                port_range_str = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
                risk_level = "MEDIUM"
                risk_description = f"Unrestricted port {port_range_str} exposed to Internet"
    else:
        # Egress analysis: 0.0.0.0/0 all egress is standard default AWS SG egress, but flag if strict compliance
        if is_unrestricted and protocol == "-1":
            risk_level = "INFO"
            risk_description = "Default outbound all-traffic rule"

    return {
        "protocol": protocol,
        "from_port": from_port,
        "to_port": to_port,
        "ip_ranges": ip_ranges,
        "ipv6_ranges": ipv6_ranges,
        "user_id_group_pairs": user_id_group_pairs,
        "prefix_lists": prefix_lists,
        "is_unrestricted": is_unrestricted,
        "has_unrestricted_ipv4": has_unrestricted_ipv4,
        "has_unrestricted_ipv6": has_unrestricted_ipv6,
        "risk_level": risk_level,
        "risk_description": risk_description,
    }


def normalize_security_group(sg: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS Security Group dictionary into clean, safe API model with posture."""
    if not isinstance(sg, dict):
        return {}

    group_id = _safe_string(sg.get("GroupId"))
    group_name = _safe_string(sg.get("GroupName"))
    description = _safe_string(sg.get("Description"))
    vpc_id = _safe_string(sg.get("VpcId"))
    owner_id = _safe_string(sg.get("OwnerId"))

    raw_ingress = sg.get("IpPermissions") or []
    raw_egress = sg.get("IpPermissionsEgress") or []

    ingress_rules = [_analyze_rule_security(p, is_egress=False) for p in raw_ingress if isinstance(p, dict)]
    egress_rules = [_analyze_rule_security(p, is_egress=True) for p in raw_egress if isinstance(p, dict)]

    raw_tags = sg.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }

    # Evaluate overall posture
    critical_rules = [r for r in ingress_rules if r["risk_level"] == "CRITICAL"]
    high_rules = [r for r in ingress_rules if r["risk_level"] == "HIGH"]
    medium_rules = [r for r in ingress_rules if r["risk_level"] == "MEDIUM"]

    if critical_rules:
        security_posture = "CRITICAL"
    elif high_rules:
        security_posture = "HIGH_RISK"
    elif medium_rules:
        security_posture = "RISK"
    else:
        security_posture = "SECURE"

    return {
        "group_id": group_id,
        "group_name": group_name,
        "resource": group_id,
        "resource_id": group_id,
        "resource_type": "SECURITY_GROUP",
        "name": tags.get("Name") or group_name or group_id,
        "description": description,
        "vpc_id": vpc_id,
        "owner_id": owner_id,
        "region": fallback_region,
        "tags": tags,
        "ingress_rules": ingress_rules,
        "egress_rules": egress_rules,
        "ingress_rule_count": len(ingress_rules),
        "egress_rule_count": len(egress_rules),
        "critical_rule_count": len(critical_rules),
        "high_risk_rule_count": len(high_rules),
        "security_posture": security_posture,
        "has_open_ssh": any(r["from_port"] == 22 and r["to_port"] == 22 and r["is_unrestricted"] for r in ingress_rules),
        "has_open_rdp": any(r["from_port"] == 3389 and r["to_port"] == 3389 and r["is_unrestricted"] for r in ingress_rules),
        "has_all_traffic_open": any(r["protocol"] == "-1" and r["is_unrestricted"] for r in ingress_rules),
    }


def normalize_route_table(rt: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS Route Table dictionary into clean, safe API model."""
    if not isinstance(rt, dict):
        return {}

    rt_id = _safe_string(rt.get("RouteTableId"))
    vpc_id = _safe_string(rt.get("VpcId"))
    owner_id = _safe_string(rt.get("OwnerId"))

    raw_routes = rt.get("Routes") or []
    routes = []
    has_direct_internet_route = False

    for r in raw_routes:
        if not isinstance(r, dict):
            continue
        dest_cidr = _safe_string(r.get("DestinationCidrBlock"))
        dest_ipv6_cidr = _safe_string(r.get("DestinationIpv6CidrBlock"))
        dest_prefix_list = _safe_string(r.get("DestinationPrefixListId"))
        gw_id = _safe_string(r.get("GatewayId"))
        nat_gw_id = _safe_string(r.get("NatGatewayId"))
        transit_gw_id = _safe_string(r.get("TransitGatewayId"))
        vpce_id = _safe_string(r.get("VpcEndpointId"))
        peering_id = _safe_string(r.get("VpcPeeringConnectionId"))
        state = _safe_string(r.get("State") or "active").lower()

        is_internet_gw = gw_id.startswith("igw-")
        if (dest_cidr == "0.0.0.0/0" or dest_ipv6_cidr == "::/0") and is_internet_gw:
            has_direct_internet_route = True

        routes.append({
            "destination_cidr_block": dest_cidr or None,
            "destination_ipv6_cidr_block": dest_ipv6_cidr or None,
            "destination_prefix_list_id": dest_prefix_list or None,
            "gateway_id": gw_id or None,
            "nat_gateway_id": nat_gw_id or None,
            "transit_gateway_id": transit_gw_id or None,
            "vpc_endpoint_id": vpce_id or None,
            "vpc_peering_connection_id": peering_id or None,
            "state": state,
            "is_internet_route": (dest_cidr == "0.0.0.0/0" or dest_ipv6_cidr == "::/0"),
        })

    raw_associations = rt.get("Associations") or []
    associations = []
    is_main = False
    for a in raw_associations:
        if not isinstance(a, dict):
            continue
        assoc_id = _safe_string(a.get("RouteTableAssociationId"))
        subnet_id = _safe_string(a.get("SubnetId"))
        main = bool(a.get("Main", False))
        if main:
            is_main = True
        associations.append({
            "association_id": assoc_id,
            "subnet_id": subnet_id or None,
            "main": main,
        })

    raw_tags = rt.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }

    return {
        "route_table_id": rt_id,
        "resource": rt_id,
        "resource_id": rt_id,
        "resource_type": "ROUTE_TABLE",
        "name": tags.get("Name") or rt_id,
        "vpc_id": vpc_id,
        "owner_id": owner_id,
        "is_main": is_main,
        "routes": routes,
        "associations": associations,
        "tags": tags,
        "region": fallback_region,
        "has_direct_internet_route": has_direct_internet_route,
        "security_posture": "PUBLIC_ROUTE" if has_direct_internet_route else "PRIVATE_ROUTE",
    }


def normalize_gateway(gw: Dict[str, Any], gw_type: str, fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS Internet Gateway or NAT Gateway dictionary."""
    if not isinstance(gw, dict):
        return {}

    raw_tags = gw.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }

    if gw_type.upper() == "IGW":
        gw_id = _safe_string(gw.get("InternetGatewayId"))
        attachments = [
            {
                "vpc_id": _safe_string(att.get("VpcId")),
                "state": _safe_string(att.get("State") or "available").lower(),
            }
            for att in (gw.get("Attachments") or [])
            if isinstance(att, dict) and att.get("VpcId")
        ]
        vpc_ids = [att["vpc_id"] for att in attachments]
        return {
            "gateway_id": gw_id,
            "resource": gw_id,
            "resource_id": gw_id,
            "resource_type": "INTERNET_GATEWAY",
            "name": tags.get("Name") or gw_id,
            "gateway_type": "INTERNET_GATEWAY",
            "state": "attached" if attachments else "detached",
            "vpc_ids": vpc_ids,
            "attachments": attachments,
            "tags": tags,
            "region": fallback_region,
            "security_posture": "ATTACHED" if attachments else "UNATTACHED",
        }
    else:
        # NAT Gateway
        gw_id = _safe_string(gw.get("NatGatewayId"))
        vpc_id = _safe_string(gw.get("VpcId"))
        subnet_id = _safe_string(gw.get("SubnetId"))
        state = _safe_string(gw.get("State") or "available").lower()
        addresses = [
            {
                "allocation_id": _safe_string(addr.get("AllocationId")),
                "public_ip": _safe_string(addr.get("PublicIp")),
                "private_ip": _safe_string(addr.get("PrivateIp")),
            }
            for addr in (gw.get("NatGatewayAddresses") or [])
            if isinstance(addr, dict)
        ]
        public_ips = [a["public_ip"] for a in addresses if a.get("public_ip")]
        return {
            "gateway_id": gw_id,
            "resource": gw_id,
            "resource_id": gw_id,
            "resource_type": "NAT_GATEWAY",
            "name": tags.get("Name") or gw_id,
            "gateway_type": "NAT_GATEWAY",
            "state": state,
            "vpc_id": vpc_id,
            "subnet_id": subnet_id,
            "public_ips": public_ips,
            "addresses": addresses,
            "tags": tags,
            "region": fallback_region,
            "security_posture": "ACTIVE" if state == "available" else "EVALUATED",
        }


def normalize_vpc_endpoint(vpce: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """Normalize raw AWS VPC Endpoint dictionary."""
    if not isinstance(vpce, dict):
        return {}

    vpce_id = _safe_string(vpce.get("VpcEndpointId"))
    vpc_id = _safe_string(vpce.get("VpcId"))
    service_name = _safe_string(vpce.get("ServiceName"))
    state = _safe_string(vpce.get("State") or "available").lower()
    endpoint_type = _safe_string(vpce.get("VpcEndpointType") or "Interface")
    route_table_ids = [
        _safe_string(rt) for rt in (vpce.get("RouteTableIds") or []) if _safe_string(rt)
    ]
    subnet_ids = [
        _safe_string(s) for s in (vpce.get("SubnetIds") or []) if _safe_string(s)
    ]
    raw_tags = vpce.get("Tags") or []
    tags = {
        _safe_string(t.get("Key")): _safe_string(t.get("Value"))
        for t in raw_tags
        if isinstance(t, dict) and t.get("Key")
    }

    return {
        "vpc_endpoint_id": vpce_id,
        "resource": vpce_id,
        "resource_id": vpce_id,
        "resource_type": "VPC_ENDPOINT",
        "name": tags.get("Name") or service_name or vpce_id,
        "vpc_id": vpc_id,
        "service_name": service_name,
        "endpoint_type": endpoint_type,
        "state": state,
        "route_table_ids": route_table_ids,
        "subnet_ids": subnet_ids,
        "tags": tags,
        "region": fallback_region,
        "security_posture": "SECURE",
    }


# ============================================================
# READ-ONLY INVENTORY QUERY METHODS
# ============================================================

def query_vpcs(
    ec2_client: Any,
    region: str,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Query VPC inventory via DescribeVpcs in a strictly read-only manner."""
    try:
        response = ec2_client.describe_vpcs()
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks ec2:DescribeVpcs permission in {region}.",
            ) from client_err
        elif code in ("Throttling", "RequestLimitExceeded"):
            raise NetworkControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS VPC service error in {region}: [{code}] {msg}",
            ) from client_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=502,
            code="VPC_CONNECTION_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS EC2 service: {str(exc)}",
        ) from exc

    raw_vpcs = response.get("Vpcs", []) or []
    normalized: List[Dict[str, Any]] = []
    for v in raw_vpcs:
        item = normalize_vpc(v, fallback_region=region)
        if not item.get("vpc_id"):
            continue
        if search:
            s = search.strip().lower()
            if s not in item["vpc_id"].lower() and s not in item["name"].lower() and s not in item["cidr_block"].lower():
                continue
        normalized.append(item)

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "vpcs": paginated,
        "summary": {
            "total_vpcs": len(normalized),
            "default_vpcs": sum(1 for v in normalized if v["is_default"]),
            "custom_vpcs": sum(1 for v in normalized if not v["is_default"]),
            "region": region,
        },
    }


def query_subnets(
    ec2_client: Any,
    region: str,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Query Subnet inventory via DescribeSubnets in a strictly read-only manner."""
    kwargs: Dict[str, Any] = {}
    if vpc_id:
        kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    try:
        response = ec2_client.describe_subnets(**kwargs)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks ec2:DescribeSubnets permission in {region}.",
            ) from client_err
        elif code in ("Throttling", "RequestLimitExceeded"):
            raise NetworkControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS Subnet service error in {region}: [{code}] {msg}",
            ) from client_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=502,
            code="SUBNET_CONNECTION_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS EC2 service: {str(exc)}",
        ) from exc

    raw_subnets = response.get("Subnets", []) or []
    normalized: List[Dict[str, Any]] = []
    for s in raw_subnets:
        item = normalize_subnet(s, fallback_region=region)
        if not item.get("subnet_id"):
            continue
        if search:
            st = search.strip().lower()
            if (
                st not in item["subnet_id"].lower()
                and st not in item["name"].lower()
                and st not in item["cidr_block"].lower()
                and st not in item["vpc_id"].lower()
            ):
                continue
        normalized.append(item)

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "subnets": paginated,
        "summary": {
            "total_subnets": len(normalized),
            "public_subnets": sum(1 for s in normalized if s["map_public_ip_on_launch"]),
            "private_subnets": sum(1 for s in normalized if not s["map_public_ip_on_launch"]),
            "region": region,
        },
    }


def query_security_groups(
    ec2_client: Any,
    region: str,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
    posture_filter: Optional[str] = None,
) -> Dict[str, Any]:
    """Query Security Group inventory via DescribeSecurityGroups in a strictly read-only manner."""
    kwargs: Dict[str, Any] = {}
    if vpc_id:
        kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    try:
        response = ec2_client.describe_security_groups(**kwargs)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks ec2:DescribeSecurityGroups permission in {region}.",
            ) from client_err
        elif code in ("Throttling", "RequestLimitExceeded"):
            raise NetworkControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS Security Group service error in {region}: [{code}] {msg}",
            ) from client_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=502,
            code="SECURITY_GROUP_CONNECTION_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS EC2 service: {str(exc)}",
        ) from exc

    raw_groups = response.get("SecurityGroups", []) or []
    normalized: List[Dict[str, Any]] = []
    for g in raw_groups:
        item = normalize_security_group(g, fallback_region=region)
        if not item.get("group_id"):
            continue
        if search:
            st = search.strip().lower()
            if (
                st not in item["group_id"].lower()
                and st not in item["group_name"].lower()
                and st not in item["vpc_id"].lower()
                and st not in item["description"].lower()
            ):
                continue
        if posture_filter and posture_filter.upper() != "ALL":
            if item["security_posture"] != posture_filter.upper():
                continue
        normalized.append(item)

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "security_groups": paginated,
        "summary": {
            "total_security_groups": len(normalized),
            "critical_count": sum(1 for g in normalized if g["security_posture"] == "CRITICAL"),
            "high_risk_count": sum(1 for g in normalized if g["security_posture"] == "HIGH_RISK"),
            "risk_count": sum(1 for g in normalized if g["security_posture"] == "RISK"),
            "secure_count": sum(1 for g in normalized if g["security_posture"] == "SECURE"),
            "open_ssh_count": sum(1 for g in normalized if g["has_open_ssh"]),
            "open_rdp_count": sum(1 for g in normalized if g["has_open_rdp"]),
            "open_all_traffic_count": sum(1 for g in normalized if g["has_all_traffic_open"]),
            "region": region,
        },
    }


def discover_multi_region_vpcs(
    session: Any,
    regions: Optional[List[str]] = None,
    max_records_per_region: Optional[int] = 50,
    search: Optional[str] = None,
    timeout_per_region: float = 6.0,
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Perform bounded, concurrent multi-region VPC discovery.
    """
    if session is None:
        raise ValueError("AWS session is required for multi-region VPC discovery.")

    target_regions = [r.strip() for r in (regions or STANDARD_AWS_REGIONS) if r and isinstance(r, str)]
    all_vpcs: List[Dict[str, Any]] = []
    regional_failures: List[Dict[str, Any]] = []
    successful_regions: List[str] = []

    client_lock = threading.Lock()

    def _query_region(reg: str) -> Dict[str, Any]:
        with client_lock:
            client = session.client("ec2", region_name=reg, config=AWS_CONFIG)
        return query_vpcs(
            ec2_client=client,
            region=reg,
            max_records=max_records_per_region,
            search=search,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_region = {
            executor.submit(_query_region, r): r
            for r in target_regions
        }
        for future in concurrent.futures.as_completed(future_to_region):
            r = future_to_region[future]
            try:
                result = future.result(timeout=timeout_per_region)
                all_vpcs.extend(result.get("vpcs", []))
                successful_regions.append(r)
            except NetworkControlExecutionError as net_err:
                regional_failures.append({
                    "region": r,
                    "code": net_err.code,
                    "error": net_err.public_message,
                })
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
                msg = ce.response.get("Error", {}).get("Message", str(ce))
                regional_failures.append({
                    "region": r,
                    "code": code,
                    "error": f"[{code}] {msg}",
                })
            except TimeoutError:
                regional_failures.append({
                    "region": r,
                    "code": "TimeoutError",
                    "error": f"VPC discovery timed out after {timeout_per_region}s for region {r}.",
                })
            except Exception as exc:
                regional_failures.append({
                    "region": r,
                    "code": type(exc).__name__,
                    "error": str(exc),
                })

    if (
        len(regional_failures) == len(target_regions)
        and all(f.get("code") in ("AWS_ACCESS_DENIED", "AccessDenied", "UnauthorizedOperation") for f in regional_failures)
    ):
        raise NetworkControlExecutionError(
            status_code=403,
            code="AWS_ACCESS_DENIED",
            category="PERMISSION_DENIED",
            message="AWS AccessDenied: The IAM role lacks ec2:DescribeVpcs permission across all queried regions.",
        )

    all_vpcs.sort(key=lambda x: (x.get("region", ""), x.get("vpc_id", "")))
    coverage = "COMPLETE" if not regional_failures else "PARTIAL"

    summary = {
        "total_vpcs": len(all_vpcs),
        "default_vpcs": sum(1 for v in all_vpcs if v.get("is_default")),
        "custom_vpcs": sum(1 for v in all_vpcs if not v.get("is_default")),
        "regions": successful_regions,
    }

    return {
        "vpcs": all_vpcs,
        "total_count": len(all_vpcs),
        "summary": summary,
        "regions_searched": target_regions,
        "successful_regions": successful_regions,
        "regional_failures": regional_failures,
        "coverage": coverage,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


def discover_multi_region_security_groups(
    session: Any,
    regions: Optional[List[str]] = None,
    max_records_per_region: Optional[int] = 50,
    search: Optional[str] = None,
    posture_filter: Optional[str] = None,
    timeout_per_region: float = 6.0,
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Perform bounded, concurrent multi-region Security Group discovery.
    """
    if session is None:
        raise ValueError("AWS session is required for multi-region Security Group discovery.")

    target_regions = [r.strip() for r in (regions or STANDARD_AWS_REGIONS) if r and isinstance(r, str)]
    all_sgs: List[Dict[str, Any]] = []
    regional_failures: List[Dict[str, Any]] = []
    successful_regions: List[str] = []

    client_lock = threading.Lock()

    def _query_region(reg: str) -> Dict[str, Any]:
        with client_lock:
            client = session.client("ec2", region_name=reg, config=AWS_CONFIG)
        return query_security_groups(
            ec2_client=client,
            region=reg,
            max_records=max_records_per_region,
            search=search,
            posture_filter=posture_filter,
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_region = {
            executor.submit(_query_region, r): r
            for r in target_regions
        }
        for future in concurrent.futures.as_completed(future_to_region):
            r = future_to_region[future]
            try:
                result = future.result(timeout=timeout_per_region)
                all_sgs.extend(result.get("security_groups", []))
                successful_regions.append(r)
            except NetworkControlExecutionError as net_err:
                regional_failures.append({
                    "region": r,
                    "code": net_err.code,
                    "error": net_err.public_message,
                })
            except ClientError as ce:
                code = ce.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
                msg = ce.response.get("Error", {}).get("Message", str(ce))
                regional_failures.append({
                    "region": r,
                    "code": code,
                    "error": f"[{code}] {msg}",
                })
            except TimeoutError:
                regional_failures.append({
                    "region": r,
                    "code": "TimeoutError",
                    "error": f"Security Group discovery timed out after {timeout_per_region}s for region {r}.",
                })
            except Exception as exc:
                regional_failures.append({
                    "region": r,
                    "code": type(exc).__name__,
                    "error": str(exc),
                })

    if (
        len(regional_failures) == len(target_regions)
        and all(f.get("code") in ("AWS_ACCESS_DENIED", "AccessDenied", "UnauthorizedOperation") for f in regional_failures)
    ):
        raise NetworkControlExecutionError(
            status_code=403,
            code="AWS_ACCESS_DENIED",
            category="PERMISSION_DENIED",
            message="AWS AccessDenied: The IAM role lacks ec2:DescribeSecurityGroups permission across all queried regions.",
        )

    all_sgs.sort(key=lambda x: (x.get("region", ""), x.get("group_id", "")))
    coverage = "COMPLETE" if not regional_failures else "PARTIAL"

    summary = {
        "total_security_groups": len(all_sgs),
        "critical_count": sum(1 for g in all_sgs if g.get("security_posture") == "CRITICAL"),
        "high_risk_count": sum(1 for g in all_sgs if g.get("security_posture") == "HIGH_RISK"),
        "risk_count": sum(1 for g in all_sgs if g.get("security_posture") == "RISK"),
        "secure_count": sum(1 for g in all_sgs if g.get("security_posture") == "SECURE"),
        "open_ssh_count": sum(1 for g in all_sgs if g.get("has_open_ssh")),
        "open_rdp_count": sum(1 for g in all_sgs if g.get("has_open_rdp")),
        "open_all_traffic_count": sum(1 for g in all_sgs if g.get("has_all_traffic_open")),
        "regions": successful_regions,
    }

    return {
        "security_groups": all_sgs,
        "total_count": len(all_sgs),
        "summary": summary,
        "regions_searched": target_regions,
        "successful_regions": successful_regions,
        "regional_failures": regional_failures,
        "coverage": coverage,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


def query_route_tables(
    ec2_client: Any,
    region: str,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Query Route Tables via DescribeRouteTables in a strictly read-only manner."""
    kwargs: Dict[str, Any] = {}
    if vpc_id:
        kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    try:
        response = ec2_client.describe_route_tables(**kwargs)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks ec2:DescribeRouteTables permission in {region}.",
            ) from client_err
        elif code in ("Throttling", "RequestLimitExceeded"):
            raise NetworkControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS Route Table service error in {region}: [{code}] {msg}",
            ) from client_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=502,
            code="ROUTE_TABLE_CONNECTION_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS EC2 service: {str(exc)}",
        ) from exc

    raw_tables = response.get("RouteTables", []) or []
    normalized: List[Dict[str, Any]] = []
    for rt in raw_tables:
        item = normalize_route_table(rt, fallback_region=region)
        if not item.get("route_table_id"):
            continue
        if search:
            st = search.strip().lower()
            if st not in item["route_table_id"].lower() and st not in item["vpc_id"].lower() and st not in item["name"].lower():
                continue
        normalized.append(item)

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "route_tables": paginated,
        "summary": {
            "total_route_tables": len(normalized),
            "public_route_tables": sum(1 for r in normalized if r["has_direct_internet_route"]),
            "private_route_tables": sum(1 for r in normalized if not r["has_direct_internet_route"]),
            "region": region,
        },
    }


def query_gateways(
    ec2_client: Any,
    region: str,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Query Internet Gateways and NAT Gateways via DescribeInternetGateways and DescribeNatGateways."""
    igw_kwargs: Dict[str, Any] = {}
    nat_kwargs: Dict[str, Any] = {}
    if vpc_id:
        igw_kwargs["Filters"] = [{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        nat_kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    normalized: List[Dict[str, Any]] = []

    # 1. Internet Gateways
    try:
        igw_resp = ec2_client.describe_internet_gateways(**igw_kwargs)
        for igw in (igw_resp.get("InternetGateways", []) or []):
            item = normalize_gateway(igw, "IGW", fallback_region=region)
            if item.get("gateway_id"):
                normalized.append(item)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        logger.warning("DescribeInternetGateways non-fatal error: %s", client_err)
    except Exception as exc:
        logger.warning("DescribeInternetGateways failed: %s", exc)

    # 2. NAT Gateways
    try:
        nat_resp = ec2_client.describe_nat_gateways(**nat_kwargs)
        for nat in (nat_resp.get("NatGateways", []) or []):
            item = normalize_gateway(nat, "NAT", fallback_region=region)
            if item.get("gateway_id"):
                normalized.append(item)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        logger.warning("DescribeNatGateways non-fatal error: %s", client_err)
    except Exception as exc:
        logger.warning("DescribeNatGateways failed: %s", exc)

    if search:
        st = search.strip().lower()
        normalized = [
            g for g in normalized
            if st in g["gateway_id"].lower() or st in g["name"].lower() or st in g.get("vpc_id", "").lower()
        ]

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "gateways": paginated,
        "summary": {
            "total_gateways": len(normalized),
            "internet_gateways": sum(1 for g in normalized if g["gateway_type"] == "INTERNET_GATEWAY"),
            "nat_gateways": sum(1 for g in normalized if g["gateway_type"] == "NAT_GATEWAY"),
            "region": region,
        },
    }


def query_vpc_endpoints(
    ec2_client: Any,
    region: str,
    vpc_id: Optional[str] = None,
    max_records: Optional[int] = 50,
    search: Optional[str] = None,
) -> Dict[str, Any]:
    """Query VPC Endpoints via DescribeVpcEndpoints."""
    kwargs: Dict[str, Any] = {}
    if vpc_id:
        kwargs["Filters"] = [{"Name": "vpc-id", "Values": [vpc_id]}]

    try:
        response = ec2_client.describe_vpc_endpoints(**kwargs)
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        if code in ("AccessDenied", "UnauthorizedOperation", "AuthFailure"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AWS AccessDenied: The IAM role lacks ec2:DescribeVpcEndpoints permission in {region}.",
            ) from client_err
        elif code in ("Throttling", "RequestLimitExceeded"):
            raise NetworkControlExecutionError(
                status_code=429,
                code="AWS_THROTTLED",
                category="RATE_LIMIT",
                message="AWS EC2 request rate limit exceeded. Please retry after a brief pause.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS VPC Endpoints service error in {region}: [{code}] {msg}",
            ) from client_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=502,
            code="VPC_ENDPOINT_CONNECTION_ERROR",
            category="NETWORK_ERROR",
            message=f"Failed to communicate with AWS EC2 service: {str(exc)}",
        ) from exc

    raw_endpoints = response.get("VpcEndpoints", []) or []
    normalized: List[Dict[str, Any]] = []
    for vpce in raw_endpoints:
        item = normalize_vpc_endpoint(vpce, fallback_region=region)
        if not item.get("vpc_endpoint_id"):
            continue
        if search:
            st = search.strip().lower()
            if (
                st not in item["vpc_endpoint_id"].lower()
                and st not in item["service_name"].lower()
                and st not in item["vpc_id"].lower()
            ):
                continue
        normalized.append(item)

    limit = max(1, min(max_records or 50, 100))
    paginated = normalized[:limit]

    return {
        "total_count": len(normalized),
        "endpoints": paginated,
        "summary": {
            "total_endpoints": len(normalized),
            "interface_endpoints": sum(1 for e in normalized if e["endpoint_type"] == "Interface"),
            "gateway_endpoints": sum(1 for e in normalized if e["endpoint_type"] == "Gateway"),
            "region": region,
        },
    }


# ============================================================
# SAFE SECURITY GROUP CONTROL / REMEDIATION MUTATION
# ============================================================

def execute_security_group_control(
    *,
    account_id: str,
    group_id: str,
    user_id: str,
    organization_id: str,
    user_role: str,
    action: str,
    region: Optional[str] = None,
    rule_spec: Optional[Dict[str, Any]] = None,
    confirmed: bool = True,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute audited, post-verified, safety-checked security group rule mutations.
    Supported actions:
      - revoke_ingress_rule (requires exact rule spec)
      - revoke_egress_rule (requires exact rule spec)
      - revoke_ssh_ingress (port 22 unrestricted 0.0.0.0/0 or ::/0)
      - revoke_rdp_ingress (port 3389 unrestricted 0.0.0.0/0 or ::/0)
      - revoke_all_traffic_ingress (protocol -1 unrestricted 0.0.0.0/0 or ::/0)
    """
    clean_action = str(action or "").strip().lower()
    clean_group_id = str(group_id or "").strip()
    clean_role = str(user_role or "").strip().lower()

    if not is_valid_security_group_id(clean_group_id):
        raise NetworkControlExecutionError(
            status_code=400,
            code="INVALID_SECURITY_GROUP_ID",
            category="VALIDATION",
            message=f"Invalid security group ID '{group_id}'. Expected format 'sg-xxxxxxxx'.",
        )

    if clean_action not in ALLOWED_NETWORK_MUTATION_ACTIONS:
        raise NetworkControlExecutionError(
            status_code=400,
            code="UNSUPPORTED_ACTION",
            category="VALIDATION",
            message=f"Action '{action}' is not supported. Allowed actions: {', '.join(sorted(ALLOWED_NETWORK_MUTATION_ACTIONS))}",
        )

    if clean_role not in MUTATION_ALLOWED_ROLES:
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"SECURITY_GROUP_{clean_action.upper()}_DENIED",
            actor_type=ACTOR_USER,
            result=RESULT_DENIED,
            details={
                "group_id": clean_group_id,
                "action": clean_action,
                "role": clean_role,
                "reason": "Only Owner and Admin roles can modify security group rules.",
            },
        )
        raise NetworkControlExecutionError(
            status_code=403,
            code="ROLE_NOT_AUTHORIZED",
            category="AUTHORIZATION",
            message="Only organization Owners and Admins are authorized to perform network remediation actions.",
            audit_recorded=True,
        )

    if confirmed is not True:
        raise NetworkControlExecutionError(
            status_code=409,
            code="CONFIRMATION_REQUIRED",
            category="VALIDATION",
            message="Explicit confirmation is required to execute network remediation actions.",
        )

    # Fetch connected AWS Account
    aws_account = get_account(
        account_id,
        organization_id=organization_id,
    )
    if not aws_account:
        raise NetworkControlExecutionError(
            status_code=404,
            code="AWS_ACCOUNT_NOT_FOUND",
            category="ACCOUNT_NOT_FOUND",
            message="Connected AWS account not found for this organization.",
        )

    account_status = _safe_string(aws_account.get("status")).lower()
    if account_status != "connected":
        raise NetworkControlExecutionError(
            status_code=400,
            code="ACCOUNT_NOT_CONNECTED",
            category="ACCOUNT_VALIDATION",
            message=f"AWS account is not connected (status: '{account_status or 'unknown'}'). Action rejected.",
        )

    # Verify organization remediation setting for VPC / Security Groups
    from app.models.remediation_settings import is_remediation_enabled
    if not is_remediation_enabled(organization_id, account_id, "vpc"):
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=EVENT_REMEDIATION_AUTHORIZATION,
            action=f"SECURITY_GROUP_{clean_action.upper()}_DENIED",
            actor_type=ACTOR_USER,
            result=RESULT_DENIED,
            details={
                "group_id": clean_group_id,
                "action": clean_action,
                "role": clean_role,
                "reason": "Remediation setting is disabled for VPC / Security Groups.",
                "error_code": "REMEDIATION_SETTING_DISABLED",
            },
        )
        raise NetworkControlExecutionError(
            status_code=403,
            code="REMEDIATION_SETTING_DISABLED",
            category="AUTHORIZATION",
            message="Remediation is disabled for VPC / Security Groups for this account.",
            audit_recorded=True,
        )

    target_region = str(region or aws_account.get("region") or "us-east-1").strip()
    if not validate_aws_region(target_region):
        target_region = "us-east-1"

    stored_aws_account_id = _safe_string(
        aws_account.get("aws_account_id") or aws_account.get("account") or ""
    )
    role_arn = _safe_string(aws_account.get("role_arn"))
    if not role_arn:
        raise NetworkControlExecutionError(
            status_code=400,
            code="AWS_ACCOUNT_INCOMPLETE",
            category="ACCOUNT_VALIDATION",
            message="Connected AWS account is missing role_arn configuration.",
        )

    # Assume AWS Role
    try:
        session = assume_aws_role(role_arn, region=target_region)
    except Exception as assume_err:
        logger.warning("AWS Role assumption failed for SG control: %s", assume_err)
        raise NetworkControlExecutionError(
            status_code=403,
            code="AWS_ASSUME_ROLE_FAILED",
            category="AUTHENTICATION",
            message="Failed to assume AWS IAM role. Verify trust policy configuration.",
        ) from assume_err

    # Verify STS Identity
    try:
        verify_aws_account(session, stored_aws_account_id)
    except PermissionError as perm_err:
        raise NetworkControlExecutionError(
            status_code=403,
            code="AWS_ACCOUNT_MISMATCH",
            category="AUTHORIZATION",
            message=str(perm_err),
        ) from perm_err
    except Exception as exc:
        raise NetworkControlExecutionError(
            status_code=403,
            code="AWS_VERIFY_IDENTITY_FAILED",
            category="AUTHORIZATION",
            message="Unable to verify AWS account identity.",
        ) from exc

    clients = get_aws_clients(session)
    ec2_client = clients.get("ec2")
    if not ec2_client:
        raise NetworkControlExecutionError(
            status_code=502,
            code="AWS_CLIENT_UNAVAILABLE",
            category="INTERNAL_ERROR",
            message="Failed to instantiate AWS EC2 client.",
        )

    # 1. Describe Security Group before action
    try:
        desc_resp = ec2_client.describe_security_groups(GroupIds=[clean_group_id])
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        if code in ("InvalidGroup.NotFound", "InvalidGroupId.Malformed"):
            raise NetworkControlExecutionError(
                status_code=404,
                code="SECURITY_GROUP_NOT_FOUND",
                category="RESOURCE_NOT_FOUND",
                message=f"Security group '{clean_group_id}' was not found in region {target_region}.",
            ) from client_err
        elif code in ("AccessDenied", "UnauthorizedOperation"):
            raise NetworkControlExecutionError(
                status_code=403,
                code="AWS_ACCESS_DENIED",
                category="PERMISSION_DENIED",
                message=f"AccessDenied: Lacks permission to describe security group '{clean_group_id}'.",
            ) from client_err
        else:
            raise NetworkControlExecutionError(
                status_code=502,
                code=code,
                category="AWS_SERVICE_ERROR",
                message=f"AWS error describing security group: [{code}] {str(client_err)}",
            ) from client_err

    groups = desc_resp.get("SecurityGroups", []) or []
    if not groups:
        raise NetworkControlExecutionError(
            status_code=404,
            code="SECURITY_GROUP_NOT_FOUND",
            category="RESOURCE_NOT_FOUND",
            message=f"Security group '{clean_group_id}' was not found.",
        )

    target_sg = groups[0]
    owner_id = _safe_string(target_sg.get("OwnerId"))
    if stored_aws_account_id and owner_id and owner_id != stored_aws_account_id:
        raise NetworkControlExecutionError(
            status_code=403,
            code="SECURITY_GROUP_ACCOUNT_MISMATCH",
            category="RESOURCE_VALIDATION",
            message=f"Security group '{clean_group_id}' does not belong to connected AWS account.",
        )

    # Build the exact IpPermission to revoke
    ip_permissions_to_revoke: List[Dict[str, Any]] = []
    is_egress = clean_action == "revoke_egress_rule"

    if clean_action == "revoke_ssh_ingress":
        target_rule = {
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
        }
        # Check presence
        found = False
        for p in (target_sg.get("IpPermissions") or []):
            if p.get("IpProtocol", "").lower() == "tcp" and p.get("FromPort") == 22 and p.get("ToPort") == 22:
                matching_p: Dict[str, Any] = {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22}
                has_sub = False
                ipv4s = [r for r in (p.get("IpRanges") or []) if r.get("CidrIp") == "0.0.0.0/0"]
                if ipv4s:
                    matching_p["IpRanges"] = ipv4s
                    has_sub = True
                ipv6s = [r for r in (p.get("Ipv6Ranges") or []) if r.get("CidrIpv6") == "::/0"]
                if ipv6s:
                    matching_p["Ipv6Ranges"] = ipv6s
                    has_sub = True
                if has_sub:
                    ip_permissions_to_revoke.append(matching_p)
                    found = True
        if not found:
            raise NetworkControlExecutionError(
                status_code=409,
                code="TARGET_RULE_NOT_FOUND",
                category="RESOURCE_VALIDATION",
                message="No open SSH (port 22) rule to 0.0.0.0/0 or ::/0 was found in this security group.",
            )

    elif clean_action == "revoke_rdp_ingress":
        found = False
        for p in (target_sg.get("IpPermissions") or []):
            if p.get("IpProtocol", "").lower() == "tcp" and p.get("FromPort") == 3389 and p.get("ToPort") == 3389:
                matching_p = {"IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389}
                has_sub = False
                ipv4s = [r for r in (p.get("IpRanges") or []) if r.get("CidrIp") == "0.0.0.0/0"]
                if ipv4s:
                    matching_p["IpRanges"] = ipv4s
                    has_sub = True
                ipv6s = [r for r in (p.get("Ipv6Ranges") or []) if r.get("CidrIpv6") == "::/0"]
                if ipv6s:
                    matching_p["Ipv6Ranges"] = ipv6s
                    has_sub = True
                if has_sub:
                    ip_permissions_to_revoke.append(matching_p)
                    found = True
        if not found:
            raise NetworkControlExecutionError(
                status_code=409,
                code="TARGET_RULE_NOT_FOUND",
                category="RESOURCE_VALIDATION",
                message="No open RDP (port 3389) rule to 0.0.0.0/0 or ::/0 was found in this security group.",
            )

    elif clean_action == "revoke_all_traffic_ingress":
        found = False
        for p in (target_sg.get("IpPermissions") or []):
            if str(p.get("IpProtocol")) == "-1":
                matching_p = {"IpProtocol": "-1"}
                has_sub = False
                ipv4s = [r for r in (p.get("IpRanges") or []) if r.get("CidrIp") == "0.0.0.0/0"]
                if ipv4s:
                    matching_p["IpRanges"] = ipv4s
                    has_sub = True
                ipv6s = [r for r in (p.get("Ipv6Ranges") or []) if r.get("CidrIpv6") == "::/0"]
                if ipv6s:
                    matching_p["Ipv6Ranges"] = ipv6s
                    has_sub = True
                if has_sub:
                    ip_permissions_to_revoke.append(matching_p)
                    found = True
        if not found:
            raise NetworkControlExecutionError(
                status_code=409,
                code="TARGET_RULE_NOT_FOUND",
                category="RESOURCE_VALIDATION",
                message="No unrestricted all-traffic (-1) ingress rule to 0.0.0.0/0 or ::/0 was found in this security group.",
            )

    elif clean_action in ("revoke_ingress_rule", "revoke_egress_rule"):
        if not rule_spec or not isinstance(rule_spec, dict):
            raise NetworkControlExecutionError(
                status_code=400,
                code="RULE_SPEC_REQUIRED",
                category="VALIDATION",
                message="rule_spec is required for specific rule revocation.",
            )
        protocol = str(rule_spec.get("protocol", "tcp")).lower()
        from_port = rule_spec.get("from_port")
        to_port = rule_spec.get("to_port")
        cidr = str(rule_spec.get("cidr") or "").strip()
        cidr_ipv6 = str(rule_spec.get("cidr_ipv6") or "").strip()
        source_group_id = str(rule_spec.get("source_group_id") or "").strip()

        perm: Dict[str, Any] = {"IpProtocol": protocol}
        if protocol != "-1":
            if from_port is not None:
                perm["FromPort"] = int(from_port)
            if to_port is not None:
                perm["ToPort"] = int(to_port)
        if cidr:
            perm["IpRanges"] = [{"CidrIp": cidr}]
        if cidr_ipv6:
            perm["Ipv6Ranges"] = [{"CidrIpv6": cidr_ipv6}]
        if source_group_id:
            perm["UserIdGroupPairs"] = [{"GroupId": source_group_id}]

        if not cidr and not cidr_ipv6 and not source_group_id:
            raise NetworkControlExecutionError(
                status_code=400,
                code="INVALID_RULE_SPEC",
                category="VALIDATION",
                message="rule_spec must contain a valid cidr, cidr_ipv6, or source_group_id.",
            )
        ip_permissions_to_revoke.append(perm)

    # 2. Record Start Audit Event
    record_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
        action=f"SECURITY_GROUP_{clean_action.upper()}",
        actor_type=ACTOR_USER,
        result=RESULT_SUCCESS,
        details={
            "group_id": clean_group_id,
            "region": target_region,
            "action": clean_action,
            "permissions_to_revoke": ip_permissions_to_revoke,
        },
    )

    # 3. Perform Mutation
    try:
        if is_egress:
            ec2_client.revoke_security_group_egress(
                GroupId=clean_group_id,
                IpPermissions=ip_permissions_to_revoke,
            )
        else:
            ec2_client.revoke_security_group_ingress(
                GroupId=clean_group_id,
                IpPermissions=ip_permissions_to_revoke,
            )
    except ClientError as client_err:
        code = client_err.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = client_err.response.get("Error", {}).get("Message", str(client_err))
        record_event(
            user_id=user_id,
            organization_id=organization_id,
            event_type=EVENT_RESOURCE_CONTROL_FAILED,
            action=f"SECURITY_GROUP_{clean_action.upper()}",
            actor_type=ACTOR_USER,
            result=RESULT_FAILURE,
            details={
                "group_id": clean_group_id,
                "error_code": code,
                "error_message": msg,
            },
        )
        raise NetworkControlExecutionError(
            status_code=502,
            code=code,
            category="AWS_MUTATION_FAILED",
            message=f"AWS Security Group rule revocation failed: [{code}] {msg}",
            audit_recorded=True,
        ) from client_err

    # 4. Post-Action Verification
    try:
        verify_resp = ec2_client.describe_security_groups(GroupIds=[clean_group_id])
        verified_sgs = verify_resp.get("SecurityGroups", []) or []
        verified_item = normalize_security_group(verified_sgs[0], fallback_region=target_region) if verified_sgs else None
    except Exception as verify_err:
        logger.warning("Post-action verification describe call failed: %s", verify_err)
        verified_item = None

    # Record Success Audit Event
    record_event(
        user_id=user_id,
        organization_id=organization_id,
        event_type=EVENT_RESOURCE_CONTROL_COMPLETED,
        action=f"SECURITY_GROUP_{clean_action.upper()}",
        actor_type=ACTOR_USER,
        result=RESULT_SUCCESS,
        details={
            "group_id": clean_group_id,
            "region": target_region,
            "action": clean_action,
            "revoked_rules": ip_permissions_to_revoke,
            "verified": bool(verified_item),
        },
    )

    return {
        "success": True,
        "action": clean_action,
        "group_id": clean_group_id,
        "region": target_region,
        "revoked_rules": ip_permissions_to_revoke,
        "security_group": verified_item,
        "message": f"Successfully revoked rule(s) from security group {clean_group_id}.",
    }
