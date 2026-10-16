"""CloudGuardAI AWS Relationship Intelligence - Phase 2.2.

Commercial-grade, evidence-backed relationship discovery. The service is
fail-closed: an edge is only emitted when AWS explicitly returns the
relationship. Permission failures are represented as incomplete discovery.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

MAX_INSTANCES = 5000
MAX_RESOURCES_PER_TYPE = 5000
MAX_RELATIONSHIPS = 20000
SOURCE = "AWS_API_RELATIONSHIP_ENRICHMENT"


def _text(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _norm_type(value: Any) -> str:
    return _text(value).upper().replace("-", "_").replace(" ", "_")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe(callable_obj, default):
    try:
        return callable_obj()
    except Exception:
        return default


def _pages(client_method, result_key: str, **kwargs) -> List[Dict[str, Any]]:
    """Paginate boto3 responses where possible; safely fall back to one call."""
    items: List[Dict[str, Any]] = []
    try:
        paginator = client_method.__self__.get_paginator(client_method.__name__)
        for page in paginator.paginate(**kwargs):
            values = page.get(result_key, []) or []
            if isinstance(values, list):
                items.extend(x for x in values if isinstance(x, dict))
                if len(items) >= MAX_RESOURCES_PER_TYPE:
                    break
        return items[:MAX_RESOURCES_PER_TYPE]
    except Exception:
        response = _safe(lambda: client_method(**kwargs), {})
        values = response.get(result_key, []) if isinstance(response, dict) else []
        return values[:MAX_RESOURCES_PER_TYPE] if isinstance(values, list) else []


def _evidence(api: str, **extra: Any) -> Dict[str, Any]:
    data = {
        "source": SOURCE,
        "verified": True,
        "retrieved_at": _now(),
        "source_api": api,
    }
    for key, value in extra.items():
        if value not in (None, "", [], {}):
            data[key] = value
    return data


def _node(node_type: str, resource_id: str, name: str = "", arn: str = "", service: str = "") -> Dict[str, Any]:
    return {
        "node_type": _norm_type(node_type),
        "resource_id": _text(resource_id),
        "resource_name": _text(name) or _text(resource_id),
        "resource_arn": _text(arn) or None,
        "service": _text(service).upper() or None,
        "signals": {},
    }


def _rel(source_type: str, source_id: str, target_type: str, target_id: str, relationship_type: str, evidence: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_type": _norm_type(source_type),
        "source_id": _text(source_id),
        "target_type": _norm_type(target_type),
        "target_id": _text(target_id),
        "relationship_type": _norm_type(relationship_type),
        "evidence": evidence,
    }


def _role_name_from_arn(arn: str) -> str:
    return _text(arn).rsplit("/", 1)[-1] if _text(arn) else ""


def _instance_pages(ec2) -> List[Dict[str, Any]]:
    reservations = _safe(lambda: _pages(ec2.describe_instances, "Reservations"), [])
    instances = []
    for reservation in reservations:
        instances.extend(reservation.get("Instances", []) or [])
    return [x for x in instances if isinstance(x, dict)][:MAX_INSTANCES]


def collect_relationship_inventory(ec2, iam, rds=None, lambda_client=None, account_id: str = "", region: str = "") -> Dict[str, Any]:
    inventory = {
        "version": "2.2",
        "source": SOURCE,
        "retrieved_at": _now(),
        "account_id": _text(account_id),
        "region": _text(region),
        "instances": {},
        "security_groups": {},
        "roles": {},
        "policies": {},
        "users": {},
        "lambdas": {},
        "rds": {},
        "vpcs": {},
        "subnets": {},
        "internet_gateways": {},
        "route_tables": {},
        "relationships": [],
        "discovery": {"complete": True, "warnings": []},
    }

    relationships = inventory["relationships"]
    def add_rel(*args):
        if len(relationships) >= MAX_RELATIONSHIPS:
            return
        relationships.append(_rel(*args))

    # EC2 / SG / IAM instance profile / role / policy
    instances = _instance_pages(ec2)
    for instance in instances:
        iid = _text(instance.get("InstanceId"))
        if not iid:
            continue
        instance_arn = f"arn:aws:ec2:{region}:{account_id}:instance/{iid}" if region and account_id else f"arn:aws:ec2:*:*:instance/{iid}"
        node = _node("EC2", iid, iid, instance_arn, "EC2")
        node.update({"vpc_id": _text(instance.get("VpcId")), "subnet_id": _text(instance.get("SubnetId"))})
        inventory["instances"][iid] = node

        for group in instance.get("SecurityGroups", []) or []:
            sgid = _text(group.get("GroupId"))
            if not sgid:
                continue
            inventory["security_groups"].setdefault(sgid, _node("SECURITY_GROUP", sgid, group.get("GroupName"), service="EC2"))
            add_rel("SECURITY_GROUP", sgid, "EC2", iid, "EXPOSES", _evidence("ec2.describe_instances", security_group_id=sgid, instance_id=iid))

        profile = instance.get("IamInstanceProfile") or {}
        profile_arn = _text(profile.get("Arn"))
        if profile_arn:
            profile_name = profile_arn.rsplit("/", 1)[-1]
            profile_obj = _safe(lambda: iam.get_instance_profile(InstanceProfileName=profile_name).get("InstanceProfile", {}), {})
            for role in profile_obj.get("Roles", []) or []:
                role_arn = _text(role.get("Arn")); role_name = _text(role.get("RoleName"))
                if not role_arn and not role_name:
                    continue
                role_id = role_arn or role_name
                inventory["roles"].setdefault(role_id, _node("IAM_ROLE", role_id, role_name, role_arn, "IAM"))
                add_rel("EC2", iid, "IAM_ROLE", role_id, "ASSUMES_ROLE", _evidence("iam.get_instance_profile", instance_id=iid, instance_profile_arn=profile_arn, role_arn=role_arn))
                if role_name:
                    attached = _safe(lambda: _pages(iam.list_attached_role_policies, "AttachedPolicies", RoleName=role_name), [])
                    for policy in attached:
                        parn = _text(policy.get("PolicyArn")); pname = _text(policy.get("PolicyName"))
                        if not parn and not pname:
                            continue
                        pid = parn or pname
                        inventory["policies"].setdefault(pid, _node("IAM_POLICY", pid, pname, parn, "IAM"))
                        add_rel("IAM_ROLE", role_id, "IAM_POLICY", pid, "GRANTS", _evidence("iam.list_attached_role_policies", role_name=role_name, role_arn=role_arn, policy_arn=parn))

    # IAM users -> attached managed policies
    users = _safe(lambda: _pages(iam.list_users, "Users"), [])
    for user in users:
        uname = _text(user.get("UserName")); uarn = _text(user.get("Arn"))
        if not uname:
            continue
        inventory["users"][uname] = _node("IAM_USER", uname, uname, uarn, "IAM")
        attached = _safe(lambda: _pages(iam.list_attached_user_policies, "AttachedPolicies", UserName=uname), [])
        for policy in attached:
            parn = _text(policy.get("PolicyArn")); pname = _text(policy.get("PolicyName"))
            pid = parn or pname
            if not pid:
                continue
            inventory["policies"].setdefault(pid, _node("IAM_POLICY", pid, pname, parn, "IAM"))
            add_rel("IAM_USER", uname, "IAM_POLICY", pid, "GRANTS", _evidence("iam.list_attached_user_policies", user_name=uname, policy_arn=parn))

    # Lambda -> execution role; Lambda VPC -> security groups/subnets
    if lambda_client is not None:
        functions = _safe(lambda: _pages(lambda_client.list_functions, "Functions"), [])
        for fn in functions:
            name = _text(fn.get("FunctionName")); arn = _text(fn.get("FunctionArn"))
            if not name:
                continue
            inventory["lambdas"][name] = _node("LAMBDA_FUNCTION", name, name, arn, "LAMBDA")
            role_arn = _text(fn.get("Role"))
            if role_arn:
                role_id = role_arn
                role_name = _role_name_from_arn(role_arn)
                inventory["roles"].setdefault(role_id, _node("IAM_ROLE", role_id, role_name, role_arn, "IAM"))
                add_rel("LAMBDA_FUNCTION", name, "IAM_ROLE", role_id, "ASSUMES_ROLE", _evidence("lambda.list_functions", function_name=name, role_arn=role_arn))
            vpc = fn.get("VpcConfig") or {}
            for sgid in vpc.get("SecurityGroupIds", []) or []:
                inventory["security_groups"].setdefault(sgid, _node("SECURITY_GROUP", sgid, sgid, service="EC2"))
                add_rel("SECURITY_GROUP", sgid, "LAMBDA_FUNCTION", name, "EXPOSES", _evidence("lambda.list_functions", function_name=name, security_group_id=sgid))
            for subnet_id in vpc.get("SubnetIds", []) or []:
                inventory["subnets"].setdefault(subnet_id, _node("SUBNET", subnet_id, subnet_id, service="VPC"))
                add_rel("SUBNET", subnet_id, "LAMBDA_FUNCTION", name, "HOSTS", _evidence("lambda.list_functions", function_name=name, subnet_id=subnet_id))

    # RDS -> security groups (relationship source is the DB instance)
    if rds is not None:
        dbs = _safe(lambda: _pages(rds.describe_db_instances, "DBInstances"), [])
        for db in dbs:
            did = _text(db.get("DBInstanceIdentifier")); darn = _text(db.get("DBInstanceArn"))
            if not did:
                continue
            inventory["rds"][did] = _node("RDS_INSTANCE", did, did, darn, "RDS")
            for sg in (db.get("VpcSecurityGroups") or []):
                sgid = _text(sg.get("VpcSecurityGroupId"))
                if sgid:
                    inventory["security_groups"].setdefault(sgid, _node("SECURITY_GROUP", sgid, sgid, service="EC2"))
                    add_rel("SECURITY_GROUP", sgid, "RDS_INSTANCE", did, "EXPOSES", _evidence("rds.describe_db_instances", db_instance_id=did, security_group_id=sgid))

    # VPC topology and public internet gateway relationships.
    vpcs = _safe(lambda: _pages(ec2.describe_vpcs, "Vpcs"), [])
    for vpc in vpcs:
        vid = _text(vpc.get("VpcId"))
        if vid:
            inventory["vpcs"][vid] = _node("VPC", vid, vpc.get("Tags", [{}])[0].get("Value", "") if vpc.get("Tags") else vid, service="VPC")
    subnets = _safe(lambda: _pages(ec2.describe_subnets, "Subnets"), [])
    for subnet in subnets:
        sid = _text(subnet.get("SubnetId")); vid = _text(subnet.get("VpcId"))
        if sid:
            inventory["subnets"][sid] = _node("SUBNET", sid, sid, service="VPC")
            if vid:
                add_rel("VPC", vid, "SUBNET", sid, "CONTAINS", _evidence("ec2.describe_subnets", vpc_id=vid, subnet_id=sid))
    igws = _safe(lambda: _pages(ec2.describe_internet_gateways, "InternetGateways"), [])
    for igw in igws:
        gid = _text(igw.get("InternetGatewayId"))
        if not gid:
            continue
        inventory["internet_gateways"][gid] = _node("RESOURCE", gid, gid, service="VPC")
        for att in igw.get("Attachments", []) or []:
            vid = _text(att.get("VpcId"))
            if vid:
                add_rel("VPC", vid, "RESOURCE", gid, "CONNECTED_TO", _evidence("ec2.describe_internet_gateways", vpc_id=vid, internet_gateway_id=gid, state=att.get("State")))

    # Explicitly mark internet exposure for public SG rules. This is evidence,
    # not an assertion that the workload is exploitable.
    sgs = _safe(lambda: _pages(ec2.describe_security_groups, "SecurityGroups"), [])
    for sg in sgs:
        sgid = _text(sg.get("GroupId"))
        if not sgid:
            continue
        inventory["security_groups"].setdefault(sgid, _node("SECURITY_GROUP", sgid, sg.get("GroupName"), service="EC2"))
        for perm in sg.get("IpPermissions", []) or []:
            for ip in perm.get("IpRanges", []) or []:
                if _text(ip.get("CidrIp")) == "0.0.0.0/0":
                    add_rel("INTERNET", "PUBLIC_INTERNET", "SECURITY_GROUP", sgid, "EXPOSES", _evidence("ec2.describe_security_groups", security_group_id=sgid, protocol=perm.get("IpProtocol"), from_port=perm.get("FromPort"), to_port=perm.get("ToPort"), cidr="0.0.0.0/0"))
                    break

    if len(relationships) >= MAX_RELATIONSHIPS:
        inventory["discovery"]["warnings"].append("Relationship limit reached; graph was bounded for safety.")
        inventory["discovery"]["complete"] = False

    return inventory


def _all_nodes(inventory: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    for key in ("instances", "security_groups", "roles", "policies", "users", "lambdas", "rds", "vpcs", "subnets", "internet_gateways"):
        yield from inventory.get(key, {}).values()


def _rule_matches_internet_edge(finding, edge):
    if not isinstance(finding, dict) or not isinstance(edge, dict):
        return False
    if _norm_type(edge.get("source_type")) != "INTERNET":
        return True
    ev=edge.get("evidence") or {}; fe=finding.get("evidence") or {}; rm=fe.get("rule_match") or {}
    ep=_text(ev.get("protocol")).lower(); fp=_text(fe.get("protocol") or rm.get("protocol")).lower()
    ef=ev.get("from_port"); et=ev.get("to_port")
    ff=fe.get("from_port") if fe.get("from_port") is not None else rm.get("from_port")
    ft=fe.get("to_port") if fe.get("to_port") is not None else rm.get("to_port")
    ec=_text(ev.get("cidr")); fc=_text(fe.get("source") if fe.get("source_type") in {"IPv4_CIDR","CIDR"} else rm.get("source"))
    if ep == "-1": return True
    if ep and fp and ep != fp: return False
    if ef is not None and ff is not None and str(ef) != str(ff): return False
    if et is not None and ft is not None and str(et) != str(ft): return False
    if ec and fc and ec != fc: return False
    return bool(fp or ff is not None or ft is not None or fc)

# Relationships that are safe and useful for bounded attack-path traversal.
# Only scanner-discovered, evidence-backed edges are eligible.
_ATTACK_PATH_RELATIONSHIPS = {
    "EXPOSES",
    "ASSUMES_ROLE",
    "GRANTS",
}
_MAX_ATTACK_PATH_HOPS = 4
_MAX_ATTACK_PATH_EDGES_PER_FINDING = 50

def _edge_key(edge):
    return (
        _norm_type(edge.get("source_type")),
        _text(edge.get("source_id")),
        _norm_type(edge.get("target_type")),
        _text(edge.get("target_id")),
        _norm_type(edge.get("relationship_type")),
    )

def _verified_attack_edge(edge):
    if not isinstance(edge, dict):
        return False
    if _norm_type(edge.get("relationship_type")) not in _ATTACK_PATH_RELATIONSHIPS:
        return False
    evidence = edge.get("evidence") or {}
    return evidence.get("verified") is True

def enrich_findings_with_relationships(findings, inventory):
    """
    Attach a bounded, evidence-backed relationship closure to each finding.

    Direct relationships are filtered to the finding's exact Internet rule.
    Then a small forward closure is built from the finding resource so the
    graph engine can traverse real chains such as:

        INTERNET -> SECURITY_GROUP -> EC2 -> IAM_ROLE -> IAM_POLICY

    This is correlation, not exploitability proof. No edge is fabricated.
    """
    if not isinstance(findings, list):
        return findings

    relationships = inventory.get("relationships", []) or []
    by_resource = {}
    outgoing = {}

    for edge in relationships:
        if not isinstance(edge, dict):
            continue
        key = (_norm_type(edge.get("source_type")), _text(edge.get("source_id")))
        by_resource.setdefault(key, []).append(edge)
        outgoing.setdefault(key, []).append(edge)
        target_key = (_norm_type(edge.get("target_type")), _text(edge.get("target_id")))
        by_resource.setdefault(target_key, []).append(edge)

    node_map = {
        (_norm_type(n.get("node_type")), _text(n.get("resource_id"))): n
        for n in _all_nodes(inventory)
        if isinstance(n, dict)
    }

    out = []

    for finding in findings:
        if not isinstance(finding, dict):
            out.append(finding)
            continue

        graph = dict(finding.get("security_graph") or {})
        resource_id = _text(
            graph.get("resource_id")
            or finding.get("resource")
            or finding.get("security_group_id")
        )
        service = _norm_type(finding.get("service"))
        resource_type = _norm_type(
            graph.get("graph_node_type") or finding.get("resource_type")
        )

        if resource_id.startswith("sg-") or "SECURITY_GROUP" in resource_type:
            resource_type = "SECURITY_GROUP"
        elif service == "EC2" and resource_id.startswith("i-"):
            resource_type = "EC2"

        graph["graph_schema_version"] = "1.1"
        graph["graph_node_type"] = resource_type or "RESOURCE"
        graph["resource_id"] = resource_id or None

        current = []
        related = []
        keys = set()
        rkeys = set()

        def add_edge(edge):
            if not isinstance(edge, dict):
                return
            if _norm_type(edge.get("source_type")) == "INTERNET" and not _rule_matches_internet_edge(finding, edge):
                return
            key = _edge_key(edge)
            if key in keys:
                return
            keys.add(key)
            current.append(edge)

            for typ, rid in (
                (edge.get("source_type"), edge.get("source_id")),
                (edge.get("target_type"), edge.get("target_id")),
            ):
                nt = _norm_type(typ)
                nr = _text(rid)
                if not nr or (nr == resource_id and nt == resource_type):
                    continue
                node = node_map.get((nt, nr))
                if not node:
                    continue
                rk = (nt, nr)
                if rk in rkeys:
                    continue
                item = dict(node)
                item["evidence"] = edge.get("evidence") or {}
                related.append(item)
                rkeys.add(rk)

        # First retain the exact direct relationship set for this finding.
        for edge in by_resource.get((resource_type, resource_id), []):
            add_edge(edge)

        # Then build a bounded forward closure from the finding resource.
        # This is what connects SG -> EC2 -> IAM_ROLE -> IAM_POLICY.
        frontier = {(resource_type, resource_id)} if resource_id else set()
        visited = set(frontier)

        for _hop in range(_MAX_ATTACK_PATH_HOPS):
            next_frontier = set()
            for source_key in frontier:
                for edge in outgoing.get(source_key, []):
                    if not _verified_attack_edge(edge):
                        continue
                    if _norm_type(edge.get("source_type")) == "INTERNET":
                        continue
                    add_edge(edge)
                    target_key = (
                        _norm_type(edge.get("target_type")),
                        _text(edge.get("target_id")),
                    )
                    if target_key not in visited:
                        visited.add(target_key)
                        next_frontier.add(target_key)
                    if len(current) >= _MAX_ATTACK_PATH_EDGES_PER_FINDING:
                        break
                if len(current) >= _MAX_ATTACK_PATH_EDGES_PER_FINDING:
                    break
            frontier = next_frontier
            if not frontier or len(current) >= _MAX_ATTACK_PATH_EDGES_PER_FINDING:
                break

        graph["relationships"] = current[:_MAX_ATTACK_PATH_EDGES_PER_FINDING]
        graph["related_resources"] = related[:500]
        graph["internet_exposed"] = any(
            _norm_type(e.get("relationship_type")) == "EXPOSES"
            and _norm_type(e.get("source_type")) == "INTERNET"
            for e in current
            if isinstance(e, dict)
        )
        graph["relationship_closure"] = {
            "enabled": True,
            "max_hops": _MAX_ATTACK_PATH_HOPS,
            "verified_only": True,
            "relationship_types": sorted(_ATTACK_PATH_RELATIONSHIPS),
        }
        graph.setdefault("privilege_escalation", False)
        graph.setdefault("lateral_movement", False)
        graph.setdefault("attack_path_score", 0)
        graph.setdefault("attack_path", [])
        graph["graph_updated_at"] = datetime.now(timezone.utc)
        finding["security_graph"] = graph
        out.append(finding)

    return out

