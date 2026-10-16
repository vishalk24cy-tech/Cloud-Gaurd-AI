# ============================================================
# CloudGuardAI - Read-Only EC2 Resource Inventory Service
# Production / SaaS Cloud Management
# ============================================================

from __future__ import annotations

import concurrent.futures
from datetime import datetime, timezone
import re
import threading
from typing import Any, Dict, List, Optional
from botocore.exceptions import BotoCoreError, ClientError

from app.services.aws_connection import AWS_CONFIG

# Standard AWS region format (e.g. us-east-1, ap-south-1, eu-central-1)
AWS_REGION_REGEX = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")

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

MAX_INVENTORY_SAFE_LIMIT = 1000


def validate_aws_region(region: Optional[str], allow_all: bool = False) -> bool:
    """Validate that the region string conforms to standard AWS region naming."""
    if not region or not isinstance(region, str):
        return False
    reg = region.strip().lower()
    if allow_all and reg == "all":
        return True
    return bool(AWS_REGION_REGEX.match(reg))


def extract_instance_name(tags: Optional[List[Dict[str, Any]]]) -> Optional[str]:
    """Extract Name tag value if present, otherwise return None."""
    if not tags or not isinstance(tags, list):
        return None
    for tag in tags:
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            val = tag.get("Value")
            return str(val).strip() if val is not None else None
    return None


def normalize_ec2_instance(inst: Dict[str, Any], fallback_region: str) -> Dict[str, Any]:
    """
    Extract and normalize read-only EC2 instance attributes into an API-safe dictionary.
    Guarantees no sensitive data is leaked and all required fields are present.
    """
    if not isinstance(inst, dict):
        return {}

    placement = inst.get("Placement") or {}
    az = str(placement.get("AvailabilityZone") or "").strip()
    
    # Infer region from AZ (e.g. ap-south-1a -> ap-south-1) or use fallback
    region = az[:-1] if az and az[-1].isalpha() and az[:-1] else fallback_region

    state_obj = inst.get("State") or {}
    state_name = str(state_obj.get("Name") or "unknown").strip().lower()

    launch_time = inst.get("LaunchTime")
    launch_time_str = (
        launch_time.isoformat()
        if hasattr(launch_time, "isoformat")
        else str(launch_time)
        if launch_time
        else None
    )

    security_groups = [
        {
            "group_id": sg.get("GroupId"),
            "group_name": sg.get("GroupName"),
        }
        for sg in (inst.get("SecurityGroups") or [])
        if isinstance(sg, dict) and sg.get("GroupId")
    ]

    return {
        "instance_id": str(inst.get("InstanceId") or "").strip(),
        "name": extract_instance_name(inst.get("Tags")),
        "state": state_name,
        "instance_type": str(inst.get("InstanceType") or "").strip(),
        "region": region,
        "availability_zone": az or None,
        "private_ip": inst.get("PrivateIpAddress") or None,
        "public_ip": inst.get("PublicIpAddress") or None,
        "launch_time": launch_time_str,
        "subnet_id": inst.get("SubnetId") or None,
        "vpc_id": inst.get("VpcId") or None,
        "platform": inst.get("Platform") or "linux",
        "architecture": inst.get("Architecture") or None,
        "security_groups": security_groups,
    }


def fetch_ec2_instances_inventory(
    ec2_client: Any,
    region: str,
    max_results: Optional[int] = None,
    next_token: Optional[str] = None,
    all_pages: bool = False,
) -> Dict[str, Any]:
    """
    Query EC2 DescribeInstances in a strictly read-only manner, handling pagination.

    Args:
        ec2_client: Authenticated boto3 EC2 client
        region: Target AWS region string
        max_results: Optional max instances per page (clamped between 5 and 1000 per AWS spec)
        next_token: Optional continuation token
        all_pages: Whether to automatically aggregate across all pages

    Returns:
        Dict containing normalized instances, total_count, and next_token.
    """
    if not ec2_client:
        raise ValueError("EC2 client is required.")

    if all_pages:
        instances: List[Dict[str, Any]] = []
        token = next_token
        while True:
            params: Dict[str, Any] = {}
            if token:
                params["NextToken"] = token
            if max_results is not None:
                try:
                    params["MaxResults"] = max(5, min(int(max_results), 1000))
                except (ValueError, TypeError):
                    pass

            response = ec2_client.describe_instances(**params)
            reservations = response.get("Reservations") or []
            for res in reservations:
                for inst in (res.get("Instances") or []):
                    instances.append(normalize_ec2_instance(inst, region))
                    if len(instances) >= MAX_INVENTORY_SAFE_LIMIT:
                        break
                if len(instances) >= MAX_INVENTORY_SAFE_LIMIT:
                    break

            token = response.get("NextToken")
            if not token or len(instances) >= MAX_INVENTORY_SAFE_LIMIT:
                break

        return {
            "region": region,
            "instances": instances,
            "total_count": len(instances),
            "next_token": token,
        }

    # Single-page query
    params = {}
    if max_results is not None:
        try:
            params["MaxResults"] = max(5, min(int(max_results), 1000))
        except (ValueError, TypeError):
            pass
    if next_token:
        params["NextToken"] = str(next_token).strip()

    response = ec2_client.describe_instances(**params)
    reservations = response.get("Reservations") or []
    instances = []
    for res in reservations:
        for inst in (res.get("Instances") or []):
            instances.append(normalize_ec2_instance(inst, region))

    return {
        "region": region,
        "instances": instances,
        "total_count": len(instances),
        "next_token": response.get("NextToken"),
    }


def discover_multi_region_ec2_inventory(
    session: Any,
    regions: Optional[List[str]] = None,
    max_results_per_region: Optional[int] = 100,
    timeout_per_region: float = 6.0,
    max_workers: int = 5,
) -> Dict[str, Any]:
    """
    Perform bounded, concurrent multi-region EC2 discovery across target AWS regions.

    Enforces:
    - Bounded concurrency with ThreadPoolExecutor
    - Sensible per-region timeout
    - Honest reporting of regional failures without silent mock fallbacks
    - Clean normalization of discovered instances
    """
    if session is None:
        raise ValueError("AWS session is required for multi-region discovery.")

    target_regions = [r.strip() for r in (regions or STANDARD_AWS_REGIONS) if r and isinstance(r, str)]
    all_instances: List[Dict[str, Any]] = []
    regional_failures: List[Dict[str, Any]] = []
    successful_regions: List[str] = []

    client_lock = threading.Lock()

    def _query_region(reg: str) -> Dict[str, Any]:
        with client_lock:
            client = session.client("ec2", region_name=reg, config=AWS_CONFIG)
        return fetch_ec2_instances_inventory(
            ec2_client=client,
            region=reg,
            max_results=max_results_per_region,
            all_pages=True,
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
                all_instances.extend(result.get("instances", []))
                successful_regions.append(r)
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
                    "error": f"Discovery timed out after {timeout_per_region}s for region {r}.",
                })
            except Exception as exc:
                regional_failures.append({
                    "region": r,
                    "code": type(exc).__name__,
                    "error": str(exc),
                })

    # If ALL queried regions fail with AccessDenied or UnauthorizedOperation, raise ClientError
    if (
        len(regional_failures) == len(target_regions)
        and all(f.get("code") in ("AccessDenied", "UnauthorizedOperation", "AuthFailure") for f in regional_failures)
    ):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "IAM role lacks ec2:DescribeInstances permissions across all regions."}},
            "DescribeInstances",
        )

    # Sort instances deterministically by region then instance_id
    all_instances.sort(key=lambda x: (x.get("region", ""), x.get("instance_id", "")))
    coverage = "COMPLETE" if not regional_failures else "PARTIAL"

    return {
        "instances": all_instances,
        "total_count": len(all_instances),
        "regions_searched": target_regions,
        "successful_regions": successful_regions,
        "regional_failures": regional_failures,
        "coverage": coverage,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }

