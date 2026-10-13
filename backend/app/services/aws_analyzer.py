# ============================================================
# CloudGuardAI - AWS Security Risk Analyzer
# Commercial / Production Risk Engine
# ============================================================

from collections import Counter
import re


# ============================================================
# SEVERITY WEIGHTS
# ============================================================

RISK_ENGINE_VERSION = "2.0"

# Severity budgets define the maximum amount each severity can contribute
# to the 100-point risk budget. This prevents repeated findings from
# collapsing every large environment to a zero score.
SEVERITY_BUDGET = {
    "CRITICAL": 30.0,
    "HIGH": 30.0,
    "MEDIUM": 20.0,
    "LOW": 10.0,
}

# Saturation constants control diminishing returns within each severity.
# A severity can approach its budget but never exceed it.
SEVERITY_SATURATION = {
    "CRITICAL": 1.0,
    "HIGH": 4.0,
    "MEDIUM": 5.0,
    "LOW": 5.0,
}

# Review/unknown findings get a small bounded portion of the remaining
# risk budget rather than behaving like confirmed vulnerabilities.
REVIEW_RISK_BUDGET = 5.0
UNKNOWN_RISK_BUDGET = 5.0

MAX_RISK = 100.0

# Backward-compatible alias for code that may import RISK_WEIGHT.
# New calculations use SEVERITY_BUDGET.
RISK_WEIGHT = SEVERITY_BUDGET


# ============================================================
# RISK SCORE CONFIGURATION
# ============================================================

MAX_RISK = 100

# First finding of a severity has full impact.
# Additional findings of the same severity have diminishing
# impact so a large environment does not automatically reach 0.
ADDITIONAL_FINDING_FACTOR = 0.25

# Information-only findings never affect the score.
INFORMATIONAL_STATUSES = {
    "INFORMATIONAL",
    "INFO",
    "PASS",
    "PASSED",
    "PROTECTED",
    "NOT_APPLICABLE",
}

# Findings requiring human review have reduced impact.
REVIEW_STATUSES = {
    "REVIEW",
    "WARNING",
}

# Findings representing an actual security problem.
FAILED_STATUSES = {
    "FAILED",
    "FAIL",
    "RISK",
    "ACTIVE",
}

# Findings whose scanner could not determine the state.
UNKNOWN_STATUSES = {
    "UNKNOWN",
}


# ============================================================
# NON-SECURITY / INVENTORY FINDINGS
# ============================================================

def _is_inventory_only_finding(finding):
    """
    Detect findings that describe absence of an AWS resource
    rather than an actual security weakness.

    Examples:
        No RDS database instances were found.
        No Lambda functions were found.
        No KMS keys were discovered.

    These should be informational instead of vulnerabilities.
    """

    issue = str(
        finding.get(
            "issue",
            ""
        )
    ).strip().lower()

    description = str(
        finding.get(
            "description",
            ""
        )
    ).strip().lower()

    text = f"{issue} {description}"

    inventory_phrases = (
        "no rds database",
        "no rds databases",
        "no lambda function",
        "no lambda functions",
        "no kms key",
        "no kms keys",
        "no database instances",
        "no resources were found",
        "no resources were discovered",
        "no resources found",
        "no resources discovered",
    )

    return any(
        phrase in text
        for phrase in inventory_phrases
    )


# ============================================================
# STATUS NORMALIZATION
# ============================================================

def _normalize_status(finding, severity):
    """
    Normalize scanner status.

    Important:
    absence of an explicit status must NOT automatically turn
    every low-severity informational message into a security
    vulnerability.
    """

    raw_status = str(
        finding.get(
            "status",
            ""
        )
    ).strip().upper()

    if raw_status:
        return raw_status

    if _is_inventory_only_finding(finding):
        return "INFORMATIONAL"

    if severity in (
        "CRITICAL",
        "HIGH",
        "MEDIUM",
    ):
        return "FAILED"

    return "INFORMATIONAL"


# ============================================================
# SERVICE NORMALIZATION
# ============================================================

def _normalize_service(value):
    """
    Normalize service names so equivalent findings can be
    compared across different AWS checkers.
    """

    service = str(
        value or ""
    ).strip().upper()

    aliases = {
        "EC2 SECURITY GROUP": "EC2",
        "VPC SECURITY GROUP": "VPC",
        "SECURITY GROUP": "SECURITY_GROUP",
        "S3 BUCKET": "S3",
        "IAM USER": "IAM",
        "IAM ACCESS KEY": "IAM",
        "IAM USER POLICY": "IAM",
        "CLOUDTRAIL": "CLOUDTRAIL",
        "RDS": "RDS",
        "LAMBDA": "LAMBDA",
        "KMS": "KMS",
    }

    return aliases.get(
        service,
        service
    )


def _infer_service(finding):
    """Infer a checker service when the checker omitted service."""
    if not isinstance(finding, dict):
        return ""

    explicit = _normalize_service(finding.get("service"))
    if explicit:
        return explicit

    resource_type = str(finding.get("resource_type", "")).strip().upper()

    if "EC2" in resource_type and "SECURITY GROUP" in resource_type:
        return "EC2"

    if "VPC" in resource_type and "SECURITY GROUP" in resource_type:
        return "VPC"

    if "SECURITY GROUP" in resource_type and finding.get("security_group_id"):
        return "SECURITY_GROUP"

    return ""


# ============================================================
# PORT EXTRACTION
# ============================================================

def _extract_port(finding):
    """
    Extract a meaningful network port from structured finding
    data or the finding text.
    """

    for key in (
        "port",
        "from_port",
        "to_port",
    ):

        value = finding.get(key)

        if value is not None:

            try:
                return int(value)

            except (
                TypeError,
                ValueError,
            ):
                pass

    text = " ".join(
        str(
            finding.get(
                key,
                ""
            )
        )
        for key in (
            "issue",
            "description",
            "resource",
        )
    ).lower()

    known_ports = (
        22,
        80,
        443,
        3389,
    )

    for port in known_ports:

        if (
            f"port {port}" in text
            or f"({port})" in text
            or f" {port} " in text
        ):
            return port

    return None


# ============================================================
# NETWORK FINDING NORMALIZATION
# ============================================================

def _extract_security_group_id(finding):
    """
    Extract a canonical security-group identifier.

    EC2 and VPC checkers may represent the same security group
    differently (resource, security_group, security_group_id, ARN,
    or inside free-form text). Prefer the AWS sg-* identifier so
    the same logical rule can be recognized across checkers.
    """

    if not isinstance(finding, dict):
        return ""

    candidates = (
        finding.get("security_group_id"),
        finding.get("security_group"),
        finding.get("resource"),
        finding.get("resource_id"),
        finding.get("resource_arn"),
    )

    for value in candidates:
        text = str(value or "").strip()
        if not text:
            continue

        match = re.search(r"\bsg-[0-9a-fA-F]+\b", text)
        if match:
            return match.group(0).lower()

    text = " ".join(
        str(finding.get(key, ""))
        for key in (
            "issue",
            "description",
            "impact",
            "resource",
            "security_group",
            "security_group_id",
        )
    )

    match = re.search(r"\bsg-[0-9a-fA-F]+\b", text)
    return match.group(0).lower() if match else ""


def _extract_protocol(finding):
    """
    Extract a canonical network protocol.
    """

    if not isinstance(finding, dict):
        return ""

    for key in ("protocol", "ip_protocol", "ipProtocol"):
        value = finding.get(key)
        if value is not None and str(value).strip():
            protocol = str(value).strip().lower()
            aliases = {
                "-1": "-1",
                "all": "-1",
                "tcp": "tcp",
                "udp": "udp",
                "icmp": "icmp",
                "icmpv6": "icmpv6",
            }
            return aliases.get(protocol, protocol)

    text = " ".join(
        str(finding.get(key, ""))
        for key in ("issue", "description", "resource")
    ).lower()

    if "all traffic" in text or "all protocols" in text:
        return "-1"
    if "tcp" in text:
        return "tcp"
    if "udp" in text:
        return "udp"

    return ""


def _extract_cidr(finding):
    """
    Extract the public CIDR represented by a network finding.
    """

    if not isinstance(finding, dict):
        return ""

    for key in (
        "cidr",
        "cidr_ip",
        "cidr_ipv4",
        "ipv4_cidr",
        "ipv6_cidr",
        "source",
        "source_cidr",
        "source_ip",
    ):
        value = finding.get(key)
        if value is None:
            continue

        text = str(value).strip()
        if text in {"0.0.0.0/0", "::/0"}:
            return text

    text = " ".join(
        str(finding.get(key, ""))
        for key in (
            "issue",
            "description",
            "impact",
            "resource",
        )
    )

    if "0.0.0.0/0" in text:
        return "0.0.0.0/0"

    if "::/0" in text:
        return "::/0"

    return ""


def _extract_port_range(finding):
    """
    Return a canonical port/range tuple.
    """

    if not isinstance(finding, dict):
        return (None, None)

    from_port = finding.get("from_port")
    to_port = finding.get("to_port")

    if from_port is None:
        from_port = finding.get("port")

    if to_port is None:
        to_port = finding.get("port")

    try:
        from_port = int(from_port) if from_port is not None else None
    except (TypeError, ValueError):
        from_port = None

    try:
        to_port = int(to_port) if to_port is not None else None
    except (TypeError, ValueError):
        to_port = None

    if from_port is not None or to_port is not None:
        return (from_port, to_port)

    port = _extract_port(finding)
    return (port, port)


def _network_issue_family(finding):
    """
    Normalize different descriptions of the same network exposure.

    This deliberately ignores the checker name and severity. A
    severity change or EC2/VPC source must not create a second
    customer finding.
    """

    text = " ".join(
        str(finding.get(key, ""))
        for key in (
            "issue",
            "description",
            "impact",
            "recommendation",
        )
    ).lower()

    if "ssh" in text or "port 22" in text or "(22)" in text:
        return "SSH_EXPOSURE"

    if "rdp" in text or "port 3389" in text or "(3389)" in text:
        return "RDP_EXPOSURE"

    if (
        "port 80" in text
        or "(80)" in text
        or "http" in text
    ):
        return "HTTP_EXPOSURE"

    if (
        "port 443" in text
        or "(443)" in text
        or "https" in text
    ):
        return "HTTPS_EXPOSURE"

    if (
        "all traffic" in text
        or "all ports" in text
        or "all protocols" in text
        or "unrestricted inbound" in text
    ):
        return "UNRESTRICTED_EXPOSURE"

    return "PUBLIC_NETWORK_EXPOSURE"


# ============================================================
# NETWORK FINDING DETECTION
# ============================================================

def _is_network_exposure(finding):
    """
    Determine whether a finding represents public inbound network
    exposure that may be reported by both EC2 and VPC checkers.
    """

    if not isinstance(finding, dict):
        return False

    service = _infer_service(finding)

    if service not in {"EC2", "VPC", "SECURITY_GROUP"}:
        return False

    text = " ".join(
        str(finding.get(key, ""))
        for key in (
            "issue",
            "description",
            "impact",
            "recommendation",
            "resource",
            "security_group",
            "security_group_id",
            "cidr",
            "cidr_ip",
            "source",
        )
    ).lower()

    indicators = (
        "0.0.0.0/0",
        "::/0",
        "open to the internet",
        "open to internet",
        "unrestricted inbound",
        "public inbound",
        "inbound port",
        "ssh",
        "rdp",
        "port 22",
        "port 80",
        "port 443",
        "port 3389",
        "all traffic",
        "all ports",
        "all protocols",
    )

    return any(indicator in text for indicator in indicators)


# ============================================================
# NETWORK DEDUPLICATION KEY
# ============================================================

def _network_dedupe_key(finding):
    """
    Create a canonical identity for one logical security-group
    exposure.

    Priority:
        security-group ID
        port/range
        protocol
        public CIDR
        issue family

    Severity and checker/service are intentionally excluded.
    """

    security_group_id = _extract_security_group_id(finding)

    from_port, to_port = _extract_port_range(finding)

    protocol = _extract_protocol(finding)

    cidr = _extract_cidr(finding)

    family = _network_issue_family(finding)

    if security_group_id:
        resource_identity = security_group_id
    else:
        resource_identity = str(
            finding.get("resource")
            or finding.get("security_group")
            or finding.get("security_group_id")
            or "unknown"
        ).strip().lower()

    return (
        "NETWORK",
        resource_identity,
        from_port,
        to_port,
        protocol,
        cidr,
        family,
    )


# ============================================================
# GENERAL DEDUPLICATION KEY
# ============================================================

def _general_dedupe_key(finding):
    """
    Create a stable logical key for non-network findings.

    Severity is intentionally excluded so a finding changing from
    MEDIUM to HIGH across scans remains the same logical finding.
    """

    service = _normalize_service(
        finding.get("service")
    )

    resource = str(
        finding.get(
            "resource",
            finding.get(
                "user",
                "unknown"
            )
        )
    ).strip().lower()

    control_id = str(
        finding.get(
            "control_id",
            ""
        )
    ).strip().upper()

    issue = str(
        finding.get(
            "issue",
            "unknown"
        )
    ).strip().lower()

    if control_id:
        return (
            "CONTROL",
            service,
            resource,
            control_id,
        )

    return (
        "FINDING",
        service,
        resource,
        issue,
    )


# ============================================================
# FINDING QUALITY / MERGE HELPERS
# ============================================================

_SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _finding_quality(finding):
    """
    Prefer the richer representation when duplicate checker
    records describe the same logical issue.
    """

    score = 0

    for key in (
        "evidence",
        "impact",
        "recommendation",
        "remediation",
        "control_id",
        "protocol",
        "from_port",
        "to_port",
        "cidr",
        "security_group_id",
    ):
        value = finding.get(key)
        if value not in (None, "", [], {}):
            score += 1

    evidence = finding.get("evidence")
    if isinstance(evidence, (dict, list, tuple)):
        score += len(evidence)

    return score


def _merge_duplicate_findings(existing, incoming):
    """
    Merge duplicate checker output into one canonical finding.

    Rules:
      - highest severity wins
      - active/failed state wins over informational state
      - richer evidence is retained
      - missing metadata is filled from the duplicate
      - checker/service identity does not split the finding
    """

    merged = dict(existing)

    existing_severity = str(
        existing.get("severity", "LOW")
    ).strip().upper()

    incoming_severity = str(
        incoming.get("severity", "LOW")
    ).strip().upper()

    if (
        _SEVERITY_RANK.get(incoming_severity, 0)
        > _SEVERITY_RANK.get(existing_severity, 0)
    ):
        merged["severity"] = incoming_severity

    existing_status = str(
        existing.get("status", "")
    ).strip().upper()

    incoming_status = str(
        incoming.get("status", "")
    ).strip().upper()

    status_priority = {
        "FAILED": 5,
        "FAIL": 5,
        "RISK": 5,
        "ACTIVE": 5,
        "REVIEW": 4,
        "WARNING": 4,
        "UNKNOWN": 3,
        "INFORMATIONAL": 1,
        "INFO": 1,
        "PASS": 0,
        "PASSED": 0,
        "PROTECTED": 0,
        "NOT_APPLICABLE": 0,
    }

    if (
        status_priority.get(incoming_status, 0)
        > status_priority.get(existing_status, 0)
    ):
        merged["status"] = incoming_status

    # Prefer the richer record as the base.
    if _finding_quality(incoming) > _finding_quality(existing):
        richer = dict(incoming)

        for key, value in merged.items():
            if key not in richer or richer.get(key) in (None, "", [], {}):
                richer[key] = value

        merged = richer

    else:
        # Fill missing fields from incoming.
        for key, value in incoming.items():
            if merged.get(key) in (None, "", [], {}):
                merged[key] = value

    # Preserve the canonical network identity fields.
    if _is_network_exposure(merged):
        sg_id = _extract_security_group_id(merged)
        if sg_id:
            merged["security_group_id"] = sg_id

        from_port, to_port = _extract_port_range(merged)

        if from_port is not None:
            merged["from_port"] = from_port

        if to_port is not None:
            merged["to_port"] = to_port

        protocol = _extract_protocol(merged)
        if protocol:
            merged["protocol"] = protocol

        cidr = _extract_cidr(merged)
        if cidr:
            merged["cidr"] = cidr

        # Preserve a real checker identity for downstream remediation.
        existing_service = _infer_service(existing)
        incoming_service = _infer_service(incoming)

        if existing_service == "EC2" or incoming_service == "EC2":
            merged["service"] = "EC2"
        elif existing_service == "VPC" or incoming_service == "VPC":
            merged["service"] = "VPC"
        else:
            merged["service"] = "SECURITY_GROUP"

    return merged


# ============================================================
# FINDING DEDUPLICATION
# ============================================================

def _deduplicate_findings(findings):
    """
    Deduplicate findings from overlapping AWS checkers.

    Returns one canonical customer finding per logical issue.
    """

    unique_by_key = {}
    order = []

    for finding in findings:

        if _is_network_exposure(finding):
            key = _network_dedupe_key(finding)
        else:
            key = _general_dedupe_key(finding)

        if key not in unique_by_key:
            unique_by_key[key] = dict(finding)
            order.append(key)
        else:
            unique_by_key[key] = _merge_duplicate_findings(
                unique_by_key[key],
                finding
            )

    return [
        unique_by_key[key]
        for key in order
    ]


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def _normalize_findings(raw_findings):
    """
    Normalize all checker output into a consistent format.
    """

    normalized = []

    for original in raw_findings:

        if not isinstance(
            original,
            dict
        ):
            continue

        finding = dict(
            original
        )

        severity = str(
            finding.get(
                "severity",
                "LOW"
            )
        ).strip().upper()

        if severity not in RISK_WEIGHT:

            severity = "LOW"

        finding["severity"] = severity

        status = _normalize_status(
            finding,
            severity
        )

        # ----------------------------------------------------
        # Convert resource-absence checks to informational.
        # ----------------------------------------------------

        if _is_inventory_only_finding(
            finding
        ):

            status = "INFORMATIONAL"

        finding["status"] = status

        # ----------------------------------------------------
        # Normalize service.
        # ----------------------------------------------------

        finding["service"] = _infer_service(
            finding
        )

        normalized.append(
            finding
        )

    return normalized


# ============================================================
# ACTIVE RISK CHECK
# ============================================================

def _is_active_risk(finding):
    """
    Determine whether a finding should contribute to risk.
    """

    status = str(
        finding.get(
            "status",
            ""
        )
    ).strip().upper()

    if status in INFORMATIONAL_STATUSES:
        return False

    if status in UNKNOWN_STATUSES:
        return True

    if status in REVIEW_STATUSES:
        return True

    if status in FAILED_STATUSES:
        return True

    return False


# ============================================================
# RISK CALCULATION
# ============================================================

def _severity_saturation(count, saturation):
    """
    Convert a finding count into a bounded 0..1 severity utilization.

    Formula:
        1 - exp(-count / saturation)

    This gives the first findings strong impact while ensuring repeated
    findings approach, but never exceed, the severity budget.
    """
    if count <= 0:
        return 0.0

    try:
        count = float(count)
        saturation = max(float(saturation), 0.1)
    except (TypeError, ValueError):
        return 0.0

    return max(0.0, min(1.0, 1.0 - __import__("math").exp(-count / saturation)))


def _calculate_risk_breakdown(findings):
    """
    Calculate the complete deterministic risk model once.

    This function is the single source of truth for:
      - risk_points
      - risk_score
      - risk_contributions

    Confirmed findings consume bounded severity budgets. Review and unknown
    states are separately bounded so uncertainty cannot dominate the score.
    """
    grouped = Counter()
    review_count = 0
    unknown_count = 0

    for finding in findings:
        if not _is_active_risk(finding):
            continue

        severity = str(
            finding.get("severity", "LOW")
        ).strip().upper()

        status = str(
            finding.get("status", "")
        ).strip().upper()

        if status in UNKNOWN_STATUSES:
            unknown_count += 1
        elif status in REVIEW_STATUSES:
            review_count += 1
        else:
            grouped[severity] += 1

    contributions = {}
    total_risk = 0.0

    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = int(grouped.get(severity, 0))
        budget = float(SEVERITY_BUDGET.get(severity, 0.0))
        saturation = float(SEVERITY_SATURATION.get(severity, 1.0))

        utilization = _severity_saturation(count, saturation)
        impact = round(budget * utilization, 2)

        if count:
            # Approximate marginal impact of the first finding and the
            # remaining findings for an understandable audit trail.
            first_utilization = _severity_saturation(1, saturation)
            first_impact = budget * first_utilization
            additional_impact = max(0.0, impact - first_impact)
        else:
            first_impact = 0.0
            additional_impact = 0.0

        contributions[severity.lower()] = {
            "count": count,
            "budget": round(budget, 2),
            "saturation": round(saturation, 2),
            "utilization_percent": round(utilization * 100.0, 2),
            "first_finding_impact": round(first_impact, 2),
            "additional_findings_impact": round(additional_impact, 2),
            "total_impact": impact,
        }

        total_risk += impact

    if review_count:
        review_impact = min(
            REVIEW_RISK_BUDGET,
            REVIEW_RISK_BUDGET
            * _severity_saturation(review_count, 5.0),
        )
    else:
        review_impact = 0.0

    if unknown_count:
        unknown_impact = min(
            UNKNOWN_RISK_BUDGET,
            UNKNOWN_RISK_BUDGET
            * _severity_saturation(unknown_count, 5.0),
        )
    else:
        unknown_impact = 0.0

    if review_count:
        contributions["review"] = {
            "count": review_count,
            "budget": REVIEW_RISK_BUDGET,
            "total_impact": round(review_impact, 2),
        }

    if unknown_count:
        contributions["unknown"] = {
            "count": unknown_count,
            "budget": UNKNOWN_RISK_BUDGET,
            "total_impact": round(unknown_impact, 2),
        }

    total_risk += review_impact + unknown_impact
    total_risk = round(min(MAX_RISK, total_risk), 2)

    risk_score = round(
        max(0.0, min(100.0, 100.0 - total_risk)),
        2,
    )

    return {
        "risk_points": total_risk,
        "risk_score": risk_score,
        "risk_contributions": contributions,
    }


def _calculate_risk_points(findings):
    """
    Backward-compatible wrapper.

    All scoring now comes from _calculate_risk_breakdown() so the returned
    risk_points and risk_contributions can never disagree.
    """
    return _calculate_risk_breakdown(findings)["risk_points"]


def _build_risk_contributions(findings):
    """
    Backward-compatible wrapper around the single-source risk model.
    """
    return _calculate_risk_breakdown(findings)["risk_contributions"]


# ============================================================
# SECURITY LEVEL
# ============================================================

def _calculate_security_level(
    findings,
    risk_score,
):
    """
    Calculate a customer-friendly security level.

    Critical findings always require attention, but the score
    also considers the overall environment.
    """

    active_findings = [

        finding

        for finding in findings

        if _is_active_risk(
            finding
        )
    ]

    critical_count = sum(

        1

        for finding in active_findings

        if finding.get(
            "severity"
        ) == "CRITICAL"
    )

    high_count = sum(

        1

        for finding in active_findings

        if finding.get(
            "severity"
        ) == "HIGH"
    )

    if critical_count >= 3:
        return "Critical"

    if critical_count >= 1:
        return "Critical"

    if high_count >= 5:
        return "High Risk"

    if risk_score < 50:
        return "High Risk"

    if risk_score < 70:
        return "Medium Risk"

    if risk_score < 85:
        return "Needs Improvement"

    if risk_score >= 95:
        return "Excellent"

    return "Good"


# ============================================================
# SECURITY POSTURE
# ============================================================

def _calculate_posture(
    risk_score
):
    """
    Convert security score into a simple posture label.
    """

    if risk_score >= 90:
        return "Excellent"

    if risk_score >= 75:
        return "Good"

    if risk_score >= 50:
        return "Needs Improvement"

    if risk_score >= 25:
        return "Poor"

    return "Critical"


# ============================================================
# RESOURCE SUMMARY
# ============================================================

def _build_resource_summary(
    resources
):
    """
    Build safe resource statistics.
    """

    if not isinstance(
        resources,
        dict
    ):
        resources = {}

    numeric_resources = {

        key: value

        for key, value
        in resources.items()

        if isinstance(
            value,
            int
        )
    }

    return {

        "total_resources":
            sum(
                numeric_resources.values()
            ),

        "resources":
            resources,
    }


# ============================================================
# MAIN ANALYZER
# ============================================================

def analyze(
    resources,
    s3_security,
    ec2_security,
    iam_security,
    cloudtrail_security=None,
    vpc_security=None,
    rds_security=None,
    lambda_security=None,
    kms_security=None,
):
    """
    Analyze AWS security checker output.

    Returns:
        risk score
        security level
        security posture
        risk breakdown
        finding summary
        resource summary
        canonical deduplicated findings
    """

    # ========================================================
    # COLLECT FINDINGS
    # ========================================================

    raw_findings = []

    security_sources = [

        s3_security,
        ec2_security,
        iam_security,
        cloudtrail_security,
        vpc_security,
        rds_security,
        lambda_security,
        kms_security,
    ]

    for source in security_sources:

        if not source:
            continue

        if not isinstance(
            source,
            list
        ):
            continue

        for item in source:

            if not isinstance(
                item,
                dict
            ):
                continue

            raw_findings.append(
                item
            )

    # ========================================================
    # NORMALIZE
    # ========================================================

    normalized_findings = (
        _normalize_findings(
            raw_findings
        )
    )

    # ========================================================
    # DEDUPLICATE
    # ========================================================

    findings = _deduplicate_findings(
        normalized_findings
    )

    # ========================================================
    # COUNT SEVERITIES
    # ========================================================

    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "LOW"
        )

        if severity == "CRITICAL":

            critical_count += 1

        elif severity == "HIGH":

            high_count += 1

        elif severity == "MEDIUM":

            medium_count += 1

        elif severity == "LOW":

            low_count += 1

    # ========================================================
    # COUNT STATUSES
    # ========================================================

    failed_count = 0
    review_count = 0
    protected_count = 0
    informational_count = 0
    unknown_count = 0

    for finding in findings:

        status = str(
            finding.get(
                "status",
                ""
            )
        ).strip().upper()

        if status in FAILED_STATUSES:

            failed_count += 1

        elif status in REVIEW_STATUSES:

            review_count += 1

        elif status in INFORMATIONAL_STATUSES:

            if status in (
                "PROTECTED",
                "PASS",
                "PASSED",
            ):

                protected_count += 1

            else:

                informational_count += 1

        elif status in UNKNOWN_STATUSES:

            unknown_count += 1

        else:

            informational_count += 1

    # ========================================================
    # RISK
    # ========================================================

    risk_model = _calculate_risk_breakdown(
        findings
    )

    risk_points = risk_model["risk_points"]
    risk_score = risk_model["risk_score"]
    risk_contributions = risk_model["risk_contributions"]

    # ========================================================
    # SECURITY LEVEL
    # ========================================================

    security_level = (
        _calculate_security_level(
            findings,
            risk_score
        )
    )

    # ========================================================
    # POSTURE
    # ========================================================

    posture = _calculate_posture(
        risk_score
    )

    # ========================================================
    # RISK BREAKDOWN
    # ========================================================

    risk_breakdown = {

        "critical":
            critical_count,

        "high":
            high_count,

        "medium":
            medium_count,

        "low":
            low_count,
    }

    # ========================================================
    # RESOURCE SUMMARY
    # ========================================================

    resource_summary = (
        _build_resource_summary(
            resources
        )
    )

    # ========================================================
    # RETURN
    # ========================================================

    return {

        "risk_score":
            risk_score,

        "security_level":
            security_level,

        "security_posture":
            posture,

        "risk_points":
            risk_points,

        "risk_engine_version":
            RISK_ENGINE_VERSION,

        "severity_summary": {

            "critical":
                critical_count,

            "high":
                high_count,

            "medium":
                medium_count,

            "low":
                low_count,
        },

        "risk_breakdown":
            risk_breakdown,

        "risk_model":
            {
                "engine_version": RISK_ENGINE_VERSION,
                "max_risk_points": MAX_RISK,
                "severity_budgets": {
                    key: value
                    for key, value in SEVERITY_BUDGET.items()
                },
                "model": "bounded_severity_saturation",
            },

        "risk_contributions":
            risk_contributions,

        "finding_summary": {

            "total":
                len(findings),

            "failed":
                failed_count,

            "review":
                review_count,

            "protected":
                protected_count,

            "informational":
                informational_count,

            "unknown":
                unknown_count,

        },

        "resource_summary":
            resource_summary,

        "total_findings":
            len(findings),

        "findings":
            findings,
    }