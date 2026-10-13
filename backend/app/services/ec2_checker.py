# ============================================================
# CloudGuardAI - AWS EC2 Security Checker
# Production Security Finding Engine
# ============================================================
#
# Responsibilities:
#   - Inspect EC2 security groups
#   - Detect dangerous public inbound rules
#   - Support IPv4 and IPv6
#   - Preserve exact AWS rule evidence
#   - Provide remediation-safe metadata
#
# IMPORTANT:
# This checker ONLY detects security issues.
# It does NOT modify AWS resources.
# ============================================================


# ============================================================
# CONSTANTS
# ============================================================

PUBLIC_IPV4 = "0.0.0.0/0"
PUBLIC_IPV6 = "::/0"

SSH_PORT = 22
RDP_PORT = 3389


# ============================================================
# SAFE INTEGER CONVERSION
# ============================================================

def _safe_int(value):
    """
    Safely convert a value to integer.

    Returns None when conversion is not possible.
    """

    if value is None:
        return None

    try:
        return int(value)

    except (TypeError, ValueError):
        return None


# ============================================================
# PORT DESCRIPTION
# ============================================================

def _get_port_description(
    protocol,
    from_port,
    to_port
):
    """
    Convert AWS port information into a human-readable value.
    """

    if protocol == "-1":
        return "All Ports"

    if from_port is None:
        return "All Ports"

    if to_port is None:
        return str(from_port)

    if from_port == to_port:
        return str(from_port)

    return f"{from_port}-{to_port}"


# ============================================================
# CLASSIFY SECURITY RISK
# ============================================================

def _classify_risk(
    protocol,
    from_port,
    to_port,
    ipv6=False
):
    """
    Determine severity and issue description.

    This function only classifies the detected exposure.
    """

    suffix = " over IPv6" if ipv6 else ""

    # --------------------------------------------------------
    # ALL TRAFFIC
    # --------------------------------------------------------

    if protocol == "-1":

        return (
            "CRITICAL",
            (
                "All inbound traffic is open "
                f"to the Internet{suffix}."
            )
        )

    # --------------------------------------------------------
    # SSH
    # --------------------------------------------------------

    if from_port == SSH_PORT:

        return (
            "HIGH",
            (
                "SSH (port 22) is open "
                f"to the Internet{suffix}."
            )
        )

    # --------------------------------------------------------
    # RDP
    # --------------------------------------------------------

    if from_port == RDP_PORT:

        return (
            "HIGH",
            (
                "RDP (port 3389) is open "
                f"to the Internet{suffix}."
            )
        )

    # --------------------------------------------------------
    # OTHER PORTS
    # --------------------------------------------------------

    port_description = _get_port_description(
        protocol,
        from_port,
        to_port
    )

    return (
        "MEDIUM",
        (
            f"Port {port_description} is open "
            f"to the Internet{suffix}."
        )
    )


# ============================================================
# BUILD REMEDIATION-SAFE EVIDENCE
# ============================================================

def _build_rule_evidence(
    security_group_id,
    security_group_name,
    protocol,
    from_port,
    to_port,
    source,
    source_type
):
    """
    Preserve the exact AWS ingress rule details.

    This evidence is consumed later by the remediation
    proposal/executor.

    IMPORTANT:
    The remediation executor must never guess these values.
    """

    return {

        # ----------------------------------------------------
        # Resource
        # ----------------------------------------------------

        "security_group_id":
            security_group_id,

        "security_group_name":
            security_group_name,

        # ----------------------------------------------------
        # AWS ingress rule
        # ----------------------------------------------------

        "protocol":
            protocol,

        "from_port":
            from_port,

        "to_port":
            to_port,

        # ----------------------------------------------------
        # Network source
        # ----------------------------------------------------

        "source":
            source,

        "source_type":
            source_type,

        # ----------------------------------------------------
        # Remediation identity
        # ----------------------------------------------------

        "rule_scope":
            "INGRESS",

        "rule_match": {

            "protocol":
                protocol,

            "from_port":
                from_port,

            "to_port":
                to_port,

            "source":
                source,

            "source_type":
                source_type

        }

    }


# ============================================================
# BUILD FINDING
# ============================================================

def _build_finding(
    security_group,
    protocol,
    from_port,
    to_port,
    source,
    source_type,
    ipv6=False
):
    """
    Build one normalized EC2 security finding.
    """

    group_id = security_group.get(
        "GroupId",
        "Unknown"
    )

    group_name = security_group.get(
        "GroupName",
        "Unknown"
    )

    severity, issue = _classify_risk(
        protocol,
        from_port,
        to_port,
        ipv6
    )

    port_description = _get_port_description(
        protocol,
        from_port,
        to_port
    )

    evidence = _build_rule_evidence(
        security_group_id=group_id,
        security_group_name=group_name,
        protocol=protocol,
        from_port=from_port,
        to_port=to_port,
        source=source,
        source_type=source_type
    )

    if ipv6:

        recommendation = (
            "Restrict IPv6 inbound access to trusted "
            "networks and avoid exposing administrative "
            "ports to ::/0."
        )

    else:

        recommendation = (
            "Restrict inbound access to trusted IP "
            "addresses or private networks. Avoid "
            "exposing administrative ports directly "
            "to the Internet."
        )

    return {

        # ====================================================
        # RESOURCE
        # ====================================================

        "resource_type":
            "EC2 Security Group",

        "resource":
            group_id,

        "security_group":
            group_name,

        "security_group_id":
            group_id,

        # ====================================================
        # RULE INFORMATION
        # ====================================================

        "protocol":
            protocol,

        "from_port":
            from_port,

        "to_port":
            to_port,

        "port":
            port_description,

        "source":
            source,

        "source_type":
            source_type,

        # ====================================================
        # SECURITY CLASSIFICATION
        # ====================================================

        "severity":
            severity,

        "status":
            "Risk",

        "detection_status":
            "RISK",

        # ====================================================
        # DESCRIPTION
        # ====================================================

        "issue":
            issue,

        "description":
            issue,

        # ====================================================
        # REMEDIATION
        # ====================================================

        "recommendation":
            recommendation,

        "remediation":
            recommendation,

        # ====================================================
        # EXACT SECURITY EVIDENCE
        # ====================================================
        #
        # This is the critical enhancement.
        #
        # The remediation workflow can now consume the
        # exact protocol / ports / CIDR instead of guessing.
        #

        "evidence":
            evidence

    }


# ============================================================
# AWS EC2 SECURITY CHECKER
# ============================================================

def check_ec2(ec2_client):

    findings = []

    # ========================================================
    # GET SECURITY GROUPS
    # ========================================================

    response = ec2_client.describe_security_groups()

    security_groups = response.get(
        "SecurityGroups",
        []
    )

    # ========================================================
    # CHECK EACH SECURITY GROUP
    # ========================================================

    for security_group in security_groups:

        group_id = security_group.get(
            "GroupId",
            "Unknown"
        )

        group_name = security_group.get(
            "GroupName",
            "Unknown"
        )

        ip_permissions = security_group.get(
            "IpPermissions",
            []
        )

        # ====================================================
        # CHECK INBOUND RULES
        # ====================================================

        for permission in ip_permissions:

            protocol = permission.get(
                "IpProtocol",
                "unknown"
            )

            # ------------------------------------------------
            # Normalize protocol
            # ------------------------------------------------

            if protocol is None:
                protocol = "unknown"

            protocol = str(
                protocol
            )

            # ------------------------------------------------
            # Ports
            # ------------------------------------------------

            from_port = _safe_int(
                permission.get(
                    "FromPort"
                )
            )

            to_port = _safe_int(
                permission.get(
                    "ToPort"
                )
            )

            # =================================================
            # IPv4 INTERNET ACCESS
            # =================================================

            for ip_range in permission.get(
                "IpRanges",
                []
            ):

                cidr = ip_range.get(
                    "CidrIp"
                )

                # ------------------------------------------------
                # Only public IPv4 exposure
                # ------------------------------------------------

                if cidr != PUBLIC_IPV4:
                    continue

                finding = _build_finding(

                    security_group={
                        "GroupId":
                            group_id,

                        "GroupName":
                            group_name
                    },

                    protocol=
                        protocol,

                    from_port=
                        from_port,

                    to_port=
                        to_port,

                    source=
                        cidr,

                    source_type=
                        "IPv4_CIDR",

                    ipv6=False

                )

                findings.append(
                    finding
                )

            # =================================================
            # IPv6 INTERNET ACCESS
            # =================================================

            for ipv6_range in permission.get(
                "Ipv6Ranges",
                []
            ):

                cidr_ipv6 = ipv6_range.get(
                    "CidrIpv6"
                )

                # ------------------------------------------------
                # Only public IPv6 exposure
                # ------------------------------------------------

                if cidr_ipv6 != PUBLIC_IPV6:
                    continue

                finding = _build_finding(

                    security_group={
                        "GroupId":
                            group_id,

                        "GroupName":
                            group_name
                    },

                    protocol=
                        protocol,

                    from_port=
                        from_port,

                    to_port=
                        to_port,

                    source=
                        cidr_ipv6,

                    source_type=
                        "IPv6_CIDR",

                    ipv6=True

                )

                findings.append(
                    finding
                )

    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings