# ============================================================
# CloudGuardAI - AWS VPC Security Checker
# ============================================================


def check_vpc(ec2):

    findings = []

    try:

        # ====================================================
        # GET SECURITY GROUPS
        # ====================================================

        response = ec2.describe_security_groups()

        security_groups = response.get(
            "SecurityGroups",
            []
        )


        # ====================================================
        # CHECK EACH SECURITY GROUP
        # ====================================================

        for group in security_groups:

            group_name = group.get(
                "GroupName",
                "Unknown"
            )

            group_id = group.get(
                "GroupId",
                "Unknown"
            )

            permissions = group.get(
                "IpPermissions",
                []
            )


            # =================================================
            # CHECK INBOUND RULES
            # =================================================

            for rule in permissions:

                protocol = rule.get(
                    "IpProtocol",
                    ""
                )

                from_port = rule.get(
                    "FromPort"
                )

                to_port = rule.get(
                    "ToPort"
                )


                # =============================================
                # DETERMINE PORT
                # =============================================

                if protocol == "-1":

                    port_description = "All Traffic"

                elif from_port is not None and to_port is not None:

                    if from_port == to_port:

                        port_description = str(
                            from_port
                        )

                    else:

                        port_description = (
                            f"{from_port}-{to_port}"
                        )

                else:

                    port_description = "All Ports"


                # =============================================
                # CHECK IPv4
                # =============================================

                for ip_range in rule.get(
                    "IpRanges",
                    []
                ):

                    cidr = ip_range.get(
                        "CidrIp",
                        ""
                    )

                    if cidr != "0.0.0.0/0":
                        continue


                    # =========================================
                    # ALL TRAFFIC
                    # =========================================

                    if protocol == "-1":

                        findings.append({

                            "resource_type":
                                "Security Group",

                            "resource":
                                group_id,

                            "service":
                                "VPC",

                            "security_group":
                                group_name,

                            "security_group_id":
                                group_id,

                            "protocol":
                                "All",

                            "port":
                                "All",

                            "source":
                                cidr,

                            "severity":
                                "CRITICAL",

                            "status":
                                "Failed",

                            "issue":
                                "Security group allows "
                                "all inbound traffic from "
                                "the Internet.",

                            "recommendation":
                                "Remove the unrestricted "
                                "inbound rule and allow only "
                                "required ports from trusted "
                                "IP addresses or security groups."

                        })


                    # =========================================
                    # SSH
                    # =========================================

                    elif from_port == 22 and to_port == 22:

                        findings.append({

                            "resource_type":
                                "Security Group",

                            "resource":
                                group_id,

                            "service":
                                "VPC",

                            "security_group":
                                group_name,

                            "security_group_id":
                                group_id,

                            "protocol":
                                protocol,

                            "port":
                                "22",

                            "source":
                                cidr,

                            "severity":
                                "HIGH",

                            "status":
                                "Failed",

                            "issue":
                                "SSH port 22 is open "
                                "to the Internet.",

                            "recommendation":
                                "Restrict SSH access to "
                                "trusted IP addresses or "
                                "use a secure management "
                                "solution such as AWS Systems Manager."

                        })


                    # =========================================
                    # RDP
                    # =========================================

                    elif from_port == 3389 and to_port == 3389:

                        findings.append({

                            "resource_type":
                                "Security Group",

                            "resource":
                                group_id,

                            "service":
                                "VPC",

                            "security_group":
                                group_name,

                            "security_group_id":
                                group_id,

                            "protocol":
                                protocol,

                            "port":
                                "3389",

                            "source":
                                cidr,

                            "severity":
                                "HIGH",

                            "status":
                                "Failed",

                            "issue":
                                "RDP port 3389 is open "
                                "to the Internet.",

                            "recommendation":
                                "Restrict RDP access to "
                                "trusted networks and avoid "
                                "public exposure."

                        })


                    # =========================================
                    # OTHER PORTS
                    # =========================================

                    else:

                        findings.append({

                            "resource_type":
                                "Security Group",

                            "resource":
                                group_id,

                            "service":
                                "VPC",

                            "security_group":
                                group_name,

                            "security_group_id":
                                group_id,

                            "protocol":
                                protocol,

                            "port":
                                port_description,

                            "source":
                                cidr,

                            "severity":
                                "MEDIUM",

                            "status":
                                "Failed",

                            "issue":
                                f"Inbound port "
                                f"{port_description} is open "
                                f"to the Internet.",

                            "recommendation":
                                "Restrict the inbound rule "
                                "to trusted IP addresses "
                                "or networks."

                        })


                # =============================================
                # CHECK IPv6
                # =============================================

                for ipv6_range in rule.get(
                    "Ipv6Ranges",
                    []
                ):

                    cidr_ipv6 = ipv6_range.get(
                        "CidrIpv6",
                        ""
                    )

                    if cidr_ipv6 != "::/0":
                        continue


                    # =========================================
                    # ALL IPv6 TRAFFIC
                    # =========================================

                    if protocol == "-1":

                        severity = "CRITICAL"

                        issue = (
                            "Security group allows all "
                            "IPv6 inbound traffic from "
                            "the Internet."
                        )

                    # =========================================
                    # SSH IPv6
                    # =========================================

                    elif from_port == 22 and to_port == 22:

                        severity = "HIGH"

                        issue = (
                            "SSH port 22 is open to "
                            "the Internet over IPv6."
                        )

                    # =========================================
                    # RDP IPv6
                    # =========================================

                    elif from_port == 3389 and to_port == 3389:

                        severity = "HIGH"

                        issue = (
                            "RDP port 3389 is open to "
                            "the Internet over IPv6."
                        )

                    # =========================================
                    # OTHER IPv6 PORT
                    # =========================================

                    else:

                        severity = "MEDIUM"

                        issue = (
                            f"Inbound port "
                            f"{port_description} is open "
                            f"to the Internet over IPv6."
                        )


                    findings.append({

                        "resource_type":
                            "Security Group",

                        "resource":
                            group_id,

                        "service":
                            "VPC",

                        "security_group":
                            group_name,

                        "security_group_id":
                            group_id,

                        "protocol":
                            "All" if protocol == "-1"
                            else protocol,

                        "port":
                            "All"
                            if protocol == "-1"
                            else port_description,

                        "source":
                            cidr_ipv6,

                        "severity":
                            severity,

                        "status":
                            "Failed",

                        "issue":
                            issue,

                        "recommendation":
                            "Restrict IPv6 inbound access "
                            "to trusted IP addresses or "
                            "required networks."

                    })


        # ====================================================
        # NO PUBLIC EXPOSURE
        # ====================================================

        if len(findings) == 0:

            findings.append({

                "resource_type":
                    "VPC Security",

                "resource":
                    "Security Groups",

                "service":
                    "VPC",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    "No unrestricted public inbound "
                    "security group exposure was detected.",

                "recommendation":
                    "Continue reviewing security group "
                    "rules regularly."

            })


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as e:

        findings.append({

            "resource_type":
                "VPC",

            "resource":
                "Security Groups",

            "service":
                "VPC",

            "severity":
                "MEDIUM",

            "status":
                "Unknown",

            "issue":
                "VPC security group check failed.",

            "recommendation":
                "Verify that the CloudGuardAI scanner "
                "role has permission to describe security groups.",

            "evidence":
                str(e)

        })


    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings