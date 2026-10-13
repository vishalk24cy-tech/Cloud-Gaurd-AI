def check_security_groups(ec2_client):

    findings = []


    try:

        response = ec2_client.describe_security_groups()


        security_groups = response.get(
            "SecurityGroups",
            []
        )


        for sg in security_groups:


            group_name = sg.get(
                "GroupName",
                "Unknown"
            )


            group_id = sg.get(
                "GroupId",
                ""
            )



            for rule in sg.get(
                "IpPermissions",
                []
            ):



                from_port = rule.get(
                    "FromPort"
                )

                to_port = rule.get(
                    "ToPort"
                )



                ip_ranges = rule.get(
                    "IpRanges",
                    []
                )



                for ip in ip_ranges:


                    cidr = ip.get(
                        "CidrIp",
                        ""
                    )



                    # =========================
                    # SSH Exposure
                    # =========================

                    if (
                        from_port == 22
                        and cidr == "0.0.0.0/0"
                    ):


                        findings.append({

                            "service":
                            "Security Group",

                            "severity":
                            "HIGH",

                            "issue":
                            f"SSH Port 22 Open To Internet ({group_name})",

                            "resource":
                            group_id,

                            "status":
                            "Failed",

                            "recommendation":
                            "Restrict SSH access to trusted IP addresses."

                        })




                    # =========================
                    # RDP Exposure
                    # =========================

                    elif (
                        from_port == 3389
                        and cidr == "0.0.0.0/0"
                    ):


                        findings.append({

                            "service":
                            "Security Group",

                            "severity":
                            "HIGH",

                            "issue":
                            f"RDP Port 3389 Open To Internet ({group_name})",

                            "resource":
                            group_id,

                            "status":
                            "Failed",

                            "recommendation":
                            "Restrict RDP access using VPN or trusted IPs."

                        })





                    # =========================
                    # Database Exposure
                    # =========================

                    elif (
                        from_port in [
                            3306,
                            5432,
                            1433,
                            27017
                        ]

                        and cidr == "0.0.0.0/0"
                    ):


                        findings.append({

                            "service":
                            "Security Group",

                            "severity":
                            "CRITICAL",

                            "issue":
                            f"Database Port {from_port} Publicly Exposed ({group_name})",

                            "resource":
                            group_id,

                            "status":
                            "Failed",

                            "recommendation":
                            "Remove public access from database ports."

                        })






        # =========================
        # No Exposure
        # =========================

        if len(findings) == 0:


            findings.append({

                "service":
                "Security Group",

                "severity":
                "LOW",

                "issue":
                "No Public Port Exposure Detected",

                "status":
                "Protected",

                "recommendation":
                "No action required."

            })





    except Exception as e:


        findings.append({

            "service":
            "Security Group",

            "severity":
            "MEDIUM",

            "issue":
            "Security Group Scan Failed",

            "status":
            "Unknown",

            "recommendation":
            str(e)

        })



    return findings