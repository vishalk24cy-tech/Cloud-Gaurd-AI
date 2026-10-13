def check_cis(findings):

    controls = []


    # =====================================
    # CIS AWS 1.5
    # Ensure MFA Enabled for IAM Users
    # =====================================

    for finding in findings:


        issue = finding.get(
            "issue",
            ""
        )


        severity = finding.get(
            "severity",
            "LOW"
        )



        if "MFA Not Enabled" in issue:


            controls.append({

                "framework":
                "CIS AWS Foundations Benchmark",


                "control_id":
                "1.5",


                "title":
                "Ensure MFA is enabled for IAM users",


                "status":
                "FAILED",


                "severity":
                severity,


                "issue":
                issue,


                "recommendation":
                "Enable MFA for all IAM users."

            })





    # =====================================
    # CIS AWS 3.1
    # CloudTrail Enabled
    # =====================================


    for finding in findings:


        if "CloudTrail Not Enabled" in finding.get(
            "issue",
            ""
        ):


            controls.append({

                "framework":
                "CIS AWS Foundations Benchmark",


                "control_id":
                "3.1",


                "title":
                "Ensure CloudTrail is enabled",


                "status":
                "FAILED",


                "severity":
                "HIGH",


                "issue":
                "CloudTrail Audit Logging Disabled",


                "recommendation":
                "Enable multi-region AWS CloudTrail logging."

            })






    # =====================================
    # CIS AWS 2.5
    # AWS Config
    # =====================================


    for finding in findings:


        if "AWS Config Recorder Not Enabled" in finding.get(
            "issue",
            ""
        ):


            controls.append({

                "framework":
                "CIS AWS Foundations Benchmark",


                "control_id":
                "2.5",


                "title":
                "Ensure AWS Config is enabled",


                "status":
                "FAILED",


                "severity":
                "HIGH",


                "issue":
                "AWS Config Recorder Disabled",


                "recommendation":
                "Enable AWS Config recorder and compliance rules."

            })






    # =====================================
    # KMS Encryption Control
    # =====================================


    for finding in findings:


        if "KMS" in finding.get(
            "service",
            ""
        ):


            controls.append({

                "framework":
                "CIS AWS Foundations Benchmark",


                "control_id":
                "2.8",


                "title":
                "Ensure customer managed encryption keys are used",


                "status":
                "FAILED",


                "severity":
                finding.get(
                    "severity",
                    "MEDIUM"
                ),


                "issue":
                finding.get(
                    "issue"
                ),


                "recommendation":
                "Create AWS KMS Customer Managed Keys."

            })







    # =====================================
    # Calculate Score
    # =====================================


    total = len(controls)


    failed = len([
        c for c in controls
        if c["status"] == "FAILED"
    ])



    passed = total - failed



    if total > 0:

        score = int(
            (passed / total) * 100
        )

    else:

        score = 100





    return {


        "framework":
        "CIS AWS Foundations Benchmark",


        "total_controls":
        total,


        "passed":
        passed,


        "failed":
        failed,


        "compliance_score":
        score,


        "controls":
        controls

    }