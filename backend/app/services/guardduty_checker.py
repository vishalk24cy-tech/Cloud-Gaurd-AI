def check_guardduty(guardduty_client):

    findings = []

    try:

        # Get GuardDuty detectors

        detectors = guardduty_client.list_detectors()


        detector_ids = detectors.get(
            "DetectorIds",
            []
        )


        if len(detector_ids) == 0:

            findings.append({

                "service":
                "GuardDuty",

                "severity":
                "HIGH",

                "issue":
                "GuardDuty Not Enabled",

                "status":
                "Failed",

                "recommendation":
                "Enable AWS GuardDuty threat detection service."

            })


            return findings



        detector_id = detector_ids[0]



        # Get findings

        response = guardduty_client.list_findings(

            DetectorId=detector_id

        )


        finding_ids = response.get(
            "FindingIds",
            []
        )



        if len(finding_ids) == 0:


            findings.append({

                "service":
                "GuardDuty",

                "severity":
                "LOW",

                "issue":
                "No Threats Detected",

                "status":
                "Protected",

                "recommendation":
                "No action required."

            })



            return findings





        # Get finding details

        details = guardduty_client.get_findings(

            DetectorId=detector_id,

            FindingIds=finding_ids[:10]

        )



        guard_findings = details.get(
            "Findings",
            []
        )



        for item in guard_findings:


            title = item.get(
                "Title",
                "Unknown Threat"
            )


            severity_value = item.get(
                "Severity",
                0
            )



            if severity_value >= 7:

                severity = "CRITICAL"


            elif severity_value >= 4:

                severity = "HIGH"


            else:

                severity = "MEDIUM"





            findings.append({

                "service":
                "GuardDuty",

                "severity":
                severity,

                "issue":
                title,

                "status":
                "Failed",

                "recommendation":
                "Investigate GuardDuty finding and follow AWS remediation guidance."

            })





    except Exception as e:


        findings.append({

            "service":
            "GuardDuty",

            "severity":
            "MEDIUM",

            "issue":
            "GuardDuty Scan Failed",

            "status":
            "Unknown",

            "recommendation":
            str(e)

        })



    return findings