# ============================================================
# CloudGuardAI - AWS CloudTrail Security Checker
# ============================================================


def check_cloudtrail(cloudtrail):

    findings = []

    # ========================================================
    # GET CLOUDTRAIL TRAILS
    # ========================================================

    try:

        response = cloudtrail.describe_trails()

        trails = response.get(
            "trailList",
            []
        )

    except Exception as e:

        findings.append({

            "resource_type":
                "CloudTrail",

            "resource":
                "CloudTrail",

            "service":
                "CloudTrail",

            "severity":
                "MEDIUM",

            "status":
                "Unknown",

            "issue":
                "CloudTrail configuration could not be verified.",

            "recommendation":
                "Verify that the scanner IAM role has permission "
                "to describe CloudTrail trails.",

            "evidence":
                str(e)

        })

        return findings


    # ========================================================
    # NO TRAIL FOUND
    # ========================================================

    if len(trails) == 0:

        findings.append({

            "resource_type":
                "CloudTrail",

            "resource":
                "CloudTrail",

            "service":
                "CloudTrail",

            "severity":
                "HIGH",

            "status":
                "Failed",

            "issue":
                "CloudTrail trail is not configured.",

            "recommendation":
                "Create and enable an AWS CloudTrail trail "
                "to monitor API activity and security events."

        })

        return findings


    # ========================================================
    # CHECK EACH TRAIL
    # ========================================================

    for trail in trails:

        trail_name = trail.get(
            "Name",
            "Unknown"
        )

        trail_arn = trail.get(
            "TrailARN",
            ""
        )

        bucket_name = trail.get(
            "S3BucketName",
            ""
        )

        is_multi_region = trail.get(
            "IsMultiRegionTrail",
            False
        )

        log_file_validation = trail.get(
            "LogFileValidationEnabled",
            False
        )

        cloudwatch_log_group = trail.get(
            "CloudWatchLogsLogGroupArn",
            ""
        )


        # ====================================================
        # 1. LOGGING STATUS
        # ====================================================

        try:

            status_response = cloudtrail.get_trail_status(
                Name=trail_name
            )

            is_logging = status_response.get(
                "IsLogging",
                False
            )


        except Exception as e:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "service":
                    "CloudTrail",

                "severity":
                    "MEDIUM",

                "status":
                    "Unknown",

                "issue":
                    f"CloudTrail logging status could not be "
                    f"verified ({trail_name}).",

                "recommendation":
                    "Verify scanner permissions and check "
                    "CloudTrail logging status manually.",

                "evidence":
                    str(e)

            })

            continue


        if not is_logging:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "HIGH",

                "status":
                    "Failed",

                "issue":
                    f"CloudTrail logging is disabled "
                    f"({trail_name}).",

                "recommendation":
                    "Enable CloudTrail logging immediately."

            })

        else:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    f"CloudTrail logging is enabled "
                    f"({trail_name}).",

                "recommendation":
                    "Continue monitoring CloudTrail logs."

            })


        # ====================================================
        # 2. MULTI-REGION TRAIL
        # ====================================================

        if not is_multi_region:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "MEDIUM",

                "status":
                    "Review",

                "issue":
                    f"CloudTrail trail is not configured "
                    f"as a multi-region trail ({trail_name}).",

                "recommendation":
                    "Enable multi-region logging so API activity "
                    "across AWS regions can be monitored."

            })

        else:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    f"Multi-region CloudTrail is enabled "
                    f"({trail_name}).",

                "recommendation":
                    "No action required."

            })


        # ====================================================
        # 3. LOG FILE VALIDATION
        # ====================================================

        if not log_file_validation:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "MEDIUM",

                "status":
                    "Review",

                "issue":
                    f"CloudTrail log file validation is disabled "
                    f"({trail_name}).",

                "recommendation":
                    "Enable log file validation to help detect "
                    "modification or tampering of CloudTrail logs."

            })

        else:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    f"CloudTrail log file validation is enabled "
                    f"({trail_name}).",

                "recommendation":
                    "No action required."

            })


        # ====================================================
        # 4. S3 LOG DESTINATION
        # ====================================================

        if not bucket_name:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "MEDIUM",

                "status":
                    "Review",

                "issue":
                    f"CloudTrail does not have an S3 "
                    f"log destination ({trail_name}).",

                "recommendation":
                    "Configure a secure S3 bucket for "
                    "CloudTrail log storage."

            })


        # ====================================================
        # 5. CLOUDWATCH LOGGING
        # ====================================================

        if not cloudwatch_log_group:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "LOW",

                "status":
                    "Review",

                "issue":
                    f"CloudTrail is not configured with "
                    f"a CloudWatch Logs group ({trail_name}).",

                "recommendation":
                    "Consider sending CloudTrail events to "
                    "CloudWatch Logs for centralized monitoring "
                    "and alerting."

            })

        else:

            findings.append({

                "resource_type":
                    "CloudTrail",

                "resource":
                    trail_name,

                "trail_arn":
                    trail_arn,

                "service":
                    "CloudTrail",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    f"CloudTrail is integrated with "
                    f"CloudWatch Logs ({trail_name}).",

                "recommendation":
                    "Continue monitoring CloudTrail events."

            })


    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings