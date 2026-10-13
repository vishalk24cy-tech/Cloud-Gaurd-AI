# ============================================================
# CloudGuardAI - AWS Lambda Security Checker
# ============================================================


def check_lambda(lambda_client):

    findings = []

    try:

        # ====================================================
        # GET LAMBDA FUNCTIONS
        # ====================================================

        response = lambda_client.list_functions()

        functions = response.get(
            "Functions",
            []
        )


        # ====================================================
        # NO FUNCTIONS FOUND
        # ====================================================

        if len(functions) == 0:

            findings.append({

                "resource_type":
                    "Lambda",

                "resource":
                    "Lambda Functions",

                "service":
                    "Lambda",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    "No Lambda functions were found.",

                "recommendation":
                    "No action required."

            })

            return findings


        # ====================================================
        # CHECK EACH FUNCTION
        # ====================================================

        for function in functions:

            name = function.get(
                "FunctionName",
                "Unknown"
            )

            arn = function.get(
                "FunctionArn",
                ""
            )

            runtime = function.get(
                "Runtime",
                "Unknown"
            )

            role = function.get(
                "Role"
            )

            kms_key = function.get(
                "KMSKeyArn"
            )

            environment = function.get(
                "Environment",
                {}
            )

            environment_variables = environment.get(
                "Variables",
                {}
            )


            # =================================================
            # 1. EXECUTION IAM ROLE
            # =================================================

            if not role:

                findings.append({

                    "resource_type":
                        "Lambda Function",

                    "resource":
                        name,

                    "resource_arn":
                        arn,

                    "service":
                        "Lambda",

                    "runtime":
                        runtime,

                    "severity":
                        "HIGH",

                    "status":
                        "Failed",

                    "issue":
                        "Lambda function does not have "
                        "an execution IAM role.",

                    "recommendation":
                        "Attach an IAM execution role with "
                        "only the permissions required by "
                        "the Lambda function."

                })

            else:

                findings.append({

                    "resource_type":
                        "Lambda Function",

                    "resource":
                        name,

                    "resource_arn":
                        arn,

                    "service":
                        "Lambda",

                    "runtime":
                        runtime,

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "Lambda function has an execution "
                        "IAM role configured.",

                    "recommendation":
                        "Review the role regularly and "
                        "maintain least-privilege permissions."

                })


            # =================================================
            # 2. ENVIRONMENT VARIABLE ENCRYPTION
            # =================================================

            if environment_variables:

                if kms_key:

                    findings.append({

                        "resource_type":
                            "Lambda Function",

                        "resource":
                            name,

                        "resource_arn":
                            arn,

                        "service":
                            "Lambda",

                        "severity":
                            "LOW",

                        "status":
                            "Protected",

                        "kms_key":
                            kms_key,

                        "issue":
                            "Lambda environment variables "
                            "use a customer-managed KMS key.",

                        "recommendation":
                            "Continue protecting the KMS key "
                            "with appropriate IAM permissions."

                    })

                else:

                    findings.append({

                        "resource_type":
                            "Lambda Function",

                        "resource":
                            name,

                        "resource_arn":
                            arn,

                        "service":
                            "Lambda",

                        "severity":
                            "MEDIUM",

                        "status":
                            "Review",

                        "issue":
                            "Lambda function contains environment "
                            "variables but no customer-managed "
                            "KMS key is configured.",

                        "recommendation":
                            "Consider using a customer-managed "
                            "AWS KMS key when stronger control "
                            "over Lambda environment-variable "
                            "encryption is required. Do not store "
                            "secrets directly in environment "
                            "variables when a dedicated secrets "
                            "service is more appropriate."

                    })

            else:

                findings.append({

                    "resource_type":
                        "Lambda Function",

                    "resource":
                        name,

                    "resource_arn":
                        arn,

                    "service":
                        "Lambda",

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "Lambda function has no environment "
                        "variables requiring additional "
                        "encryption review.",

                    "recommendation":
                        "No action required."

                })


            # =================================================
            # 3. PUBLIC RESOURCE POLICY
            # =================================================

            try:

                policy_response = lambda_client.get_policy(
                    FunctionName=name
                )

                policy_text = policy_response.get(
                    "Policy",
                    ""
                )


                # ------------------------------------------------
                # Check whether wildcard Principal is present
                # ------------------------------------------------

                if '"Principal":"*"' in policy_text:

                    findings.append({

                        "resource_type":
                            "Lambda Function",

                        "resource":
                            name,

                        "resource_arn":
                            arn,

                        "service":
                            "Lambda",

                        "severity":
                            "CRITICAL",

                        "status":
                            "Failed",

                        "issue":
                            "Lambda function resource policy "
                            "allows access from a wildcard "
                            "principal.",

                        "recommendation":
                            "Remove unnecessary wildcard "
                            "permissions and restrict the "
                            "function policy to trusted AWS "
                            "accounts, services, or principals."

                    })

                elif '"Principal":{"AWS":"*"}' in policy_text:

                    findings.append({

                        "resource_type":
                            "Lambda Function",

                        "resource":
                            name,

                        "resource_arn":
                            arn,

                        "service":
                            "Lambda",

                        "severity":
                            "CRITICAL",

                        "status":
                            "Failed",

                        "issue":
                            "Lambda function resource policy "
                            "allows wildcard AWS principals.",

                        "recommendation":
                            "Restrict the Lambda resource policy "
                            "to specific trusted principals."

                    })


            except Exception as policy_error:

                error_text = str(
                    policy_error
                ).lower()


                # A missing policy normally means the function
                # does not have a resource-based policy.

                if (
                    "resourceNotFound" not in error_text
                    and "not found" not in error_text
                    and "policy" not in error_text
                ):

                    findings.append({

                        "resource_type":
                            "Lambda Function",

                        "resource":
                            name,

                        "resource_arn":
                            arn,

                        "service":
                            "Lambda",

                        "severity":
                            "LOW",

                        "status":
                            "Unknown",

                        "issue":
                            "Lambda resource policy could "
                            "not be fully verified.",

                        "recommendation":
                            "Verify that the scanner role has "
                            "permission to retrieve Lambda "
                            "resource policies."

                    })


            # =================================================
            # 4. RUNTIME INFORMATION
            # =================================================

            if runtime == "Unknown":

                findings.append({

                    "resource_type":
                        "Lambda Function",

                    "resource":
                        name,

                    "resource_arn":
                        arn,

                    "service":
                        "Lambda",

                    "severity":
                        "LOW",

                    "status":
                        "Unknown",

                    "issue":
                        "Lambda runtime could not be determined.",

                    "recommendation":
                        "Verify Lambda function configuration "
                        "and scanner permissions."

                })


        # ====================================================
        # RETURN FINDINGS
        # ====================================================

        return findings


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as e:

        findings.append({

            "resource_type":
                "Lambda",

            "resource":
                "Lambda Functions",

            "service":
                "Lambda",

            "severity":
                "MEDIUM",

            "status":
                "Unknown",

            "issue":
                "Lambda security scan failed.",

            "recommendation":
                "Verify that the CloudGuardAI scanner role "
                "has permission to list and inspect Lambda "
                "functions.",

            "evidence":
                str(e)

        })

        return findings