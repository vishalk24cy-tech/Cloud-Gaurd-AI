# ============================================================
# CloudGuardAI - AWS IAM Security Checker
# ============================================================


def check_iam(iam_client):

    findings = []

    # ========================================================
    # GET IAM USERS
    # ========================================================

    response = iam_client.list_users()

    users = response.get(
        "Users",
        []
    )


    # ========================================================
    # CHECK EACH IAM USER
    # ========================================================

    for user in users:

        username = user.get(
            "UserName",
            "Unknown"
        )

        user_arn = user.get(
            "Arn",
            ""
        )


        # ====================================================
        # 1. MFA CHECK
        # ====================================================

        try:

            mfa_response = iam_client.list_mfa_devices(
                UserName=username
            )

            mfa_devices = mfa_response.get(
                "MFADevices",
                []
            )


            if len(mfa_devices) == 0:

                findings.append({

                    "resource_type":
                        "IAM User",

                    "resource":
                        username,

                    "user":
                        username,

                    "severity":
                        "HIGH",

                    "status":
                        "Risk",

                    "issue":
                        "MFA is not enabled for IAM user.",

                    "recommendation":
                        "Enable Multi-Factor Authentication "
                        "for the IAM user, especially for "
                        "privileged or console-enabled accounts."

                })


        except Exception:

            findings.append({

                "resource_type":
                    "IAM User",

                "resource":
                    username,

                "user":
                    username,

                "severity":
                    "MEDIUM",

                "status":
                    "Unknown",

                "issue":
                    "CloudGuardAI could not verify "
                    "MFA configuration.",

                "recommendation":
                    "Grant the scanner role permission to "
                    "list MFA devices and verify the user's "
                    "MFA configuration."

            })


        # ====================================================
        # 2. LOGIN PROFILE / CONSOLE ACCESS
        # ====================================================

        has_console_access = False

        try:

            iam_client.get_login_profile(
                UserName=username
            )

            has_console_access = True


        except Exception as error:

            error_message = str(error).lower()

            # NoSuchEntity normally means the user does not
            # have a console login profile.

            if "nosuchentity" in error_message:

                has_console_access = False

            elif "no such entity" in error_message:

                has_console_access = False

            elif "not found" in error_message:

                has_console_access = False

            elif "accessdenied" in error_message:

                findings.append({

                    "resource_type":
                        "IAM User",

                    "resource":
                        username,

                    "user":
                        username,

                    "severity":
                        "LOW",

                    "status":
                        "Unknown",

                    "issue":
                        "Console login access could not "
                        "be verified.",

                    "recommendation":
                        "Grant the scanner role permission "
                        "to verify IAM login profiles."

                })


        # ====================================================
        # 3. ACCESS KEY CHECK
        # ====================================================

        try:

            keys_response = iam_client.list_access_keys(
                UserName=username
            )

            access_keys = keys_response.get(
                "AccessKeyMetadata",
                []
            )


            for key in access_keys:

                access_key_id = key.get(
                    "AccessKeyId",
                    "Unknown"
                )

                key_status = key.get(
                    "Status",
                    "Unknown"
                )

                created_date = key.get(
                    "CreateDate"
                )


                # ============================================
                # INACTIVE ACCESS KEY
                # ============================================

                if key_status != "Active":

                    findings.append({

                        "resource_type":
                            "IAM Access Key",

                        "resource":
                            access_key_id,

                        "user":
                            username,

                        "access_key_id":
                            access_key_id,

                        "severity":
                            "LOW",

                        "status":
                            "Inactive",

                        "issue":
                            "IAM access key is inactive.",

                        "recommendation":
                            "Remove unused IAM access keys "
                            "after confirming they are no longer "
                            "required."

                    })


                # ============================================
                # ACTIVE ACCESS KEY
                # ============================================

                else:

                    findings.append({

                        "resource_type":
                            "IAM Access Key",

                        "resource":
                            access_key_id,

                        "user":
                            username,

                        "access_key_id":
                            access_key_id,

                        "severity":
                            "LOW",

                        "status":
                            "Active",

                        "issue":
                            "IAM access key is active.",

                        "recommendation":
                            "Review the access key regularly "
                            "and rotate or remove it when "
                            "no longer required."

                    })


        except Exception:

            findings.append({

                "resource_type":
                    "IAM User",

                "resource":
                    username,

                "user":
                    username,

                "severity":
                    "MEDIUM",

                "status":
                    "Unknown",

                "issue":
                    "CloudGuardAI could not verify "
                    "IAM access keys.",

                "recommendation":
                    "Grant the scanner role permission "
                    "to list IAM access keys."

            })


        # ====================================================
        # 4. USER ATTACHED MANAGED POLICIES
        # ====================================================

        try:

            policies_response = iam_client.list_attached_user_policies(
                UserName=username
            )

            policies = policies_response.get(
                "AttachedPolicies",
                []
            )


            for policy in policies:

                policy_name = policy.get(
                    "PolicyName",
                    "Unknown"
                )

                policy_arn = policy.get(
                    "PolicyArn",
                    ""
                )


                # =================================================
                # ADMINISTRATOR ACCESS
                # =================================================

                if policy_name.lower() == "administratoraccess":

                    findings.append({

                        "resource_type":
                            "IAM User Policy",

                        "resource":
                            username,

                        "user":
                            username,

                        "policy":
                            policy_name,

                        "policy_arn":
                            policy_arn,

                        "severity":
                            "CRITICAL",

                        "status":
                            "High Privilege",

                        "issue":
                            "IAM user has the AWS "
                            "AdministratorAccess managed policy.",

                        "recommendation":
                            "Apply least privilege and replace "
                            "full administrator access with only "
                            "the permissions required by the user."

                    })


        except Exception:

            findings.append({

                "resource_type":
                    "IAM User",

                "resource":
                    username,

                "user":
                    username,

                "severity":
                    "LOW",

                "status":
                    "Unknown",

                "issue":
                    "CloudGuardAI could not verify "
                    "attached IAM policies.",

                "recommendation":
                    "Grant the scanner role permission "
                    "to list policies attached to IAM users."

            })


        # ====================================================
        # 5. USER INLINE POLICIES
        # ====================================================

        try:

            inline_response = iam_client.list_user_policies(
                UserName=username
            )

            inline_policies = inline_response.get(
                "PolicyNames",
                []
            )


            if len(inline_policies) > 0:

                findings.append({

                    "resource_type":
                        "IAM User",

                    "resource":
                        username,

                    "user":
                        username,

                    "severity":
                        "LOW",

                    "status":
                        "Review",

                    "issue":
                        "IAM user has inline policies attached.",

                    "recommendation":
                        "Review inline policies and prefer "
                        "managed policies where practical "
                        "to simplify permission management."

                })


        except Exception:

            pass


    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings