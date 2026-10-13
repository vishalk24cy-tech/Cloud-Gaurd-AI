# ============================================================
# CloudGuardAI - AWS KMS Security Checker
# ============================================================


def check_kms(kms_client):

    findings = []

    try:

        # ====================================================
        # GET KMS KEYS
        # ====================================================

        response = kms_client.list_keys()

        keys = response.get(
            "Keys",
            []
        )


        # ====================================================
        # NO KEYS FOUND
        # ====================================================

        if len(keys) == 0:

            findings.append({

                "resource_type":
                    "KMS",

                "resource":
                    "KMS Keys",

                "service":
                    "KMS",

                "severity":
                    "MEDIUM",

                "status":
                    "Review",

                "issue":
                    "No KMS keys were discovered.",

                "recommendation":
                    "Review encryption requirements and "
                    "use appropriate AWS KMS keys for "
                    "protected data."

            })

            return findings


        # ====================================================
        # CHECK EACH KEY
        # ====================================================

        for key in keys:

            key_id = key.get(
                "KeyId",
                "Unknown"
            )


            # =================================================
            # GET KEY METADATA
            # =================================================

            try:

                metadata_response = kms_client.describe_key(
                    KeyId=key_id
                )

                key_info = metadata_response.get(
                    "KeyMetadata",
                    {}
                )


            except Exception as e:

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "service":
                        "KMS",

                    "severity":
                        "MEDIUM",

                    "status":
                        "Unknown",

                    "issue":
                        "KMS key metadata could not "
                        "be verified.",

                    "recommendation":
                        "Verify that the CloudGuardAI "
                        "scanner role can describe KMS keys.",

                    "evidence":
                        str(e)

                })

                continue


            # =================================================
            # KEY INFORMATION
            # =================================================

            key_state = key_info.get(
                "KeyState",
                "Unknown"
            )

            key_manager = key_info.get(
                "KeyManager",
                "Unknown"
            )

            key_arn = key_info.get(
                "Arn",
                ""
            )

            description = key_info.get(
                "Description",
                ""
            )

            enabled = key_info.get(
                "Enabled",
                False
            )


            # =================================================
            # 1. KEY STATE
            # =================================================

            if key_state != "Enabled":

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "key_state":
                        key_state,

                    "key_manager":
                        key_manager,

                    "severity":
                        "HIGH",

                    "status":
                        "Failed",

                    "issue":
                        f"KMS key is not enabled "
                        f"({key_id}).",

                    "recommendation":
                        "Investigate the key state and "
                        "enable or replace the key when "
                        "appropriate. Check dependencies "
                        "before making changes."

                })

                # Do not perform normal rotation checks
                # on a key that isn't enabled.
                continue


            # =================================================
            # 2. KEY TYPE
            # =================================================

            if key_manager == "AWS":

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "key_manager":
                        key_manager,

                    "severity":
                        "LOW",

                    "status":
                        "Informational",

                    "issue":
                        "AWS-managed KMS key is in use.",

                    "recommendation":
                        "AWS-managed keys are appropriate "
                        "for many AWS services. Use a "
                        "customer-managed key when your "
                        "organization requires additional "
                        "control over key policies, rotation, "
                        "or lifecycle management."

                })

            elif key_manager == "CUSTOMER":

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "key_manager":
                        key_manager,

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "Customer-managed KMS key is configured.",

                    "recommendation":
                        "Continue monitoring the key policy, "
                        "rotation, and lifecycle."

                })


            # =================================================
            # 3. KEY ROTATION
            # =================================================

            rotation_checked = False
            rotation_enabled = False


            try:

                rotation_response = (
                    kms_client.get_key_rotation_status(
                        KeyId=key_id
                    )
                )

                rotation_enabled = rotation_response.get(
                    "KeyRotationEnabled",
                    False
                )

                rotation_checked = True


            except Exception as rotation_error:

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "severity":
                        "MEDIUM",

                    "status":
                        "Unknown",

                    "issue":
                        "KMS key rotation status could "
                        "not be verified.",

                    "recommendation":
                        "Verify scanner permissions and "
                        "review the key rotation configuration.",

                    "evidence":
                        str(rotation_error)

                })


            if rotation_checked:

                if rotation_enabled:

                    findings.append({

                        "resource_type":
                            "KMS Key",

                        "resource":
                            key_id,

                        "resource_arn":
                            key_arn,

                        "service":
                            "KMS",

                        "rotation_enabled":
                            True,

                        "severity":
                            "LOW",

                        "status":
                            "Protected",

                        "issue":
                            "Automatic KMS key rotation "
                            "is enabled.",

                        "recommendation":
                            "Continue monitoring key lifecycle "
                            "and access policies."

                    })

                else:

                    # AWS-managed keys have AWS-controlled
                    # rotation behavior, so don't mark them
                    # as a failed customer configuration.

                    if key_manager == "CUSTOMER":

                        findings.append({

                            "resource_type":
                                "KMS Key",

                            "resource":
                                key_id,

                            "resource_arn":
                                key_arn,

                            "service":
                                "KMS",

                            "rotation_enabled":
                                False,

                            "severity":
                                "MEDIUM",

                            "status":
                                "Review",

                            "issue":
                                "Automatic rotation is not "
                                "enabled for a customer-managed "
                                "KMS key.",

                            "recommendation":
                                "Enable automatic key rotation "
                                "where appropriate and verify "
                                "that the key policy supports "
                                "your security requirements."

                        })

                    else:

                        findings.append({

                            "resource_type":
                                "KMS Key",

                            "resource":
                                key_id,

                            "resource_arn":
                                key_arn,

                            "service":
                                "KMS",

                            "rotation_enabled":
                                False,

                            "severity":
                                "LOW",

                            "status":
                                "Informational",

                            "issue":
                                "Rotation status is not "
                                "enabled for this AWS-managed "
                                "key.",

                            "recommendation":
                                "AWS manages the lifecycle "
                                "of AWS-managed keys. Review "
                                "the service's encryption "
                                "configuration as needed."

                        })


            # =================================================
            # 4. KEY ENABLED STATUS
            # =================================================

            if enabled:

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "KMS key is currently enabled.",

                    "recommendation":
                        "No action required."

                })


            # =================================================
            # 5. DESCRIPTION / METADATA
            # =================================================

            if description:

                findings.append({

                    "resource_type":
                        "KMS Key",

                    "resource":
                        key_id,

                    "resource_arn":
                        key_arn,

                    "service":
                        "KMS",

                    "severity":
                        "LOW",

                    "status":
                        "Informational",

                    "issue":
                        f"KMS key description: {description}",

                    "recommendation":
                        "No action required."

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
                "KMS",

            "resource":
                "KMS Keys",

            "service":
                "KMS",

            "severity":
                "MEDIUM",

            "status":
                "Unknown",

            "issue":
                "KMS security scan failed.",

            "recommendation":
                "Verify that the CloudGuardAI scanner "
                "role has permission to list and inspect "
                "KMS keys.",

            "evidence":
                str(e)

        })

        return findings