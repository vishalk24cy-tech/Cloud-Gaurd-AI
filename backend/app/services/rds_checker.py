# ============================================================
# CloudGuardAI - AWS RDS Security Checker
# ============================================================


def check_rds(rds):

    findings = []

    try:

        # ====================================================
        # GET RDS DATABASE INSTANCES
        # ====================================================

        response = rds.describe_db_instances()

        databases = response.get(
            "DBInstances",
            []
        )


        # ====================================================
        # NO DATABASES FOUND
        # ====================================================

        if len(databases) == 0:

            findings.append({

                "resource_type":
                    "RDS",

                "resource":
                    "RDS Database",

                "service":
                    "RDS",

                "severity":
                    "LOW",

                "status":
                    "Protected",

                "issue":
                    "No RDS database instances were found.",

                "recommendation":
                    "No action required."

            })

            return findings


        # ====================================================
        # CHECK EACH DATABASE
        # ====================================================

        for db in databases:

            identifier = db.get(
                "DBInstanceIdentifier",
                "Unknown"
            )

            arn = db.get(
                "DBInstanceArn",
                ""
            )

            engine = db.get(
                "Engine",
                "Unknown"
            )

            publicly_accessible = db.get(
                "PubliclyAccessible",
                False
            )

            storage_encrypted = db.get(
                "StorageEncrypted",
                False
            )

            backup_retention = db.get(
                "BackupRetentionPeriod",
                0
            )

            deletion_protection = db.get(
                "DeletionProtection",
                False
            )

            kms_key_id = db.get(
                "KmsKeyId",
                ""
            )


            # =================================================
            # 1. PUBLIC ACCESSIBILITY
            # =================================================

            if publicly_accessible:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "engine":
                        engine,

                    "severity":
                        "CRITICAL",

                    "status":
                        "Failed",

                    "issue":
                        "RDS database is publicly accessible.",

                    "recommendation":
                        "Disable public accessibility and "
                        "place the database in private network "
                        "segments. Restrict access through "
                        "security groups."

                })

            else:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "engine":
                        engine,

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "RDS database is not publicly accessible.",

                    "recommendation":
                        "No action required."

                })


            # =================================================
            # 2. STORAGE ENCRYPTION
            # =================================================

            if not storage_encrypted:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "engine":
                        engine,

                    "severity":
                        "HIGH",

                    "status":
                        "Failed",

                    "issue":
                        "RDS storage encryption is disabled.",

                    "recommendation":
                        "Enable encryption at rest using "
                        "AWS KMS. For an existing database, "
                        "use an appropriate snapshot/restore "
                        "migration strategy."

                })

            else:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "engine":
                        engine,

                    "kms_key_id":
                        kms_key_id,

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "RDS storage encryption is enabled.",

                    "recommendation":
                        "Continue protecting the KMS key "
                        "with appropriate IAM controls."

                })


            # =================================================
            # 3. AUTOMATED BACKUPS
            # =================================================

            if backup_retention <= 0:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "severity":
                        "MEDIUM",

                    "status":
                        "Failed",

                    "issue":
                        "Automated RDS backups are disabled.",

                    "recommendation":
                        "Enable automated backups and configure "
                        "an appropriate backup retention period "
                        "based on business recovery requirements."

                })

            else:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "backup_retention_days":
                        backup_retention,

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        f"Automated backups are enabled "
                        f"with {backup_retention} day(s) "
                        f"of retention.",

                    "recommendation":
                        "No action required."

                })


            # =================================================
            # 4. DELETION PROTECTION
            # =================================================

            if not deletion_protection:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "severity":
                        "MEDIUM",

                    "status":
                        "Review",

                    "issue":
                        "RDS deletion protection is disabled.",

                    "recommendation":
                        "Enable deletion protection for "
                        "production databases to reduce "
                        "the risk of accidental deletion."

                })

            else:

                findings.append({

                    "resource_type":
                        "RDS Database",

                    "resource":
                        identifier,

                    "resource_arn":
                        arn,

                    "service":
                        "RDS",

                    "severity":
                        "LOW",

                    "status":
                        "Protected",

                    "issue":
                        "RDS deletion protection is enabled.",

                    "recommendation":
                        "No action required."

                })


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as e:

        findings.append({

            "resource_type":
                "RDS",

            "resource":
                "RDS Database",

            "service":
                "RDS",

            "severity":
                "MEDIUM",

            "status":
                "Unknown",

            "issue":
                "RDS security scan failed.",

            "recommendation":
                "Verify that the CloudGuardAI scanner role "
                "has permission to describe RDS instances.",

            "evidence":
                str(e)

        })


    # ========================================================
    # RETURN FINDINGS
    # ========================================================

    return findings