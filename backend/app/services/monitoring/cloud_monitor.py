# ============================================================
# CloudGuardAI - Background Cloud Monitoring
# ============================================================

from app.api.cloud import scan_aws

from app.models.aws_account import (
    get_all_connected_accounts
)

from app.services.scan_service import (
    get_latest_account_scan
)

from app.services.monitoring.change_detector import (
    detect_changes
)

from app.services.notification_service import (
    create_alert
)


# ============================================================
# RUN CLOUD MONITOR
# ============================================================

def run_cloud_monitor():

    print(
        "[INFO] CloudGuardAI Monitoring Scan Started"
    )

    try:

        # ====================================================
        # GET ALL CONNECTED ACCOUNTS
        # ====================================================

        accounts = get_all_connected_accounts()

        if not accounts:

            print(
                "[INFO] No connected AWS accounts found"
            )

            return []

        print(
            f"[INFO] Monitoring {len(accounts)} "
            f"AWS account(s)"
        )

        monitored_scans = []

        # ====================================================
        # PROCESS EACH AWS ACCOUNT
        # ====================================================

        for account in accounts:

            account_id = str(
                account.get("_id", "")
            )

            user_id = str(
                account.get("user_id", "")
            )

            account_name = account.get(
                "account_name",
                "AWS Account"
            )

            # =================================================
            # VALIDATION
            # =================================================

            if not account_id:

                print(
                    "[WARNING] Skipping account: "
                    "missing account_id"
                )

                continue

            if not user_id:

                print(
                    "[WARNING] Skipping account "
                    f"{account_id}: missing user_id"
                )

                continue

            print(
                "[INFO] Monitoring account: "
                f"{account_name} "
                f"({account_id})"
            )

            try:

                # =============================================
                # GET PREVIOUS SCAN
                #
                # SAME USER + SAME AWS ACCOUNT
                # =============================================

                old_scan = get_latest_account_scan(
                    user_id,
                    account_id
                )

                print(
                    "[INFO] Previous scan: "
                    f"{'FOUND' if old_scan else 'NOT FOUND'}"
                )

                # =============================================
                # RUN AWS SECURITY SCAN
                #
                # scan_aws() is normally called by FastAPI:
                #
                #     scan_aws(account_id, current_user)
                #
                # The background scheduler has no JWT.
                #
                # So we explicitly provide the authenticated
                # user's payload.
                # =============================================

                current_user = {
                    "_id": user_id
                }

                new_scan_response = scan_aws(
                    account_id,
                    current_user
                )

                # =============================================
                # VALIDATE SCAN RESPONSE
                # =============================================

                if not isinstance(
                    new_scan_response,
                    dict
                ):

                    print(
                        "[WARNING] Invalid scan response "
                        f"for account {account_id}"
                    )

                    continue

                new_scan = new_scan_response.get(
                    "scan"
                )

                if not new_scan:

                    print(
                        "[WARNING] Scan returned no scan data "
                        f"for account {account_id}"
                    )

                    continue

                monitored_scans.append(
                    new_scan
                )

                print(
                    "[OK] AWS scan completed for "
                    f"{account_name}"
                )

                # =============================================
                # CHANGE DETECTION
                # =============================================

                if old_scan:

                    changes = detect_changes(
                        old_scan,
                        new_scan
                    )

                    if changes:

                        print(
                            "[WARNING] Security changes "
                            f"detected for {account_name}"
                        )

                        # =====================================
                        # CREATE MONITORING ALERT
                        # =====================================

                        create_alert(

                            title=(
                                "Cloud Security Change Detected"
                            ),

                            message="\n".join(
                                changes
                            ),

                            severity="HIGH",

                            user_id=user_id,

                            account_id=account_id,

                            aws_account_id=(
                                new_scan.get(
                                    "aws_account_id"
                                )
                            ),

                            account_name=account_name,

                        )

                        print(
                            "[ALERT] Monitoring alert created "
                            f"for {account_name}"
                        )

                    else:

                        print(
                            "[OK] No security changes detected "
                            f"for {account_name}"
                        )

                else:

                    print(
                        "[INFO] First scan for "
                        f"{account_name}; "
                        "change detection skipped"
                    )

            except Exception as account_error:

                print(
                    "[ERROR] Monitoring failed for "
                    f"{account_name}: "
                    f"{account_error}"
                )

                # Continue monitoring other customers/accounts
                continue

        # ====================================================
        # MONITORING COMPLETE
        # ====================================================

        print(
            "[OK] CloudGuardAI Monitoring Completed"
        )

        print(
            f"[INFO] Successfully monitored "
            f"{len(monitored_scans)} account(s)"
        )

        return monitored_scans

    except Exception as e:

        print(
            "[ERROR] CloudGuardAI Monitoring Failed:",
            e
        )

        return None