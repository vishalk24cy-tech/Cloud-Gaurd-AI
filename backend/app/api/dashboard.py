from fastapi import APIRouter, Depends

from app.services.scan_service import get_all_scans
from app.middleware.auth_middleware import verify_token


router = APIRouter()


# ============================================================
# CLOUDGUARD AI - DASHBOARD API
# Optimized Version
#
# IMPORTANT:
# - Only ONE database read is performed.
# - Statistics are calculated from the same scan data.
# - This removes the duplicate get_all_scans() call.
# - Projection limits MongoDB response to required fields.
# ============================================================


@router.get("/")
def dashboard(
    current_user=Depends(verify_token)
):

    # ========================================================
    # GET USER ID
    # ========================================================

    user_id = str(
        current_user.get("_id")
        or current_user.get("id")
        or current_user.get("user_id")
        or ""
    )

    if not user_id:

        return {
            "total_scans": 0,
            "latest_risk_score": 0,
            "average_risk_score": 0,
            "security_level": "Unknown",
            "aws_accounts": 0,

            "total_resources": 0,
            "critical_findings": 0,
            "compliance_score": 100,

            "highest_risk": 0,
            "lowest_risk": 0,
            "average_risk": 0,
            "critical_scans": 0,

            "risk_trend": [],
            "severity_distribution": {
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },

            "resource_distribution": {
                "ec2": 0,
                "s3": 0,
                "iam": 0,
            },

            "recent_scans": [],
        }


    # ========================================================
    # ONE DATABASE QUERY ONLY
    # ========================================================
    #
    # Projection:
    # Return only fields required by this dashboard.
    #
    # This avoids loading unrelated scan fields such as:
    # generated_policies, metadata, timestamps, etc.
    # ========================================================

    scans = get_all_scans(
        user_id,
        projection={
            "_id": 1,
            "account": 1,
            "account_id": 1,
            "aws_account_id": 1,
            "account_name": 1,
            "risk_score": 1,
            "security_level": 1,
            "resources": 1,
            "findings": 1,
            "scan_time": 1,
        },
        limit=20
    )


    # ========================================================
    # DEFAULT VALUES
    # ========================================================

    highest_risk = 0
    lowest_risk = 0
    average_risk = 0

    critical_scans = 0

    risk_trend = []
    recent_scans = []

    severity = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    resources = {
        "ec2": 0,
        "s3": 0,
        "iam": 0,
    }

    risk_scores = []

    aws_accounts = set()


    # ========================================================
    # PROCESS SCANS
    # ========================================================

    for scan in scans:

        if not isinstance(scan, dict):
            continue


        # ----------------------------------------------------
        # RISK SCORE
        # ----------------------------------------------------

        try:

            score = float(
                scan.get(
                    "risk_score",
                    0
                )
            )

        except (
            ValueError,
            TypeError
        ):

            score = 0


        risk_scores.append(score)


        # ----------------------------------------------------
        # RISK TREND
        # ----------------------------------------------------

        risk_trend.append(
            {
                "risk_score": score,
                "scan_time": str(
                    scan.get(
                        "scan_time",
                        "Unknown"
                    )
                )
            }
        )


        # ----------------------------------------------------
        # RESOURCES
        # ----------------------------------------------------

        scan_resources = scan.get(
            "resources",
            {}
        )

        if not isinstance(
            scan_resources,
            dict
        ):

            scan_resources = {}


        try:

            resources["ec2"] += int(
                scan_resources.get(
                    "ec2",
                    0
                ) or 0
            )

        except (
            ValueError,
            TypeError
        ):

            pass


        try:

            resources["s3"] += int(
                scan_resources.get(
                    "s3",
                    0
                ) or 0
            )

        except (
            ValueError,
            TypeError
        ):

            pass


        try:

            resources["iam"] += int(
                scan_resources.get(
                    "iam",
                    0
                ) or 0
            )

        except (
            ValueError,
            TypeError
        ):

            pass


        # ----------------------------------------------------
        # SECURITY LEVEL
        # ----------------------------------------------------

        security_level = str(
            scan.get(
                "security_level",
                ""
            )
            or ""
        ).strip().lower()


        if security_level == "critical":

            critical_scans += 1


        # ----------------------------------------------------
        # ACCOUNT
        # ----------------------------------------------------

        account_id = scan.get(
            "account_id"
        )

        aws_account_id = scan.get(
            "aws_account_id"
        )

        account = scan.get(
            "account"
        )

        account_name = scan.get(
            "account_name"
        )


        if account_id:

            aws_accounts.add(
                f"internal:{account_id}"
            )

        elif aws_account_id:

            aws_accounts.add(
                f"aws:{aws_account_id}"
            )

        elif account:

            aws_accounts.add(
                f"name:{account}"
            )

        elif account_name:

            aws_accounts.add(
                f"name:{account_name}"
            )


        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        findings = scan.get(
            "findings",
            []
        )

        if not isinstance(
            findings,
            list
        ):

            findings = []


        for finding in findings:

            if not isinstance(
                finding,
                dict
            ):

                continue


            severity_value = str(
                finding.get(
                    "severity",
                    "INFO"
                )
                or "INFO"
            ).strip().upper()


            if severity_value in severity:

                severity[
                    severity_value
                ] += 1


    # ========================================================
    # CALCULATE RISK STATISTICS
    # ========================================================

    if risk_scores:

        highest_risk = max(
            risk_scores
        )

        lowest_risk = min(
            risk_scores
        )

        average_risk = (
            sum(risk_scores)
            /
            len(risk_scores)
        )

        average_risk = round(
            average_risk,
            2
        )


    # ========================================================
    # TOTAL RESOURCES
    # ========================================================

    total_resources = (
        resources["ec2"]
        +
        resources["s3"]
        +
        resources["iam"]
    )


    # ========================================================
    # LATEST SCAN
    # ========================================================

    latest_risk_score = 0

    latest_security_level = "Unknown"


    if scans:

        latest_scan = scans[0]

        try:

            latest_risk_score = float(
                latest_scan.get(
                    "risk_score",
                    0
                )
            )

        except (
            ValueError,
            TypeError
        ):

            latest_risk_score = 0


        latest_security_level = str(
            latest_scan.get(
                "security_level",
                "Unknown"
            )
            or "Unknown"
        )


    # ========================================================
    # SECURITY LEVEL
    # ========================================================

    if average_risk <= 20:

        security_level = "Excellent"

    elif average_risk <= 40:

        security_level = "Good"

    elif average_risk <= 60:

        security_level = "Medium"

    elif average_risk <= 80:

        security_level = "High"

    else:

        security_level = "Critical"


    # ========================================================
    # COMPLIANCE SCORE
    # ========================================================

    compliance_score = max(
        0,
        round(
            100 - average_risk,
            2
        )
    )


    # ========================================================
    # CRITICAL FINDINGS
    # ========================================================

    critical_findings = (
        severity["HIGH"]
    )


    # ========================================================
    # RECENT SCANS
    # ========================================================

    for scan in scans[:5]:

        if not isinstance(
            scan,
            dict
        ):

            continue


        recent_scans.append(
            {
                "id": str(
                    scan.get(
                        "_id",
                        ""
                    )
                ),

                "account": scan.get(
                    "account",
                    scan.get(
                        "aws_account_id",
                        scan.get(
                            "account_name",
                            "AWS Account"
                        )
                    )
                ),

                "risk_score": scan.get(
                    "risk_score",
                    0
                ),

                "security_level": scan.get(
                    "security_level",
                    "Unknown"
                ),

                "scan_time": str(
                    scan.get(
                        "scan_time",
                        "Unknown"
                    )
                )
            }
        )


    # ========================================================
    # FINAL RESPONSE
    # ========================================================

    return {

        # Basic dashboard statistics

        "total_scans": len(scans),

        "latest_risk_score":
            latest_risk_score,

        "average_risk_score":
            average_risk,

        "security_level":
            security_level,

        "aws_accounts":
            len(aws_accounts),


        # Resource statistics

        "total_resources":
            total_resources,

        "critical_findings":
            critical_findings,

        "compliance_score":
            compliance_score,


        # Risk statistics

        "highest_risk":
            highest_risk,

        "lowest_risk":
            lowest_risk,

        "average_risk":
            average_risk,

        "critical_scans":
            critical_scans,


        # Charts

        "risk_trend":
            risk_trend,

        "severity_distribution":
            severity,

        "resource_distribution":
            resources,


        # Recent scans

        "recent_scans":
            recent_scans,
    }