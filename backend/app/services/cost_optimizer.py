import boto3
from botocore.exceptions import ClientError


# ============================================================
# COST OPTIMIZER
# ============================================================

def get_cost_overview(session, days=30):
    """
    Get real AWS Cost Explorer data for the selected period.
    """

    try:

        ce = session.client(
            "ce",
            region_name="us-east-1"
        )

        from datetime import date, timedelta

        end_date = date.today()
        start_date = end_date - timedelta(days=days)

        response = ce.get_cost_and_usage(
            TimePeriod={
                "Start": start_date.strftime("%Y-%m-%d"),
                "End": end_date.strftime("%Y-%m-%d")
            },
            Granularity="DAILY",
            Metrics=[
                "UnblendedCost"
            ],
            GroupBy=[
                {
                    "Type": "DIMENSION",
                    "Key": "SERVICE"
                }
            ]
        )

        total_cost = 0.0
        services = []

        for result in response.get("ResultsByTime", []):

            for group in result.get("Groups", []):

                service_name = group["Keys"][0]

                amount = float(
                    group["Metrics"]["UnblendedCost"]["Amount"]
                )

                total_cost += amount

                services.append({
                    "service": service_name,
                    "cost": round(amount, 2)
                })

        # Combine same services
        service_totals = {}

        for item in services:

            service = item["service"]

            if service not in service_totals:
                service_totals[service] = 0.0

            service_totals[service] += item["cost"]

        service_breakdown = []

        for service, cost in service_totals.items():

            service_breakdown.append({
                "service": service,
                "cost": round(cost, 2)
            })

        # Highest cost services first
        service_breakdown.sort(
            key=lambda x: x["cost"],
            reverse=True
        )

        return {
            "status": "success",
            "period_days": days,
            "currency": "USD",
            "total_cost": round(total_cost, 2),
            "service_breakdown": service_breakdown
        }

    except ClientError as e:

        print(
            "AWS Cost Explorer Error:",
            str(e)
        )

        return {
            "status": "error",
            "message": str(e)
        }

    except Exception as e:

        print(
            "Cost Optimizer Error:",
            str(e)
        )

        return {
            "status": "error",
            "message": str(e)
        }


# ============================================================
# COST OPTIMIZATION RECOMMENDATIONS
# ============================================================

def get_cost_recommendations(session):

    recommendations = []

    try:

        ec2 = session.client("ec2")

        # ----------------------------------------------------
        # 1. STOPPED EC2 INSTANCES
        # ----------------------------------------------------

        response = ec2.describe_instances(
            Filters=[
                {
                    "Name": "instance-state-name",
                    "Values": ["stopped"]
                }
            ]
        )

        stopped_instances = []

        for reservation in response.get(
            "Reservations", []
        ):

            for instance in reservation.get(
                "Instances", []
            ):

                stopped_instances.append(
                    instance["InstanceId"]
                )

        if stopped_instances:

            recommendations.append({

                "type": "EC2",

                "category": "Unused Resource",

                "severity": "MEDIUM",

                "title": "Stopped EC2 Instances",

                "description":
                    f"{len(stopped_instances)} EC2 "
                    "instance(s) are currently stopped. "
                    "Review them and terminate unused "
                    "instances if they are no longer required.",

                "resource_count":
                    len(stopped_instances),

                "resources":
                    stopped_instances,

                "action":
                    "Review and terminate unused instances"

            })

        # ----------------------------------------------------
        # 2. UNUSED EBS VOLUMES
        # ----------------------------------------------------

        volume_response = ec2.describe_volumes(
            Filters=[
                {
                    "Name": "status",
                    "Values": ["available"]
                }
            ]
        )

        unused_volumes = []

        for volume in volume_response.get(
            "Volumes", []
        ):

            unused_volumes.append(
                volume["VolumeId"]
            )

        if unused_volumes:

            recommendations.append({

                "type": "EBS",

                "category": "Unused Storage",

                "severity": "MEDIUM",

                "title": "Unused EBS Volumes",

                "description":
                    f"{len(unused_volumes)} EBS "
                    "volume(s) are not attached to "
                    "any EC2 instance.",

                "resource_count":
                    len(unused_volumes),

                "resources":
                    unused_volumes,

                "action":
                    "Review and delete unused EBS volumes"

            })

        # ----------------------------------------------------
        # 3. OLD EBS SNAPSHOTS
        # ----------------------------------------------------

        sts = session.client("sts")

        identity = sts.get_caller_identity()

        account_id = identity["Account"]

        snapshot_response = ec2.describe_snapshots(
            OwnerIds=[account_id]
        )

        from datetime import datetime, timezone

        old_snapshots = []

        for snapshot in snapshot_response.get(
            "Snapshots", []
        ):

            start_time = snapshot.get(
                "StartTime"
            )

            if not start_time:
                continue

            age_days = (
                datetime.now(timezone.utc)
                - start_time
            ).days

            if age_days > 90:

                old_snapshots.append({
                    "snapshot_id":
                        snapshot["SnapshotId"],

                    "age_days":
                        age_days
                })

        if old_snapshots:

            recommendations.append({

                "type": "EBS Snapshot",

                "category": "Old Backup",

                "severity": "LOW",

                "title": "Old EBS Snapshots",

                "description":
                    f"{len(old_snapshots)} snapshot(s) "
                    "are older than 90 days. Review "
                    "whether they are still required.",

                "resource_count":
                    len(old_snapshots),

                "resources":
                    old_snapshots,

                "action":
                    "Review and delete unnecessary old snapshots"

            })

        # ----------------------------------------------------
        # SUMMARY
        # ----------------------------------------------------

        return {

            "status": "success",

            "total_opportunities":
                len(recommendations),

            "recommendations":
                recommendations

        }

    except ClientError as e:

        print(
            "AWS Cost Recommendation Error:",
            str(e)
        )

        return {

            "status": "error",

            "message":
                str(e)

        }

    except Exception as e:

        print(
            "Cost Recommendation Error:",
            str(e)
        )

        return {

            "status": "error",

            "message":
                str(e)

        }