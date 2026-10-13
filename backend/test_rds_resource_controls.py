# ============================================================
# CloudGuardAI - Unit & Regression Tests for RDS Resource Controls
# Phase 4: AWS RDS Resource Management & Database Security
# ============================================================

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.api.cloud import control_rds_instance, list_rds_clusters, list_rds_instances, RDSActionRequest
from app.models.audit_log import (
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_RESOURCE_CONTROL_COMPLETED,
    EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
    EVENT_RESOURCE_CONTROL_FAILED,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
)
from app.services.rds_control_service import (
    ALLOWED_RDS_ACTIONS,
    RDSControlExecutionError,
    execute_rds_instance_action,
    fetch_rds_clusters_inventory,
    fetch_rds_instances_inventory,
    is_valid_rds_identifier,
    normalize_rds_cluster,
    normalize_rds_instance,
    validate_aws_region,
)


class TestRDSResourceInventoryUnit(unittest.TestCase):
    """Unit tests for RDS validation helpers, normalization, and inventory fetching."""

    def test_validate_aws_region(self):
        """Validates region string format."""
        self.assertTrue(validate_aws_region("us-east-1"))
        self.assertTrue(validate_aws_region("ap-south-1"))
        self.assertTrue(validate_aws_region("eu-central-1"))

        self.assertFalse(validate_aws_region(""))
        self.assertFalse(validate_aws_region("invalid_region"))
        self.assertFalse(validate_aws_region("us-east-1a"))
        self.assertFalse(validate_aws_region(None))

    def test_is_valid_rds_identifier(self):
        """Validates RDS DB instance and cluster identifier naming rules."""
        self.assertTrue(is_valid_rds_identifier("prod-db-postgres-01"))
        self.assertTrue(is_valid_rds_identifier("mydb"))
        self.assertTrue(is_valid_rds_identifier("cloudguard-aurora-cluster"))

        # Invalid identifiers
        self.assertFalse(is_valid_rds_identifier(""))
        self.assertFalse(is_valid_rds_identifier("1-leading-number-not-standard"))
        self.assertFalse(is_valid_rds_identifier("trailing-dash-"))
        self.assertFalse(is_valid_rds_identifier("double--dash"))
        self.assertFalse(is_valid_rds_identifier("a" * 64))
        self.assertFalse(is_valid_rds_identifier(None))

    def test_normalize_rds_instance(self):
        """Normalizes RDS instance dictionary into API model with posture."""
        raw_db = {
            "DBInstanceIdentifier": "prod-orders-db",
            "DBInstanceArn": "arn:aws:rds:us-east-1:123456789012:db:prod-orders-db",
            "Engine": "postgres",
            "EngineVersion": "15.4",
            "DBInstanceClass": "db.r6g.xlarge",
            "DBInstanceStatus": "available",
            "AvailabilityZone": "us-east-1b",
            "MultiAZ": True,
            "PubliclyAccessible": False,
            "StorageEncrypted": True,
            "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/abc-123",
            "BackupRetentionPeriod": 7,
            "DeletionProtection": True,
            "Endpoint": {"Address": "prod-orders.123456789012.us-east-1.rds.amazonaws.com", "Port": 5432},
            "DBSubnetGroup": {"VpcId": "vpc-01234567", "DBSubnetGroupName": "main-subnets"},
            "VpcSecurityGroups": [{"VpcSecurityGroupId": "sg-01234567", "Status": "active"}],
        }

        res = normalize_rds_instance(raw_db, fallback_region="us-east-1")
        self.assertEqual(res["db_instance_identifier"], "prod-orders-db")
        self.assertEqual(res["engine"], "postgres")
        self.assertEqual(res["region"], "us-east-1")
        self.assertEqual(res["security_posture"], "SECURE")
        self.assertFalse(res["publicly_accessible"])
        self.assertTrue(res["storage_encrypted"])
        self.assertTrue(res["multi_az"])
        self.assertEqual(res["endpoint"]["port"], 5432)

    def test_normalize_rds_instance_critical_posture(self):
        """Instances with PubliclyAccessible=True are marked CRITICAL."""
        raw_db = {
            "DBInstanceIdentifier": "dev-public-mysql",
            "Engine": "mysql",
            "DBInstanceClass": "db.t3.micro",
            "DBInstanceStatus": "available",
            "PubliclyAccessible": True,
            "StorageEncrypted": False,
            "BackupRetentionPeriod": 0,
            "DeletionProtection": False,
        }

        res = normalize_rds_instance(raw_db, fallback_region="ap-south-1")
        self.assertEqual(res["security_posture"], "CRITICAL")
        self.assertTrue(res["publicly_accessible"])
        self.assertFalse(res["storage_encrypted"])

    def test_fetch_rds_instances_inventory(self):
        """Fetches and filters RDS inventory with pagination support."""
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": "finance-db-prod",
                    "Engine": "postgres",
                    "DBInstanceClass": "db.m5.large",
                    "DBInstanceStatus": "available",
                    "AvailabilityZone": "us-east-1a",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 14,
                    "DeletionProtection": True,
                },
                {
                    "DBInstanceIdentifier": "analytics-db-dev",
                    "Engine": "mysql",
                    "DBInstanceClass": "db.t3.small",
                    "DBInstanceStatus": "stopped",
                    "AvailabilityZone": "us-east-1b",
                    "PubliclyAccessible": False,
                    "StorageEncrypted": True,
                    "BackupRetentionPeriod": 1,
                    "DeletionProtection": False,
                },
            ],
            "Marker": "next-page-marker",
        }

        inv = fetch_rds_instances_inventory(
            rds_client=mock_rds,
            region="us-east-1",
            max_records=50,
        )

        self.assertEqual(inv["total_count"], 2)
        self.assertEqual(inv["summary"]["available_instances"], 1)
        self.assertEqual(inv["summary"]["stopped_instances"], 1)
        self.assertEqual(inv["next_token"], "next-page-marker")


class TestRDSControlExecution(unittest.TestCase):
    """Tests for safe RDS control actions, state transition validation, and audit logging."""

    def setUp(self):
        self.account_id = str(ObjectId())
        self.aws_account_id = "123456789012"
        self.user_id = "user-rds-admin-1"
        self.org_id = "org-enterprise-rds"
        self.instance_id = "prod-pg-database"

        self.mock_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "account_name": "Prod Data Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardAIRole",
            "organization_id": self.org_id,
            "region": "us-east-1",
            "status": "connected",
        }

        from app.database.connection import db
        db.aws_accounts.insert_one(dict(self.mock_account))
        db.remediation_settings.insert_one({
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "services": {
                "ec2": True,
                "s3": True,
                "vpc": True,
                "rds": True,
                "iam": True,
                "cloudtrail": True,
            },
        })

    def tearDown(self):
        from app.database.connection import db
        db.aws_accounts.delete_many({"organization_id": self.org_id})
        db.remediation_settings.delete_many({"organization_id": self.org_id})

    @patch("app.services.rds_control_service.record_event")
    @patch("app.services.rds_control_service.get_aws_clients")
    @patch("app.services.rds_control_service.verify_aws_account")
    @patch("app.services.rds_control_service.assume_aws_role")
    @patch("app.services.rds_control_service.get_account")
    def test_start_stopped_instance_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_record_event,
    ):
        """Starts a stopped standalone RDS DB instance."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_rds = MagicMock()
        mock_clients.return_value = {"rds": mock_rds}

        # Pre-state: stopped
        mock_rds.describe_db_instances.side_effect = [
            {"DBInstances": [{"DBInstanceIdentifier": self.instance_id, "DBInstanceStatus": "stopped"}]},
            {"DBInstances": [{"DBInstanceIdentifier": self.instance_id, "DBInstanceStatus": "starting"}]},
        ]

        res = execute_rds_instance_action(
            account_id=self.account_id,
            instance_id=self.instance_id,
            action="start",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="admin",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action"], "start")
        self.assertEqual(res["verification_status"], "VERIFIED")

        mock_rds.start_db_instance.assert_called_once_with(DBInstanceIdentifier=self.instance_id)

        # Audit events check
        event_types = [call[1]["event_type"] for call in mock_record_event.call_args_list]
        self.assertIn(EVENT_RESOURCE_CONTROL_EXECUTION_STARTED, event_types)
        self.assertIn(EVENT_RESOURCE_CONTROL_COMPLETED, event_types)

    @patch("app.services.rds_control_service.get_aws_clients")
    @patch("app.services.rds_control_service.verify_aws_account")
    @patch("app.services.rds_control_service.assume_aws_role")
    @patch("app.services.rds_control_service.get_account")
    def test_start_already_available_instance_rejected(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
    ):
        """Starting an already available instance is rejected with 400 state error."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_rds = MagicMock()
        mock_clients.return_value = {"rds": mock_rds}

        # Pre-state: available
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [{"DBInstanceIdentifier": self.instance_id, "DBInstanceStatus": "available"}]
        }

        with self.assertRaises(RDSControlExecutionError) as ctx:
            execute_rds_instance_action(
                account_id=self.account_id,
                instance_id=self.instance_id,
                action="start",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="owner",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.code, "INVALID_STATE_TRANSITION")

    @patch("app.services.rds_control_service.record_event")
    @patch("app.services.rds_control_service.get_aws_clients")
    @patch("app.services.rds_control_service.verify_aws_account")
    @patch("app.services.rds_control_service.assume_aws_role")
    @patch("app.services.rds_control_service.get_account")
    def test_disable_public_access_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_record_event,
    ):
        """Disables public accessibility on a public RDS instance."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_rds = MagicMock()
        mock_clients.return_value = {"rds": mock_rds}

        # Pre-state: PubliclyAccessible=True
        mock_rds.describe_db_instances.side_effect = [
            {"DBInstances": [{"DBInstanceIdentifier": self.instance_id, "DBInstanceStatus": "available", "PubliclyAccessible": True}]},
            {"DBInstances": [{"DBInstanceIdentifier": self.instance_id, "DBInstanceStatus": "modifying", "PubliclyAccessible": False}]},
        ]

        res = execute_rds_instance_action(
            account_id=self.account_id,
            instance_id=self.instance_id,
            action="disable_public_access",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="owner",
        )

        self.assertEqual(res["status"], "success")
        mock_rds.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier=self.instance_id,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )

    def test_viewer_role_rejected(self):
        """Viewer role is rejected with 403 and logged."""
        with patch("app.services.rds_control_service.record_event") as mock_record_event:
            with self.assertRaises(RDSControlExecutionError) as ctx:
                execute_rds_instance_action(
                    account_id=self.account_id,
                    instance_id=self.instance_id,
                    action="stop",
                    confirmed=True,
                    user_id=self.user_id,
                    organization_id=self.org_id,
                    role="viewer",
                )
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.code, "PERMISSION_DENIED")

            call_kwargs = mock_record_event.call_args[1]
            self.assertEqual(call_kwargs["event_type"], EVENT_REMEDIATION_AUTHORIZATION)
            self.assertEqual(call_kwargs["result"], RESULT_DENIED)

    def test_unconfirmed_action_rejected(self):
        """Unconfirmed action is rejected with 400."""
        with self.assertRaises(RDSControlExecutionError) as ctx:
            execute_rds_instance_action(
                account_id=self.account_id,
                instance_id=self.instance_id,
                action="stop",
                confirmed=False,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.code, "CONFIRMATION_REQUIRED")

    def test_unsafe_actions_rejected(self):
        """Destructive actions like delete_db_instance are rejected."""
        unsafe = ["delete_db_instance", "delete_db_cluster", "delete_db_snapshot", "make_public"]
        for bad_action in unsafe:
            with self.assertRaises(RDSControlExecutionError) as ctx:
                execute_rds_instance_action(
                    account_id=self.account_id,
                    instance_id=self.instance_id,
                    action=bad_action,
                    confirmed=True,
                    user_id=self.user_id,
                    organization_id=self.org_id,
                    role="admin",
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.code, "UNSUPPORTED_ACTION")


class TestRDSEndpointsAPI(unittest.TestCase):
    """Integration tests for RDS FastAPI route endpoints."""

    def setUp(self):
        self.account_id = str(ObjectId())
        self.aws_account_id = "123456789012"
        self.user_id = str(ObjectId())
        self.org_id = "org-test-rds-endpoints"
        self.user_context = {
            "_id": self.user_id,
            "organization": self.org_id,
            "role": "admin",
        }
        self.mock_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "account_name": "Endpoints Test Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardAIRole",
            "organization_id": self.org_id,
            "region": "us-east-1",
            "status": "connected",
        }
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})
        db.aws_accounts.delete_many({"organization_id": self.org_id})
        db.remediation_settings.delete_many({"organization_id": self.org_id})

        db.organization_members.insert_one({
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "role": "admin",
            "status": "active",
        })
        db.aws_accounts.insert_one(dict(self.mock_account))
        db.remediation_settings.insert_one({
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "services": {
                "ec2": True,
                "s3": True,
                "vpc": True,
                "rds": True,
                "iam": True,
                "cloudtrail": True,
            },
        })

    def tearDown(self):
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})
        db.aws_accounts.delete_many({"organization_id": self.org_id})
        db.remediation_settings.delete_many({"organization_id": self.org_id})

    @patch("app.api.cloud.fetch_rds_instances_inventory")
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_list_rds_instances_endpoint_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_fetch,
    ):
        """list_rds_instances endpoint returns structured inventory."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_rds = MagicMock()
        mock_clients.return_value = {"rds": mock_rds}

        mock_fetch.return_value = {
            "total_count": 1,
            "instances": [{"db_instance_identifier": "test-db", "engine": "postgres", "status": "available"}],
            "next_token": None,
            "summary": {"total_instances": 1, "available_instances": 1},
            "coverage": "COMPLETE",
        }

        resp = list_rds_instances(
            account_id=self.account_id,
            region="us-east-1",
            current_user=self.user_context,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["total_count"], 1)
        self.assertEqual(len(resp["instances"]), 1)

    @patch("app.api.cloud.execute_rds_instance_action")
    def test_control_rds_instance_endpoint_success(self, mock_execute):
        """control_rds_instance endpoint delegates to service when authorized."""
        mock_execute.return_value = {
            "status": "success",
            "action": "reboot",
            "instance_id": "test-db",
            "verification_status": "VERIFIED",
        }

        payload = RDSActionRequest(
            action="reboot",
            region="us-east-1",
            confirmed=True,
        )

        resp = control_rds_instance(
            account_id=self.account_id,
            instance_id="test-db",
            payload=payload,
            current_user=self.user_context,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["action"], "reboot")

    def test_control_rds_instance_viewer_denied(self):
        """Viewer role in organization_members must be denied with 403."""
        from app.database.connection import db
        db.organization_members.update_one(
            {"user_id": self.user_id, "organization_id": self.org_id},
            {"$set": {"role": "viewer"}}
        )
        payload = RDSActionRequest(
            action="reboot",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_rds_instance(
                account_id=self.account_id,
                instance_id="test-db",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)

    def test_control_rds_instance_missing_membership_denied(self):
        """Missing organization membership must raise 403."""
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})
        payload = RDSActionRequest(
            action="reboot",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_rds_instance(
                account_id=self.account_id,
                instance_id="test-db",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)

    def test_control_rds_instance_inactive_membership_denied(self):
        """Inactive membership status must raise 403."""
        from app.database.connection import db
        db.organization_members.update_one(
            {"user_id": self.user_id, "organization_id": self.org_id},
            {"$set": {"status": "inactive"}}
        )
        payload = RDSActionRequest(
            action="reboot",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_rds_instance(
                account_id=self.account_id,
                instance_id="test-db",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
