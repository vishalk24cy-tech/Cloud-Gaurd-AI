# ============================================================
# CloudGuardAI - Unit & Regression Tests for S3 Resource Controls
# Phase 3: Secure AWS S3 Resource Management
# ============================================================

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.api.cloud import control_s3_bucket, list_s3_buckets, S3ActionRequest
from app.models.audit_log import (
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_RESOURCE_CONTROL_COMPLETED,
    EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
    EVENT_RESOURCE_CONTROL_FAILED,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
)
from app.services.s3_control_service import (
    ALLOWED_S3_ACTIONS,
    S3ControlExecutionError,
    execute_s3_bucket_action,
    fetch_s3_buckets_inventory,
    inspect_single_bucket_posture,
    is_valid_bucket_name,
    validate_aws_region,
)


class TestS3ResourceControlsUnit(unittest.TestCase):
    """Unit tests for S3 validation helpers, posture inspection, and inventory logic."""

    def test_validate_aws_region(self):
        """Validates standard AWS region format."""
        self.assertTrue(validate_aws_region("us-east-1"))
        self.assertTrue(validate_aws_region("ap-south-1"))
        self.assertTrue(validate_aws_region("eu-west-1"))
        self.assertTrue(validate_aws_region("sa-east-1"))

        self.assertFalse(validate_aws_region(""))
        self.assertFalse(validate_aws_region("invalid_region"))
        self.assertFalse(validate_aws_region("us-east-"))
        self.assertFalse(validate_aws_region("us-east-1a"))  # AZ, not region
        self.assertFalse(validate_aws_region(None))

    def test_is_valid_bucket_name(self):
        """Tests strict RFC/AWS S3 bucket name validation."""
        self.assertTrue(is_valid_bucket_name("my-valid-bucket-123"))
        self.assertTrue(is_valid_bucket_name("cloudguard-audit-2026"))
        self.assertTrue(is_valid_bucket_name("a.b.c.d"))

        # Invalid bucket names
        self.assertFalse(is_valid_bucket_name(""))
        self.assertFalse(is_valid_bucket_name("UPPERCASE-BUCKET"))
        self.assertFalse(is_valid_bucket_name("192.168.1.1"))  # IP address formatted
        self.assertFalse(is_valid_bucket_name("bucket..double-dot"))
        self.assertFalse(is_valid_bucket_name("bucket.-dash-dot"))
        self.assertFalse(is_valid_bucket_name("-leading-dash"))
        self.assertFalse(is_valid_bucket_name("trailing-dash-"))
        self.assertFalse(is_valid_bucket_name("xn--punycode-bucket"))
        self.assertFalse(is_valid_bucket_name("bucket-s3alias"))
        self.assertFalse(is_valid_bucket_name("a" * 64))  # Exceeds 63 chars
        self.assertFalse(is_valid_bucket_name(None))

    def test_inspect_single_bucket_posture_secure(self):
        """Inspects single bucket with fully protected configuration (SECURE)."""
        mock_client = MagicMock()
        mock_client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_client.get_bucket_policy_status.return_value = {
            "PolicyStatus": {"IsPublic": False}
        }
        mock_client.get_bucket_acl.return_value = {
            "Grants": [
                {"Grantee": {"DisplayName": "owner"}, "Permission": "FULL_CONTROL"}
            ]
        }
        mock_client.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            }
        }
        mock_client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_client.get_bucket_logging.return_value = {
            "LoggingEnabled": {"TargetBucket": "audit-logs-target", "TargetPrefix": "s3/"}
        }

        result = inspect_single_bucket_posture(
            regional_client=mock_client,
            bucket_name="secure-vault",
            bucket_region="us-east-1",
            account_id="123456789012",
        )

        self.assertEqual(result["bucket_name"], "secure-vault")
        self.assertEqual(result["region"], "us-east-1")
        self.assertEqual(result["security_posture"], "SECURE")
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertTrue(result["block_public_access"]["all_protected"])
        self.assertTrue(result["encryption"]["enabled"])
        self.assertEqual(result["encryption"]["algorithm"], "AES256")
        self.assertTrue(result["versioning"]["enabled"])
        self.assertTrue(result["logging"]["enabled"])

    def test_inspect_single_bucket_posture_risk_and_unverified(self):
        """Inspects bucket missing BPA and encryption (RISK) or with AccessDenied (PARTIAL)."""
        mock_client = MagicMock()
        mock_client.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}},
            "GetPublicAccessBlock",
        )
        mock_client.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy"}},
            "GetBucketPolicyStatus",
        )
        mock_client.get_bucket_acl.return_value = {"Grants": []}
        mock_client.get_bucket_encryption.side_effect = ClientError(
            {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}},
            "GetBucketEncryption",
        )
        mock_client.get_bucket_versioning.return_value = {"Status": "Suspended"}
        mock_client.get_bucket_logging.return_value = {}

        result = inspect_single_bucket_posture(
            regional_client=mock_client,
            bucket_name="unprotected-bucket",
            bucket_region="ap-south-1",
        )

        self.assertEqual(result["security_posture"], "RISK")
        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertFalse(result["block_public_access"]["all_protected"])
        self.assertEqual(result["block_public_access"]["status"], "NOT_CONFIGURED")
        self.assertFalse(result["encryption"]["enabled"])
        self.assertFalse(result["versioning"]["enabled"])

    def test_fetch_s3_buckets_inventory_pagination_and_filter(self):
        """Tests inventory pagination, region filter, and search filter."""
        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "alpha-prod-data", "CreationDate": datetime.now(timezone.utc)},
                {"Name": "beta-test-data", "CreationDate": datetime.now(timezone.utc)},
                {"Name": "gamma-eu-data", "CreationDate": datetime.now(timezone.utc)},
            ]
        }
        # Location constraints
        def mock_location(Bucket):
            if Bucket == "gamma-eu-data":
                return {"LocationConstraint": "eu-west-1"}
            return {"LocationConstraint": "ap-south-1"}

        mock_s3.get_bucket_location.side_effect = mock_location

        with patch("app.services.s3_control_service.get_regional_s3_client", return_value=mock_s3), \
             patch("app.services.s3_control_service.inspect_single_bucket_posture") as mock_inspect:
            mock_inspect.side_effect = lambda regional_client, bucket_name, bucket_region, account_id, created_str: {
                "bucket_name": bucket_name,
                "region": bucket_region,
                "security_posture": "SECURE",
                "coverage": "COMPLETE",
                "block_public_access": {"all_protected": True},
                "encryption": {"enabled": True},
            }

            # Filter by region
            inv_region = fetch_s3_buckets_inventory(
                s3_client=mock_s3,
                region_filter="eu-west-1",
            )
            self.assertEqual(inv_region["total_count"], 1)
            self.assertEqual(inv_region["buckets"][0]["bucket_name"], "gamma-eu-data")

            # Filter by search
            inv_search = fetch_s3_buckets_inventory(
                s3_client=mock_s3,
                search="alpha",
            )
            self.assertEqual(inv_search["total_count"], 1)
            self.assertEqual(inv_search["buckets"][0]["bucket_name"], "alpha-prod-data")

            # Pagination
            inv_page = fetch_s3_buckets_inventory(
                s3_client=mock_s3,
                page_size=2,
                next_token="0",
            )
            self.assertEqual(len(inv_page["buckets"]), 2)
            self.assertEqual(inv_page["next_token"], "2")


class TestS3ControlExecution(unittest.TestCase):
    """Tests for S3 control execution, mutation safety, authorization, and audit logging."""

    def setUp(self):
        self.account_id = str(ObjectId())
        self.aws_account_id = "123456789012"
        self.user_id = "user-s3-admin-100"
        self.org_id = "org-enterprise-s3"
        self.bucket_name = "cloudguard-secure-storage"

        self.mock_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "account_name": "Prod Security Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardAIRole",
            "organization_id": self.org_id,
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

    @patch("app.services.s3_control_service.record_event")
    @patch("app.services.s3_control_service.inspect_single_bucket_posture")
    @patch("app.services.s3_control_service.get_regional_s3_client")
    @patch("app.services.s3_control_service.resolve_bucket_region", return_value="us-east-1")
    @patch("app.services.s3_control_service.get_aws_clients")
    @patch("app.services.s3_control_service.verify_aws_account")
    @patch("app.services.s3_control_service.assume_aws_role")
    @patch("app.services.s3_control_service.get_account")
    def test_enable_block_public_access_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_resolve,
        mock_get_regional,
        mock_inspect,
        mock_record_event,
    ):
        """Enables Block Public Access on a bucket with verified post-state and audit events."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_s3 = MagicMock()
        mock_clients.return_value = {"s3": mock_s3}
        mock_regional_s3 = MagicMock()
        mock_get_regional.return_value = mock_regional_s3

        # Post-state verification returns protected
        mock_inspect.return_value = {
            "bucket_name": self.bucket_name,
            "region": "us-east-1",
            "security_posture": "SECURE",
            "block_public_access": {"all_protected": True},
        }

        res = execute_s3_bucket_action(
            account_id=self.account_id,
            bucket_name=self.bucket_name,
            action="enable_block_public_access",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="admin",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["verification_status"], "VERIFIED")
        self.assertEqual(res["action"], "enable_block_public_access")

        # Assert mutation API called with all 4 BPA flags True
        mock_regional_s3.put_public_access_block.assert_called_once_with(
            Bucket=self.bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            ExpectedBucketOwner=self.aws_account_id,
        )

        # Verify audit logs recorded START and COMPLETED
        event_types = [call[1]["event_type"] for call in mock_record_event.call_args_list]
        self.assertIn(EVENT_RESOURCE_CONTROL_EXECUTION_STARTED, event_types)
        self.assertIn(EVENT_RESOURCE_CONTROL_COMPLETED, event_types)

    @patch("app.services.s3_control_service.record_event")
    @patch("app.services.s3_control_service.inspect_single_bucket_posture")
    @patch("app.services.s3_control_service.get_regional_s3_client")
    @patch("app.services.s3_control_service.resolve_bucket_region", return_value="us-east-1")
    @patch("app.services.s3_control_service.get_aws_clients")
    @patch("app.services.s3_control_service.verify_aws_account")
    @patch("app.services.s3_control_service.assume_aws_role")
    @patch("app.services.s3_control_service.get_account")
    def test_enable_encryption_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_resolve,
        mock_get_regional,
        mock_inspect,
        mock_record_event,
    ):
        """Enables default AES-256 SSE encryption on an S3 bucket."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_s3 = MagicMock()
        mock_clients.return_value = {"s3": mock_s3}
        mock_regional_s3 = MagicMock()
        mock_get_regional.return_value = mock_regional_s3

        mock_inspect.return_value = {
            "bucket_name": self.bucket_name,
            "region": "us-east-1",
            "security_posture": "SECURE",
            "encryption": {"enabled": True, "algorithm": "AES256"},
        }

        res = execute_s3_bucket_action(
            account_id=self.account_id,
            bucket_name=self.bucket_name,
            action="enable_encryption",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="owner",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["verification_status"], "VERIFIED")

        # Assert mutation API called with AES256
        mock_regional_s3.put_bucket_encryption.assert_called_once_with(
            Bucket=self.bucket_name,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        }
                    }
                ]
            },
            ExpectedBucketOwner=self.aws_account_id,
        )

    @patch("app.services.s3_control_service.record_event")
    @patch("app.services.s3_control_service.inspect_single_bucket_posture")
    @patch("app.services.s3_control_service.get_regional_s3_client")
    @patch("app.services.s3_control_service.resolve_bucket_region", return_value="us-east-1")
    @patch("app.services.s3_control_service.get_aws_clients")
    @patch("app.services.s3_control_service.verify_aws_account")
    @patch("app.services.s3_control_service.assume_aws_role")
    @patch("app.services.s3_control_service.get_account")
    def test_enable_versioning_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_resolve,
        mock_get_regional,
        mock_inspect,
        mock_record_event,
    ):
        """Enables S3 bucket versioning."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_s3 = MagicMock()
        mock_clients.return_value = {"s3": mock_s3}
        mock_regional_s3 = MagicMock()
        mock_get_regional.return_value = mock_regional_s3

        mock_inspect.return_value = {
            "bucket_name": self.bucket_name,
            "region": "us-east-1",
            "versioning": {"enabled": True},
        }

        res = execute_s3_bucket_action(
            account_id=self.account_id,
            bucket_name=self.bucket_name,
            action="enable_versioning",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="owner",
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["verification_status"], "VERIFIED")

        mock_regional_s3.put_bucket_versioning.assert_called_once_with(
            Bucket=self.bucket_name,
            VersioningConfiguration={"Status": "Enabled"},
            ExpectedBucketOwner=self.aws_account_id,
        )

    def test_viewer_role_rejected(self):
        """Viewer role is rejected with 403 and records denial audit event."""
        with patch("app.services.s3_control_service.record_event") as mock_record_event:
            with self.assertRaises(S3ControlExecutionError) as ctx:
                execute_s3_bucket_action(
                    account_id=self.account_id,
                    bucket_name=self.bucket_name,
                    action="enable_block_public_access",
                    confirmed=True,
                    user_id=self.user_id,
                    organization_id=self.org_id,
                    role="viewer",
                )
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertEqual(ctx.exception.code, "PERMISSION_DENIED")

            mock_record_event.assert_called_once()
            call_kwargs = mock_record_event.call_args[1]
            self.assertEqual(call_kwargs["event_type"], EVENT_REMEDIATION_AUTHORIZATION)
            self.assertEqual(call_kwargs["result"], RESULT_DENIED)

    def test_unconfirmed_action_rejected(self):
        """Unconfirmed action is rejected with 400."""
        with self.assertRaises(S3ControlExecutionError) as ctx:
            execute_s3_bucket_action(
                account_id=self.account_id,
                bucket_name=self.bucket_name,
                action="enable_block_public_access",
                confirmed=False,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.code, "CONFIRMATION_REQUIRED")

    def test_unsafe_actions_rejected(self):
        """Unsafe or destructive actions are strictly rejected with 400."""
        unsafe_actions = [
            "delete_bucket",
            "delete_objects",
            "disable_block_public_access",
            "make_public",
            "remove_encryption",
            "disable_versioning",
        ]
        for bad_action in unsafe_actions:
            with self.assertRaises(S3ControlExecutionError) as ctx:
                execute_s3_bucket_action(
                    account_id=self.account_id,
                    bucket_name=self.bucket_name,
                    action=bad_action,
                    confirmed=True,
                    user_id=self.user_id,
                    organization_id=self.org_id,
                    role="admin",
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertEqual(ctx.exception.code, "UNSUPPORTED_ACTION")

    def test_invalid_bucket_name_rejected(self):
        """Invalid S3 bucket name is rejected with 400."""
        with self.assertRaises(S3ControlExecutionError) as ctx:
            execute_s3_bucket_action(
                account_id=self.account_id,
                bucket_name="192.168.1.1",
                action="enable_block_public_access",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertEqual(ctx.exception.code, "INVALID_BUCKET_NAME")

    @patch("app.services.s3_control_service.get_account", return_value=None)
    def test_cross_tenant_account_lookup_rejected(self, mock_get_account):
        """Cross-tenant account lookup returns 404."""
        with self.assertRaises(S3ControlExecutionError) as ctx:
            execute_s3_bucket_action(
                account_id="foreign-account-id",
                bucket_name=self.bucket_name,
                action="enable_block_public_access",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertEqual(ctx.exception.code, "ACCOUNT_NOT_FOUND")

    @patch("app.services.s3_control_service.record_event")
    @patch("app.services.s3_control_service.get_regional_s3_client")
    @patch("app.services.s3_control_service.resolve_bucket_region", return_value="us-east-1")
    @patch("app.services.s3_control_service.get_aws_clients")
    @patch("app.services.s3_control_service.verify_aws_account")
    @patch("app.services.s3_control_service.assume_aws_role")
    @patch("app.services.s3_control_service.get_account")
    def test_aws_api_failure_records_failed_audit_event(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_resolve,
        mock_get_regional,
        mock_record_event,
    ):
        """AWS ClientError during mutation is caught, audited with RESULT_FAILURE, and raises safe error."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_s3 = MagicMock()
        mock_clients.return_value = {"s3": mock_s3}
        mock_regional_s3 = MagicMock()
        mock_get_regional.return_value = mock_regional_s3

        mock_regional_s3.put_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized to put BPA"}},
            "PutPublicAccessBlock",
        )

        with self.assertRaises(S3ControlExecutionError) as ctx:
            execute_s3_bucket_action(
                account_id=self.account_id,
                bucket_name=self.bucket_name,
                action="enable_block_public_access",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )

        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(ctx.exception.code, "AWS_ACCESS_DENIED")

        event_types = [call[1]["event_type"] for call in mock_record_event.call_args_list]
        self.assertIn(EVENT_RESOURCE_CONTROL_FAILED, event_types)


class TestS3EndpointsAPI(unittest.TestCase):
    """Integration & route tests for GET and POST S3 endpoints in cloud.py."""

    def setUp(self):
        self.account_id = str(ObjectId())
        self.aws_account_id = "123456789012"
        self.user_id = str(ObjectId())
        self.org_id = "org-test-s3-endpoints"
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
        }
        from app.database.connection import db
        db.organization_members.insert_one({
            "organization_id": self.org_id,
            "user_id": self.user_id,
            "role": "admin",
            "status": "active"
        })

    def tearDown(self):
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})

    @patch("app.api.cloud.fetch_s3_buckets_inventory")
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_list_s3_buckets_endpoint_success(
        self,
        mock_get_account,
        mock_assume,
        mock_verify,
        mock_clients,
        mock_fetch,
    ):
        """list_s3_buckets endpoint returns structured response."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_s3 = MagicMock()
        mock_clients.return_value = {"s3": mock_s3}
        mock_fetch.return_value = {
            "total_count": 2,
            "buckets": [
                {"bucket_name": "bucket-one", "region": "us-east-1", "security_posture": "SECURE"},
                {"bucket_name": "bucket-two", "region": "us-east-1", "security_posture": "RISK"},
            ],
            "next_token": None,
            "summary": {"total_buckets": 2, "secure_buckets": 1, "risk_buckets": 1},
            "coverage": "COMPLETE",
        }

        resp = list_s3_buckets(
            account_id=self.account_id,
            region="us-east-1",
            page_size=50,
            current_user=self.user_context,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["total_count"], 2)
        self.assertEqual(resp["account_id"], self.account_id)
        self.assertEqual(resp["aws_account_id"], self.aws_account_id)
        self.assertEqual(len(resp["buckets"]), 2)

    def test_list_s3_buckets_endpoint_invalid_region(self):
        """Invalid region format raises 400."""
        with self.assertRaises(HTTPException) as ctx:
            list_s3_buckets(
                account_id=self.account_id,
                region="bad_region_1",
                current_user=self.user_context,
            )
        self.assertEqual(ctx.exception.status_code, 400)

    @patch("app.api.cloud.execute_s3_bucket_action")
    def test_control_s3_bucket_endpoint_success(self, mock_execute):
        """control_s3_bucket endpoint delegates to service and returns result."""
        mock_execute.return_value = {
            "status": "success",
            "action": "enable_block_public_access",
            "bucket_name": "my-target-bucket",
            "verification_status": "VERIFIED",
        }

        payload = S3ActionRequest(
            action="enable_block_public_access",
            region="us-east-1",
            confirmed=True,
        )

        resp = control_s3_bucket(
            account_id=self.account_id,
            bucket_name="my-target-bucket",
            payload=payload,
            current_user=self.user_context,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["action"], "enable_block_public_access")
        mock_execute.assert_called_once_with(
            account_id=self.account_id,
            bucket_name="my-target-bucket",
            action="enable_block_public_access",
            region="us-east-1",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="admin",
        )


if __name__ == "__main__":
    unittest.main()
