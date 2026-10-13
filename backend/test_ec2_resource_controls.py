# ============================================================
# CloudGuardAI - Unit & Regression Tests for EC2 Resource Controls
# Phase 2A: Read-Only EC2 Resource Inventory
# ============================================================

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.api.cloud import list_ec2_instances
from app.services.ec2_inventory_service import (
    extract_instance_name,
    fetch_ec2_instances_inventory,
    normalize_ec2_instance,
    validate_aws_region,
)


class TestEC2ResourceInventoryUnit(unittest.TestCase):
    """Unit tests for EC2 inventory helpers and normalizer."""

    def test_validate_aws_region(self):
        """Validates region string format."""
        self.assertTrue(validate_aws_region("us-east-1"))
        self.assertTrue(validate_aws_region("ap-south-1"))
        self.assertTrue(validate_aws_region("eu-central-1"))
        self.assertTrue(validate_aws_region("sa-east-1"))

        self.assertFalse(validate_aws_region(""))
        self.assertFalse(validate_aws_region("invalid_region"))
        self.assertFalse(validate_aws_region("us-east-"))
        self.assertFalse(validate_aws_region("us-east-1a"))  # AZ, not region
        self.assertFalse(validate_aws_region("../../etc"))
        self.assertFalse(validate_aws_region(None))

    def test_extract_instance_name(self):
        """Extracts Name tag correctly or returns None."""
        tags = [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Name", "Value": "web-prod-01"},
        ]
        self.assertEqual(extract_instance_name(tags), "web-prod-01")

        # Missing Name tag
        self.assertIsNone(extract_instance_name([{"Key": "Env", "Value": "Prod"}]))
        self.assertIsNone(extract_instance_name([]))
        self.assertIsNone(extract_instance_name(None))

    def test_normalize_ec2_instance(self):
        """Normalizes AWS EC2 instance structure to API model."""
        now = datetime.now(timezone.utc)
        raw_instance = {
            "InstanceId": "i-0123456789abcdef0",
            "InstanceType": "t3.micro",
            "State": {"Name": "running"},
            "Placement": {"AvailabilityZone": "us-east-1b"},
            "PrivateIpAddress": "10.0.1.50",
            "PublicIpAddress": "54.210.10.20",
            "LaunchTime": now,
            "SubnetId": "subnet-01234567",
            "VpcId": "vpc-09876543",
            "Platform": "linux",
            "Architecture": "x86_64",
            "Tags": [{"Key": "Name", "Value": "api-gateway"}],
            "SecurityGroups": [
                {"GroupId": "sg-12345678", "GroupName": "web-sec-group"}
            ],
        }

        norm = normalize_ec2_instance(raw_instance, fallback_region="us-east-1")

        self.assertEqual(norm["instance_id"], "i-0123456789abcdef0")
        self.assertEqual(norm["name"], "api-gateway")
        self.assertEqual(norm["state"], "running")
        self.assertEqual(norm["instance_type"], "t3.micro")
        self.assertEqual(norm["region"], "us-east-1")
        self.assertEqual(norm["availability_zone"], "us-east-1b")
        self.assertEqual(norm["private_ip"], "10.0.1.50")
        self.assertEqual(norm["public_ip"], "54.210.10.20")
        self.assertEqual(norm["subnet_id"], "subnet-01234567")
        self.assertEqual(norm["vpc_id"], "vpc-09876543")
        self.assertEqual(norm["launch_time"], now.isoformat())
        self.assertEqual(len(norm["security_groups"]), 1)
        self.assertEqual(norm["security_groups"][0]["group_id"], "sg-12345678")


class TestEC2ResourceInventoryEndpoint(unittest.TestCase):
    """End-to-end tests for the GET /cloud/aws/ec2/{account_id}/instances endpoint."""

    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_id = str(ObjectId())
        self.account_oid = ObjectId()
        self.account_id_str = str(self.account_oid)
        self.aws_account_num = "138218764724"

        self.current_user = {
            "_id": self.user_id,
            "organization": self.org_id,
            "role": "admin",
            "email": "admin@cloudguard.ai",
        }

        self.mock_account = {
            "_id": self.account_oid,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_name": "Production Account",
            "aws_account_id": self.aws_account_num,
            "account": self.aws_account_num,
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
        }

    def _setup_mocks(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        ec2_client=None,
    ):
        mock_get_account.return_value = self.mock_account

        mock_session = MagicMock()
        mock_assume_role.return_value = mock_session

        mock_verify_account.return_value = {"Account": self.aws_account_num}

        if ec2_client is None:
            ec2_client = MagicMock()
        mock_get_clients.return_value = {"ec2": ec2_client}
        return ec2_client

    # --------------------------------------------------------
    # 1. Successful inventory response
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_successful_inventory_response(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Returns 200 with complete normalized EC2 instance inventory."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-aaa111bbb222ccc33",
                            "InstanceType": "t3.medium",
                            "State": {"Name": "running"},
                            "Placement": {"AvailabilityZone": "us-east-1a"},
                            "PrivateIpAddress": "172.31.10.15",
                            "PublicIpAddress": "34.200.15.80",
                            "LaunchTime": datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc),
                            "SubnetId": "subnet-aaa111",
                            "VpcId": "vpc-bbb222",
                            "Tags": [{"Key": "Name", "Value": "frontend-web"}],
                        }
                    ]
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        resp = list_ec2_instances(
            account_id=self.account_id_str,
            region=None,
            current_user=self.current_user,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["account_id"], self.account_id_str)
        self.assertEqual(resp["aws_account_id"], self.aws_account_num)
        self.assertEqual(resp["region"], "us-east-1")
        self.assertEqual(resp["total_count"], 1)
        self.assertEqual(len(resp["instances"]), 1)

        inst = resp["instances"][0]
        self.assertEqual(inst["instance_id"], "i-aaa111bbb222ccc33")
        self.assertEqual(inst["name"], "frontend-web")
        self.assertEqual(inst["state"], "running")
        self.assertEqual(inst["instance_type"], "t3.medium")
        self.assertEqual(inst["region"], "us-east-1")
        self.assertEqual(inst["availability_zone"], "us-east-1a")
        self.assertEqual(inst["private_ip"], "172.31.10.15")
        self.assertEqual(inst["public_ip"], "34.200.15.80")
        self.assertEqual(inst["subnet_id"], "subnet-aaa111")
        self.assertEqual(inst["vpc_id"], "vpc-bbb222")
        self.assertIn("2026-10-01", inst["launch_time"])

        # Safety check: only describe_instances was called
        mock_ec2.describe_instances.assert_called_once()
        self.assertFalse(mock_ec2.start_instances.called)
        self.assertFalse(mock_ec2.stop_instances.called)
        self.assertFalse(mock_ec2.reboot_instances.called)
        self.assertFalse(mock_ec2.terminate_instances.called)

    # --------------------------------------------------------
    # 2. Multiple pages of EC2 results
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_multiple_pages_with_token_and_auto_paginate(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Handles pagination tokens and auto-pagination across multiple pages."""
        mock_ec2 = MagicMock()
        page1 = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-page1", "State": {"Name": "running"}}]}
            ],
            "NextToken": "page-2-token",
        }
        page2 = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-page2", "State": {"Name": "stopped"}}]}
            ]
        }

        # Case A: Requesting first page returns NextToken
        mock_ec2.describe_instances.return_value = page1
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        resp1 = list_ec2_instances(
            account_id=self.account_id_str,
            next_token=None,
            all_pages=False,
            current_user=self.current_user,
        )
        self.assertEqual(resp1["total_count"], 1)
        self.assertEqual(resp1["instances"][0]["instance_id"], "i-page1")
        self.assertEqual(resp1["next_token"], "page-2-token")

        # Case B: Requesting second page with NextToken
        mock_ec2.describe_instances.return_value = page2
        resp2 = list_ec2_instances(
            account_id=self.account_id_str,
            next_token="page-2-token",
            all_pages=False,
            current_user=self.current_user,
        )
        self.assertEqual(resp2["total_count"], 1)
        self.assertEqual(resp2["instances"][0]["instance_id"], "i-page2")
        self.assertIsNone(resp2["next_token"])

        # Case C: all_pages=True aggregates across both pages
        mock_ec2.describe_instances.side_effect = [page1, page2]
        resp_all = list_ec2_instances(
            account_id=self.account_id_str,
            all_pages=True,
            current_user=self.current_user,
        )
        self.assertEqual(resp_all["total_count"], 2)
        ids = [x["instance_id"] for x in resp_all["instances"]]
        self.assertIn("i-page1", ids)
        self.assertIn("i-page2", ids)

    # --------------------------------------------------------
    # 3. Empty account/region result
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_empty_account_region_result(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Returns 200 with empty instances list when account has zero EC2 instances."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        resp = list_ec2_instances(
            account_id=self.account_id_str,
            region="us-west-2",
            current_user=self.current_user,
        )
        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["total_count"], 0)
        self.assertEqual(resp["instances"], [])
        self.assertEqual(resp["region"], "us-west-2")

    # --------------------------------------------------------
    # 4. Missing Name tag
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_missing_name_tag_handled_gracefully(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Instances without a Name tag return name: None without errors."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-unnamed-001",
                            "State": {"Name": "running"},
                            "Tags": [{"Key": "Environment", "Value": "Staging"}],
                        },
                        {
                            "InstanceId": "i-notags-002",
                            "State": {"Name": "stopped"},
                            # No Tags key at all
                        },
                    ]
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        resp = list_ec2_instances(
            account_id=self.account_id_str,
            current_user=self.current_user,
        )
        self.assertEqual(resp["total_count"], 2)
        self.assertIsNone(resp["instances"][0]["name"])
        self.assertIsNone(resp["instances"][1]["name"])

    # --------------------------------------------------------
    # 5. Assumed-account mismatch
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_assumed_account_mismatch_raises_403(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Rejects request with 403 when assumed STS role belongs to wrong account."""
        mock_verify_account.side_effect = PermissionError("AWS account identity mismatch.")
        mock_get_account.return_value = self.mock_account
        mock_assume_role.return_value = MagicMock()

        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("mismatch", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 6. Unauthenticated or missing organization
    # --------------------------------------------------------
    def test_missing_organization_context_raises_403(self):
        """Requests without organization context are rejected with 403."""
        unauthed_user = {
            "_id": self.user_id,
            "organization": None,  # Missing organization
        }
        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                current_user=unauthed_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("organization context is required", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 7. Organization/tenant isolation
    # --------------------------------------------------------
    @patch("app.api.cloud.get_account")
    def test_cross_tenant_account_access_returns_404(self, mock_get_account):
        """Attempting to access another organization's account returns 404 Not Found."""
        # get_account scoped to current org returns None
        mock_get_account.return_value = None

        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id="other-org-account-id",
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("account not found", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 8. AWS AccessDenied response
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_aws_access_denied_returns_403(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """AWS AccessDenied or UnauthorizedOperation is mapped to safe 403 error."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized to perform ec2:DescribeInstances"}},
            "DescribeInstances",
        )
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("accessdenied", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 9. Throttling or service failure
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_throttling_and_service_failure_mapped_safely(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Throttling returns 429; network/service errors return safe 502 without leaking secrets."""
        mock_ec2 = MagicMock()
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        # 9A: Throttling / RequestLimitExceeded -> 429
        mock_ec2.describe_instances.side_effect = ClientError(
            {"Error": {"Code": "RequestLimitExceeded", "Message": "Rate exceeded"}},
            "DescribeInstances",
        )
        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 429)

        # 9B: BotoCore network failure -> 502
        mock_ec2.describe_instances.side_effect = BotoCoreError()
        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 502)

    # --------------------------------------------------------
    # 10. Invalid account ID or region parameter
    # --------------------------------------------------------
    def test_invalid_parameters_rejected(self):
        """Invalid region format or empty account ID returns 400 Bad Request."""
        # 10A: Empty account ID
        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id="   ",
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)

        # 10B: Invalid region format
        with self.assertRaises(HTTPException) as ctx:
            list_ec2_instances(
                account_id=self.account_id_str,
                region="not_a_valid_region!",
                current_user=self.current_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("invalid aws region", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 11. Read-Only Safety Verification
    # --------------------------------------------------------
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_read_only_safety_no_mutations_called(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Asserts that NO mutation APIs are ever invoked by the inventory endpoint."""
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        list_ec2_instances(
            account_id=self.account_id_str,
            current_user=self.current_user,
        )

        # Explicitly verify all mutation methods were NOT called
        forbidden_calls = [
            "start_instances",
            "stop_instances",
            "reboot_instances",
            "terminate_instances",
            "modify_instance_attribute",
            "create_tags",
            "delete_tags",
            "run_instances",
        ]
        for method_name in forbidden_calls:
            self.assertFalse(
                getattr(mock_ec2, method_name).called,
                f"Safety violation: {method_name} was called during read-only inventory!",
            )

    # --------------------------------------------------------
    # 12. Route Registration Verification
    # --------------------------------------------------------
    def test_route_registration(self):
        """Verify /aws/ec2/{account_id}/instances is registered in cloud_router with GET method."""
        from app.api.cloud import router as cloud_router
        route_paths = [getattr(route, "path", "") for route in cloud_router.routes]
        self.assertIn("/aws/ec2/{account_id}/instances", route_paths)

        matching_routes = [
            route for route in cloud_router.routes
            if getattr(route, "path", "") == "/aws/ec2/{account_id}/instances"
        ]
        self.assertTrue(len(matching_routes) > 0)
        self.assertIn("GET", matching_routes[0].methods)


class TestEC2ResourceMutationControls(unittest.TestCase):
    """Tests for Phase 2C: Secure EC2 Start, Stop, and Reboot Controls."""

    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_id = str(ObjectId())
        self.account_oid = ObjectId()
        self.account_id_str = str(self.account_oid)
        self.aws_account_num = "138218764724"
        self.valid_instance_id = "i-0123456789abcdef0"

        self.admin_user = {
            "_id": self.user_id,
            "organization": self.org_id,
            "role": "admin",
            "email": "admin@cloudguard.ai",
        }

        self.viewer_user = {
            "_id": str(ObjectId()),
            "organization": self.org_id,
            "role": "viewer",
            "email": "viewer@cloudguard.ai",
        }

        self.mock_account = {
            "_id": self.account_oid,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_name": "Production Account",
            "aws_account_id": self.aws_account_num,
            "account": self.aws_account_num,
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
        }

        from app.database.connection import db
        db.organization_members.insert_many([
            {
                "organization_id": self.org_id,
                "user_id": self.admin_user["_id"],
                "role": "admin",
                "status": "active"
            },
            {
                "organization_id": self.org_id,
                "user_id": self.viewer_user["_id"],
                "role": "viewer",
                "status": "active"
            }
        ])
        db.aws_accounts.insert_one(dict(self.mock_account))
        db.remediation_settings.insert_one({
            "organization_id": self.org_id,
            "account_id": self.account_id_str,
            "aws_account_id": self.aws_account_num,
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

    def _setup_mocks(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        ec2_client=None,
    ):
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume_role.return_value = mock_session
        mock_verify_account.return_value = {"Account": self.aws_account_num}

        if ec2_client is None:
            ec2_client = MagicMock()
        mock_get_clients.return_value = {"ec2": ec2_client}
        return ec2_client

    # --------------------------------------------------------
    # 1. Start Instance Success
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_start_instance_success(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """Starting a stopped instance calls start_instances and verifies post-state."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "stopped"},
                        }
                    ]
                }
            ]
        }
        mock_ec2.start_instances.return_value = {
            "StartingInstances": [
                {
                    "InstanceId": self.valid_instance_id,
                    "CurrentState": {"Name": "pending"},
                    "PreviousState": {"Name": "stopped"},
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        res = control_ec2_instance(
            account_id=self.account_id_str,
            instance_id=self.valid_instance_id,
            payload=req,
            current_user=self.admin_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action"], "start")
        self.assertEqual(res["instance_id"], self.valid_instance_id)
        self.assertEqual(res["previous_state"], "stopped")
        self.assertEqual(res["current_state"], "pending")
        mock_ec2.start_instances.assert_called_once_with(
            InstanceIds=[self.valid_instance_id]
        )
        self.assertTrue(mock_record_event.called)

    # --------------------------------------------------------
    # 2. Stop Instance Success
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_stop_instance_success(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """Stopping a running instance calls stop_instances and verifies post-state."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [
                {
                    "InstanceId": self.valid_instance_id,
                    "CurrentState": {"Name": "stopping"},
                    "PreviousState": {"Name": "running"},
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        res = control_ec2_instance(
            account_id=self.account_id_str,
            instance_id=self.valid_instance_id,
            payload=req,
            current_user=self.admin_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action"], "stop")
        self.assertEqual(res["previous_state"], "running")
        self.assertEqual(res["current_state"], "stopping")
        mock_ec2.stop_instances.assert_called_once_with(
            InstanceIds=[self.valid_instance_id]
        )

    # --------------------------------------------------------
    # 3. Reboot Instance Success
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_reboot_instance_success(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """Rebooting a running instance calls reboot_instances successfully."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
        mock_ec2.reboot_instances.return_value = {}
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        req = EC2ActionRequest(action="reboot", region="us-east-1", confirmed=True)
        res = control_ec2_instance(
            account_id=self.account_id_str,
            instance_id=self.valid_instance_id,
            payload=req,
            current_user=self.admin_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["action"], "reboot")
        mock_ec2.reboot_instances.assert_called_once_with(
            InstanceIds=[self.valid_instance_id]
        )

    # --------------------------------------------------------
    # 4. Unauthorized Role Rejected (403)
    # --------------------------------------------------------
    def test_viewer_role_rejected_with_403(self):
        """Users with viewer/read-only roles are rejected with 403 Forbidden."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.viewer_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("admin or owner", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 5. Unconfirmed Mutation Rejected (400)
    # --------------------------------------------------------
    def test_unconfirmed_action_rejected_with_400(self):
        """Requests without explicit confirmed=True are rejected with 400 Bad Request."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=False)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("confirmation", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 6. Disallowed Destructive Action Rejected (400)
    # --------------------------------------------------------
    def test_disallowed_destructive_action_rejected(self):
        """Attempting destructive actions like terminate or delete is rejected with 400."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        for forbidden in ["terminate", "delete", "destroy", "stop_and_terminate"]:
            req = EC2ActionRequest(action=forbidden, region="us-east-1", confirmed=True)
            with self.assertRaises(HTTPException) as ctx:
                control_ec2_instance(
                    account_id=self.account_id_str,
                    instance_id=self.valid_instance_id,
                    payload=req,
                    current_user=self.admin_user,
                )
            self.assertEqual(ctx.exception.status_code, 400)
            self.assertIn("disallowed action", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 7. Invalid Instance ID Format (400)
    # --------------------------------------------------------
    def test_invalid_instance_id_format_rejected(self):
        """Malformed instance IDs return 400 Bad Request."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        for bad_id in ["invalid-id", "i-123", "i-123456789abcdef0123456789", ""]:
            req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
            with self.assertRaises(HTTPException) as ctx:
                control_ec2_instance(
                    account_id=self.account_id_str,
                    instance_id=bad_id,
                    payload=req,
                    current_user=self.admin_user,
                )
            self.assertEqual(ctx.exception.status_code, 400)

    # --------------------------------------------------------
    # 8. Invalid State Transition Rejected (409)
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_invalid_state_transition_raises_409(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """Starting a running instance or stopping a stopped instance returns 409 Conflict."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        # Instance is already running
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        # Attempt to start an already running instance
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 409)
        self.assertIn("cannot start", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 9. Cross-Tenant Account Isolation (404)
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.get_account")
    def test_cross_tenant_control_returns_404(self, mock_get_account):
        """Attempting to control another tenant's account returns 404 Not Found."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_get_account.return_value = None

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id="other-tenant-account",
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)

    # --------------------------------------------------------
    # 10. Assumed Account Mismatch (403)
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_assumed_account_mismatch_raises_403(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
    ):
        """Caller identity mismatch with assumed AWS role raises 403 Forbidden."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_get_account.return_value = self.mock_account
        mock_assume_role.return_value = MagicMock()
        mock_verify_account.side_effect = PermissionError("AWS account identity mismatch.")

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("mismatch", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 11. AWS AccessDenied Mapped to 403
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_aws_access_denied_mapped_to_403(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """AWS ClientError AccessDenied during mutation is mapped to 403 without secrets."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
        mock_ec2.stop_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User lacks ec2:StopInstances"}},
            "StopInstances",
        )
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("accessdenied", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # 12. Audit Event Recorded on Auth Denial
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    def test_audit_event_recorded_on_auth_denied(self, mock_record_event):
        """When user role check fails, an audit DENIED event is recorded."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException):
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.viewer_user,
            )

        self.assertTrue(mock_record_event.called)
        call_kwargs = mock_record_event.call_args[1]
        self.assertEqual(call_kwargs["result"], "DENIED")
        self.assertEqual(call_kwargs["resource_id"], self.valid_instance_id)

    # --------------------------------------------------------
    # 13. Audit Event Recorded on State Transition Failure
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_audit_event_recorded_on_state_failure(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """When an invalid state transition is attempted, a FAILURE audit event is recorded."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "stopped"},
                        }
                    ]
                }
            ]
        }
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        # Try to stop a stopped instance
        req = EC2ActionRequest(action="stop", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException):
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )

        self.assertTrue(mock_record_event.called)
        # Verify failure audit event was emitted
        failure_calls = [
            c for c in mock_record_event.call_args_list
            if c[1].get("result") == "FAILURE"
        ]
        self.assertTrue(len(failure_calls) > 0)
        self.assertEqual(
            failure_calls[0][1]["metadata"]["error_code"],
            "INVALID_STATE_TRANSITION"
        )

    # --------------------------------------------------------
    # 14. Explicit Region Parameter Respected
    # --------------------------------------------------------
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.get_account")
    def test_explicit_region_parameter_respected(
        self,
        mock_get_account,
        mock_assume_role,
        mock_verify_account,
        mock_get_clients,
        mock_record_event,
    ):
        """Passing an explicit target region assumes role in that region."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": self.valid_instance_id,
                            "State": {"Name": "running"},
                        }
                    ]
                }
            ]
        }
        mock_ec2.reboot_instances.return_value = {}
        self._setup_mocks(
            mock_get_account,
            mock_assume_role,
            mock_verify_account,
            mock_get_clients,
            mock_ec2,
        )

        req = EC2ActionRequest(action="reboot", region="ap-south-1", confirmed=True)
        res = control_ec2_instance(
            account_id=self.account_id_str,
            instance_id=self.valid_instance_id,
            payload=req,
            current_user=self.admin_user,
        )

        self.assertEqual(res["region"], "ap-south-1")
        mock_assume_role.assert_called_once_with(
            self.mock_account["role_arn"],
            region="ap-south-1",
        )

    # --------------------------------------------------------
    # 15. Mutation Control Route Registration
    # --------------------------------------------------------
    def test_control_route_registration(self):
        """Verify POST /aws/ec2/{account_id}/instances/{instance_id}/action is registered in cloud_router."""
        from app.api.cloud import router as cloud_router

        target_path = "/aws/ec2/{account_id}/instances/{instance_id}/action"
        matching_routes = [
            route for route in cloud_router.routes
            if getattr(route, "path", "") == target_path
        ]
        self.assertTrue(len(matching_routes) > 0)
        self.assertIn("POST", matching_routes[0].methods)


    # --------------------------------------------------------
    # Tenant-Specific Role Resolution (Phase 8 Fix)
    # --------------------------------------------------------
    # --------------------------------------------------------
    # Tenant-Specific Role Resolution & Fail-Closed Logic (Phase 8 Fix)
    # --------------------------------------------------------
    
    def test_missing_membership_denied(self):
        """Missing membership record results in 403 Access Denied."""
        from app.database.connection import db
        # Delete the viewer membership to simulate a missing record
        db.organization_members.delete_many({"user_id": self.viewer_user["_id"]})
        
        from app.api.cloud import control_ec2_instance, EC2ActionRequest
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.viewer_user, # Global role viewer, but tenant membership missing
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("not found", ctx.exception.detail.lower())

    def test_inactive_membership_denied(self):
        """Inactive membership results in 403 Access Denied without falling back."""
        from app.database.connection import db
        # Update the admin membership to be inactive
        db.organization_members.update_one(
            {"user_id": self.admin_user["_id"]},
            {"$set": {"status": "inactive"}}
        )
        
        from app.api.cloud import control_ec2_instance, EC2ActionRequest
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user, # Global role admin, but tenant membership inactive
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("is inactive", ctx.exception.detail.lower())

    def test_revoked_membership_denied(self):
        """Revoked membership results in 403 Access Denied."""
        from app.database.connection import db
        db.organization_members.update_one(
            {"user_id": self.admin_user["_id"]},
            {"$set": {"status": "revoked"}}
        )
        
        from app.api.cloud import control_ec2_instance, EC2ActionRequest
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id_str,
                instance_id=self.valid_instance_id,
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("is revoked", ctx.exception.detail.lower())

    def test_database_lookup_failure_returns_500(self):
        """Database lookup exception fails closed with 500 Internal Error."""
        from app.api.cloud import control_ec2_instance, EC2ActionRequest
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        
        with patch("pymongo.collection.Collection.find_one", side_effect=Exception("DB Connection Lost")):
            with self.assertRaises(HTTPException) as ctx:
                control_ec2_instance(
                    account_id=self.account_id_str,
                    instance_id=self.valid_instance_id,
                    payload=req,
                    current_user=self.admin_user,
                )
            self.assertEqual(ctx.exception.status_code, 500)
            self.assertIn("internal error resolving organization membership", ctx.exception.detail.lower())

if __name__ == "__main__":
    unittest.main()
