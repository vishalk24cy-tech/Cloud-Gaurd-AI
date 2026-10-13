# ============================================================
# CloudGuardAI - Unit & Regression Tests for IAM Resource Controls
# Phase 6: AWS IAM Identity & Access Management
# ============================================================

import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api.cloud import list_iam_inventory, control_iam_resource, IAMActionRequest
from app.services.iam_control_service import fetch_iam_inventory, execute_iam_action, IAMControlExecutionError

class TestIAMResourceInventoryUnit(unittest.TestCase):
    def test_fetch_iam_inventory_success(self):
        mock_iam = MagicMock()
        mock_iam.list_users.return_value = {
            "Users": [{"UserName": "test-user", "UserId": "U123", "Arn": "arn:aws:iam::123:user/test-user"}]
        }
        mock_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [{"AccessKeyId": "AKIA123", "Status": "Active"}]
        }
        mock_iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "arn:aws:iam::123:mfa/test-user"}]}
        mock_iam.get_login_profile.return_value = {"LoginProfile": {"UserName": "test-user"}}
        mock_iam.list_roles.return_value = {
            "Roles": [{"RoleName": "test-role", "RoleId": "R123", "Arn": "arn:aws:iam::123:role/test-role"}]
        }
        mock_iam.list_policies.return_value = {
            "Policies": [{"PolicyName": "test-policy", "PolicyId": "P123", "Arn": "arn:aws:iam::123:policy/test-policy", "AttachmentCount": 1}]
        }

        inventory = fetch_iam_inventory(mock_iam)

        self.assertEqual(inventory["total_users"], 1)
        self.assertEqual(inventory["users"][0]["user_name"], "test-user")
        self.assertTrue(inventory["users"][0]["mfa_enabled"])
        self.assertTrue(inventory["users"][0]["console_access"])
        self.assertEqual(len(inventory["users"][0]["access_keys"]), 1)
        self.assertEqual(inventory["total_roles"], 1)
        self.assertEqual(inventory["total_policies"], 1)

class TestIAMResourceControlsEndpoint(unittest.TestCase):
    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_id = str(ObjectId())
        self.account_oid = ObjectId()
        self.account_id_str = str(self.account_oid)
        self.aws_account_num = "123456789012"

        self.current_user = {
            "_id": self.user_id,
            "organization": self.org_id,
            "role": "admin",
            "email": "admin@cloudguard.ai",
        }
        self.current_viewer = {
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
                "user_id": self.current_user["_id"],
                "role": "admin",
                "status": "active"
            },
            {
                "organization_id": self.org_id,
                "user_id": self.current_viewer["_id"],
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

    def _setup_mocks(self, mock_get_account, mock_assume_role, mock_verify_account, mock_get_clients, iam_client=None):
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume_role.return_value = mock_session
        mock_verify_account.return_value = {"Account": self.aws_account_num}
        if iam_client is None:
            iam_client = MagicMock()
        mock_get_clients.return_value = {"iam": iam_client}
        return iam_client

    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_account")
    def test_list_iam_inventory(self, mock_get_account, mock_assume_role, mock_verify_account, mock_get_clients):
        mock_iam = MagicMock()
        mock_iam.list_users.return_value = {"Users": []}
        mock_iam.list_roles.return_value = {"Roles": []}
        mock_iam.list_policies.return_value = {"Policies": []}
        
        self._setup_mocks(mock_get_account, mock_assume_role, mock_verify_account, mock_get_clients, mock_iam)

        resp = list_iam_inventory(
            account_id=self.account_id_str,
            current_user=self.current_user,
        )

        self.assertEqual(resp["status"], "success")
        self.assertEqual(resp["inventory"]["total_users"], 0)

    @patch("app.services.iam_control_service.record_event")
    @patch("app.services.iam_control_service.get_aws_clients")
    @patch("app.services.iam_control_service.verify_aws_account")
    @patch("app.services.iam_control_service.assume_aws_role")
    @patch("app.services.iam_control_service.get_account")
    def test_control_iam_resource_disable_key(self, mock_get_account, mock_assume_role, mock_verify_account, mock_get_clients, mock_record_event):
        mock_iam = MagicMock()
        self._setup_mocks(mock_get_account, mock_assume_role, mock_verify_account, mock_get_clients, mock_iam)

        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "test-user"},
            confirmed=True
        )

        resp = control_iam_resource(
            account_id=self.account_id_str,
            resource_id="AKIA123",
            payload=payload,
            current_user=self.current_user,
        )

        mock_iam.update_access_key.assert_called_once_with(
            UserName="test-user",
            AccessKeyId="AKIA123",
            Status="Inactive"
        )
        self.assertEqual(resp["status"], "success")

    @patch("app.services.iam_control_service.record_event")
    def test_control_iam_unconfirmed(self, mock_record_event):
        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "test-user"},
            confirmed=False
        )

        with self.assertRaises(HTTPException) as cm:
            control_iam_resource(
                account_id=self.account_id_str,
                resource_id="AKIA123",
                payload=payload,
                current_user=self.current_user,
            )
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("Explicit user confirmation is required", cm.exception.detail)

    @patch("app.services.iam_control_service.record_event")
    def test_control_iam_unauthorized(self, mock_record_event):
        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "test-user"},
            confirmed=True
        )

        with self.assertRaises(HTTPException) as cm:
            control_iam_resource(
                account_id=self.account_id_str,
                resource_id="AKIA123",
                payload=payload,
                current_user=self.current_viewer,
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("Admin or Owner", cm.exception.detail)

if __name__ == "__main__":
    unittest.main()
