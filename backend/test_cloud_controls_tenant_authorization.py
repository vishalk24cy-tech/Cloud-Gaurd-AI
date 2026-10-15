# ============================================================
# CloudGuardAI - Cloud Resource Controls Tenant Authorization & RBAC Tests
# Phase 3C Step 4: Direct Cloud Resource Control Authorization
# ============================================================

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, patch

from bson import ObjectId
from fastapi import HTTPException

from app.api.cloud import (
    control_ec2_instance,
    control_s3_bucket,
    control_rds_instance,
    control_security_group,
    control_iam_resource,
    list_ec2_instances,
    list_s3_buckets,
    EC2ActionRequest,
    S3ActionRequest,
    RDSActionRequest,
    SecurityGroupActionPayload,
    IAMActionRequest,
)
from app.services.tenant_context import TenantContext


class TestCloudControlsTenantAuthorization(unittest.TestCase):
    """
    Validates tenant isolation, active membership verification, role-based
    access control (Owner/Admin only for mutations), disconnected account rejection,
    and defense-in-depth across direct cloud resource control endpoints.
    """

    def setUp(self):
        self.org_id = str(ObjectId())
        self.foreign_org_id = str(ObjectId())

        self.owner_id = str(ObjectId())
        self.admin_id = str(ObjectId())
        self.analyst_id = str(ObjectId())
        self.viewer_id = str(ObjectId())
        self.no_membership_id = str(ObjectId())
        self.inactive_user_id = str(ObjectId())
        self.unknown_role_id = str(ObjectId())

        self.account_id = str(ObjectId())
        self.disconnected_account_id = str(ObjectId())
        self.foreign_account_id = str(ObjectId())
        self.aws_account_num = "123456789012"

        self.owner_user = {
            "_id": self.owner_id,
            "organization": self.org_id,
            "email": "owner@cloudguard.ai",
        }
        self.admin_user = {
            "_id": self.admin_id,
            "organization": self.org_id,
            "email": "admin@cloudguard.ai",
        }
        self.analyst_user = {
            "_id": self.analyst_id,
            "organization": self.org_id,
            "email": "analyst@cloudguard.ai",
        }
        self.viewer_user = {
            "_id": self.viewer_id,
            "organization": self.org_id,
            "email": "viewer@cloudguard.ai",
        }
        self.no_membership_user = {
            "_id": self.no_membership_id,
            "organization": self.org_id,
            "email": "nomember@cloudguard.ai",
        }
        self.inactive_user = {
            "_id": self.inactive_user_id,
            "organization": self.org_id,
            "email": "inactive@cloudguard.ai",
        }
        self.unknown_role_user = {
            "_id": self.unknown_role_id,
            "organization": self.org_id,
            "email": "unknown@cloudguard.ai",
        }

        now = datetime.now(timezone.utc)

        # Connected AWS Account in Org
        self.connected_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Primary Production Account",
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
            "organization_id": self.org_id,
            "created_at": now,
        }

        # Disconnected AWS Account in Org
        self.disconnected_account = {
            "_id": ObjectId(self.disconnected_account_id),
            "account_id": self.disconnected_account_id,
            "aws_account_id": "999888777666",
            "account_name": "Disconnected Legacy Account",
            "role_arn": "arn:aws:iam::999888777666:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "disconnected",
            "organization_id": self.org_id,
            "created_at": now,
        }

        # Foreign AWS Account in Foreign Org
        self.foreign_account = {
            "_id": ObjectId(self.foreign_account_id),
            "account_id": self.foreign_account_id,
            "aws_account_id": "555444333222",
            "account_name": "Foreign Tenant Account",
            "role_arn": "arn:aws:iam::555444333222:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
            "organization_id": self.foreign_org_id,
            "created_at": now,
        }

        self.members_store = {
            (self.org_id, self.owner_id): {
                "organization_id": self.org_id,
                "user_id": self.owner_id,
                "role": "owner",
                "status": "active",
            },
            (self.org_id, self.admin_id): {
                "organization_id": self.org_id,
                "user_id": self.admin_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_id, self.analyst_id): {
                "organization_id": self.org_id,
                "user_id": self.analyst_id,
                "role": "analyst",
                "status": "active",
            },
            (self.org_id, self.viewer_id): {
                "organization_id": self.org_id,
                "user_id": self.viewer_id,
                "role": "viewer",
                "status": "active",
            },
            (self.org_id, self.inactive_user_id): {
                "organization_id": self.org_id,
                "user_id": self.inactive_user_id,
                "role": "admin",
                "status": "inactive",
            },
            (self.org_id, self.unknown_role_id): {
                "organization_id": self.org_id,
                "user_id": self.unknown_role_id,
                "role": "superhero",
                "status": "active",
            },
        }

        self.accounts_store = {
            str(self.account_id): dict(self.connected_account),
            str(self.disconnected_account_id): dict(self.disconnected_account),
            str(self.foreign_account_id): dict(self.foreign_account),
        }

        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member

        self.patchers = [
            patch("app.services.tenant_context.db", self.mock_db),
            patch("app.models.remediation_settings.is_remediation_enabled", return_value=True),
            patch("app.api.cloud.get_account", side_effect=self._mock_get_account),
            patch("app.services.ec2_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.s3_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.rds_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.network_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.iam_control_service.get_account", side_effect=self._mock_get_account),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def _mock_find_member(self, query, *args, **kwargs):
        org_id = str(query.get("organization_id", ""))
        user_id = str(query.get("user_id", ""))
        member = self.members_store.get((org_id, user_id))
        return dict(member) if member else None

    def _mock_get_account(self, account_id, user_id=None, organization_id=None):
        acc = self.accounts_store.get(str(account_id))
        if not acc:
            return None
        if organization_id and str(acc.get("organization_id")) != str(organization_id):
            return None
        return dict(acc)

    # ========================================================
    # 1. EC2 RESOURCE CONTROL TESTS
    # ========================================================

    @patch("app.api.cloud.execute_ec2_instance_action")
    def test_ec2_owner_and_admin_authorized(self, mock_execute):
        """Owner and Admin can execute permitted EC2 action."""
        mock_execute.return_value = {
            "status": "success",
            "action": "start",
            "instance_id": "i-0123456789abcdef0",
        }

        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)

        # Admin execution
        res_admin = control_ec2_instance(
            account_id=self.account_id,
            instance_id="i-0123456789abcdef0",
            payload=req,
            current_user=self.admin_user,
        )
        self.assertEqual(res_admin["status"], "success")

        # Owner execution
        res_owner = control_ec2_instance(
            account_id=self.account_id,
            instance_id="i-0123456789abcdef0",
            payload=req,
            current_user=self.owner_user,
        )
        self.assertEqual(res_owner["status"], "success")

    def test_ec2_analyst_and_viewer_denied(self):
        """Analyst and Viewer roles are denied direct EC2 mutation with 403."""
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)

        for user in [self.analyst_user, self.viewer_user]:
            with self.assertRaises(HTTPException) as ctx:
                control_ec2_instance(
                    account_id=self.account_id,
                    instance_id="i-0123456789abcdef0",
                    payload=req,
                    current_user=user,
                )
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("admin or owner", ctx.exception.detail.lower())

    def test_ec2_cross_tenant_account_rejected_404(self):
        """Attempting to mutate foreign tenant account returns 404 without disclosure."""
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.foreign_account_id,
                instance_id="i-0123456789abcdef0",
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_ec2_disconnected_account_rejected_400(self):
        """Disconnected account rejects mutation with 400 before SDK call."""
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.disconnected_account_id,
                instance_id="i-0123456789abcdef0",
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not connected", ctx.exception.detail.lower())

    def test_ec2_inactive_and_missing_membership_denied(self):
        """Inactive or missing memberships fail closed with 403."""
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)

        # Inactive membership
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id,
                instance_id="i-0123456789abcdef0",
                payload=req,
                current_user=self.inactive_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("inactive", ctx.exception.detail.lower())

        # Missing membership
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id,
                instance_id="i-0123456789abcdef0",
                payload=req,
                current_user=self.no_membership_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("membership not found", ctx.exception.detail.lower())

    def test_ec2_unknown_role_fails_closed(self):
        """Unknown or invalid role fails closed with 403."""
        req = EC2ActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_ec2_instance(
                account_id=self.account_id,
                instance_id="i-0123456789abcdef0",
                payload=req,
                current_user=self.unknown_role_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("invalid or unsupported", ctx.exception.detail.lower())

    # ========================================================
    # 2. S3 RESOURCE CONTROL TESTS
    # ========================================================

    @patch("app.api.cloud.execute_s3_bucket_action")
    def test_s3_owner_and_admin_authorized(self, mock_execute):
        """Owner and Admin can execute permitted S3 control actions."""
        mock_execute.return_value = {
            "status": "success",
            "action": "enable_block_public_access",
            "bucket_name": "cloudguard-audit-bucket",
        }

        req = S3ActionRequest(action="enable_block_public_access", confirmed=True)

        res_admin = control_s3_bucket(
            account_id=self.account_id,
            bucket_name="cloudguard-audit-bucket",
            payload=req,
            current_user=self.admin_user,
        )
        self.assertEqual(res_admin["status"], "success")

        res_owner = control_s3_bucket(
            account_id=self.account_id,
            bucket_name="cloudguard-audit-bucket",
            payload=req,
            current_user=self.owner_user,
        )
        self.assertEqual(res_owner["status"], "success")

    def test_s3_analyst_and_viewer_denied(self):
        """Analyst and Viewer denied direct S3 mutation with 403."""
        req = S3ActionRequest(action="enable_block_public_access", confirmed=True)
        for user in [self.analyst_user, self.viewer_user]:
            with self.assertRaises(HTTPException) as ctx:
                control_s3_bucket(
                    account_id=self.account_id,
                    bucket_name="cloudguard-audit-bucket",
                    payload=req,
                    current_user=user,
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_s3_cross_tenant_account_rejected_404(self):
        """Cross-tenant S3 action returns 404."""
        req = S3ActionRequest(action="enable_block_public_access", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_s3_bucket(
                account_id=self.foreign_account_id,
                bucket_name="cloudguard-audit-bucket",
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)

    def test_s3_disconnected_account_rejected_400(self):
        """Disconnected account rejected with 400 for S3 controls."""
        req = S3ActionRequest(action="enable_block_public_access", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_s3_bucket(
                account_id=self.disconnected_account_id,
                bucket_name="cloudguard-audit-bucket",
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not connected", ctx.exception.detail.lower())

    # ========================================================
    # 3. RDS RESOURCE CONTROL TESTS
    # ========================================================

    @patch("app.api.cloud.execute_rds_instance_action")
    def test_rds_owner_and_admin_authorized(self, mock_execute):
        """Owner and Admin can execute permitted RDS action."""
        mock_execute.return_value = {
            "status": "success",
            "action": "start",
            "instance_id": "prod-db-1",
        }

        req = RDSActionRequest(action="start", region="us-east-1", confirmed=True)

        res_admin = control_rds_instance(
            account_id=self.account_id,
            instance_id="prod-db-1",
            payload=req,
            current_user=self.admin_user,
        )
        self.assertEqual(res_admin["status"], "success")

        res_owner = control_rds_instance(
            account_id=self.account_id,
            instance_id="prod-db-1",
            payload=req,
            current_user=self.owner_user,
        )
        self.assertEqual(res_owner["status"], "success")

    def test_rds_analyst_and_viewer_denied(self):
        """Analyst and Viewer denied direct RDS mutation with 403."""
        req = RDSActionRequest(action="start", region="us-east-1", confirmed=True)
        for user in [self.analyst_user, self.viewer_user]:
            with self.assertRaises(HTTPException) as ctx:
                control_rds_instance(
                    account_id=self.account_id,
                    instance_id="prod-db-1",
                    payload=req,
                    current_user=user,
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_rds_disconnected_account_rejected_400(self):
        """Disconnected account rejected with 400 for RDS controls."""
        req = RDSActionRequest(action="start", region="us-east-1", confirmed=True)
        with self.assertRaises(HTTPException) as ctx:
            control_rds_instance(
                account_id=self.disconnected_account_id,
                instance_id="prod-db-1",
                payload=req,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not connected", ctx.exception.detail.lower())

    # ========================================================
    # 4. NETWORK (SECURITY GROUP) RESOURCE CONTROL TESTS
    # ========================================================

    @patch("app.api.cloud.execute_security_group_control")
    def test_network_owner_and_admin_authorized(self, mock_execute):
        """Owner and Admin can execute permitted security group remediation action."""
        mock_execute.return_value = {
            "status": "success",
            "action": "revoke_ssh_ingress",
            "group_id": "sg-01234567",
        }

        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )

        res_admin = control_security_group(
            account_id=self.account_id,
            group_id="sg-01234567",
            payload=payload,
            current_user=self.admin_user,
        )
        self.assertEqual(res_admin["status"], "success")

        res_owner = control_security_group(
            account_id=self.account_id,
            group_id="sg-01234567",
            payload=payload,
            current_user=self.owner_user,
        )
        self.assertEqual(res_owner["status"], "success")

    def test_network_analyst_and_viewer_denied(self):
        """Analyst and Viewer denied direct security group mutation with 403."""
        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )
        for user in [self.analyst_user, self.viewer_user]:
            with self.assertRaises(HTTPException) as ctx:
                control_security_group(
                    account_id=self.account_id,
                    group_id="sg-01234567",
                    payload=payload,
                    current_user=user,
                )
            self.assertEqual(ctx.exception.status_code, 403)

    def test_network_disconnected_account_rejected_400(self):
        """Disconnected account rejected with 400 for network controls."""
        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as ctx:
            control_security_group(
                account_id=self.disconnected_account_id,
                group_id="sg-01234567",
                payload=payload,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not connected", ctx.exception.detail.lower())

    # ========================================================
    # 5. IAM RESOURCE CONTROL TESTS
    # ========================================================

    @patch("app.services.iam_control_service.get_aws_clients")
    @patch("app.services.iam_control_service.verify_aws_account")
    @patch("app.services.iam_control_service.assume_aws_role")
    def test_iam_owner_and_admin_authorized(
        self, mock_assume, mock_verify, mock_clients
    ):
        """Owner and Admin can execute permitted IAM control actions."""
        mock_iam = MagicMock()
        mock_clients.return_value = {"iam": mock_iam}
        mock_verify.return_value = {"Account": self.aws_account_num}

        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "dev-user"},
            confirmed=True,
        )

        res_admin = control_iam_resource(
            account_id=self.account_id,
            resource_id="AKIA1111222233334444",
            payload=payload,
            current_user=self.admin_user,
        )
        self.assertEqual(res_admin["status"], "success")

        res_owner = control_iam_resource(
            account_id=self.account_id,
            resource_id="AKIA1111222233334444",
            payload=payload,
            current_user=self.owner_user,
        )
        self.assertEqual(res_owner["status"], "success")

    def test_iam_analyst_and_viewer_denied(self):
        """Analyst and Viewer denied direct IAM mutation with 403."""
        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "dev-user"},
            confirmed=True,
        )
        for user in [self.analyst_user, self.viewer_user]:
            with self.assertRaises(HTTPException) as ctx:
                control_iam_resource(
                    account_id=self.account_id,
                    resource_id="AKIA1111222233334444",
                    payload=payload,
                    current_user=user,
                )
            self.assertEqual(ctx.exception.status_code, 403)
            self.assertIn("Admin or Owner", ctx.exception.detail)

    def test_iam_disconnected_account_rejected_400(self):
        """Disconnected account rejected with 400 for IAM controls."""
        payload = IAMActionRequest(
            action="disable_access_key",
            resource_type="user",
            parameters={"username": "dev-user"},
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as ctx:
            control_iam_resource(
                account_id=self.disconnected_account_id,
                resource_id="AKIA1111222233334444",
                payload=payload,
                current_user=self.admin_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("not connected", ctx.exception.detail.lower())

    # ========================================================
    # 6. READ-ONLY INVENTORY & NO MUTATION ON REJECTED REQUESTS
    # ========================================================

    @patch("app.api.cloud.fetch_ec2_instances_inventory")
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.verify_aws_account")
    @patch("app.api.cloud.assume_aws_role")
    def test_read_only_inventory_analyst_and_viewer_permitted(
        self, mock_assume, mock_verify, mock_clients, mock_fetch
    ):
        """Read-only EC2 instance listing remains permitted for analyst and viewer."""
        mock_fetch.return_value = {
            "total_count": 0,
            "instances": [],
            "summary": {},
            "next_token": None,
        }
        mock_clients.return_value = {"ec2": MagicMock()}
        mock_verify.return_value = {"Account": self.aws_account_num}

        for user in [self.analyst_user, self.viewer_user]:
            res = list_ec2_instances(
                account_id=self.account_id,
                current_user=user,
            )
            self.assertEqual(res["status"], "success")

    def test_no_aws_mutation_on_rejected_requests(self):
        """Verify that when authorization or confirmation fails, no AWS mutation is called."""
        with patch("app.services.ec2_control_service.assume_aws_role") as mock_assume:
            req = EC2ActionRequest(action="start", region="us-east-1", confirmed=False)  # Unconfirmed
            with self.assertRaises(HTTPException):
                control_ec2_instance(
                    account_id=self.account_id,
                    instance_id="i-0123456789abcdef0",
                    payload=req,
                    current_user=self.admin_user,
                )
            mock_assume.assert_not_called()


if __name__ == "__main__":
    unittest.main()
