# ============================================================
# CloudGuardAI - Step 5: Integration, Regression & Security
# Verification Test Suite for Remediation Governance Settings
# ============================================================

import unittest
from unittest.mock import MagicMock, patch
from bson import ObjectId
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.remediation_settings import (
    RemediationSettingsUpdateRequest,
    _get_settings_handler,
    _update_settings_handler,
)
from app.database.connection import db
from app.models.remediation_settings import (
    DEFAULT_SERVICES,
    get_remediation_settings,
    is_remediation_enabled,
    update_remediation_settings,
)
from app.services.ec2_control_service import (
    EC2ControlExecutionError,
    execute_ec2_instance_action,
)
from app.services.s3_control_service import (
    S3ControlExecutionError,
    execute_s3_bucket_action,
)
from app.services.network_control_service import (
    NetworkControlExecutionError,
    execute_security_group_control,
)
from app.services.rds_control_service import (
    RDSControlExecutionError,
    execute_rds_instance_action,
)
from app.services.iam_control_service import (
    IAMControlExecutionError,
    execute_iam_action,
)
from app.services.aws_remediation_executor import (
    RemediationSecurityError,
    execute_approved_remediation,
)
from botocore.exceptions import ClientError


class TestRemediationSettingsIntegrationStep5(unittest.TestCase):
    """
    Step 5 Comprehensive Integration, Security and Regression Verification
    """

    def setUp(self):
        self.org_a_id = str(ObjectId())
        self.org_b_id = str(ObjectId())
        self.user_owner_id = str(ObjectId())
        self.user_admin_id = str(ObjectId())
        self.user_viewer_id = str(ObjectId())

        self.account_a1_oid = ObjectId()
        self.account_a1_id = str(self.account_a1_oid)
        self.account_a2_oid = ObjectId()
        self.account_a2_id = str(self.account_a2_oid)

        self.aws_account_num = "111222333444"

        # Setup in-memory / test DB fixtures
        db.aws_accounts.delete_many({
            "_id": {"$in": [self.account_a1_oid, self.account_a2_oid]}
        })
        db.remediation_settings.delete_many({
            "account_id": {"$in": [self.account_a1_id, self.account_a2_id]}
        })
        db.organization_members.delete_many({
            "organization_id": {"$in": [self.org_a_id, self.org_b_id]}
        })

        # Insert AWS accounts for Org A
        db.aws_accounts.insert_one({
            "_id": self.account_a1_oid,
            "organization_id": self.org_a_id,
            "user_id": self.user_owner_id,
            "account_name": "Org A - Prod Account",
            "aws_account_id": self.aws_account_num,
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
        })

        db.aws_accounts.insert_one({
            "_id": self.account_a2_oid,
            "organization_id": self.org_a_id,
            "user_id": self.user_owner_id,
            "account_name": "Org A - Dev Account",
            "aws_account_id": "555666777888",
            "role_arn": "arn:aws:iam::555666777888:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
        })

        # Insert Org A memberships
        db.organization_members.insert_one({
            "organization_id": self.org_a_id,
            "user_id": self.user_owner_id,
            "role": "owner",
            "status": "active",
        })
        db.organization_members.insert_one({
            "organization_id": self.org_a_id,
            "user_admin_id": self.user_admin_id,
            "user_id": self.user_admin_id,
            "role": "admin",
            "status": "active",
        })
        db.organization_members.insert_one({
            "organization_id": self.org_a_id,
            "user_id": self.user_viewer_id,
            "role": "viewer",
            "status": "active",
        })

    def tearDown(self):
        db.aws_accounts.delete_many({
            "_id": {"$in": [self.account_a1_oid, self.account_a2_oid]}
        })
        db.remediation_settings.delete_many({
            "account_id": {"$in": [self.account_a1_id, self.account_a2_id]}
        })
        db.organization_members.delete_many({
            "organization_id": {"$in": [self.org_a_id, self.org_b_id]}
        })

    # =========================================================================
    # 1. PERSISTENCE & MULTI-TENANT ISOLATION (Requirement 2)
    # =========================================================================
    def test_settings_persist_across_reloads_and_remain_isolated(self):
        """Settings persist in DB and are strictly isolated by organization and account."""
        owner_user = {"id": self.user_owner_id, "organization_id": self.org_a_id}

        # 1. Org A Owner enables EC2 and S3 on Account A1
        update_payload = RemediationSettingsUpdateRequest(ec2=True, s3=True)
        res = _update_settings_handler(self.account_a1_id, update_payload, owner_user)
        self.assertEqual(res["status"], "success")
        self.assertTrue(res["services"]["ec2"])
        self.assertTrue(res["services"]["s3"])
        self.assertFalse(res["services"]["vpc"])

        # 2. Simulate page reload: Retrieve settings fresh from database
        fresh_res = _get_settings_handler(self.account_a1_id, owner_user)
        self.assertTrue(fresh_res["services"]["ec2"])
        self.assertTrue(fresh_res["services"]["s3"])
        self.assertFalse(fresh_res["services"]["vpc"])
        self.assertFalse(fresh_res["services"]["rds"])
        self.assertFalse(fresh_res["services"]["iam"])
        self.assertFalse(fresh_res["services"]["cloudtrail"])
        self.assertTrue(fresh_res["exists"])

        # 3. Account A2 in same Org remains isolated and defaults to all False
        a2_res = _get_settings_handler(self.account_a2_id, owner_user)
        for svc, val in a2_res["services"].items():
            self.assertFalse(val, f"Account A2 service {svc} should default to False")

        # 4. Cross-Tenant Isolation: User from Org B cannot read Account A1 settings
        org_b_user = {"id": str(ObjectId()), "organization_id": self.org_b_id}
        db.organization_members.insert_one({
            "organization_id": self.org_b_id,
            "user_id": org_b_user["id"],
            "role": "owner",
            "status": "active",
        })
        with self.assertRaises(HTTPException) as cm:
            _get_settings_handler(self.account_a1_id, org_b_user)
        self.assertEqual(cm.exception.status_code, 404)
        self.assertIn("not found for this organization", cm.exception.detail)

    # =========================================================================
    # 2. ALL SIX SERVICES DEFAULT TO DISABLED (Requirement 3)
    # =========================================================================
    def test_all_six_services_default_to_disabled_when_missing(self):
        """When no settings document exists in DB, all 6 services must return False."""
        owner_user = {"id": self.user_owner_id, "organization_id": self.org_a_id}

        res = _get_settings_handler(self.account_a1_id, owner_user)
        self.assertFalse(res["exists"])
        services = res["services"]
        expected_keys = {"ec2", "s3", "vpc", "rds", "iam", "cloudtrail"}
        self.assertEqual(set(services.keys()), expected_keys)
        for key in expected_keys:
            self.assertFalse(services[key], f"{key} must default to False")

    # =========================================================================
    # 3. SERVICE KEY INDEPENDENCE (Requirement 4)
    # =========================================================================
    def test_enabling_one_service_does_not_enable_any_other(self):
        """Toggling one service key must strictly leave all other keys untouched."""
        owner_user = {"id": self.user_owner_id, "organization_id": self.org_a_id}

        # Enable only IAM
        _update_settings_handler(
            self.account_a1_id,
            RemediationSettingsUpdateRequest(iam=True),
            owner_user,
        )
        res = _get_settings_handler(self.account_a1_id, owner_user)
        self.assertTrue(res["services"]["iam"])
        self.assertFalse(res["services"]["ec2"])
        self.assertFalse(res["services"]["s3"])
        self.assertFalse(res["services"]["vpc"])
        self.assertFalse(res["services"]["rds"])
        self.assertFalse(res["services"]["cloudtrail"])

        # Enable CloudTrail: IAM remains True, others remain False
        _update_settings_handler(
            self.account_a1_id,
            RemediationSettingsUpdateRequest(cloudtrail=True),
            owner_user,
        )
        res2 = _get_settings_handler(self.account_a1_id, owner_user)
        self.assertTrue(res2["services"]["iam"])
        self.assertTrue(res2["services"]["cloudtrail"])
        self.assertFalse(res2["services"]["ec2"])
        self.assertFalse(res2["services"]["s3"])
        self.assertFalse(res2["services"]["vpc"])
        self.assertFalse(res2["services"]["rds"])

    # =========================================================================
    # 4. VIEWER ROLE & ROLE AUTHORIZATION (Requirement 6)
    # =========================================================================
    def test_viewer_cannot_update_settings_but_can_read(self):
        """Viewers can inspect settings (read-only) but cannot mutate them."""
        viewer_user = {"id": self.user_viewer_id, "organization_id": self.org_a_id}

        # Viewer can read settings
        read_res = _get_settings_handler(self.account_a1_id, viewer_user)
        self.assertEqual(read_res["status"], "success")

        # Viewer cannot update settings
        with self.assertRaises(HTTPException) as cm:
            _update_settings_handler(
                self.account_a1_id,
                RemediationSettingsUpdateRequest(ec2=True),
                viewer_user,
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertIn("Only organization Owners and Admins", cm.exception.detail)

    def test_inactive_and_revoked_memberships_fail_closed(self):
        """Users with inactive or suspended status are denied access."""
        inactive_user_id = str(ObjectId())
        db.organization_members.insert_one({
            "organization_id": self.org_a_id,
            "user_id": inactive_user_id,
            "role": "admin",
            "status": "inactive",
        })
        user_ctx = {"id": inactive_user_id, "organization_id": self.org_a_id}

        with self.assertRaises(HTTPException) as cm:
            _get_settings_handler(self.account_a1_id, user_ctx)
        self.assertEqual(cm.exception.status_code, 403)

        with self.assertRaises(HTTPException) as cm:
            _update_settings_handler(
                self.account_a1_id,
                RemediationSettingsUpdateRequest(ec2=True),
                user_ctx,
            )
        self.assertEqual(cm.exception.status_code, 403)

    # =========================================================================
    # 5. DISCONNECTED ACCOUNTS & VALIDATION (Requirement 7)
    # =========================================================================
    def test_disconnected_account_cannot_be_updated(self):
        """Disconnected accounts reject settings updates with 400 Bad Request."""
        db.aws_accounts.update_one(
            {"_id": self.account_a1_oid},
            {"$set": {"status": "disconnected"}}
        )
        owner_user = {"id": self.user_owner_id, "organization_id": self.org_a_id}

        with self.assertRaises(HTTPException) as cm:
            _update_settings_handler(
                self.account_a1_id,
                RemediationSettingsUpdateRequest(ec2=True),
                owner_user,
            )
        self.assertEqual(cm.exception.status_code, 400)
        self.assertIn("disconnected AWS account", cm.exception.detail)

    def test_strict_payload_validation_rejects_extra_keys_and_bad_types(self):
        """Payload validation strictly forbids unknown service keys and non-boolean types."""
        # Non-boolean type
        with self.assertRaises(ValidationError):
            RemediationSettingsUpdateRequest(ec2="true")

        # Unknown service key
        with self.assertRaises(ValidationError):
            RemediationSettingsUpdateRequest(ec2=True, lambda_svc=True)

    # =========================================================================
    # 6. MUTATION PATH FAIL-CLOSED ENFORCEMENT (Requirement 5 & 9)
    # =========================================================================
    @patch("app.services.ec2_control_service.assume_aws_role")
    def test_direct_ec2_control_blocks_when_disabled(self, mock_assume):
        """Direct EC2 control aborts and raises 403 when ec2 is disabled."""
        # Settings in DB: ec2 is False
        db.remediation_settings.update_one(
            {"account_id": self.account_a1_id},
            {"$set": {"services.ec2": False}},
            upsert=True,
        )

        with self.assertRaises(EC2ControlExecutionError) as cm:
            execute_ec2_instance_action(
                account_id=self.account_a1_id,
                instance_id="i-0123456789abcdef0",
                action="stop",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()

    @patch("app.services.s3_control_service.assume_aws_role")
    def test_direct_s3_control_blocks_when_disabled(self, mock_assume):
        """Direct S3 control aborts and raises 403 when s3 is disabled."""
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.s3": False}},
            upsert=True,
        )

        with self.assertRaises(S3ControlExecutionError) as cm:
            execute_s3_bucket_action(
                account_id=self.account_a1_id,
                bucket_name="secure-bucket",
                action="enable_block_public_access",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()

    @patch("app.services.network_control_service.assume_aws_role")
    def test_direct_vpc_control_blocks_when_disabled(self, mock_assume):
        """Direct VPC control aborts and raises 403 when vpc is disabled."""
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.vpc": False}},
            upsert=True,
        )

        with self.assertRaises(NetworkControlExecutionError) as cm:
            execute_security_group_control(
                account_id=self.account_a1_id,
                group_id="sg-01234567",
                action="revoke_ssh_ingress",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                user_role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()

    @patch("app.services.rds_control_service.assume_aws_role")
    def test_direct_rds_control_blocks_when_disabled(self, mock_assume):
        """Direct RDS control aborts and raises 403 when rds is disabled."""
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.rds": False}},
            upsert=True,
        )

        with self.assertRaises(RDSControlExecutionError) as cm:
            execute_rds_instance_action(
                account_id=self.account_a1_id,
                instance_id="prod-db",
                action="stop",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()

    @patch("app.services.iam_control_service.assume_aws_role")
    def test_direct_iam_control_blocks_when_disabled(self, mock_assume):
        """Direct IAM control aborts and raises 403 when iam is disabled."""
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.iam": False}},
            upsert=True,
        )

        with self.assertRaises(IAMControlExecutionError) as cm:
            execute_iam_action(
                account_id=self.account_a1_id,
                resource_id="AKIA1234567890ABCDEF",
                resource_type="access_key",
                action="disable_access_key",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()

    @patch("app.services.aws_remediation_executor.assume_aws_role")
    def test_general_executor_blocks_when_disabled(self, mock_assume):
        """General executor engine aborts when mapped service setting is False."""
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.s3": False}},
            upsert=True,
        )
        remediation_oid = ObjectId()
        remediation_id = str(remediation_oid)
        finding_oid = ObjectId()
        finding_id = str(finding_oid)

        db.remediations.insert_one({
            "_id": remediation_oid,
            "user_id": self.user_owner_id,
            "account_id": self.account_a1_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "status": "APPROVED",
            "service": "S3",
            "action_type": "DISABLE_PUBLIC_ACCESS",
            "resource": "test-bucket",
            "finding_id": finding_id,
        })
        db.findings.insert_one({
            "_id": finding_oid,
            "account_id": self.account_a1_id,
            "user_id": self.user_owner_id,
            "status": "OPEN",
        })

        try:
            with self.assertRaises(RemediationSecurityError) as cm:
                execute_approved_remediation(
                    remediation_id=remediation_id,
                    user_id=self.user_owner_id,
                )
            self.assertIn("Remediation setting is disabled for s3", str(cm.exception))
            mock_assume.assert_not_called()
        finally:
            db.remediations.delete_one({"_id": remediation_oid})
            db.findings.delete_one({"_id": finding_oid})

    # =========================================================================
    # 7. AWS PERMISSION DENIAL HANDLING (Requirement 7)
    # =========================================================================
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.get_aws_clients")
    def test_aws_access_denied_handled_cleanly_when_setting_enabled(
        self, mock_clients, mock_verify, mock_assume
    ):
        """
        When setting is enabled, but cross-account IAM role lacks AWS permission,
        system raises 403 AWS_ACCESS_DENIED without crashing or corrupting state.
        """
        db.remediation_settings.update_one(
            {"organization_id": self.org_a_id, "account_id": self.account_a1_id},
            {"$set": {"services.ec2": True}},
            upsert=True,
        )

        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_verify.return_value = {"Account": self.aws_account_num}

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [
                {"Instances": [{"InstanceId": "i-0123456789abcdef0", "State": {"Name": "running"}}]}
            ]
        }
        # Simulate AWS IAM AccessDenied on ec2:StopInstances
        mock_ec2.stop_instances.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "User is not authorized to perform: ec2:StopInstances"}},
            "StopInstances",
        )
        mock_clients.return_value = {"ec2": mock_ec2}

        with self.assertRaises(EC2ControlExecutionError) as cm:
            execute_ec2_instance_action(
                account_id=self.account_a1_id,
                instance_id="i-0123456789abcdef0",
                action="stop",
                confirmed=True,
                user_id=self.user_owner_id,
                organization_id=self.org_a_id,
                role="owner",
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "AWS_ACCESS_DENIED")


if __name__ == "__main__":
    unittest.main()
