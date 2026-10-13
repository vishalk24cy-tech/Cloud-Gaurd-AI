# ============================================================
# CloudGuardAI - Unit & Regression Tests for Step 3:
# Remediation Settings Enforcement Across All Execution Paths
# ============================================================

from datetime import datetime, timezone
import unittest
from unittest.mock import MagicMock, Mock, patch

from bson import ObjectId

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

from app.services.remediation.ec2_execution import (
    EC2StopExecutionError,
    execute_ec2_stop,
)
from app.services.remediation.s3_execution import (
    S3BlockPublicAccessError,
    execute_s3_block_public_access,
)
from app.services.remediation.vpc_execution import (
    VPCIngressExecutionError,
    execute_vpc_remove_ssh_ingress,
)
from app.services.remediation.rds_execution import (
    RDSDisablePublicAccessError,
    execute_rds_disable_public_access,
)
from app.services.remediation.iam_execution import (
    IAMAccessKeyExecutionError,
    execute_iam_disable_access_key,
)
from app.services.remediation.cloudtrail_execution import (
    CloudTrailEnableLoggingError,
    execute_cloudtrail_enable_logging,
)
from app.services.aws_remediation_executor import (
    RemediationSecurityError,
    execute_approved_remediation,
)


class TestRemediationSettingsEnforcement(unittest.TestCase):
    """
    Step 3 Verification Test Suite:
    Enforces that saved remediation settings govern EVERY backend execution path
    for EC2, S3, VPC/Security Groups, RDS, IAM, and CloudTrail.
    """

    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_id = str(ObjectId())
        self.account_oid = ObjectId()
        self.account_id = str(self.account_oid)
        self.aws_account_num = "123456789012"

        self.mock_account = {
            "_id": self.account_oid,
            "account_id": self.account_id,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_name": "Test Account",
            "aws_account_id": self.aws_account_num,
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
        }

    # -------------------------------------------------------------------------
    # 1. DIRECT EC2 CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.ec2_control_service.get_account")
    @patch("app.services.ec2_control_service.record_event")
    @patch("app.services.ec2_control_service.assume_aws_role")
    def test_direct_ec2_control_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account

        with self.assertRaises(EC2ControlExecutionError) as cm:
            execute_ec2_instance_action(
                account_id=self.account_id,
                instance_id="i-0123456789abcdef0",
                action="stop",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["metadata"]["error_code"], "REMEDIATION_SETTING_DISABLED")

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=True)
    @patch("app.services.ec2_control_service.get_account")
    @patch("app.services.ec2_control_service.assume_aws_role")
    @patch("app.services.ec2_control_service.verify_aws_account")
    @patch("app.services.ec2_control_service.get_aws_clients")
    @patch("app.services.ec2_control_service.record_event")
    def test_direct_ec2_control_allowed_when_enabled(
        self, mock_record_event, mock_clients, mock_verify, mock_assume, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_verify.return_value = {"Account": self.aws_account_num}

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.side_effect = [
            {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0", "State": {"Name": "running"}}]}]},
            {"Reservations": [{"Instances": [{"InstanceId": "i-0123456789abcdef0", "State": {"Name": "stopped"}}]}]},
        ]
        mock_ec2.stop_instances.return_value = {
            "StoppingInstances": [{"CurrentState": {"Name": "stopping"}}]
        }
        mock_clients.return_value = {"ec2": mock_ec2}

        res = execute_ec2_instance_action(
            account_id=self.account_id,
            instance_id="i-0123456789abcdef0",
            action="stop",
            confirmed=True,
            user_id=self.user_id,
            organization_id=self.org_id,
            role="admin",
        )
        self.assertEqual(res["status"], "success")
        self.assertEqual(res["current_state"], "stopping")

    # -------------------------------------------------------------------------
    # 2. DIRECT S3 CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.s3_control_service.get_account")
    @patch("app.services.s3_control_service.record_event")
    @patch("app.services.s3_control_service.assume_aws_role")
    def test_direct_s3_control_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account

        with self.assertRaises(S3ControlExecutionError) as cm:
            execute_s3_bucket_action(
                account_id=self.account_id,
                bucket_name="secure-bucket",
                action="enable_block_public_access",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["details"]["reason"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 3. DIRECT VPC / SECURITY GROUP CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.network_control_service.get_account")
    @patch("app.services.network_control_service.record_event")
    @patch("app.services.network_control_service.assume_aws_role")
    def test_direct_vpc_control_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account

        with self.assertRaises(NetworkControlExecutionError) as cm:
            execute_security_group_control(
                account_id=self.account_id,
                group_id="sg-01234567",
                action="revoke_ssh_ingress",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                user_role="admin",
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["details"]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 4. DIRECT RDS CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.rds_control_service.get_account")
    @patch("app.services.rds_control_service.record_event")
    @patch("app.services.rds_control_service.assume_aws_role")
    def test_direct_rds_control_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account

        with self.assertRaises(RDSControlExecutionError) as cm:
            execute_rds_instance_action(
                account_id=self.account_id,
                instance_id="prod-db",
                action="start",
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["details"]["reason"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 5. DIRECT IAM CONTROL ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.iam_control_service.get_account")
    @patch("app.services.iam_control_service.record_event")
    @patch("app.services.iam_control_service.assume_aws_role")
    def test_direct_iam_control_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account

        with self.assertRaises(IAMControlExecutionError) as cm:
            execute_iam_action(
                account_id=self.account_id,
                resource_id="AKIA1234567890ABCDEF",
                resource_type="access_key",
                action="disable_access_key",
                parameters={"user_name": "app-user"},
                confirmed=True,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["metadata"]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 6. REMEDIATION PROPOSAL PATHS: EC2
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.ec2_execution.get_account")
    @patch("app.services.remediation.ec2_execution._record_event")
    @patch("app.services.remediation.ec2_execution.assume_aws_role")
    def test_remediation_ec2_stop_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-ec2-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "action_type": "EC2_STOP_INSTANCE",
            "service": "EC2",
            "resource_type": "EC2_INSTANCE",
            "resource": "i-0123456789abcdef0",
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(EC2StopExecutionError) as cm:
            execute_ec2_stop(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 7. REMEDIATION PROPOSAL PATHS: S3
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.s3_execution.get_account")
    @patch("app.services.remediation.s3_execution._record_event")
    @patch("app.services.remediation.s3_execution.assume_aws_role")
    def test_remediation_s3_bpa_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-s3-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "action_type": "S3_ENABLE_BLOCK_PUBLIC_ACCESS",
            "service": "S3",
            "resource_type": "S3_BUCKET",
            "resource": "cloudguard-test-bucket-2026",
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(S3BlockPublicAccessError) as cm:
            execute_s3_block_public_access(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 8. REMEDIATION PROPOSAL PATHS: VPC
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.vpc_execution.get_account")
    @patch("app.services.remediation.vpc_execution._record_event")
    @patch("app.services.remediation.vpc_execution.assume_aws_role")
    def test_remediation_vpc_ingress_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-vpc-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": "finding-1",
            "action_type": "VPC_REMOVE_INSECURE_INGRESS",
            "service": "VPC",
            "resource_type": "SECURITY_GROUP",
            "resource": "sg-12345678",
            "operation": {
                "security_group_id": "sg-12345678",
                "protocol": "tcp",
                "from_port": 22,
                "to_port": 22,
                "source": "0.0.0.0/0",
                "source_type": "IPV4_CIDR",
                "rule_scope": "INGRESS",
                "execution_mode": "SERVER_SIDE_ONLY",
            },
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(VPCIngressExecutionError) as cm:
            execute_vpc_remove_ssh_ingress(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 9. REMEDIATION PROPOSAL PATHS: RDS
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.rds_execution.get_account")
    @patch("app.services.remediation.rds_execution._record_event")
    @patch("app.services.remediation.rds_execution.assume_aws_role")
    def test_remediation_rds_public_access_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-rds-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": "finding-rds-1",
            "action_type": "RDS_DISABLE_PUBLIC_ACCESS",
            "service": "RDS",
            "resource_type": "RDS_INSTANCE",
            "resource": "prod-db-1",
            "operation": {"db_instance_identifier": "prod-db-1", "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(RDSDisablePublicAccessError) as cm:
            execute_rds_disable_public_access(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 10. REMEDIATION PROPOSAL PATHS: IAM
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.iam_execution.get_account")
    @patch("app.services.remediation.iam_execution._record_event")
    @patch("app.services.remediation.iam_execution.assume_aws_role")
    def test_remediation_iam_disable_key_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-iam-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "action_type": "IAM_DISABLE_ACCESS_KEY",
            "service": "IAM",
            "resource_type": "IAM_ACCESS_KEY",
            "resource": "AKIA1234567890ABCDEF",
            "operation": {"username": "scanner-user", "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(IAMAccessKeyExecutionError) as cm:
            execute_iam_disable_access_key(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 11. REMEDIATION PROPOSAL PATHS: CLOUDTRAIL
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.remediation.cloudtrail_execution.get_account")
    @patch("app.services.remediation.cloudtrail_execution._record_event")
    @patch("app.services.remediation.cloudtrail_execution.assume_aws_role")
    def test_remediation_cloudtrail_enable_logging_blocked_when_disabled(
        self, mock_assume, mock_record_event, mock_get_account, mock_is_enabled
    ):
        mock_get_account.return_value = self.mock_account
        remediation = {
            "_id": "rem-ct-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": "finding-cloudtrail-1",
            "action_type": "CLOUDTRAIL_ENABLE_LOGGING",
            "service": "CLOUDTRAIL",
            "resource_type": "CLOUDTRAIL_TRAIL",
            "resource": "prod-security-trail",
            "operation": {"trail_name": "prod-security-trail", "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": self.user_id,
            "approved_at": "2026-10-08T00:00:00Z",
        }

        with self.assertRaises(CloudTrailEnableLoggingError) as cm:
            execute_cloudtrail_enable_logging(
                remediation=remediation,
                user_id=self.user_id,
                organization_id=self.org_id,
                role="admin",
                confirmed=True,
            )

        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "REMEDIATION_SETTING_DISABLED")
        mock_assume.assert_not_called()
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["error_code"], "REMEDIATION_SETTING_DISABLED")

    # -------------------------------------------------------------------------
    # 12. GENERAL REMEDIATION EXECUTOR ENGINE ENFORCEMENT
    # -------------------------------------------------------------------------

    @patch("app.models.remediation_settings.is_remediation_enabled", return_value=False)
    @patch("app.services.aws_remediation_executor.get_remediation")
    @patch("app.services.aws_remediation_executor.get_account")
    @patch("app.services.aws_remediation_executor.get_finding_for_account")
    @patch("app.services.aws_remediation_executor.validate_remediation")
    @patch("app.services.aws_remediation_executor.assume_aws_role")
    def test_general_executor_engine_blocked_when_disabled(
        self, mock_assume, mock_val, mock_get_finding, mock_get_account, mock_get_rem, mock_is_enabled
    ):
        remediation = {
            "_id": "rem-gen-1",
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_id,
            "status": "APPROVED",
            "finding_id": "find-1",
            "action_type": "DISABLE_PUBLIC_ACCESS",
            "service": "S3",
            "resource": "test-bucket",
        }
        mock_get_rem.return_value = remediation
        mock_get_account.return_value = self.mock_account
        mock_get_finding.return_value = {"_id": "find-1", "status": "OPEN"}

        with self.assertRaises(RemediationSecurityError) as cm:
            execute_approved_remediation(
                remediation_id="rem-gen-1",
                user_id=self.user_id,
            )

        self.assertIn("Remediation setting is disabled for s3", str(cm.exception))
        mock_assume.assert_not_called()

    # -------------------------------------------------------------------------
    # 13. FAIL CLOSED ON MISSING SETTINGS & DB ERRORS
    # -------------------------------------------------------------------------

    def test_fail_closed_with_real_model_when_settings_missing(self):
        """When no remediation_settings document exists in DB, it defaults to False."""
        from app.models.remediation_settings import is_remediation_enabled
        from app.database.connection import db

        db.remediation_settings.delete_many({"account_id": self.account_id})

        for svc in ["ec2", "s3", "vpc", "rds", "iam", "cloudtrail"]:
            self.assertFalse(
                is_remediation_enabled(self.org_id, self.account_id, svc),
                f"Service {svc} must fail closed when settings document is missing",
            )

    @patch("app.models.remediation_settings.remediation_settings_collection.find_one", side_effect=Exception("DB unavailable"))
    def test_fail_closed_on_db_exception(self, mock_find_one):
        """When database throws an unexpected error, is_remediation_enabled returns False."""
        from app.models.remediation_settings import is_remediation_enabled

        self.assertFalse(is_remediation_enabled(self.org_id, self.account_id, "ec2"))
        self.assertFalse(is_remediation_enabled(self.org_id, self.account_id, "s3"))

    def test_fail_closed_on_cross_org_access(self):
        """Cross-organization queries fail closed."""
        from app.models.remediation_settings import is_remediation_enabled
        from app.database.connection import db

        attacker_org = str(ObjectId())
        db.aws_accounts.insert_one(dict(self.mock_account))
        db.remediation_settings.insert_one({
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "services": {"ec2": True, "s3": True, "vpc": True, "rds": True, "iam": True, "cloudtrail": True},
        })
        try:
            self.assertFalse(is_remediation_enabled(attacker_org, self.account_id, "ec2"))
            self.assertFalse(is_remediation_enabled(attacker_org, self.account_id, "s3"))
        finally:
            db.aws_accounts.delete_many({"account_id": self.account_id})
            db.remediation_settings.delete_many({"account_id": self.account_id})


if __name__ == "__main__":
    unittest.main()
