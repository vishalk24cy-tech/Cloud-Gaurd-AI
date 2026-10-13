import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as api
from app.models import audit_log
from app.services.remediation import rds_execution
from app.services.remediation.remediation_models import RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID


class RDSRemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.action_id = RDS_DISABLE_PUBLIC_ACCESS_ACTION_ID
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.identifier = "prod-db-1"
        self.remediation = {
            "_id": "rem-rds-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "finding_id": "finding-rds-1",
            "action_type": self.action_id,
            "service": "RDS",
            "resource_type": "RDS_INSTANCE",
            "resource": self.identifier,
            "operation": {"db_instance_identifier": self.identifier, "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardRDSRemediation",
            "region": "ap-south-1",
            "status": "connected",
        }
        self._remediation_settings_patcher = patch(
            "app.models.remediation_settings.is_remediation_enabled",
            return_value=True,
        )
        self._remediation_settings_patcher.start()

    def tearDown(self):
        self._remediation_settings_patcher.stop()

    def _db_instance(self, publicly_accessible=True, account_id="123456789012", region="ap-south-1"):
        return {
            "DBInstanceIdentifier": self.identifier,
            "DBInstanceArn": f"arn:aws:rds:{region}:{account_id}:db:{self.identifier}",
            "PubliclyAccessible": publicly_accessible,
            "DBInstanceStatus": "available",
        }

    def _mock_rds(self, verified_public=False):
        rds = Mock()
        rds.describe_db_instances.side_effect = [
            {"DBInstances": [self._db_instance(True)], "ResponseMetadata": {"RequestId": "aws-rds-before"}},
            {"DBInstances": [self._db_instance(verified_public)], "ResponseMetadata": {"RequestId": "aws-rds-after"}},
        ]
        rds.modify_db_instance.return_value = {"ResponseMetadata": {"RequestId": "aws-rds-modify"}}
        rds.get_waiter.return_value.wait.return_value = None
        return rds

    def _patches(self, rds, audit=True):
        session = Mock()
        session.client.return_value = rds
        return [
            patch.object(rds_execution, "get_account", return_value=self.account),
            patch.object(rds_execution, "assume_aws_role", return_value=session),
            patch.object(rds_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(rds_execution, "transition_to_executing", return_value=True),
            patch.object(rds_execution, "update_execution_result", return_value=True),
            patch.object(rds_execution, "transition_to_completed", return_value=True),
            patch.object(rds_execution, "transition_to_failed", return_value=True),
            patch.object(rds_execution, "record_remediation_event", return_value={"_id": "audit"} if audit else None),
        ]

    def _execute(self, remediation=None, **kwargs):
        params = {"remediation": remediation or self.remediation, "user_id": "user-1", "organization_id": "org-1", "role": "owner", "confirmed": True}
        params.update(kwargs)
        return rds_execution.execute_rds_disable_public_access(**params)

    def test_success_disables_and_verifies_public_access(self):
        rds = self._mock_rds(False)
        patches = self._patches(rds)
        with patches[0] as account_lookup, patches[1] as assume, patches[2], patches[3], patches[4] as persist, patches[5], patches[6], patches[7] as audit:
            result = self._execute(request_id="app-rds-request")
        assume.assert_called_once()
        account_lookup.assert_called_once_with("account-1", user_id="user-1", organization_id="org-1")
        rds.modify_db_instance.assert_called_once_with(
            DBInstanceIdentifier=self.identifier,
            PubliclyAccessible=False,
            ApplyImmediately=True,
        )
        rds.get_waiter.assert_called_once_with("db_instance_available")
        self.assertEqual(rds.describe_db_instances.call_count, 2)
        self.assertTrue(result["verification"]["verified"])
        self.assertFalse(result["verification"]["observed_publicly_accessible"])
        self.assertEqual(audit.call_count, 2)
        self.assertEqual(audit.call_args_list[0].kwargs["aws_request_id"], "aws-rds-before")
        self.assertEqual(audit.call_args_list[1].kwargs["aws_request_id"], "aws-rds-after")
        self.assertEqual(audit.call_args_list[0].kwargs["request_id"], "app-rds-request")
        self.assertEqual(persist.call_args.kwargs["verification"]["expected_publicly_accessible"], False)

    def test_role_tenant_account_approval_confirmation_and_identifier_validation(self):
        with patch.object(rds_execution, "record_remediation_event", return_value={"_id": "audit"}), patch.object(rds_execution, "assume_aws_role") as assume:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute(role="viewer")
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

        for remediation, kwargs, expected in (
            (self.remediation, {"organization_id": "org-other"}, "ORGANIZATION_MISMATCH"),
            ({**self.remediation, "status": "PENDING_APPROVAL", "approved_by": None, "approved_at": None}, {}, "APPROVAL_REQUIRED"),
            (self.remediation, {"confirmed": False}, "CONFIRMATION_REQUIRED"),
            ({**self.remediation, "resource": "bad--identifier"}, {}, "INVALID_RDS_IDENTIFIER"),
            ({**self.remediation, "status": "APPROVED"}, {}, "RDS_NOT_PUBLIC"),
        ):
            with self.subTest(expected=expected):
                if expected == "RDS_NOT_PUBLIC":
                    rds = self._mock_rds(verified_public=False)
                    rds.describe_db_instances.side_effect = None
                    rds.describe_db_instances.return_value = {"DBInstances": [self._db_instance(False)]}
                    patches = self._patches(rds)
                    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
                        with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                            self._execute(remediation=remediation, **kwargs)
                else:
                    with patch.object(rds_execution, "assume_aws_role") as assume:
                        with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                            self._execute(remediation=remediation, **kwargs)
                    assume.assert_not_called()
                self.assertEqual(raised.exception.code, expected)

    def test_aws_account_arn_and_assumed_account_mismatches(self):
        remediation = {**self.remediation, "aws_account_id": "999999999999"}
        with patch.object(rds_execution, "get_account", return_value=self.account), patch.object(rds_execution, "assume_aws_role") as assume:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute(remediation=remediation)
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        assume.assert_not_called()

        rds = self._mock_rds()
        rds.describe_db_instances.side_effect = None
        rds.describe_db_instances.return_value = {"DBInstances": [self._db_instance(account_id="999999999999")]}
        patches = self._patches(rds)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "RDS_ACCOUNT_MISMATCH")
        transition.assert_not_called()
        rds.modify_db_instance.assert_not_called()

        rds = self._mock_rds()
        patches = self._patches(rds)
        patches[2] = patch.object(rds_execution, "verify_aws_account", side_effect=PermissionError("wrong account"))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        rds.describe_db_instances.assert_not_called()

    def test_mutation_failure_verification_failure_and_audit_failure(self):
        rds = self._mock_rds()
        rds.modify_db_instance.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "secret"}}, "ModifyDBInstance")
        patches = self._patches(rds)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7] as audit:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute()
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("secret", raised.exception.public_message)
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("error_code") == "AccessDenied" for call in audit.call_args_list))

        rds = self._mock_rds(True)
        patches = self._patches(rds)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7]:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "RDS_PUBLIC_ACCESS_VERIFICATION_FAILED")
        completed.assert_not_called()
        failed.assert_called_once()

        rds = self._mock_rds()
        patches = self._patches(rds, audit=False)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(rds_execution.RDSDisablePublicAccessError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        rds.modify_db_instance.assert_not_called()

    def test_proposal_approval_execution_api_and_registry_gating(self):
        finding = {"finding_id": "finding-rds-1", "service": "RDS", "resource_type": "RDS Database", "resource": self.identifier, "issue": "RDS database is publicly accessible.", "status": "OPEN"}
        account = {"_id": "account-1", "aws_account_id": "123456789012", "status": "connected"}
        member = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=member)))
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-api-rds"))
        payload = api.CreateRemediationActionRequest(account_id="account-1", finding_id="finding-rds-1")
        proposed = {**self.remediation, "status": "PROPOSED"}
        approved = dict(self.remediation)

        with patch.object(api, "db", fake_db), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "get_active_remediation", return_value=None), patch.object(api, "create_remediation", return_value=proposed) as create, patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            proposal = api.create_remediation_action_proposal(self.action_id, payload, request, self.user)
        self.assertTrue(proposal["created"])
        self.assertEqual(create.call_args.args[0]["resource"], self.identifier)
        self.assertEqual(create.call_args.args[0]["operation"]["db_instance_identifier"], self.identifier)

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", side_effect=[proposed, approved]), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "update_remediation_status", return_value=True), patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            approval = api.approve_remediation("rem-rds-1", api.ApproveRemediationRequest(), request, self.user)
        self.assertEqual(approval["remediation"]["status"], "APPROVED")

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", return_value=approved), patch.object(api, "execute_rds_disable_public_access", return_value={"success": True, "status": "COMPLETED", "verification": {"verified": True}}) as execute:
            response = api.execute_remediation("rem-rds-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(response["status"], "success")
        self.assertEqual(execute.call_args.kwargs["request_id"], "request-api-rds")

        other = {**approved, "action_type": "RDS_ENABLE_ENCRYPTION"}
        with patch.object(api, "get_remediation", return_value=other), patch.object(api, "execute_rds_disable_public_access") as execute:
            with self.assertRaises(HTTPException) as raised:
                api.execute_remediation("rem-rds-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_audit_contains_target_context_and_filters_credentials(self):
        captured = {}
        def insert(document):
            captured.update(document)
            return Mock(inserted_id="audit-rds")
        with patch.object(audit_log.audit_logs_collection, "insert_one", side_effect=insert):
            audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id=self.action_id,
                event_type=audit_log.EVENT_REMEDIATION_COMPLETED,
                action="RDS public accessibility disabled",
                resource_id=self.identifier,
                service="RDS",
                resource_type="RDS_INSTANCE",
                metadata={"verified": True, "secret_access_key": "never-store", "session_token": "never-store"},
            )
        self.assertEqual(captured["organization_id"], "org-1")
        self.assertEqual(captured["action_id"], self.action_id)
        self.assertEqual(captured["resource_id"], self.identifier)
        self.assertNotIn("secret_access_key", captured["metadata"])
        self.assertNotIn("session_token", captured["metadata"])


if __name__ == "__main__":
    unittest.main()
