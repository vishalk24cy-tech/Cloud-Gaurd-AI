import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as api
from app.models import audit_log
from app.services.remediation import cloudtrail_execution
from app.services.remediation.remediation_models import CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID


class CloudTrailRemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.action_id = CLOUDTRAIL_ENABLE_LOGGING_ACTION_ID
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.trail_name = "prod-security-trail"
        self.trail_arn = "arn:aws:cloudtrail:ap-south-1:123456789012:trail/prod-security-trail"
        self.remediation = {
            "_id": "rem-cloudtrail-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "finding_id": "finding-cloudtrail-1",
            "action_type": self.action_id,
            "service": "CLOUDTRAIL",
            "resource_type": "CLOUDTRAIL_TRAIL",
            "resource": self.trail_name,
            "operation": {"trail_name": self.trail_name, "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardTrailRemediation",
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

    def _trail_description(self, trail_arn=None, home_region="ap-south-1"):
        return {
            "trailList": [{
                "Name": self.trail_name,
                "TrailARN": trail_arn or self.trail_arn,
                "HomeRegion": home_region,
            }],
            "ResponseMetadata": {"RequestId": "aws-describe-trail"},
        }

    def _mock_cloudtrail(self, final_logging=True, trail_arn=None):
        cloudtrail = Mock()
        cloudtrail.describe_trails.return_value = self._trail_description(trail_arn=trail_arn)
        cloudtrail.get_trail_status.side_effect = [
            {"IsLogging": False, "ResponseMetadata": {"RequestId": "aws-status-before"}},
            {"IsLogging": final_logging, "ResponseMetadata": {"RequestId": "aws-status-after"}},
        ]
        cloudtrail.start_logging.return_value = {"ResponseMetadata": {"RequestId": "aws-start-request"}}
        return cloudtrail

    def _patches(self, cloudtrail, audit=True):
        session = Mock()
        session.client.return_value = cloudtrail
        return [
            patch.object(cloudtrail_execution, "get_account", return_value=self.account),
            patch.object(cloudtrail_execution, "assume_aws_role", return_value=session),
            patch.object(cloudtrail_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(cloudtrail_execution, "transition_to_executing", return_value=True),
            patch.object(cloudtrail_execution, "update_execution_result", return_value=True),
            patch.object(cloudtrail_execution, "transition_to_completed", return_value=True),
            patch.object(cloudtrail_execution, "transition_to_failed", return_value=True),
            patch.object(cloudtrail_execution, "record_remediation_event", return_value={"_id": "audit"} if audit else None),
        ]

    def _execute(self, remediation=None, **kwargs):
        values = {"remediation": remediation or self.remediation, "user_id": "user-1", "organization_id": "org-1", "role": "owner", "confirmed": True}
        values.update(kwargs)
        return cloudtrail_execution.execute_cloudtrail_enable_logging(**values)

    def test_success_starts_existing_trail_and_verifies_logging(self):
        cloudtrail = self._mock_cloudtrail()
        patches = self._patches(cloudtrail)
        with patches[0] as account_lookup, patches[1] as assume, patches[2], patches[3], patches[4] as persist, patches[5], patches[6], patches[7] as audit:
            result = self._execute(request_id="app-cloudtrail-request")
        assume.assert_called_once()
        account_lookup.assert_called_once_with("account-1", user_id="user-1", organization_id="org-1")
        cloudtrail.describe_trails.assert_called_once_with(trailNameList=[self.trail_name], includeShadowTrails=False)
        cloudtrail.start_logging.assert_called_once_with(Name=self.trail_arn)
        cloudtrail.get_trail_status.assert_has_calls([
            unittest.mock.call(Name=self.trail_arn),
            unittest.mock.call(Name=self.trail_arn),
        ])
        self.assertTrue(result["verification"]["verified"])
        self.assertTrue(result["verification"]["observed_is_logging"])
        self.assertEqual(persist.call_args.kwargs["verification"]["verified"], True)
        self.assertEqual(audit.call_count, 2)
        self.assertEqual(audit.call_args_list[0].kwargs["action_id"], self.action_id)
        self.assertEqual(audit.call_args_list[0].kwargs["request_id"], "app-cloudtrail-request")
        self.assertEqual(audit.call_args_list[0].kwargs["aws_request_id"], "aws-status-before")
        self.assertEqual(audit.call_args_list[1].kwargs["aws_request_id"], "aws-status-after")

    def test_role_tenant_approval_confirmation_and_invalid_trail_are_rejected(self):
        with patch.object(cloudtrail_execution, "record_remediation_event", return_value={"_id": "audit"}), patch.object(cloudtrail_execution, "assume_aws_role") as assume:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute(role="viewer")
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

        cases = [
            ({}, {"organization_id": "org-other"}, "ORGANIZATION_MISMATCH"),
            ({"status": "PENDING_APPROVAL", "approved_by": None, "approved_at": None}, {}, "APPROVAL_REQUIRED"),
            ({}, {"confirmed": False}, "CONFIRMATION_REQUIRED"),
            ({"resource": "bad trail"}, {}, "INVALID_TRAIL_NAME"),
        ]
        for changes, kwargs, expected in cases:
            with self.subTest(code=expected), patch.object(cloudtrail_execution, "assume_aws_role") as assume:
                with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                    self._execute(remediation={**self.remediation, **changes}, **kwargs)
                self.assertEqual(raised.exception.code, expected)
                assume.assert_not_called()

    def test_account_arn_and_assumed_account_mismatches_are_rejected(self):
        with patch.object(cloudtrail_execution, "get_account", return_value=self.account), patch.object(cloudtrail_execution, "assume_aws_role") as assume:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute(remediation={**self.remediation, "aws_account_id": "999999999999"})
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        assume.assert_not_called()

        cloudtrail = self._mock_cloudtrail(trail_arn="arn:aws:cloudtrail:ap-south-1:999999999999:trail/prod-security-trail")
        patches = self._patches(cloudtrail)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "TRAIL_ACCOUNT_MISMATCH")
        transition.assert_not_called()
        cloudtrail.start_logging.assert_not_called()

        cloudtrail = self._mock_cloudtrail()
        patches = self._patches(cloudtrail)
        patches[2] = patch.object(cloudtrail_execution, "verify_aws_account", side_effect=PermissionError("wrong account"))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        cloudtrail.describe_trails.assert_not_called()

    def test_disabled_state_mutation_failure_verification_failure_and_audit_failure(self):
        cloudtrail = self._mock_cloudtrail()
        cloudtrail.start_logging.side_effect = ClientError({"Error": {"Code": "AccessDenied", "Message": "secret"}}, "StartLogging")
        patches = self._patches(cloudtrail)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7] as audit:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute()
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("secret", raised.exception.public_message)
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("error_code") == "AccessDenied" for call in audit.call_args_list))

        cloudtrail = self._mock_cloudtrail(final_logging=False)
        patches = self._patches(cloudtrail)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7]:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "TRAIL_LOGGING_VERIFICATION_FAILED")
        completed.assert_not_called()
        failed.assert_called_once()

        cloudtrail = self._mock_cloudtrail()
        patches = self._patches(cloudtrail, audit=False)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(cloudtrail_execution.CloudTrailEnableLoggingError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        cloudtrail.start_logging.assert_not_called()

    def test_proposal_approval_execute_api_and_registry_gating(self):
        finding = {"finding_id": "finding-cloudtrail-1", "service": "CloudTrail", "resource_type": "CloudTrail", "resource": self.trail_name, "issue": f"CloudTrail logging is disabled ({self.trail_name}).", "status": "OPEN"}
        account = {"_id": "account-1", "aws_account_id": "123456789012", "status": "connected"}
        membership = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=membership)))
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-api-cloudtrail"))
        payload = api.CreateRemediationActionRequest(account_id="account-1", finding_id="finding-cloudtrail-1")
        proposed = {**self.remediation, "status": "PROPOSED"}
        approved = dict(self.remediation)

        with patch.object(api, "db", fake_db), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "get_active_remediation", return_value=None), patch.object(api, "create_remediation", return_value=proposed) as create, patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            proposal = api.create_remediation_action_proposal(self.action_id, payload, request, self.user)
        self.assertTrue(proposal["created"])
        self.assertEqual(create.call_args.args[0]["resource"], self.trail_name)
        self.assertEqual(create.call_args.args[0]["operation"]["trail_name"], self.trail_name)

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", side_effect=[proposed, approved]), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "update_remediation_status", return_value=True), patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            approval = api.approve_remediation("rem-cloudtrail-1", api.ApproveRemediationRequest(), request, self.user)
        self.assertEqual(approval["remediation"]["status"], "APPROVED")

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", return_value=approved), patch.object(api, "execute_cloudtrail_enable_logging", return_value={"success": True, "status": "COMPLETED", "verification": {"verified": True}}) as execute:
            response = api.execute_remediation("rem-cloudtrail-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(response["status"], "success")
        self.assertEqual(execute.call_args.kwargs["request_id"], "request-api-cloudtrail")

        other = {**approved, "action_type": "KMS_UPDATE_KEY_POLICY"}
        with patch.object(api, "get_remediation", return_value=other), patch.object(api, "execute_cloudtrail_enable_logging") as execute:
            with self.assertRaises(HTTPException) as raised:
                api.execute_remediation("rem-cloudtrail-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_audit_contains_trail_and_filters_credentials(self):
        captured = {}
        def insert(document):
            captured.update(document)
            return Mock(inserted_id="audit-cloudtrail")
        with patch.object(audit_log.audit_logs_collection, "insert_one", side_effect=insert):
            audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id=self.action_id,
                event_type=audit_log.EVENT_REMEDIATION_COMPLETED,
                action="CloudTrail logging enabled",
                resource_id=self.trail_name,
                service="CLOUDTRAIL",
                resource_type="CLOUDTRAIL_TRAIL",
                metadata={"aws_request_id": "aws-request-1", "secret_access_key": "never-store", "session_token": "never-store"},
            )
        self.assertEqual(captured["organization_id"], "org-1")
        self.assertEqual(captured["action_id"], self.action_id)
        self.assertEqual(captured["resource_id"], self.trail_name)
        self.assertNotIn("secret_access_key", captured["metadata"])
        self.assertNotIn("session_token", captured["metadata"])


if __name__ == "__main__":
    unittest.main()
