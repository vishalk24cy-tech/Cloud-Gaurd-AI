import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as remediation_api
from app.models import audit_log
from app.services.remediation import iam_execution
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.remediation_models import IAM_DISABLE_ACCESS_KEY_ACTION_ID


class IAMRemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.action_id = IAM_DISABLE_ACCESS_KEY_ACTION_ID
        self.action = get_default_engine().get_action(self.action_id)
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.username = "scanner-user"
        self.key_id = "AKIAABCDEFGHIJKLMNOP"
        self.masked_key_id = "AKIA...MNOP"
        self.remediation = {
            "_id": "remediation-iam-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "action_type": self.action_id,
            "service": "IAM",
            "resource_type": "IAM_ACCESS_KEY",
            "resource": self.key_id,
            "operation": {"username": self.username, "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardIAMRemediation",
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

    def _key_response(self, status, request_id):
        return {
            "AccessKeyMetadata": [{
                "UserName": self.username,
                "AccessKeyId": self.key_id,
                "Status": status,
            }],
            "ResponseMetadata": {"RequestId": request_id},
        }

    def _mock_iam(self, post_status="Inactive"):
        iam = Mock()
        iam.list_access_keys.side_effect = [
            self._key_response("Active", "aws-list-before"),
            self._key_response(post_status, "aws-list-after"),
        ]
        iam.update_access_key.return_value = {
            "ResponseMetadata": {"RequestId": "aws-update-request"},
        }
        return iam

    def _patch_executor(self, iam_client, audit_result=None):
        session = Mock()
        session.client.return_value = iam_client
        return [
            patch.object(iam_execution, "get_account", return_value=self.account),
            patch.object(iam_execution, "assume_aws_role", return_value=session),
            patch.object(iam_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(iam_execution, "transition_to_executing", return_value=True),
            patch.object(iam_execution, "update_execution_result", return_value=True),
            patch.object(iam_execution, "transition_to_completed", return_value=True),
            patch.object(iam_execution, "transition_to_failed", return_value=True),
            patch.object(iam_execution, "record_remediation_event", return_value=audit_result or {"_id": "audit-1"}),
        ]

    def _execute(self, remediation=None, **kwargs):
        values = {
            "remediation": remediation or self.remediation,
            "user_id": "user-1",
            "organization_id": "org-1",
            "role": "owner",
            "confirmed": True,
        }
        values.update(kwargs)
        return iam_execution.execute_iam_disable_access_key(**values)

    def test_successful_disable_and_inactive_verification(self):
        iam = self._mock_iam()
        patches = self._patch_executor(iam)
        with patches[0] as account_lookup, patches[1] as assume, patches[2], patches[3], patches[4] as persist, patches[5], patches[6], patches[7] as audit:
            result = self._execute(request_id="app-request-1")

        assume.assert_called_once()
        account_lookup.assert_called_once_with("account-1", user_id="user-1", organization_id="org-1")
        iam.list_access_keys.assert_has_calls([
            unittest.mock.call(UserName="scanner-user"),
            unittest.mock.call(UserName="scanner-user"),
        ])
        iam.update_access_key.assert_called_once_with(
            UserName="scanner-user",
            AccessKeyId=self.key_id,
            Status="Inactive",
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["verification"]["observed_status"], "Inactive")
        self.assertEqual(result["resource_id"], self.masked_key_id)
        self.assertNotIn(self.key_id, str(result))
        self.assertEqual(persist.call_args.kwargs["after_state"]["resource_id"], self.masked_key_id)
        self.assertEqual(audit.call_count, 2)
        self.assertEqual(audit.call_args_list[0].kwargs["organization_id"], "org-1")
        self.assertEqual(audit.call_args_list[0].kwargs["action_id"], self.action_id)
        self.assertEqual(audit.call_args_list[0].kwargs["resource_id"], self.masked_key_id)
        self.assertEqual(audit.call_args_list[0].kwargs["request_id"], "app-request-1")
        self.assertEqual(audit.call_args_list[0].kwargs["aws_request_id"], "aws-list-before")
        self.assertEqual(audit.call_args_list[1].kwargs["aws_request_id"], "aws-list-after")

    def test_unauthorized_role_and_tenant_mismatch_prevent_assumerole(self):
        with patch.object(iam_execution, "record_remediation_event", return_value={"_id": "audit-denied"}), patch.object(iam_execution, "assume_aws_role") as assume:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute(role="viewer")
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

        with patch.object(iam_execution, "assume_aws_role") as assume:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute(organization_id="org-other")
        self.assertEqual(raised.exception.code, "ORGANIZATION_MISMATCH")
        assume.assert_not_called()

    def test_invalid_action_user_key_approval_and_confirmation_are_rejected(self):
        cases = [
            ({"action_type": "IAM_REMOVE_EXCESSIVE_POLICY"}, True, "ACTION_POLICY_MISMATCH"),
            ({"resource": "not-an-access-key"}, True, "INVALID_ACCESS_KEY_ID"),
            ({"operation": {"username": "bad username"}}, True, "INVALID_IAM_USERNAME"),
            ({"status": "PENDING_APPROVAL", "approved_by": None, "approved_at": None}, True, "APPROVAL_REQUIRED"),
            ({}, False, "CONFIRMATION_REQUIRED"),
        ]
        for changes, confirmed, expected in cases:
            with self.subTest(code=expected), patch.object(iam_execution, "assume_aws_role") as assume:
                with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                    self._execute(remediation={**self.remediation, **changes}, confirmed=confirmed)
                self.assertEqual(raised.exception.code, expected)
                assume.assert_not_called()

    def test_account_identity_mismatch_is_rejected_before_assumerole(self):
        account = {**self.account, "aws_account_id": "999999999999"}
        with patch.object(iam_execution, "get_account", return_value=account), patch.object(iam_execution, "assume_aws_role") as assume:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        assume.assert_not_called()

    def test_sts_identity_mismatch_and_key_ownership_mismatch_block_update(self):
        iam = self._mock_iam()
        patches = self._patch_executor(iam)
        with patches[0], patches[1], patch.object(iam_execution, "verify_aws_account", side_effect=PermissionError("wrong account")), patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        iam.list_access_keys.assert_not_called()
        iam.update_access_key.assert_not_called()

        iam = self._mock_iam()
        iam.list_access_keys.return_value = {"AccessKeyMetadata": [{"UserName": "different-user", "AccessKeyId": self.key_id, "Status": "Active"}]}
        iam.list_access_keys.side_effect = None
        patches = self._patch_executor(iam)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "ACCESS_KEY_OWNERSHIP_NOT_VERIFIED")
        transition.assert_not_called()
        iam.update_access_key.assert_not_called()

    def test_assumerole_failure_is_sanitized_and_audited(self):
        iam = self._mock_iam()
        patches = self._patch_executor(iam)
        patches[1] = patch.object(iam_execution, "assume_aws_role", side_effect=RuntimeError("secret-session-token"))
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7] as audit:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertNotIn("secret-session-token", raised.exception.public_message)
        self.assertEqual(audit.call_args.kwargs["execution_state"], "NOT_STARTED")
        iam.update_access_key.assert_not_called()

    def test_iam_mutation_failure_is_sanitized_and_audited(self):
        iam = self._mock_iam()
        iam.update_access_key.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "secret-session-token"}, "ResponseMetadata": {"RequestId": "aws-denied"}},
            "UpdateAccessKey",
        )
        patches = self._patch_executor(iam)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7] as audit:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("secret-session-token", raised.exception.public_message)
        self.assertEqual(failed.call_count, 1)
        self.assertTrue(any(call.kwargs.get("error_code") == "AccessDenied" for call in audit.call_args_list))

    def test_verification_failure_does_not_mark_completed(self):
        iam = self._mock_iam(post_status="Active")
        patches = self._patch_executor(iam)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7] as audit:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "ACCESS_KEY_VERIFICATION_FAILED")
        completed.assert_not_called()
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("verification_result") == "FAILED" for call in audit.call_args_list))

    def test_start_audit_failure_blocks_update(self):
        iam = self._mock_iam()
        patches = self._patch_executor(iam)
        patches[7] = patch.object(iam_execution, "record_remediation_event", return_value=None)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7]:
            with self.assertRaises(iam_execution.IAMAccessKeyExecutionError) as raised:
                self._execute()
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        iam.update_access_key.assert_not_called()
        failed.assert_called_once()

    def test_api_proposal_approval_execute_and_registry_gate(self):
        membership = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=membership)))
        request = SimpleNamespace(state=SimpleNamespace(request_id="app-request-api"))
        proposed = {**self.remediation, "status": "PROPOSED", "approved_by": None, "approved_at": None}
        approved = dict(self.remediation)
        payload = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id=self.key_id, username=self.username)
        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account", return_value=self.account), patch.object(remediation_api, "get_active_remediation", return_value=None), patch.object(remediation_api, "create_remediation", return_value=proposed) as create, patch.object(remediation_api, "record_remediation_event", return_value={"_id": "audit-1"}):
            proposal = remediation_api.create_remediation_action_proposal(self.action_id, payload, request, self.user)
        self.assertTrue(proposal["created"])
        self.assertNotIn(self.key_id, str(proposal))
        self.assertEqual(create.call_args.args[0]["organization_id"], "org-1")
        self.assertEqual(create.call_args.args[0]["operation"]["username"], self.username)
        self.assertNotIn(self.key_id, str(create.call_args.args[0]["operation"]))

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_remediation", side_effect=[proposed, approved]), patch.object(remediation_api, "get_account", return_value=self.account), patch.object(remediation_api, "update_remediation_status", return_value=True), patch.object(remediation_api, "record_remediation_event", return_value={"_id": "audit-2"}):
            approval = remediation_api.approve_remediation("remediation-iam-1", remediation_api.ApproveRemediationRequest(comment="approved"), request, self.user)
        self.assertNotIn(self.key_id, str(approval))

        result = {"success": True, "status": "COMPLETED", "action_id": self.action_id, "resource_id": self.masked_key_id, "verification": {"verified": True, "observed_status": "Inactive"}}
        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_remediation", return_value=approved), patch.object(remediation_api, "execute_iam_disable_access_key", return_value=result) as execute:
            response = remediation_api.execute_remediation("remediation-iam-1", request, remediation_api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(response["status"], "success")
        self.assertEqual(execute.call_args.kwargs["request_id"], "app-request-api")

        other = {**approved, "action_type": "IAM_REMOVE_EXCESSIVE_POLICY"}
        with patch.object(remediation_api, "get_remediation", return_value=other), patch.object(remediation_api, "execute_iam_disable_access_key") as execute:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.execute_remediation("remediation-iam-1", request, remediation_api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_proposal_api_rejects_bad_role_action_key_user_and_account_tenant(self):
        owner = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        owner_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=owner)))
        viewer_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value={**owner, "role": "viewer"})))
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-test"))
        good = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id=self.key_id, username=self.username)

        with patch.object(remediation_api, "db", owner_db):
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal("NOT_REGISTERED", good, request, self.user)
        self.assertEqual(raised.exception.status_code, 404)

        with patch.object(remediation_api, "db", viewer_db), patch.object(remediation_api, "get_account") as get_account:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(self.action_id, good, request, self.user)
        self.assertEqual(raised.exception.status_code, 403)
        get_account.assert_not_called()

        bad_key = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="not-a-key", username=self.username)
        with patch.object(remediation_api, "db", owner_db), patch.object(remediation_api, "get_account") as get_account:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(self.action_id, bad_key, request, self.user)
        self.assertEqual(raised.exception.status_code, 400)
        get_account.assert_not_called()

        bad_user = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id=self.key_id, username="bad username")
        with patch.object(remediation_api, "db", owner_db), patch.object(remediation_api, "get_account") as get_account:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(self.action_id, bad_user, request, self.user)
        self.assertEqual(raised.exception.status_code, 400)
        get_account.assert_not_called()

        with patch.object(remediation_api, "db", owner_db), patch.object(remediation_api, "get_account", return_value=None) as get_account:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(self.action_id, good, request, self.user)
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(get_account.call_args.kwargs["organization_id"], "org-1")

    def test_audit_model_does_not_store_full_key_identifier_or_credentials(self):
        captured = {}
        def insert(document):
            captured.update(document)
            return Mock(inserted_id="audit-id")
        with patch.object(audit_log.audit_logs_collection, "insert_one", side_effect=insert):
            audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id=self.action_id,
                event_type=audit_log.EVENT_REMEDIATION_COMPLETED,
                action="IAM access key disabled",
                resource_id=self.masked_key_id,
                service="IAM",
                resource_type="IAM_ACCESS_KEY",
                metadata={"aws_request_id": "aws-request-1", "secret_access_key": "never-store", "session_token": "never-store"},
            )
        self.assertNotIn(self.key_id, str(captured))
        self.assertNotIn("secret_access_key", captured["metadata"])
        self.assertNotIn("session_token", captured["metadata"])
        self.assertEqual(captured["resource_id"], self.masked_key_id)


if __name__ == "__main__":
    unittest.main()
