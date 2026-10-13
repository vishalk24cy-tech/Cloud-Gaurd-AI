import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as remediation_api
from app.models import audit_log
from app.services.remediation import s3_execution
from app.services.remediation.remediation_engine import get_default_engine
from app.services.remediation.remediation_models import S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID


class S3RemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.action_id = S3_ENABLE_BLOCK_PUBLIC_ACCESS_ACTION_ID
        self.action = get_default_engine().get_action(self.action_id)
        self.remediation = {
            "_id": "remediation-s3-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "action_type": self.action_id,
            "service": "S3",
            "resource_type": "S3_BUCKET",
            "resource": "cloudguard-test-bucket-2026",
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardS3Remediation",
            "region": "ap-south-1",
            "status": "connected",
        }
        self.enabled_configuration = dict(s3_execution.PUBLIC_ACCESS_BLOCK_CONFIGURATION)
        self._remediation_settings_patcher = patch(
            "app.models.remediation_settings.is_remediation_enabled",
            return_value=True,
        )
        self._remediation_settings_patcher.start()

    def tearDown(self):
        self._remediation_settings_patcher.stop()

    def _mock_s3(self, final_configuration=None):
        client = Mock()
        client.get_bucket_location.return_value = {
            "LocationConstraint": "ap-south-1",
            "ResponseMetadata": {"RequestId": "aws-location-request"},
        }
        if final_configuration is None:
            final_configuration = self.enabled_configuration
        client.get_public_access_block.side_effect = [
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
                "ResponseMetadata": {"RequestId": "aws-read-before"},
            },
            {
                "PublicAccessBlockConfiguration": final_configuration,
                "ResponseMetadata": {"RequestId": "aws-read-after"},
            },
        ]
        client.put_public_access_block.return_value = {
            "ResponseMetadata": {"RequestId": "aws-put-request"},
        }
        return client

    def _patch_executor(self, client, audit_return=None):
        session = Mock()
        session.client.return_value = client
        return [
            patch.object(s3_execution, "get_account", return_value=self.account),
            patch.object(s3_execution, "assume_aws_role", return_value=session),
            patch.object(s3_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(s3_execution, "transition_to_executing", return_value=True),
            patch.object(s3_execution, "update_execution_result", return_value=True),
            patch.object(s3_execution, "transition_to_completed", return_value=True),
            patch.object(s3_execution, "transition_to_failed", return_value=True),
            patch.object(s3_execution, "record_remediation_event", return_value=audit_return or {"_id": "audit-1"}),
        ]

    def test_successful_execution_sets_and_verifies_all_public_access_flags(self):
        s3 = self._mock_s3()
        patches = self._patch_executor(s3)
        with patches[0] as account_lookup, patches[1] as assume, patches[2], patches[3], patches[4], patches[5], patches[6], patches[7] as audit:
            result = s3_execution.execute_s3_block_public_access(
                remediation=self.remediation,
                user_id="user-1",
                organization_id="org-1",
                role="owner",
                confirmed=True,
                request_id="app-request-1",
            )
        assume.assert_called_once()
        account_lookup.assert_called_once_with(
            "account-1", user_id="user-1", organization_id="org-1"
        )
        self.assertEqual(result["status"], "COMPLETED")
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(result["verification"]["observed_configuration"], self.enabled_configuration)
        s3.get_bucket_location.assert_called_once_with(
            Bucket="cloudguard-test-bucket-2026",
            ExpectedBucketOwner="123456789012",
        )
        s3.put_public_access_block.assert_called_once_with(
            Bucket="cloudguard-test-bucket-2026",
            ExpectedBucketOwner="123456789012",
            PublicAccessBlockConfiguration=self.enabled_configuration,
        )
        self.assertEqual(s3.get_public_access_block.call_count, 2)
        self.assertEqual(audit.call_count, 2)
        self.assertTrue(all(call.kwargs["request_id"] == "app-request-1" for call in audit.call_args_list))
        self.assertEqual(audit.call_args_list[0].kwargs["aws_request_id"], "aws-read-before")
        self.assertEqual(audit.call_args_list[1].kwargs["aws_request_id"], "aws-read-after")
        self.assertEqual(audit.call_args_list[0].kwargs["organization_id"], "org-1")
        self.assertEqual(audit.call_args_list[0].kwargs["action_id"], self.action_id)
        self.assertFalse({"access_key_id", "secret_access_key", "session_token"} & set(result))

    def test_owner_admin_role_and_tenant_are_required_before_assumerole(self):
        with patch.object(s3_execution, "record_remediation_event", return_value={"_id": "audit-1"}), patch.object(s3_execution, "assume_aws_role") as assume:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="viewer",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

        with patch.object(s3_execution, "assume_aws_role") as assume:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-other",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "ORGANIZATION_MISMATCH")
        assume.assert_not_called()

    def test_invalid_action_bucket_approval_and_confirmation_are_rejected(self):
        for changes, confirmed, expected_code in (
            ({"action_type": "S3_ENABLE_ENCRYPTION"}, True, "ACTION_POLICY_MISMATCH"),
            ({"resource": "BadBucket"}, True, "INVALID_BUCKET_NAME"),
            ({"status": "PENDING_APPROVAL", "approved_by": None, "approved_at": None}, True, "APPROVAL_REQUIRED"),
            ({}, False, "CONFIRMATION_REQUIRED"),
        ):
            with self.subTest(code=expected_code), patch.object(s3_execution, "assume_aws_role") as assume:
                with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                    s3_execution.execute_s3_block_public_access(
                        remediation={**self.remediation, **changes},
                        user_id="user-1",
                        organization_id="org-1",
                        role="owner",
                        confirmed=confirmed,
                    )
                self.assertEqual(raised.exception.code, expected_code)
                assume.assert_not_called()

    def test_account_identity_mismatch_is_rejected_before_assumerole(self):
        account = {**self.account, "aws_account_id": "999999999999"}
        with patch.object(s3_execution, "get_account", return_value=account), patch.object(s3_execution, "assume_aws_role") as assume:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        assume.assert_not_called()

    def test_wrong_assumed_account_and_bucket_owner_are_rejected(self):
        s3 = self._mock_s3()
        patches = self._patch_executor(s3)
        with patches[0], patches[1], patch.object(s3_execution, "verify_aws_account", side_effect=PermissionError("wrong account")), patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.category, "ACCOUNT_VALIDATION")
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        s3.get_bucket_location.assert_not_called()

        s3 = self._mock_s3()
        s3.get_bucket_location.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "private"}, "ResponseMetadata": {"RequestId": "aws-denied"}},
            "GetBucketLocation",
        )
        patches = self._patch_executor(s3)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "AccessDenied")
        self.assertEqual(raised.exception.status_code, 403)
        transition.assert_not_called()
        s3.put_public_access_block.assert_not_called()

    def test_aws_mutation_failure_is_sanitized_and_audited(self):
        s3 = self._mock_s3()
        s3.put_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "secret-session-token"}, "ResponseMetadata": {"RequestId": "aws-mutation-denied"}},
            "PutPublicAccessBlock",
        )
        patches = self._patch_executor(s3)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7] as audit:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                    request_id="app-request-fail",
                )
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("secret-session-token", raised.exception.public_message)
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("aws_request_id") == "aws-mutation-denied" for call in audit.call_args_list))

    def test_verification_failure_does_not_mark_completed(self):
        disabled = {flag: False for flag in self.enabled_configuration}
        s3 = self._mock_s3(final_configuration=disabled)
        patches = self._patch_executor(s3)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7] as audit:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "PUBLIC_ACCESS_VERIFICATION_FAILED")
        s3.put_public_access_block.assert_called_once()
        completed.assert_not_called()
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("verification_result") == "FAILED" for call in audit.call_args_list))

    def test_execution_start_audit_failure_blocks_mutation(self):
        s3 = self._mock_s3()
        patches = self._patch_executor(s3, audit_return=None)
        patches[7] = patch.object(s3_execution, "record_remediation_event", return_value=None)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7]:
            with self.assertRaises(s3_execution.S3BlockPublicAccessError) as raised:
                s3_execution.execute_s3_block_public_access(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        s3.put_public_access_block.assert_not_called()
        failed.assert_called_once()

    def test_shared_api_proposal_approval_execution_and_registry_gate(self):
        membership = {
            "organization_id": "org-1",
            "user_id": "user-1",
            "status": "active",
            "role": "owner",
        }
        fake_db = SimpleNamespace(
            organization_members=SimpleNamespace(find_one=Mock(return_value=membership))
        )
        request = SimpleNamespace(state=SimpleNamespace(request_id="app-request-api"))
        account = dict(self.account)
        proposed = {**self.remediation, "status": "PROPOSED", "approved_by": None, "approved_at": None}
        approved = {**self.remediation}
        payload = remediation_api.CreateRemediationActionRequest(
            account_id="account-1",
            resource_id="cloudguard-test-bucket-2026",
        )

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account", return_value=account), patch.object(remediation_api, "get_active_remediation", return_value=None), patch.object(remediation_api, "create_remediation", return_value=proposed) as create, patch.object(remediation_api, "record_remediation_event", return_value={"_id": "audit-1"}):
            proposal_response = remediation_api.create_remediation_action_proposal(
                self.action_id,
                payload,
                request,
                self.user,
            )
        self.assertTrue(proposal_response["created"])
        data = create.call_args.args[0]
        self.assertEqual(data["organization_id"], "org-1")
        self.assertEqual(data["aws_account_id"], "123456789012")
        self.assertEqual(data["action_type"], self.action_id)

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_remediation", side_effect=[proposed, approved]), patch.object(remediation_api, "get_account", return_value=account), patch.object(remediation_api, "update_remediation_status", return_value=True), patch.object(remediation_api, "record_remediation_event", return_value={"_id": "audit-2"}):
            approval_response = remediation_api.approve_remediation(
                "remediation-s3-1",
                remediation_api.ApproveRemediationRequest(comment="Approved"),
                request,
                self.user,
            )
        self.assertEqual(approval_response["remediation"]["status"], "APPROVED")

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_remediation", return_value=approved), patch.object(remediation_api, "execute_s3_block_public_access", return_value={"success": True, "status": "COMPLETED", "verification": {"verified": True}}) as execute:
            execution_response = remediation_api.execute_remediation(
                "remediation-s3-1",
                request,
                remediation_api.ExecuteRemediationRequest(confirmed=True),
                self.user,
            )
        self.assertEqual(execution_response["status"], "success")
        self.assertTrue(execution_response["remediation"]["verification"]["verified"])
        self.assertEqual(execute.call_args.kwargs["request_id"], "app-request-api")

        other_action = {**approved, "action_type": "EC2_START_INSTANCE"}
        with patch.object(remediation_api, "get_remediation", return_value=other_action), patch.object(remediation_api, "execute_s3_block_public_access") as execute:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.execute_remediation(
                    "remediation-s3-1",
                    request,
                    remediation_api.ExecuteRemediationRequest(confirmed=True),
                    self.user,
                )
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_api_rejects_unauthorized_invalid_bucket_and_wrong_tenant_account(self):
        owner_membership = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_owner_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=owner_membership)))
        viewer_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value={**owner_membership, "role": "viewer"})))
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-test"))
        payload = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="cloudguard-test-bucket-2026")

        with patch.object(remediation_api, "db", fake_owner_db):
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "NOT_REGISTERED", payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 404)

        with patch.object(remediation_api, "db", viewer_db), patch.object(remediation_api, "get_account") as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    self.action_id, payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 403)
        account_lookup.assert_not_called()

        invalid_payload = remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="BadBucket")
        with patch.object(remediation_api, "db", fake_owner_db), patch.object(remediation_api, "get_account") as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    self.action_id, invalid_payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 400)
        account_lookup.assert_not_called()

        with patch.object(remediation_api, "db", fake_owner_db), patch.object(remediation_api, "get_account", return_value=None) as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    self.action_id, payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(account_lookup.call_args.kwargs["organization_id"], "org-1")

    def test_audit_model_secret_filtering_keeps_safe_aws_request_id(self):
        inserted_id = "audit-id"
        with patch.object(
            audit_log.audit_logs_collection,
            "insert_one",
            return_value=Mock(inserted_id=inserted_id),
        ):
            event = audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id=self.action_id,
                event_type=audit_log.EVENT_REMEDIATION_COMPLETED,
                action="S3 Block Public Access completed",
                service="S3",
                resource_type="S3_BUCKET",
                resource_id="cloudguard-test-bucket-2026",
                metadata={
                    "aws_secret_access_key": "do-not-store",
                    "aws_session_token": "do-not-store",
                    "aws_request_id": "aws-request-safe",
                },
            )
        self.assertEqual(event["organization_id"], "org-1")
        self.assertEqual(event["action_id"], self.action_id)
        self.assertNotIn("aws_secret_access_key", event["metadata"])
        self.assertNotIn("aws_session_token", event["metadata"])
        self.assertEqual(event["metadata"]["aws_request_id"], "aws-request-safe")


if __name__ == "__main__":
    unittest.main()
