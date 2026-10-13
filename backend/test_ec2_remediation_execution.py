import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from bson import ObjectId
from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as remediation_api
from app.models import audit_log
from app.models import remediation as remediation_model
from app.services.remediation import ec2_execution
from app.services.remediation.remediation_engine import get_default_engine


class EC2RemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.action = get_default_engine().get_action("EC2_STOP_INSTANCE")
        self.remediation = {
            "_id": "remediation-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "action_type": "EC2_STOP_INSTANCE",
            "service": "EC2",
            "resource_type": "EC2_INSTANCE",
            "resource": "i-12345678",
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardReadWrite",
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

    @staticmethod
    def _instance(state):
        return {
            "Reservations": [{
                "OwnerId": "123456789012",
                "Instances": [{
                    "InstanceId": "i-12345678",
                    "State": {"Name": state},
                }],
            }],
        }

    def _execution_patches(self, ec2_client):
        session = Mock()
        session.client.return_value = ec2_client
        return [
            patch.object(ec2_execution, "get_account", return_value=self.account),
            patch.object(ec2_execution, "assume_aws_role", return_value=session),
            patch.object(ec2_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(ec2_execution, "transition_to_executing", return_value=True),
            patch.object(ec2_execution, "update_execution_result", return_value=True),
            patch.object(ec2_execution, "transition_to_completed", return_value=True),
            patch.object(ec2_execution, "transition_to_failed", return_value=True),
            patch.object(ec2_execution, "record_remediation_event", return_value={"_id": "audit-1"}),
        ]

    def test_success_stops_and_verifies_only_target_instance(self):
        ec2 = Mock()
        ec2.describe_instances.side_effect = [
            self._instance("running"),
            self._instance("stopped"),
        ]
        patches = self._execution_patches(ec2)
        with patches[0], patches[1] as assume, patches[2], patches[3], patches[4], patches[5], patches[6], patches[7] as audit:
            result = ec2_execution.execute_ec2_stop(
                remediation=self.remediation,
                user_id="user-1",
                organization_id="org-1",
                role="owner",
                confirmed=True,
                request_id="request-1",
            )

        assume.assert_called_once()
        ec2.stop_instances.assert_called_once_with(InstanceIds=["i-12345678"])
        ec2.get_waiter.assert_called_once_with("instance_stopped")
        self.assertTrue(result["success"])
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(result["verification"]["observed_state"], "stopped")
        self.assertFalse({"access_key_id", "secret_access_key", "session_token"} & set(result))
        self.assertEqual(audit.call_count, 2)
        self.assertTrue(all(call.kwargs["request_id"] == "request-1" for call in audit.call_args_list))
        self.assertEqual(audit.call_args_list[0].kwargs["organization_id"], "org-1")
        self.assertEqual(audit.call_args_list[0].kwargs["action_id"], "EC2_STOP_INSTANCE")
        self.assertEqual(audit.call_args_list[1].kwargs["verification_result"], "VERIFIED_STOPPED")

    def test_unauthorized_role_is_rejected_before_assumerole(self):
        with patch.object(ec2_execution, "record_remediation_event", return_value={"_id": "audit-1"}), patch.object(ec2_execution, "assume_aws_role") as assume:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="viewer",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

    def test_tenant_mismatch_is_rejected_before_assumerole(self):
        with patch.object(ec2_execution, "assume_aws_role") as assume:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-other",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

    def test_unregistered_action_is_rejected(self):
        record = {**self.remediation, "action_type": "EC2_START_INSTANCE"}
        with patch.object(ec2_execution, "get_account") as account_lookup:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=record,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "ACTION_POLICY_MISMATCH")
        account_lookup.assert_not_called()

    def test_invalid_resource_and_missing_confirmation_are_rejected(self):
        invalid = {**self.remediation, "resource": "i-not-valid"}
        with patch.object(ec2_execution, "get_account") as account_lookup:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=invalid,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "INVALID_INSTANCE_ID")
        account_lookup.assert_not_called()

        with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
            ec2_execution.execute_ec2_stop(
                remediation=self.remediation,
                user_id="user-1",
                organization_id="org-1",
                role="owner",
                confirmed=False,
            )
        self.assertEqual(raised.exception.code, "CONFIRMATION_REQUIRED")

    def test_unapproved_proposal_is_rejected_before_assumerole(self):
        pending = {
            **self.remediation,
            "status": "PENDING_APPROVAL",
            "approved_by": None,
            "approved_at": None,
        }
        with patch.object(ec2_execution, "assume_aws_role") as assume:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=pending,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "APPROVAL_REQUIRED")
        assume.assert_not_called()

    def test_aws_stop_failure_is_sanitized_and_audited(self):
        ec2 = Mock()
        ec2.describe_instances.return_value = self._instance("running")
        ec2.stop_instances.side_effect = ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "secret-token-value"}},
            "StopInstances",
        )
        patches = self._execution_patches(ec2)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7] as audit:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.status_code, 502)
        self.assertNotIn("secret-token-value", raised.exception.public_message)
        self.assertEqual(failed.call_count, 1)
        self.assertTrue(any(call.kwargs.get("error_code") == "UnauthorizedOperation" for call in audit.call_args_list))

    def test_instance_owner_mismatch_prevents_mutation(self):
        ec2 = Mock()
        wrong_owner = self._instance("running")
        wrong_owner["Reservations"][0]["OwnerId"] = "999999999999"
        ec2.describe_instances.return_value = wrong_owner
        patches = self._execution_patches(ec2)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "INSTANCE_ACCOUNT_MISMATCH")
        transition.assert_not_called()
        ec2.stop_instances.assert_not_called()

    def test_unverified_final_state_is_not_marked_completed(self):
        ec2 = Mock()
        ec2.describe_instances.side_effect = [
            self._instance("running"),
            self._instance("running"),
        ]
        patches = self._execution_patches(ec2)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7] as audit:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "STATE_VERIFICATION_FAILED")
        completed.assert_not_called()
        failed.assert_called_once()
        self.assertTrue(any(call.kwargs.get("verification_result") == "FAILED" for call in audit.call_args_list))

    def test_start_audit_failure_blocks_aws_mutation(self):
        ec2 = Mock()
        ec2.describe_instances.return_value = self._instance("running")
        patches = self._execution_patches(ec2)
        patches[7] = patch.object(ec2_execution, "record_remediation_event", return_value=None)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6] as failed, patches[7]:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        ec2.stop_instances.assert_not_called()
        failed.assert_called_once()

    def test_missing_connected_account_prevents_assumerole(self):
        with patch.object(ec2_execution, "get_account", return_value=None) as account_lookup, patch.object(ec2_execution, "assume_aws_role") as assume:
            with self.assertRaises(ec2_execution.EC2StopExecutionError) as raised:
                ec2_execution.execute_ec2_stop(
                    remediation=self.remediation,
                    user_id="user-1",
                    organization_id="org-1",
                    role="owner",
                    confirmed=True,
                )
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_NOT_FOUND")
        self.assertEqual(account_lookup.call_args.kwargs["organization_id"], "org-1")
        assume.assert_not_called()

    def test_execute_api_dispatches_only_ec2_stop_action(self):
        membership = {
            "organization_id": "org-1",
            "user_id": "user-1",
            "status": "active",
            "role": "owner",
        }
        fake_db = SimpleNamespace(
            organization_members=SimpleNamespace(find_one=Mock(return_value=membership))
        )
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-2"))
        result = {
            "success": True,
            "status": "COMPLETED",
            "action_id": "EC2_STOP_INSTANCE",
            "verification": {"verified": True, "observed_state": "stopped"},
        }
        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_remediation", return_value=self.remediation), patch.object(remediation_api, "execute_ec2_stop", return_value=result) as execute:
            response = remediation_api.execute_remediation(
                "remediation-1",
                request,
                remediation_api.ExecuteRemediationRequest(confirmed=True),
                self.user,
            )
        self.assertEqual(response["remediation"], result)
        self.assertEqual(execute.call_args.kwargs["request_id"], "request-2")

        legacy = {**self.remediation, "action_type": "RESTRICT_SECURITY_GROUP"}
        with patch.object(remediation_api, "get_remediation", return_value=legacy), patch.object(remediation_api, "execute_ec2_stop") as execute:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.execute_remediation(
                    "remediation-1",
                    request,
                    remediation_api.ExecuteRemediationRequest(confirmed=True),
                    self.user,
                )
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_proposal_rejects_unknown_action_and_account_tenant_mismatch(self):
        membership = {
            "organization_id": "org-1",
            "user_id": "user-1",
            "status": "active",
            "role": "owner",
        }
        fake_db = SimpleNamespace(
            organization_members=SimpleNamespace(find_one=Mock(return_value=membership))
        )
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-3"))
        payload = remediation_api.CreateRemediationActionRequest(
            account_id="account-other",
            resource_id="i-12345678",
        )

        with patch.object(remediation_api, "db", fake_db):
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "NOT_IN_REGISTRY", payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 404)

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account", return_value=None) as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "EC2_STOP_INSTANCE", payload, request, self.user
                )
        self.assertEqual(raised.exception.status_code, 404)
        self.assertEqual(account_lookup.call_args.kwargs["organization_id"], "org-1")

    def test_proposal_api_enforces_role_tenant_and_resource_validation(self):
        membership = {
            "organization_id": "org-1",
            "user_id": "user-1",
            "status": "active",
            "role": "owner",
        }
        fake_db = SimpleNamespace(
            organization_members=SimpleNamespace(find_one=Mock(return_value=membership))
        )
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-1"))
        account = {**self.account}
        created = {**self.remediation, "status": "PROPOSED", "finding_id": None}

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account", return_value=account) as account_lookup, patch.object(remediation_api, "get_active_remediation", return_value=None), patch.object(remediation_api, "create_remediation", return_value=created), patch.object(remediation_api, "record_remediation_event", return_value={"_id": "audit-1"}):
            response = remediation_api.create_remediation_action_proposal(
                "EC2_STOP_INSTANCE",
                remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="i-12345678"),
                request,
                self.user,
            )
        self.assertTrue(response["created"])
        self.assertEqual(account_lookup.call_args.kwargs["organization_id"], "org-1")

        viewer_db = SimpleNamespace(
            organization_members=SimpleNamespace(
                find_one=Mock(return_value={**membership, "role": "viewer"})
            )
        )
        with patch.object(remediation_api, "db", viewer_db), patch.object(remediation_api, "get_account") as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "EC2_STOP_INSTANCE",
                    remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="i-12345678"),
                    request,
                    self.user,
                )
        self.assertEqual(raised.exception.status_code, 403)
        account_lookup.assert_not_called()

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account") as account_lookup:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "EC2_STOP_INSTANCE",
                    remediation_api.CreateRemediationActionRequest(account_id="account-1", resource_id="not-an-instance"),
                    request,
                    self.user,
                )
        self.assertEqual(raised.exception.status_code, 400)
        account_lookup.assert_not_called()

    def test_audit_model_filters_credential_fields(self):
        inserted_id = ObjectId()
        with patch.object(
            audit_log.audit_logs_collection,
            "insert_one",
            return_value=Mock(inserted_id=inserted_id),
        ):
            record = audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id="EC2_STOP_INSTANCE",
                event_type=audit_log.EVENT_REMEDIATION_EXECUTION_STARTED,
                action="EC2 stop execution started",
                metadata={
                    "aws_secret_access_key": "never-persist",
                    "aws_session_token": "never-persist",
                    "authorization_result": "AUTHORIZED",
                },
            )
        self.assertEqual(record["organization_id"], "org-1")
        self.assertEqual(record["action_id"], "EC2_STOP_INSTANCE")
        self.assertNotIn("aws_secret_access_key", record["metadata"])
        self.assertNotIn("aws_session_token", record["metadata"])


if __name__ == "__main__":
    unittest.main()