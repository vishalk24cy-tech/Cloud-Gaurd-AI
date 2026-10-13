import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError
from fastapi import HTTPException

from app.api import remediation as api
from app.models import audit_log
from app.models import audit_log
from app.services.remediation import vpc_execution
from app.services.remediation.remediation_models import VPC_REMOVE_INSECURE_INGRESS_ACTION_ID


class VPCRemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.action_id = VPC_REMOVE_INSECURE_INGRESS_ACTION_ID
        self.user = {"_id": "user-1", "organization": "org-1"}
        self.operation = {
            "security_group_id": "sg-12345678",
            "protocol": "tcp",
            "from_port": 22,
            "to_port": 22,
            "source": "0.0.0.0/0",
            "source_type": "IPV4_CIDR",
            "rule_scope": "INGRESS",
        }
        self.remediation = {
            "_id": "rem-vpc-1",
            "user_id": "user-1",
            "organization_id": "org-1",
            "account_id": "account-1",
            "aws_account_id": "123456789012",
            "finding_id": "finding-1",
            "action_type": self.action_id,
            "service": "VPC",
            "resource_type": "SECURITY_GROUP",
            "resource": "sg-12345678",
            "operation": {**self.operation, "execution_mode": "SERVER_SIDE_ONLY"},
            "status": "APPROVED",
            "approved_by": "user-1",
            "approved_at": "2026-10-08T00:00:00Z",
        }
        self.account = {
            "_id": "account-1",
            "organization_id": "org-1",
            "user_id": "user-1",
            "aws_account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardVPCRemediation",
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

    def _group(self, include_rule=True, owner="123456789012"):
        permissions = []
        if include_rule:
            permissions.append({
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                "Ipv6Ranges": [],
            })
        return {
            "SecurityGroups": [{"GroupId": "sg-12345678", "OwnerId": owner, "IpPermissions": permissions}],
            "ResponseMetadata": {"RequestId": "aws-describe-request"},
        }

    def _mock_ec2(self, final_group=None):
        ec2 = Mock()
        ec2.describe_security_groups.side_effect = [self._group(), final_group or self._group(False)]
        ec2.revoke_security_group_ingress.return_value = {"ResponseMetadata": {"RequestId": "aws-revoke-request"}}
        return ec2

    def _patches(self, ec2, audit=True):
        session = Mock()
        session.client.return_value = ec2
        return [
            patch.object(vpc_execution, "get_account", return_value=self.account),
            patch.object(vpc_execution, "assume_aws_role", return_value=session),
            patch.object(vpc_execution, "verify_aws_account", return_value={"Account": "123456789012"}),
            patch.object(vpc_execution, "transition_to_executing", return_value=True),
            patch.object(vpc_execution, "update_execution_result", return_value=True),
            patch.object(vpc_execution, "transition_to_completed", return_value=True),
            patch.object(vpc_execution, "transition_to_failed", return_value=True),
            patch.object(vpc_execution, "record_remediation_event", return_value={"_id": "audit"} if audit else None),
        ]

    def test_success_removes_only_public_ssh_rule_and_verifies_absence(self):
        ec2 = self._mock_ec2()
        patches = self._patches(ec2)
        with patches[0], patches[1] as assume, patches[2], patches[3], patches[4] as persist, patches[5], patches[6], patches[7] as audit:
            result = vpc_execution.execute_vpc_remove_ssh_ingress(
                remediation=self.remediation,
                user_id="user-1",
                organization_id="org-1",
                role="owner",
                confirmed=True,
                request_id="app-request-vpc",
            )
        assume.assert_called_once()
        ec2.revoke_security_group_ingress.assert_called_once_with(
            GroupId="sg-12345678",
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        ec2.describe_security_groups.assert_has_calls([
            unittest.mock.call(GroupIds=["sg-12345678"]),
            unittest.mock.call(GroupIds=["sg-12345678"]),
        ])
        self.assertTrue(result["verification"]["verified"])
        self.assertEqual(persist.call_args.kwargs["verification"]["verified"], True)
        self.assertEqual(audit.call_count, 2)
        self.assertEqual(audit.call_args_list[0].kwargs["action_id"], self.action_id)
        self.assertEqual(audit.call_args_list[0].kwargs["request_id"], "app-request-vpc")

    def test_rejects_unauthorized_role_tenant_and_non_ssh_rule(self):
        with patch.object(vpc_execution, "record_remediation_event", return_value={"_id": "audit"}), patch.object(vpc_execution, "assume_aws_role") as assume:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-1", role="viewer", confirmed=True)
        self.assertEqual(raised.exception.status_code, 403)
        assume.assert_not_called()

        with patch.object(vpc_execution, "assume_aws_role") as assume:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-other", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "ORGANIZATION_MISMATCH")
        assume.assert_not_called()

        invalid = {**self.remediation, "operation": {**self.operation, "from_port": 443, "to_port": 443}}
        with patch.object(vpc_execution, "get_account") as account_lookup:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=invalid, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "UNSUPPORTED_RULE_TARGET")
        account_lookup.assert_not_called()

    def test_rejects_unapproved_unconfirmed_and_rule_not_found(self):
        for remediation, confirmed, expected in (
            ({**self.remediation, "status": "PENDING_APPROVAL", "approved_by": None, "approved_at": None}, True, "APPROVAL_REQUIRED"),
            (self.remediation, False, "CONFIRMATION_REQUIRED"),
        ):
            with self.subTest(expected=expected), patch.object(vpc_execution, "assume_aws_role") as assume:
                with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                    vpc_execution.execute_vpc_remove_ssh_ingress(remediation=remediation, user_id="user-1", organization_id="org-1", role="owner", confirmed=confirmed)
                self.assertEqual(raised.exception.code, expected)
                assume.assert_not_called()

        ec2 = Mock()
        ec2.describe_security_groups.return_value = self._group(False)
        patches = self._patches(ec2)
        with patches[0], patches[1], patches[2], patches[3] as transition, patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "TARGET_RULE_NOT_FOUND")
        transition.assert_not_called()
        ec2.revoke_security_group_ingress.assert_not_called()

    def test_account_group_owner_mutation_verification_and_audit_failures(self):
        wrong_account = {**self.remediation, "aws_account_id": "999999999999"}
        with patch.object(vpc_execution, "get_account", return_value=self.account), patch.object(vpc_execution, "assume_aws_role") as assume:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=wrong_account, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "AWS_ACCOUNT_MISMATCH")
        assume.assert_not_called()

        ec2 = self._mock_ec2(final_group=self._group(owner="999999999999"))
        patches = self._patches(ec2)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5] as completed, patches[6] as failed, patches[7]:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "SECURITY_GROUP_VERIFICATION_FAILED")
        completed.assert_not_called()
        failed.assert_called_once()

        ec2 = self._mock_ec2()
        ec2.revoke_security_group_ingress.side_effect = ClientError({"Error": {"Code": "UnauthorizedOperation", "Message": "secret"}}, "RevokeSecurityGroupIngress")
        patches = self._patches(ec2)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7] as audit:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.status_code, 403)
        self.assertNotIn("secret", raised.exception.public_message)
        self.assertTrue(any(call.kwargs.get("error_code") == "UnauthorizedOperation" for call in audit.call_args_list))

        ec2 = self._mock_ec2()
        patches = self._patches(ec2, audit=False)
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6], patches[7]:
            with self.assertRaises(vpc_execution.VPCIngressExecutionError) as raised:
                vpc_execution.execute_vpc_remove_ssh_ingress(remediation=self.remediation, user_id="user-1", organization_id="org-1", role="owner", confirmed=True)
        self.assertEqual(raised.exception.code, "AUDIT_UNAVAILABLE")
        ec2.revoke_security_group_ingress.assert_not_called()

    def test_proposal_approval_execution_api_uses_finding_and_registry_gate(self):
        finding = {"finding_id": "finding-1", "service": "VPC", "resource_type": "Security Group", "resource": "sg-12345678", "issue": "SSH port 22 is open to the Internet.", "status": "OPEN"}
        account = {"_id": "account-1", "aws_account_id": "123456789012", "status": "connected"}
        membership = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=membership)))
        request = SimpleNamespace(state=SimpleNamespace(request_id="request-api"))
        payload = api.CreateRemediationActionRequest(account_id="account-1", finding_id="finding-1")
        proposed = {**self.remediation, "status": "PROPOSED"}
        approved = {**self.remediation, "status": "APPROVED"}

        with patch.object(api, "db", fake_db), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "get_active_remediation", return_value=None), patch.object(api, "create_remediation", return_value=proposed) as create, patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            result = api.create_remediation_action_proposal(self.action_id, payload, request, self.user)
        self.assertEqual(create.call_args.args[0]["resource"], "sg-12345678")
        self.assertEqual(create.call_args.args[0]["operation"]["source"], "0.0.0.0/0")
        self.assertTrue(result["created"])

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", side_effect=[proposed, approved]), patch.object(api, "get_account", return_value=account), patch.object(api, "get_finding_for_account", return_value=finding), patch.object(api, "is_finding_actionable", return_value=True), patch.object(api, "update_remediation_status", return_value=True), patch.object(api, "record_remediation_event", return_value={"_id": "audit"}):
            approval = api.approve_remediation("rem-vpc-1", api.ApproveRemediationRequest(), request, self.user)
        self.assertEqual(approval["remediation"]["status"], "APPROVED")

        with patch.object(api, "db", fake_db), patch.object(api, "get_remediation", return_value=approved), patch.object(api, "execute_vpc_remove_ssh_ingress", return_value={"success": True, "status": "COMPLETED", "verification": {"verified": True}}) as execute:
            response = api.execute_remediation("rem-vpc-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(response["status"], "success")
        self.assertEqual(execute.call_args.kwargs["request_id"], "request-api")

        disabled = {**approved, "action_type": "VPC_REPLACE_UNRESTRICTED_SOURCE"}
        with patch.object(api, "get_remediation", return_value=disabled), patch.object(api, "execute_vpc_remove_ssh_ingress") as execute:
            with self.assertRaises(HTTPException) as raised:
                api.execute_remediation("rem-vpc-1", request, api.ExecuteRemediationRequest(confirmed=True), self.user)
        self.assertEqual(raised.exception.status_code, 409)
        execute.assert_not_called()

    def test_audit_contains_target_context_and_filters_credentials(self):
        captured = {}
        def insert(document):
            captured.update(document)
            return Mock(inserted_id="audit-vpc")
        with patch.object(audit_log.audit_logs_collection, "insert_one", side_effect=insert):
            audit_log.create_audit_log(
                user_id="user-1",
                organization_id="org-1",
                action_id=self.action_id,
                event_type=audit_log.EVENT_REMEDIATION_COMPLETED,
                action="VPC ingress rule removed",
                resource_id="sg-12345678",
                service="VPC",
                resource_type="SECURITY_GROUP",
                metadata={"protocol": "tcp", "secret_access_key": "never-store", "session_token": "never-store"},
            )
        self.assertEqual(captured["organization_id"], "org-1")
        self.assertEqual(captured["action_id"], self.action_id)
        self.assertEqual(captured["resource_id"], "sg-12345678")
        self.assertNotIn("secret_access_key", captured["metadata"])
        self.assertNotIn("session_token", captured["metadata"])


if __name__ == "__main__":
    unittest.main()
