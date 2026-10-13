import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.api import remediation as remediation_api
from app.services.kms_checker import check_kms
from app.services.remediation.remediation_engine import get_default_engine


class KMSRemediationSafetyGateTests(unittest.TestCase):
    def test_registered_policy_action_lacks_policy_finding_evidence(self):
        action = get_default_engine().get_action("KMS_UPDATE_KEY_POLICY")
        self.assertIsNotNone(action)
        self.assertEqual(action.classification.value, "APPROVAL_REQUIRED")

        kms = Mock()
        kms.list_keys.return_value = {"Keys": [{"KeyId": "key-1234"}]}
        kms.describe_key.return_value = {
            "KeyMetadata": {
                "KeyState": "Enabled",
                "KeyManager": "CUSTOMER",
                "Arn": "arn:aws:kms:ap-south-1:123456789012:key/key-1234",
                "Description": "customer key",
                "Enabled": True,
            }
        }
        kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}

        findings = check_kms(kms)
        self.assertTrue(any("rotation is not enabled" in item.get("issue", "").lower() for item in findings))
        self.assertFalse(any("policy" in item.get("issue", "").lower() for item in findings))
        kms.get_key_policy.assert_not_called()

    def test_key_policy_action_is_rejected_before_account_or_aws_access(self):
        current_user = {"_id": "user-1", "organization": "org-1"}
        membership = {"organization_id": "org-1", "user_id": "user-1", "status": "active", "role": "owner"}
        fake_db = SimpleNamespace(organization_members=SimpleNamespace(find_one=Mock(return_value=membership)))
        request = SimpleNamespace(state=SimpleNamespace(request_id="kms-gate-request"))
        payload = remediation_api.CreateRemediationActionRequest(
            account_id="account-1",
            resource_id="key-1234",
        )

        with patch.object(remediation_api, "db", fake_db), patch.object(remediation_api, "get_account") as get_account:
            with self.assertRaises(HTTPException) as raised:
                remediation_api.create_remediation_action_proposal(
                    "KMS_UPDATE_KEY_POLICY",
                    payload,
                    request,
                    current_user,
                )

        self.assertEqual(raised.exception.status_code, 409)
        get_account.assert_not_called()


if __name__ == "__main__":
    unittest.main()
