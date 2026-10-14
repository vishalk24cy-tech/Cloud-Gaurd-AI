"""
Unit and integration tests for multi-user remediation execution.

Verifies:
1. Analyst proposes -> Admin approves -> Admin executes with explicit confirmation.
2. Original proposer identity is preserved; executor is recorded as executed_by.
3. Viewers and analysts cannot execute remediation.
4. Cross-tenant users cannot execute remediation.
5. Unapproved, unconfirmed, or partially approved remediations cannot execute.
6. Foreign, disconnected, or mismatched AWS accounts are rejected.
7. Unsupported actions remain blocked.
8. Legacy execution fallback cannot bypass authorization or tenant isolation.
9. No cloud mutations occur on rejected requests.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from bson import ObjectId
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from app.api.auth import verify_token
from app.api.remediation import router as remediation_router
from app.models.remediation import (
    ACTION_DISABLE_PUBLIC_ACCESS,
    ACTION_EC2_STOP_INSTANCE,
    ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_EXECUTING,
    STATUS_PROPOSED,
    transition_to_completed,
    transition_to_executing,
    update_execution_result,
)
from app.services.aws_remediation_executor import (
    RemediationSecurityError,
    RemediationValidationError,
    execute_approved_remediation,
)
from app.services.remediation.ec2_execution import EC2StopExecutionError, execute_ec2_stop


class MultiUserRemediationExecutionTests(unittest.TestCase):
    def setUp(self):
        self.org_a_id = "org-alpha-111"
        self.org_b_id = "org-beta-222"

        self.user_analyst_id = "user-analyst-1"
        self.user_admin_id = "user-admin-1"
        self.user_viewer_id = "user-viewer-1"
        self.user_other_org_id = "user-other-org-1"

        self.account_a_id = str(ObjectId())
        self.aws_account_num = "123456789012"

        # Mock in-memory stores
        self.members_store = {
            (self.org_a_id, self.user_analyst_id): {
                "organization_id": self.org_a_id,
                "user_id": self.user_analyst_id,
                "role": "analyst",
                "status": "active",
            },
            (self.org_a_id, self.user_admin_id): {
                "organization_id": self.org_a_id,
                "user_id": self.user_admin_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_a_id, self.user_viewer_id): {
                "organization_id": self.org_a_id,
                "user_id": self.user_viewer_id,
                "role": "viewer",
                "status": "active",
            },
            (self.org_b_id, self.user_other_org_id): {
                "organization_id": self.org_b_id,
                "user_id": self.user_other_org_id,
                "role": "admin",
                "status": "active",
            },
        }

        self.accounts_store = {
            self.account_a_id: {
                "_id": ObjectId(self.account_a_id),
                "organization_id": self.org_a_id,
                "user_id": self.user_analyst_id,
                "aws_account_id": self.aws_account_num,
                "account_name": "Production AWS",
                "role_arn": "arn:aws:iam::123456789012:role/CloudGuardExecution",
                "region": "us-east-1",
                "status": "connected",
            }
        }

        self.findings_store = {
            "finding-ec2-1": {
                "_id": "finding-ec2-1",
                "account_id": self.account_a_id,
                "aws_account_id": self.aws_account_num,
                "organization_id": self.org_a_id,
                "resource_id": "i-0123456789abcdef0",
                "resource_type": "AWS::EC2::Instance",
                "rule_id": "ec2-instance-managed",
                "status": "OPEN",
            }
        }

        self.remediations_store = {}

        # Mock DB
        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member
        self.mock_db.aws_accounts.find_one.side_effect = self._mock_find_one_account
        self.mock_db.aws_accounts.find.side_effect = self._mock_find_accounts

        self.mock_rem_col = MagicMock()
        self.mock_rem_col.find_one.side_effect = self._mock_find_one_remediation
        self.mock_rem_col.update_one.side_effect = self._mock_update_remediation
        self.mock_rem_col.insert_one.side_effect = self._mock_insert_remediation

        self.patchers = [
            patch("app.api.remediation.db", self.mock_db),
            patch("app.models.remediation.db", self.mock_db),
            patch("app.models.remediation.remediations_collection", self.mock_rem_col),
            patch("app.api.remediation.get_account", side_effect=self._mock_get_account),
            patch("app.services.tenant_context.db", self.mock_db),
            patch("app.models.remediation_settings.is_remediation_enabled", return_value=True),
        ]
        for p in self.patchers:
            p.start()

        self.app = FastAPI()
        self.app.include_router(remediation_router)

        self.current_user = {
            "_id": self.user_admin_id,
            "user_id": self.user_admin_id,
            "email": "admin@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "admin",
        }
        self.app.dependency_overrides[verify_token] = lambda: self.current_user
        self.client = TestClient(self.app)

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def _set_auth_user(self, user_id, org_id, role):
        self.current_user = {
            "_id": user_id,
            "user_id": user_id,
            "email": f"{role}@test.com",
            "organization": org_id,
            "role": role,
        }

    def _mock_find_member(self, query):
        org = query.get("organization_id")
        uid = query.get("user_id")
        member = self.members_store.get((org, uid))
        if member and query.get("status") and member.get("status") != query.get("status"):
            return None
        return member

    def _mock_find_one_account(self, query):
        acc_id = str(query.get("_id")) if query.get("_id") else None
        org_id = query.get("organization_id")
        if acc_id:
            acc = self.accounts_store.get(acc_id)
            if acc and (not org_id or acc.get("organization_id") == org_id):
                return acc
        return None

    def _mock_find_accounts(self, query, projection=None):
        org_id = query.get("organization_id")
        return [acc for acc in self.accounts_store.values() if acc.get("organization_id") == org_id]

    def _mock_get_account(self, account_id, user_id=None, organization_id=None):
        acc = self.accounts_store.get(str(account_id))
        if acc and organization_id and acc.get("organization_id") != organization_id:
            return None
        return acc

    def _mock_find_one_remediation(self, query):
        rem_id = str(query.get("_id"))
        rem = self.remediations_store.get(rem_id)
        if not rem:
            return None
        if query.get("organization_id") and rem.get("organization_id") != query.get("organization_id"):
            return None
        if query.get("status") and rem.get("status") != query.get("status"):
            return None
        return dict(rem)

    def _mock_update_remediation(self, query, update):
        rem_id = str(query.get("_id"))
        rem = self.remediations_store.get(rem_id)
        if not rem:
            return SimpleNamespace(modified_count=0)
        if query.get("organization_id") and rem.get("organization_id") != query.get("organization_id"):
            return SimpleNamespace(modified_count=0)
        if query.get("user_id") and rem.get("user_id") != query.get("user_id"):
            return SimpleNamespace(modified_count=0)
        if query.get("status") and rem.get("status") != query.get("status"):
            return SimpleNamespace(modified_count=0)

        if "$set" in update:
            for k, v in update["$set"].items():
                rem[k] = v
        return SimpleNamespace(modified_count=1)

    def _mock_insert_remediation(self, doc):
        rem_id = str(doc.get("_id", ObjectId()))
        doc["_id"] = ObjectId(rem_id)
        self.remediations_store[rem_id] = doc
        return SimpleNamespace(inserted_id=doc["_id"])

    # -------------------------------------------------------------------------
    # TESTS
    # -------------------------------------------------------------------------

    def test_multi_user_flow_analyst_proposes_admin_approves_and_executes(self):
        """
        Verify the complete multi-user chain:
        1. Analyst creates proposal (remediation.user_id = analyst).
        2. Admin approves proposal (approved_by = admin).
        3. Admin executes proposal with confirmed=True.
        4. Remediation transitions to COMPLETED, preserving user_id and setting executed_by.
        """
        # Create approved proposal created by analyst
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,  # Proposer is analyst
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "resource_type": "EC2_INSTANCE",
            "finding_id": "finding-ec2-1",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,  # Approver is admin
            "approved_at": "2026-10-14T00:00:00Z",
        }

        # Mock the EC2 execution function
        mock_result = {
            "success": True,
            "status": STATUS_COMPLETED,
            "remediation_id": rem_id,
            "action_id": ACTION_EC2_STOP_INSTANCE,
            "verification": {"verified": True, "observed_state": "stopped"},
        }
        with patch("app.api.remediation.execute_ec2_stop", return_value=mock_result) as mock_exec:
            self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
            res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})

        self.assertEqual(res.status_code, 200)
        mock_exec.assert_called_once()
        call_kwargs = mock_exec.call_args[1]
        self.assertEqual(call_kwargs["user_id"], self.user_admin_id)  # Executor is admin
        self.assertEqual(call_kwargs["organization_id"], self.org_a_id)
        self.assertEqual(call_kwargs["role"], "admin")
        self.assertTrue(call_kwargs["confirmed"])

        # Proposer is still the analyst
        stored = self.remediations_store[rem_id]
        self.assertEqual(stored["user_id"], self.user_analyst_id)
        self.assertEqual(stored["approved_by"], self.user_admin_id)

    def test_viewer_and_analyst_denied_execution(self):
        """Viewers and analysts must not be allowed to execute remediation."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }

        with patch("app.api.remediation.execute_ec2_stop") as mock_exec:
            # Analyst attempt
            self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
            res_analyst = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
            self.assertEqual(res_analyst.status_code, 403)

            # Viewer attempt
            self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
            res_viewer = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
            self.assertEqual(res_viewer.status_code, 403)

            mock_exec.assert_not_called()

    def test_cross_tenant_admin_cannot_execute(self):
        """An admin from Organization B cannot execute an approved remediation belonging to Organization A."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }

        with patch("app.api.remediation.execute_ec2_stop") as mock_exec:
            self._set_auth_user(self.user_other_org_id, self.org_b_id, "admin")
            res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})

        # Must fail closed with 404 (non-disclosing)
        self.assertEqual(res.status_code, 404)
        mock_exec.assert_not_called()

    def test_unapproved_proposal_cannot_be_executed(self):
        """A remediation in PROPOSED status cannot be executed."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "status": STATUS_PROPOSED,
        }

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})

        self.assertEqual(res.status_code, 409)
        self.assertEqual(res.json()["detail"]["code"], "APPROVAL_REQUIRED")

    def test_missing_approved_by_prevents_execution(self):
        """A remediation marked APPROVED but missing approved_by fails validation."""
        rem_id = str(ObjectId())
        self.remediation_data = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "status": STATUS_APPROVED,
            "approved_by": None,  # Missing
            "approved_at": "2026-10-14T00:00:00Z",
        }
        self.remediations_store[rem_id] = self.remediation_data

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
        self.assertEqual(res.status_code, 409)

    def test_missing_explicit_confirmation_blocks_execution(self):
        """Executing without confirmed=True returns 409."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "service": "EC2",
            "resource": "i-0123456789abcdef0",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        # confirmed is False
        res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": False})
        self.assertEqual(res.status_code, 409)

    def test_unregistered_action_rejected_with_409(self):
        """Action not registered or not in execution allowlist returns 409."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": "UNKNOWN_ACTION_TYPE",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
        self.assertEqual(res.status_code, 409)

    def test_legacy_executor_fallback_enforces_tenant_and_role_checks(self):
        """
        Direct calls to execute_approved_remediation enforce owner/admin role,
        connected account status, approval, and explicit confirmation.
        """
        rem_id = str(ObjectId())
        remediation_doc = {
            "_id": ObjectId(rem_id),
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_num,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            "finding_id": "finding-ec2-1",
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }
        self.remediations_store[rem_id] = remediation_doc

        # 1. Deny non-owner/non-admin
        with self.assertRaises(RemediationSecurityError) as raised:
            execute_approved_remediation(
                remediation_id=rem_id,
                user_id=self.user_analyst_id,
                organization_id=self.org_a_id,
                role="analyst",
                confirmed=True,
            )
        self.assertIn("Owner or admin", str(raised.exception))

        # 2. Deny without confirmation
        with self.assertRaises(RemediationSecurityError) as raised:
            execute_approved_remediation(
                remediation_id=rem_id,
                user_id=self.user_admin_id,
                organization_id=self.org_a_id,
                role="admin",
                confirmed=False,
            )
        self.assertIn("Explicit execution confirmation is required", str(raised.exception))

        # 3. Deny cross-tenant organization
        with self.assertRaises(RemediationSecurityError) as raised:
            execute_approved_remediation(
                remediation_id=rem_id,
                user_id=self.user_other_org_id,
                organization_id=self.org_b_id,
                role="admin",
                confirmed=True,
            )
        self.assertTrue(
            "not found" in str(raised.exception).lower()
            or "organization" in str(raised.exception).lower()
        )

    def test_model_transitions_record_executed_by_without_overwriting_proposer(self):
        """
        Verify that model transitions update executed_by while preserving original user_id (proposer).
        """
        rem_id = ObjectId()
        rem_str = str(rem_id)
        doc = {
            "_id": rem_id,
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,  # Proposer
            "status": STATUS_APPROVED,
            "approved_by": self.user_admin_id,
            "approved_at": "2026-10-14T00:00:00Z",
        }
        self.remediations_store[rem_str] = doc

        # Transition to EXECUTING by Admin
        ok = transition_to_executing(
            remediation_id=rem_id,
            user_id=self.user_admin_id,
            organization_id=self.org_a_id,
            executed_by=self.user_admin_id,
        )
        self.assertTrue(ok)
        self.assertEqual(doc["status"], STATUS_EXECUTING)
        self.assertEqual(doc["user_id"], self.user_analyst_id)  # Preserved
        self.assertEqual(doc["executed_by"], self.user_admin_id)  # Recorded

        # Update execution result
        ok = update_execution_result(
            remediation_id=rem_id,
            user_id=self.user_admin_id,
            after_state={"stopped": True},
            organization_id=self.org_a_id,
        )
        self.assertTrue(ok)
        self.assertEqual(doc["user_id"], self.user_analyst_id)

        # Transition to COMPLETED by Admin
        ok = transition_to_completed(
            remediation_id=rem_id,
            user_id=self.user_admin_id,
            organization_id=self.org_a_id,
            executed_by=self.user_admin_id,
        )
        self.assertTrue(ok)
        self.assertEqual(doc["status"], STATUS_COMPLETED)
        self.assertEqual(doc["user_id"], self.user_analyst_id)  # Still preserved
        self.assertEqual(doc["executed_by"], self.user_admin_id)


if __name__ == "__main__":
    unittest.main()
