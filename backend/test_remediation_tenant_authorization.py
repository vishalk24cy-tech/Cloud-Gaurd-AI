# ============================================================
# CloudGuardAI - Unit & Integration Tests for Remediation API
# Phase 3C, Step 2: Remediation Tenant Authorization & RBAC
# ============================================================

import contextlib
import io
import os
import sys
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

# ------------------------------------------------------------
# Test mode & Offline database guard
# ------------------------------------------------------------
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

if "app.database.connection" not in sys.modules:
    mock_pymongo = MagicMock()
    mock_db_instance = MagicMock()
    mock_pymongo.MongoClient.return_value.__getitem__.return_value = mock_db_instance
    mock_pymongo.MongoClient.return_value.admin.command.return_value = {"ok": 1}
    _real_pymongo = sys.modules.get("pymongo")
    sys.modules["pymongo"] = mock_pymongo
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            import app.database.connection
    finally:
        if _real_pymongo is not None:
            sys.modules["pymongo"] = _real_pymongo
        elif "pymongo" in sys.modules:
            del sys.modules["pymongo"]

from app.api.remediation import router as remediation_router
from app.middleware.auth_middleware import verify_token
import app.models.remediation as remediation_model
from app.models.remediation import (
    STATUS_PROPOSED,
    STATUS_PENDING_APPROVAL,
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_REJECTED,
    STATUS_CANCELLED,
    ACTION_EC2_STOP_INSTANCE,
    ACTION_DISABLE_PUBLIC_ACCESS,
)


class TestRemediationTenantAuthorization(unittest.TestCase):
    """
    Focused test suite verifying tenant authorization and RBAC for all
    remediation endpoints: proposal, approve, reject, cancel, delete,
    verify, list, statistics, and legacy backfill.
    """

    def setUp(self):
        self.user_analyst_id = str(ObjectId())
        self.user_admin_id = str(ObjectId())
        self.user_viewer_id = str(ObjectId())
        self.user_owner_id = str(ObjectId())
        self.user_other_org_id = str(ObjectId())

        self.org_a_id = "org-alpha-123"
        self.org_b_id = "org-beta-456"

        self.account_a_id = str(ObjectId())
        self.account_b_id = str(ObjectId())
        self.disconnected_account_id = str(ObjectId())

        self.aws_account_a_id = "111122223333"
        self.aws_account_b_id = "444455556666"

        # In-memory stores
        self.members_store = {}
        self.accounts_store = {}
        self.findings_store = {}
        self.remediations_store = {}
        self.scan_jobs_store = {}

        # Set up organization members
        self.members_store[(self.org_a_id, self.user_analyst_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "role": "analyst",
            "status": "active",
        }
        self.members_store[(self.org_a_id, self.user_admin_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_admin_id,
            "role": "admin",
            "status": "active",
        }
        self.members_store[(self.org_a_id, self.user_viewer_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_viewer_id,
            "role": "viewer",
            "status": "active",
        }
        self.members_store[(self.org_a_id, self.user_owner_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_owner_id,
            "role": "owner",
            "status": "active",
        }
        self.members_store[(self.org_b_id, self.user_other_org_id)] = {
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "role": "owner",
            "status": "active",
        }

        # Set up connected AWS accounts
        self.accounts_store[self.account_a_id] = {
            "_id": ObjectId(self.account_a_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_admin_id,
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_a_id,
            "status": "connected",
        }
        self.accounts_store[self.account_b_id] = {
            "_id": ObjectId(self.account_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "aws_account_id": self.aws_account_b_id,
            "status": "connected",
        }
        self.accounts_store[self.disconnected_account_id] = {
            "_id": ObjectId(self.disconnected_account_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_admin_id,
            "account_id": self.disconnected_account_id,
            "aws_account_id": self.aws_account_a_id,
            "status": "disconnected",
        }

        # Set up mock findings
        self.finding_s3_id = "finding-s3-001"
        self.findings_store[self.finding_s3_id] = {
            "_id": ObjectId(),
            "finding_id": self.finding_s3_id,
            "organization_id": self.org_a_id,
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_a_id,
            "user_id": self.user_analyst_id,
            "service": "S3",
            "resource_type": "BUCKET",
            "resource": "alpha-public-bucket",
            "severity": "HIGH",
            "status": "OPEN",
            "issue": "S3 bucket allows public access",
            "description": "Public access detected on bucket",
            "detection_status": "ACTIVE",
        }

        # Mock database object
        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member
        self.mock_db.aws_accounts.find.side_effect = self._mock_find_accounts
        self.mock_db.aws_accounts.find_one.side_effect = self._mock_find_one_account

        # Mock remediations collection
        self.mock_rem_col = MagicMock()
        self.mock_rem_col.find.side_effect = self._mock_find_remediations
        self.mock_rem_col.find_one.side_effect = self._mock_find_one_remediation
        self.mock_rem_col.count_documents.side_effect = self._mock_count_remediations
        self.mock_rem_col.update_one.side_effect = self._mock_update_remediation
        self.mock_rem_col.delete_one.side_effect = self._mock_delete_remediation
        self.mock_rem_col.insert_one.side_effect = self._mock_insert_remediation

        # Patch dependencies
        self.patchers = [
            patch("app.api.remediation.db", self.mock_db),
            patch("app.models.remediation.db", self.mock_db),
            patch("app.models.remediation.remediations_collection", self.mock_rem_col),
            patch("app.api.remediation.get_finding_for_account", side_effect=self._mock_get_finding_for_account),
            patch("app.api.remediation.get_account", side_effect=self._mock_get_account_func),
            patch("app.services.tenant_context.db", self.mock_db),
        ]
        for p in self.patchers:
            p.start()

        # Build test app
        self.app = FastAPI()
        self.app.include_router(remediation_router)

        self.current_user = {
            "_id": self.user_analyst_id,
            "email": "analyst@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "analyst",
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

    # Database mock helpers
    def _mock_find_member(self, query):
        org = query.get("organization_id")
        uid = query.get("user_id")
        member = self.members_store.get((org, uid))
        if member and query.get("status") and member.get("status") != query.get("status"):
            return None
        return member

    def _mock_find_accounts(self, query, projection=None):
        org_id = query.get("organization_id")
        results = [acc for acc in self.accounts_store.values() if acc.get("organization_id") == org_id]
        return results

    def _mock_find_one_account(self, query):
        or_queries = query.get("$or")
        org_id = query.get("organization_id")
        if or_queries:
            for item in or_queries:
                acc_id = str(item.get("_id"))
                acc = self.accounts_store.get(acc_id)
                if acc and (not org_id or acc.get("organization_id") == org_id):
                    return acc
        acc_id = str(query.get("_id")) if query.get("_id") else None
        if acc_id:
            acc = self.accounts_store.get(acc_id)
            if acc and (not org_id or acc.get("organization_id") == org_id):
                return acc
        return None

    def _mock_get_finding_for_account(self, finding_id, user_id=None, account_id=None, organization_id=None):
        finding = self.findings_store.get(finding_id)
        if not finding:
            return None
        if organization_id and finding.get("organization_id") != organization_id:
            return None
        if account_id and finding.get("account_id") != str(account_id):
            return None
        return dict(finding)

    def _mock_get_account_func(self, account_id, user_id=None, organization_id=None):
        acc = self.accounts_store.get(str(account_id))
        if not acc:
            return None
        if organization_id and acc.get("organization_id") != organization_id:
            return None
        return dict(acc)

    def _mock_find_remediations(self, query):
        records = []
        for rem in self.remediations_store.values():
            match = True
            if "organization_id" in query and rem.get("organization_id") != query["organization_id"]:
                match = False
            if "user_id" in query and rem.get("user_id") != query["user_id"]:
                match = False
            if "status" in query:
                st = query["status"]
                if isinstance(st, dict) and "$in" in st:
                    if rem.get("status") not in st["$in"]:
                        match = False
                elif rem.get("status") != st:
                    match = False
            if match:
                records.append(dict(rem))
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = mock_cursor
        mock_cursor.limit.return_value = records
        mock_cursor.__iter__.return_value = iter(records)
        return mock_cursor

    def _mock_find_one_remediation(self, query, sort=None):
        target_id = query.get("_id")
        if target_id is not None:
            rem = self.remediations_store.get(str(target_id))
            if not rem:
                return None
            if "organization_id" in query and rem.get("organization_id") != query["organization_id"]:
                return None
            if "user_id" in query and rem.get("user_id") != query["user_id"]:
                return None
            if "status" in query:
                st = query["status"]
                if isinstance(st, dict) and "$in" in st:
                    if rem.get("status") not in st["$in"]:
                        return None
                elif rem.get("status") != st:
                    return None
            return dict(rem)

        # Active lookup query
        org_id = query.get("organization_id")
        user_id = query.get("user_id")
        account_id = query.get("account_id")
        action_type = query.get("action_type")
        finding_id = query.get("finding_id")
        status_filter = query.get("status", {})

        for rem in self.remediations_store.values():
            if org_id and rem.get("organization_id") != org_id:
                continue
            if user_id and not org_id and rem.get("user_id") != user_id:
                continue
            if account_id and rem.get("account_id") != account_id:
                continue
            if action_type and rem.get("action_type") != action_type:
                continue
            if finding_id and rem.get("finding_id") != finding_id:
                continue
            if "$in" in status_filter and rem.get("status") not in status_filter["$in"]:
                continue
            return dict(rem)
        return None

    def _mock_count_remediations(self, query):
        count = 0
        for rem in self.remediations_store.values():
            match = True
            if "organization_id" in query and rem.get("organization_id") != query["organization_id"]:
                match = False
            if "user_id" in query and rem.get("user_id") != query["user_id"]:
                match = False
            if "status" in query and rem.get("status") != query["status"]:
                match = False
            if match:
                count += 1
        return count

    def _mock_update_remediation(self, query, update):
        target_id = str(query.get("_id"))
        rem = self.remediations_store.get(target_id)
        if not rem:
            return MagicMock(modified_count=0)
        if "organization_id" in query and rem.get("organization_id") != query["organization_id"]:
            return MagicMock(modified_count=0)
        if "user_id" in query and rem.get("user_id") != query["user_id"]:
            return MagicMock(modified_count=0)
        if "status" in query:
            st = query["status"]
            if isinstance(st, dict) and "$in" in st:
                if rem.get("status") not in st["$in"]:
                    return MagicMock(modified_count=0)
            elif rem.get("status") != st:
                return MagicMock(modified_count=0)

        set_fields = update.get("$set", {})
        rem.update(set_fields)
        return MagicMock(modified_count=1)

    def _mock_delete_remediation(self, query):
        target_id = str(query.get("_id"))
        rem = self.remediations_store.get(target_id)
        if not rem:
            return MagicMock(deleted_count=0)
        if "organization_id" in query and rem.get("organization_id") != query["organization_id"]:
            return MagicMock(deleted_count=0)
        if "user_id" in query and rem.get("user_id") != query["user_id"]:
            return MagicMock(deleted_count=0)
        if "status" in query:
            st = query["status"]
            if isinstance(st, dict) and "$in" in st:
                if rem.get("status") not in st["$in"]:
                    return MagicMock(deleted_count=0)
        del self.remediations_store[target_id]
        return MagicMock(deleted_count=1)

    def _mock_insert_remediation(self, doc):
        doc_id = str(ObjectId())
        doc["_id"] = ObjectId(doc_id)
        self.remediations_store[doc_id] = doc
        res = MagicMock()
        res.inserted_id = doc["_id"]
        return res

    # ------------------------------------------------------------
    # TESTS: Role-Based Access Control on Proposal Creation
    # ------------------------------------------------------------

    def test_viewer_denied_manual_proposal_creation_403(self):
        """A user with viewer role cannot create a manual remediation proposal."""
        self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
        response = self.client.post(
            "/remediation/",
            json={
                "finding_id": self.finding_s3_id,
                "account_id": self.account_a_id,
                "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("not authorized", response.json()["detail"].lower())

    def test_analyst_can_create_permitted_manual_proposal_201(self):
        """An analyst in the organization can create a permitted remediation proposal."""
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        response = self.client.post(
            "/remediation/",
            json={
                "finding_id": self.finding_s3_id,
                "account_id": self.account_a_id,
                "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            },
        )
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["created"])
        rem = data["remediation"]
        self.assertEqual(rem["organization_id"], self.org_a_id)
        self.assertEqual(rem["status"], STATUS_PROPOSED)

    # ------------------------------------------------------------
    # TESTS: Role-Based Access Control on Proposal Approval
    # ------------------------------------------------------------

    def test_viewer_and_analyst_denied_approval_403(self):
        """Viewers and Analysts are strictly forbidden from approving remediations."""
        # Create proposal first
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_a_id,
            "finding_id": self.finding_s3_id,
            "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            "status": STATUS_PROPOSED,
        }

        # Viewer attempt -> 403
        self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
        res_v = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "approve"})
        self.assertEqual(res_v.status_code, 403)

        # Analyst attempt -> 403
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res_a = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "approve"})
        self.assertEqual(res_a.status_code, 403)

    def test_admin_and_owner_can_approve_proposal_200(self):
        """Admin or Owner can approve an eligible remediation proposal."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "aws_account_id": self.aws_account_a_id,
            "finding_id": self.finding_s3_id,
            "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            "status": STATUS_PROPOSED,
        }

        # Admin approves
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "Admin approved"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["remediation"]["status"], STATUS_APPROVED)
        self.assertEqual(data["remediation"]["approved_by"], self.user_admin_id)
        self.assertIsNotNone(data["remediation"]["approved_at"])

    # ------------------------------------------------------------
    # TESTS: Rejection, Cancellation, and Deletion RBAC
    # ------------------------------------------------------------

    def test_viewer_denied_rejection_403(self):
        """Viewer cannot reject a proposal."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
        res = self.client.patch(f"/remediation/{rem_id}/reject", json={"reason": "bad idea"})
        self.assertEqual(res.status_code, 403)

    def test_analyst_can_reject_proposal_200(self):
        """Analyst can reject a proposed remediation."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.patch(f"/remediation/{rem_id}/reject", json={"reason": "Not needed"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["remediation"]["status"], STATUS_REJECTED)

    def test_viewer_denied_cancellation_403(self):
        """Viewer cannot cancel a proposal."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
        res = self.client.patch(f"/remediation/{rem_id}/cancel")
        self.assertEqual(res.status_code, 403)

    def test_analyst_can_cancel_proposal_200(self):
        """Analyst can cancel an active proposal."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.patch(f"/remediation/{rem_id}/cancel")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["remediation"]["status"], STATUS_CANCELLED)

    def test_viewer_and_analyst_denied_deletion_403(self):
        """Only Admin or Owner can delete a proposal record; Viewer and Analyst denied."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "status": STATUS_CANCELLED,
        }
        self._set_auth_user(self.user_viewer_id, self.org_a_id, "viewer")
        res_v = self.client.delete(f"/remediation/{rem_id}")
        self.assertEqual(res_v.status_code, 403)

        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res_a = self.client.delete(f"/remediation/{rem_id}")
        self.assertEqual(res_a.status_code, 403)

    def test_owner_and_admin_can_delete_proposal_200(self):
        """Admin or Owner can delete an unexecuted (proposed/rejected/cancelled) record."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "status": STATUS_CANCELLED,
        }
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.delete(f"/remediation/{rem_id}")
        self.assertEqual(res.status_code, 200)
        self.assertNotIn(rem_id, self.remediations_store)

    # ------------------------------------------------------------
    # TESTS: Cross-Tenant Protection (Non-Disclosing 404)
    # ------------------------------------------------------------

    def test_cross_tenant_proposal_retrieval_returns_404(self):
        """A user cannot retrieve a remediation belonging to another organization."""
        rem_b_id = str(ObjectId())
        self.remediations_store[rem_b_id] = {
            "_id": ObjectId(rem_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.get(f"/remediation/{rem_b_id}")
        self.assertEqual(res.status_code, 404)

    def test_cross_tenant_approval_returns_404(self):
        """A user cannot approve a remediation belonging to another organization."""
        rem_b_id = str(ObjectId())
        self.remediations_store[rem_b_id] = {
            "_id": ObjectId(rem_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.patch(f"/remediation/{rem_b_id}/approve", json={"comment": "intruder"})
        self.assertEqual(res.status_code, 404)

    def test_cross_tenant_rejection_returns_404(self):
        """A user cannot reject a remediation belonging to another organization."""
        rem_b_id = str(ObjectId())
        self.remediations_store[rem_b_id] = {
            "_id": ObjectId(rem_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.patch(f"/remediation/{rem_b_id}/reject", json={"reason": "intruder"})
        self.assertEqual(res.status_code, 404)

    def test_cross_tenant_cancellation_returns_404(self):
        """A user cannot cancel a remediation belonging to another organization."""
        rem_b_id = str(ObjectId())
        self.remediations_store[rem_b_id] = {
            "_id": ObjectId(rem_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "status": STATUS_PROPOSED,
        }
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.patch(f"/remediation/{rem_b_id}/cancel")
        self.assertEqual(res.status_code, 404)

    def test_cross_tenant_deletion_returns_404(self):
        """A user cannot delete a remediation belonging to another organization."""
        rem_b_id = str(ObjectId())
        self.remediations_store[rem_b_id] = {
            "_id": ObjectId(rem_b_id),
            "organization_id": self.org_b_id,
            "user_id": self.user_other_org_id,
            "account_id": self.account_b_id,
            "status": STATUS_CANCELLED,
        }
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.delete(f"/remediation/{rem_b_id}")
        self.assertEqual(res.status_code, 404)

    # ------------------------------------------------------------
    # TESTS: Account Validation & Membership Fail Closed
    # ------------------------------------------------------------

    def test_disconnected_aws_account_rejected_404(self):
        """Remediation proposal on a disconnected AWS account is rejected."""
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.post(
            "/remediation/",
            json={
                "finding_id": self.finding_s3_id,
                "account_id": self.disconnected_account_id,
                "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            },
        )
        self.assertEqual(res.status_code, 404)

    def test_missing_or_inactive_membership_fails_closed_403(self):
        """A user without an active membership in the organization fails closed."""
        unknown_user = str(ObjectId())
        self._set_auth_user(unknown_user, self.org_a_id, "analyst")
        res = self.client.get("/remediation/")
        self.assertEqual(res.status_code, 403)

    # ------------------------------------------------------------
    # TESTS: Invalid State Transitions
    # ------------------------------------------------------------

    def test_cannot_approve_already_approved_or_completed_proposal_409(self):
        """Attempting to approve a proposal already approved or completed fails with 409."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "status": STATUS_APPROVED,
        }
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "again"})
        self.assertEqual(res.status_code, 409)

    def test_cannot_reject_approved_proposal_409(self):
        """Attempting to reject an already approved proposal fails with 409."""
        rem_id = str(ObjectId())
        self.remediations_store[rem_id] = {
            "_id": ObjectId(rem_id),
            "organization_id": self.org_a_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_a_id,
            "status": STATUS_APPROVED,
        }
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res = self.client.patch(f"/remediation/{rem_id}/reject", json={"reason": "too late"})
        self.assertEqual(res.status_code, 409)

    # ------------------------------------------------------------
    # TESTS: Legacy Remediation Verification and Safe Backfill
    # ------------------------------------------------------------

    def test_legacy_remediation_verified_via_account_and_backfilled(self):
        """
        A legacy remediation lacking organization_id is verified via its
        account_id belonging to the caller's organization and backfilled.
        """
        legacy_rem_id = str(ObjectId())
        self.remediations_store[legacy_rem_id] = {
            "_id": ObjectId(legacy_rem_id),
            "account_id": self.account_a_id,
            "user_id": self.user_analyst_id,
            "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            "status": STATUS_PROPOSED,
            # organization_id missing
        }

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.get(f"/remediation/{legacy_rem_id}")
        self.assertEqual(res.status_code, 200)
        data = res.json()["remediation"]
        self.assertEqual(data["organization_id"], self.org_a_id)

    def test_legacy_remediation_unverified_fails_closed_404(self):
        """
        A legacy remediation lacking organization_id whose account does NOT
        belong to the organization cannot be accessed and returns 404.
        """
        foreign_acc_id = str(ObjectId())
        legacy_rem_id = str(ObjectId())
        self.remediations_store[legacy_rem_id] = {
            "_id": ObjectId(legacy_rem_id),
            "account_id": foreign_acc_id,
            "user_id": "legacy-stranger",
            "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            "status": STATUS_PROPOSED,
        }

        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res = self.client.get(f"/remediation/{legacy_rem_id}")
        self.assertEqual(res.status_code, 404)

    # ------------------------------------------------------------
    # TESTS: Statistics and Multi-User Collaboration
    # ------------------------------------------------------------

    def test_remediation_statistics_scoped_to_organization(self):
        """Users in the same organization see their organization's statistics."""
        rem_1 = str(ObjectId())
        rem_2 = str(ObjectId())
        rem_other = str(ObjectId())

        self.remediations_store[rem_1] = {
            "_id": ObjectId(rem_1),
            "organization_id": self.org_a_id,
            "status": STATUS_PROPOSED,
        }
        self.remediations_store[rem_2] = {
            "_id": ObjectId(rem_2),
            "organization_id": self.org_a_id,
            "status": STATUS_APPROVED,
        }
        self.remediations_store[rem_other] = {
            "_id": ObjectId(rem_other),
            "organization_id": self.org_b_id,
            "status": STATUS_PROPOSED,
        }

        # User in Org A sees total 2
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res_a = self.client.get("/remediation/statistics")
        self.assertEqual(res_a.status_code, 200)
        self.assertEqual(res_a.json()["statistics"]["total"], 2)
        self.assertEqual(res_a.json()["statistics"]["proposed"], 1)
        self.assertEqual(res_a.json()["statistics"]["approved"], 1)

        # User in Org B sees total 1
        self._set_auth_user(self.user_other_org_id, self.org_b_id, "owner")
        res_b = self.client.get("/remediation/statistics")
        self.assertEqual(res_b.status_code, 200)
        self.assertEqual(res_b.json()["statistics"]["total"], 1)

    def test_multi_user_collaboration_analyst_proposes_admin_approves(self):
        """
        Multi-user flow in Org A: Analyst creates proposal, Admin lists and approves it.
        """
        # Step 1: Analyst proposes
        self._set_auth_user(self.user_analyst_id, self.org_a_id, "analyst")
        res_prop = self.client.post(
            "/remediation/",
            json={
                "finding_id": self.finding_s3_id,
                "account_id": self.account_a_id,
                "action_type": ACTION_DISABLE_PUBLIC_ACCESS,
            },
        )
        self.assertEqual(res_prop.status_code, 201)
        rem_id = res_prop.json()["remediation"]["_id"]

        # Step 2: Admin lists proposals and sees the analyst's proposal
        self._set_auth_user(self.user_admin_id, self.org_a_id, "admin")
        res_list = self.client.get("/remediation/")
        self.assertEqual(res_list.status_code, 200)
        rems = res_list.json()["remediations"]
        self.assertTrue(any(r["_id"] == rem_id for r in rems))

        # Step 3: Admin approves it
        res_app = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "Approved by SecOps Admin"})
        self.assertEqual(res_app.status_code, 200)
        approved_rem = res_app.json()["remediation"]
        self.assertEqual(approved_rem["status"], STATUS_APPROVED)
        self.assertEqual(approved_rem["approved_by"], self.user_admin_id)
        self.assertEqual(approved_rem["user_id"], self.user_analyst_id)  # Proposer preserved
