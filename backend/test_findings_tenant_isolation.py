# ============================================================
# CloudGuardAI - Unit & Integration Tests for Findings API
# Phase 3C, Step 1: Findings Tenant Isolation & RBAC
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

# Prevent live MongoDB Atlas network connection on initial import
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

from app.api.findings import router as findings_router
from app.middleware.auth_middleware import verify_token
import app.models.finding as finding_model


class TestFindingsTenantIsolation(unittest.TestCase):
    """
    Focused test suite verifying tenant isolation, multi-user collaboration,
    RBAC enforcement, legacy finding safe handling, and cross-tenant protection.
    """

    def setUp(self):
        self.user_a_id = str(ObjectId())
        self.user_b_id = str(ObjectId())  # Second user in Org A
        self.user_c_id = str(ObjectId())  # User in Org B

        self.org_a_id = "org-alpha-123"
        self.org_b_id = "org-beta-456"

        self.account_a_id = str(ObjectId())
        self.account_b_id = str(ObjectId())

        # In-memory collections for testing
        self.members_store = {}
        self.accounts_store = {}
        self.scan_jobs_store = {}
        self.findings_store = {}

        # Set up members
        self.members_store[(self.org_a_id, self.user_a_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "role": "analyst",
            "status": "active",
        }
        self.members_store[(self.org_a_id, self.user_b_id)] = {
            "organization_id": self.org_a_id,
            "user_id": self.user_b_id,
            "role": "admin",
            "status": "active",
        }
        self.members_store[(self.org_b_id, self.user_c_id)] = {
            "organization_id": self.org_b_id,
            "user_id": self.user_c_id,
            "role": "analyst",
            "status": "active",
        }

        # Set up connected AWS accounts
        self.accounts_store[self.account_a_id] = {
            "_id": ObjectId(self.account_a_id),
            "organization_id": self.org_a_id,
            "account_id": self.account_a_id,
            "status": "connected",
        }
        self.accounts_store[self.account_b_id] = {
            "_id": ObjectId(self.account_b_id),
            "organization_id": self.org_b_id,
            "account_id": self.account_b_id,
            "status": "connected",
        }

        # Mock database object
        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member
        self.mock_db.aws_accounts.find.side_effect = self._mock_find_accounts
        self.mock_db.aws_accounts.find_one.side_effect = self._mock_find_one_account
        self.mock_db.scan_jobs.find_one.side_effect = self._mock_find_one_scan_job

        # Mock findings_collection
        self.mock_findings_col = MagicMock()
        self.mock_findings_col.find.side_effect = self._mock_find_findings
        self.mock_findings_col.find_one.side_effect = self._mock_find_one_finding
        self.mock_findings_col.count_documents.side_effect = self._mock_count_findings
        self.mock_findings_col.update_one.side_effect = self._mock_update_finding
        self.mock_findings_col.delete_one.side_effect = self._mock_delete_finding
        self.mock_findings_col.aggregate.side_effect = self._mock_aggregate_findings

        # Patch db and findings_collection in finding_model and tenant_context
        self.db_patcher = patch("app.services.tenant_context.db", self.mock_db)
        self.model_db_patcher = patch("app.models.finding.db", self.mock_db)
        self.model_col_patcher = patch("app.models.finding.findings_collection", self.mock_findings_col)

        self.db_patcher.start()
        self.model_db_patcher.start()
        self.model_col_patcher.start()

        # Build FastAPI test app
        self.app = FastAPI()
        self.app.include_router(findings_router)

        # Authenticated user state for TestClient
        self.authenticated_user = {
            "_id": self.user_a_id,
            "email": "analyst@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "analyst",
        }

        self.app.dependency_overrides[verify_token] = lambda: self.authenticated_user
        self.client = TestClient(self.app)

    def tearDown(self):
        self.db_patcher.stop()
        self.model_db_patcher.stop()
        self.model_col_patcher.stop()

    # ------------------------------------------------------------
    # Mock Helpers
    # ------------------------------------------------------------
    def _mock_find_member(self, query):
        org_id = query.get("organization_id")
        user_id = query.get("user_id")
        return self.members_store.get((org_id, user_id))

    def _mock_find_accounts(self, query, projection=None):
        org_id = query.get("organization_id")
        res = []
        for acc in self.accounts_store.values():
            if acc.get("organization_id") == org_id:
                res.append(acc)
        mock_cursor = MagicMock()
        mock_cursor.__iter__.return_value = iter(res)
        return mock_cursor

    def _mock_find_one_account(self, query):
        org_id = query.get("organization_id")
        or_clauses = query.get("$or", [])
        for acc in self.accounts_store.values():
            if org_id and acc.get("organization_id") != org_id:
                continue
            for clause in or_clauses:
                clause_id = clause.get("_id") or clause.get("account_id")
                if str(acc.get("_id")) == str(clause_id) or str(acc.get("account_id")) == str(clause_id):
                    return acc
        return None

    def _mock_find_one_scan_job(self, query):
        org_id = query.get("organization_id")
        or_clauses = query.get("$or", [])
        for job in self.scan_jobs_store.values():
            if org_id and job.get("organization_id") != org_id:
                continue
            for clause in or_clauses:
                clause_id = clause.get("_id")
                if str(job.get("_id")) == str(clause_id):
                    return job
        return None

    def _mock_find_findings(self, query):
        res = self._filter_findings(query)
        mock_cursor = MagicMock()
        mock_cursor.sort.return_value = res
        mock_cursor.__iter__.return_value = iter(res)
        return mock_cursor

    def _mock_find_one_finding(self, query):
        res = self._filter_findings(query)
        return res[0] if res else None

    def _mock_count_findings(self, query, limit=None):
        res = self._filter_findings(query)
        count = len(res)
        return min(count, limit) if limit else count

    def _mock_update_finding(self, query, update):
        res = self._filter_findings(query)
        if not res:
            return MagicMock(matched_count=0, modified_count=0)
        target = res[0]
        set_fields = update.get("$set", {})
        target.update(set_fields)
        return MagicMock(matched_count=1, modified_count=1)

    def _mock_delete_finding(self, query):
        res = self._filter_findings(query)
        if not res:
            return MagicMock(deleted_count=0)
        target = res[0]
        del self.findings_store[str(target["_id"])]
        return MagicMock(deleted_count=1)

    def _mock_aggregate_findings(self, pipeline):
        # Support basic service/severity grouping in tests
        match_stage = next((s["$match"] for s in pipeline if "$match" in s), {})
        group_stage = next((s["$group"] for s in pipeline if "$group" in s), {})
        filtered = self._filter_findings(match_stage)
        group_field = group_stage.get("_id", "").replace("$", "")

        counts = {}
        for item in filtered:
            val = item.get(group_field, "UNKNOWN")
            counts[val] = counts.get(val, 0) + 1

        return [{"_id": k, "count": v} for k, v in counts.items()]

    def _filter_findings(self, query):
        matched = []
        for f in self.findings_store.values():
            if not self._finding_matches(f, query):
                continue
            matched.append(f)
        return matched

    def _finding_matches(self, finding, query):
        for key, expected in query.items():
            if key == "_id":
                if str(finding.get("_id")) != str(expected):
                    return False
            elif key == "finding_id":
                if str(finding.get("finding_id")) != str(expected):
                    return False
            elif key == "organization_id":
                if finding.get("organization_id") != expected:
                    return False
            elif key == "user_id":
                if finding.get("user_id") != expected:
                    return False
            elif key == "account_id":
                if str(finding.get("account_id")) != str(expected):
                    return False
            elif key == "status":
                if isinstance(expected, dict):
                    if "$ne" in expected and finding.get("status") == expected["$ne"]:
                        return False
                elif finding.get("status") != expected:
                    return False
            elif key == "$or":
                sub_matched = False
                for sub_clause in expected:
                    all_sub_match = True
                    for sk, sv in sub_clause.items():
                        if sk == "organization_id":
                            if isinstance(sv, dict) and "$in" in sv:
                                if finding.get("organization_id") not in sv["$in"]:
                                    all_sub_match = False
                            elif finding.get("organization_id") != sv:
                                all_sub_match = False
                        elif sk == "account_id":
                            if isinstance(sv, dict) and "$in" in sv:
                                if str(finding.get("account_id")) not in sv["$in"]:
                                    all_sub_match = False
                            elif str(finding.get("account_id")) != str(sv):
                                all_sub_match = False
                    if all_sub_match:
                        sub_matched = True
                        break
                if not sub_matched:
                    return False
        return True

    # ------------------------------------------------------------
    # Tests
    # ------------------------------------------------------------

    def test_list_findings_scoped_to_organization(self):
        """Org A user sees only Org A findings; Org B findings are completely excluded."""
        fid_a = ObjectId()
        fid_b = ObjectId()
        self.findings_store[str(fid_a)] = {
            "_id": fid_a,
            "finding_id": "FINDING-ALPHA",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
            "service": "EC2",
            "severity": "HIGH",
        }
        self.findings_store[str(fid_b)] = {
            "_id": fid_b,
            "finding_id": "FINDING-BETA",
            "organization_id": self.org_b_id,
            "user_id": self.user_c_id,
            "status": "OPEN",
            "service": "S3",
            "severity": "CRITICAL",
        }

        resp = self.client.get("/findings/")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["count"], 1)
        self.assertEqual(data["findings"][0]["finding_id"], "FINDING-ALPHA")

    def test_same_org_multi_user_access(self):
        """User B (Admin) in Org A can see and triage findings created by User A (Analyst) in Org A."""
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-MULTIUSER",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,  # Created by User A
            "status": "OPEN",
            "service": "EC2",
            "severity": "HIGH",
            "issue": "Unrestricted inbound port",
        }

        # Switch client to User B (Admin in same org)
        self.authenticated_user = {
            "_id": self.user_b_id,
            "email": "admin@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "admin",
        }

        resp = self.client.get(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["finding"]["finding_id"], "FINDING-MULTIUSER")

        # User B triages User A's finding
        triage_resp = self.client.patch(
            f"/findings/{fid}/status",
            json={"status": "IN_PROGRESS"},
        )
        self.assertEqual(triage_resp.status_code, 200)
        self.assertEqual(triage_resp.json()["finding"]["status"], "IN_PROGRESS")

    def test_cross_tenant_get_finding_returns_404(self):
        """Querying finding belonging to Org B with Org A context returns 404 without disclosure."""
        fid_b = ObjectId()
        self.findings_store[str(fid_b)] = {
            "_id": fid_b,
            "finding_id": "FINDING-BETA-PRIVATE",
            "organization_id": self.org_b_id,
            "user_id": self.user_c_id,
            "status": "OPEN",
            "service": "S3",
            "severity": "CRITICAL",
        }

        resp = self.client.get(f"/findings/{fid_b}")
        self.assertEqual(resp.status_code, 404)
        self.assertEqual(resp.json()["detail"], "Finding not found")

    def test_viewer_can_read_findings_and_statistics(self):
        """Viewer role can access list, get, statistics, by-service, and by-severity."""
        self.members_store[(self.org_a_id, self.user_a_id)]["role"] = "viewer"
        self.authenticated_user["role"] = "viewer"

        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-VIEWER",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
            "service": "EC2",
            "severity": "MEDIUM",
        }

        self.assertEqual(self.client.get("/findings/").status_code, 200)
        self.assertEqual(self.client.get(f"/findings/{fid}").status_code, 200)
        self.assertEqual(self.client.get("/findings/statistics").status_code, 200)
        self.assertEqual(self.client.get("/findings/by-service").status_code, 200)
        self.assertEqual(self.client.get("/findings/by-severity").status_code, 200)

    def test_viewer_denied_status_update_403(self):
        """Viewer role cannot change finding workflow status."""
        self.members_store[(self.org_a_id, self.user_a_id)]["role"] = "viewer"
        self.authenticated_user["role"] = "viewer"

        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-V1",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        resp = self.client.patch(f"/findings/{fid}/status", json={"status": "IN_PROGRESS"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("analyst", resp.json()["detail"])

    def test_viewer_denied_assign_403(self):
        """Viewer role cannot assign findings."""
        self.members_store[(self.org_a_id, self.user_a_id)]["role"] = "viewer"
        self.authenticated_user["role"] = "viewer"

        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-V2",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        resp = self.client.patch(f"/findings/{fid}/assign", json={"assigned_to": "engineer@cloudguard.ai"})
        self.assertEqual(resp.status_code, 403)

    def test_viewer_denied_notes_update_403(self):
        """Viewer role cannot update finding notes."""
        self.members_store[(self.org_a_id, self.user_a_id)]["role"] = "viewer"
        self.authenticated_user["role"] = "viewer"

        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-V3",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        resp = self.client.patch(f"/findings/{fid}/notes", json={"notes": "Investigated by security team"})
        self.assertEqual(resp.status_code, 403)

    def test_viewer_denied_delete_finding_403(self):
        """Viewer role cannot delete findings."""
        self.members_store[(self.org_a_id, self.user_a_id)]["role"] = "viewer"
        self.authenticated_user["role"] = "viewer"

        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-V4",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        resp = self.client.delete(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 403)

    def test_analyst_can_triage_findings(self):
        """Analyst can update status, assign, and add notes."""
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-A1",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
            "issue": "Public S3 bucket",
        }

        # Status update
        resp1 = self.client.patch(f"/findings/{fid}/status", json={"status": "IN_PROGRESS"})
        self.assertEqual(resp1.status_code, 200)

        # Assignment
        resp2 = self.client.patch(f"/findings/{fid}/assign", json={"assigned_to": "engineer@cloudguard.ai"})
        self.assertEqual(resp2.status_code, 200)

        # Notes
        resp3 = self.client.patch(f"/findings/{fid}/notes", json={"notes": "Bucket verified open to world"})
        self.assertEqual(resp3.status_code, 200)

    def test_analyst_denied_delete_finding_403(self):
        """Analyst role cannot permanently delete findings (requires admin or owner)."""
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-A2",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        resp = self.client.delete(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("admin, owner", resp.json()["detail"])

    def test_admin_and_owner_can_delete_finding(self):
        """Admin or Owner role can permanently delete findings."""
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-DELETE-ME",
            "organization_id": self.org_a_id,
            "user_id": self.user_a_id,
            "status": "OPEN",
        }

        # User B is Admin
        self.authenticated_user = {
            "_id": self.user_b_id,
            "email": "admin@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "admin",
        }

        resp = self.client.delete(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["message"], "Finding deleted successfully")
        self.assertNotIn(str(fid), self.findings_store)

    def test_cross_tenant_mutations_return_404(self):
        """Attempting to mutate or delete another tenant's finding returns 404 Not Found."""
        fid_b = ObjectId()
        self.findings_store[str(fid_b)] = {
            "_id": fid_b,
            "finding_id": "FINDING-ORG-B",
            "organization_id": self.org_b_id,
            "user_id": self.user_c_id,
            "status": "OPEN",
        }

        # Admin in Org A tries to mutate Org B finding
        self.authenticated_user = {
            "_id": self.user_b_id,
            "email": "admin@alpha.cloudguard.ai",
            "organization": self.org_a_id,
            "role": "admin",
        }

        resp_patch = self.client.patch(f"/findings/{fid_b}/status", json={"status": "RESOLVED"})
        self.assertEqual(resp_patch.status_code, 404)

        resp_delete = self.client.delete(f"/findings/{fid_b}")
        self.assertEqual(resp_delete.status_code, 404)

    def test_inactive_and_revoked_memberships_denied_403(self):
        """Inactive or revoked organization memberships are denied access."""
        self.members_store[(self.org_a_id, self.user_a_id)]["status"] = "inactive"
        resp = self.client.get("/findings/")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("inactive", resp.json()["detail"].lower())

    def test_missing_membership_denied_403(self):
        """User without membership document in target organization is denied access."""
        del self.members_store[(self.org_a_id, self.user_a_id)]
        resp = self.client.get("/findings/")
        self.assertEqual(resp.status_code, 403)

    def test_legacy_finding_with_missing_org_verified_via_account_and_backfilled(self):
        """
        Legacy finding with organization_id=None whose account_id belongs to Org A
        is verified, backfilled with organization_id=Org A, and returned.
        """
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-LEGACY-VERIFIED",
            "organization_id": None,  # Legacy un-migrated finding
            "account_id": self.account_a_id,  # Belongs to Org A
            "user_id": self.user_a_id,
            "status": "OPEN",
            "service": "EC2",
            "severity": "HIGH",
        }

        resp = self.client.get(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 200)
        finding_data = resp.json()["finding"]
        self.assertEqual(finding_data["finding_id"], "FINDING-LEGACY-VERIFIED")

        # Verify that organization_id was backfilled
        self.assertEqual(self.findings_store[str(fid)]["organization_id"], self.org_a_id)

    def test_legacy_finding_with_unverified_account_fails_closed_404(self):
        """
        Legacy finding with organization_id=None whose account_id does NOT belong
        to Org A fails closed with 404 and is not backfilled.
        """
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-LEGACY-UNVERIFIED",
            "organization_id": None,
            "account_id": self.account_b_id,  # Belongs to Org B!
            "user_id": self.user_c_id,
            "status": "OPEN",
            "service": "S3",
            "severity": "HIGH",
        }

        resp = self.client.get(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 404)
        # organization_id should NOT be modified
        self.assertIsNone(self.findings_store[str(fid)]["organization_id"])

    def test_legacy_finding_empty_string_org_handled_safely(self):
        """Legacy finding with empty string organization_id is checked via trusted account."""
        fid = ObjectId()
        self.findings_store[str(fid)] = {
            "_id": fid,
            "finding_id": "FINDING-EMPTY-ORG",
            "organization_id": "",  # Empty string
            "account_id": self.account_a_id,  # Belongs to Org A
            "user_id": self.user_a_id,
            "status": "OPEN",
            "service": "EC2",
            "severity": "LOW",
        }

        resp = self.client.get(f"/findings/{fid}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.findings_store[str(fid)]["organization_id"], self.org_a_id)


if __name__ == "__main__":
    unittest.main()
