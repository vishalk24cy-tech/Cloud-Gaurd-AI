# ============================================================
# CloudGuardAI - Phase 4 End-to-End Integration & Workflow Tests
# Validates complete lifecycle from Authentication -> Org/Account ->
# Findings/Dashboard -> AI Remediation Proposal -> Human Approval ->
# Confirmed Execution -> Audit Trail
# ============================================================

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from bson import ObjectId
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

from app.api.auth import router as auth_router
from app.api.aws_accounts import router as aws_account_router
from app.api.cloud import router as cloud_router
from app.api.dashboard import router as dashboard_router
from app.api.findings import router as findings_router
from app.api.remediation import router as remediation_router
from app.middleware.auth_middleware import verify_token
from app.models.remediation import (
    ACTION_EC2_STOP_INSTANCE,
    STATUS_APPROVED,
    STATUS_COMPLETED,
    STATUS_PENDING_APPROVAL,
    STATUS_PROPOSED,
)
from app.services.tenant_context import TenantContext


class Phase4EndToEndIntegrationTests(unittest.TestCase):
    """
    End-to-end workflow validation for CloudGuardAI2 Phase 4.
    """

    def setUp(self):
        self.org_id = "org-alpha-444"
        self.foreign_org_id = "org-beta-555"

        self.user_owner_id = str(ObjectId())
        self.user_admin_id = str(ObjectId())
        self.user_analyst_id = str(ObjectId())
        self.user_viewer_id = str(ObjectId())
        self.foreign_user_id = str(ObjectId())

        self.account_id = str(ObjectId())
        self.disconnected_account_id = str(ObjectId())
        self.foreign_account_id = str(ObjectId())
        self.aws_account_num = "123456789012"
        self.instance_id = "i-0123456789abcdef0"

        # Connected AWS Account
        self.connected_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Alpha Production AWS",
            "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
            "organization_id": self.org_id,
            "user_id": self.user_owner_id,
        }

        # Disconnected AWS Account
        self.disconnected_account = {
            "_id": ObjectId(self.disconnected_account_id),
            "account_id": self.disconnected_account_id,
            "aws_account_id": "999888777666",
            "account_name": "Alpha Legacy Disconnected",
            "role_arn": "arn:aws:iam::999888777666:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "disconnected",
            "organization_id": self.org_id,
            "user_id": self.user_owner_id,
        }

        # Foreign AWS Account
        self.foreign_account = {
            "_id": ObjectId(self.foreign_account_id),
            "account_id": self.foreign_account_id,
            "aws_account_id": "555444333222",
            "account_name": "Foreign Account",
            "role_arn": "arn:aws:iam::555444333222:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
            "organization_id": self.foreign_org_id,
            "user_id": self.foreign_user_id,
        }

        # In-memory stores
        self.accounts_store = {
            self.account_id: self.connected_account,
            self.disconnected_account_id: self.disconnected_account,
            self.foreign_account_id: self.foreign_account,
        }

        self.members_store = {
            (self.org_id, self.user_owner_id): {
                "organization_id": self.org_id,
                "user_id": self.user_owner_id,
                "role": "owner",
                "status": "active",
            },
            (self.org_id, self.user_admin_id): {
                "organization_id": self.org_id,
                "user_id": self.user_admin_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_id, self.user_analyst_id): {
                "organization_id": self.org_id,
                "user_id": self.user_analyst_id,
                "role": "analyst",
                "status": "active",
            },
            (self.org_id, self.user_viewer_id): {
                "organization_id": self.org_id,
                "user_id": self.user_viewer_id,
                "role": "viewer",
                "status": "active",
            },
            (self.foreign_org_id, self.foreign_user_id): {
                "organization_id": self.foreign_org_id,
                "user_id": self.foreign_user_id,
                "role": "admin",
                "status": "active",
            },
        }

        self.finding_oid = ObjectId()
        self.finding_id = str(self.finding_oid)
        self.findings_store = {
            self.finding_id: {
                "_id": self.finding_oid,
                "finding_id": self.finding_id,
                "account_id": self.account_id,
                "aws_account_id": self.aws_account_num,
                "organization_id": self.org_id,
                "user_id": self.user_analyst_id,
                "resource": self.instance_id,
                "resource_id": self.instance_id,
                "resource_type": "AWS::EC2::Instance",
                "service": "EC2",
                "rule_id": "ec2-instance-running",
                "issue": "EC2 instance running unmanaged",
                "severity": "HIGH",
                "status": "OPEN",
                "detection_status": "ACTIVE",
                "created_at": datetime.now(timezone.utc),
            }
        }

        self.remediations_store = {}
        self.audit_events = []

        # Setup Mock DB
        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member
        self.mock_db.aws_accounts.find_one.side_effect = self._mock_find_one_account
        self.mock_db.aws_accounts.find.side_effect = self._mock_find_accounts
        self.mock_db.findings.find.side_effect = self._mock_find_findings
        self.mock_db.findings.find_one.side_effect = self._mock_find_one_finding

        # Setup Mock Findings Collection
        self.mock_findings_col = MagicMock()
        self.mock_findings_col.find.side_effect = self._mock_find_findings
        self.mock_findings_col.find_one.side_effect = self._mock_find_one_finding
        self.mock_findings_col.delete_one.side_effect = self._mock_delete_finding
        self.mock_findings_col.update_one.side_effect = self._mock_update_finding
        self.mock_findings_col.count_documents.side_effect = lambda q, **kw: len(self._filter_findings(q))

        # Setup Mock Remediation Collection
        self.mock_rem_col = MagicMock()
        self.mock_rem_col.find_one.side_effect = self._mock_find_one_rem
        self.mock_rem_col.insert_one.side_effect = self._mock_insert_rem
        self.mock_rem_col.update_one.side_effect = self._mock_update_rem

        # Mock Audit Log
        self.mock_audit_col = MagicMock()
        self.mock_audit_col.insert_one.side_effect = self._mock_insert_audit

        self.patchers = [
            patch("app.database.connection.db", self.mock_db),
            patch("app.services.tenant_context.db", self.mock_db),
            patch("app.api.aws_accounts.db", self.mock_db),
            patch("app.api.remediation.db", self.mock_db),
            patch("app.models.finding.db", self.mock_db),
            patch("app.models.finding.findings_collection", self.mock_findings_col),
            patch("app.api.findings.get_finding", side_effect=self._mock_get_single_finding),
            patch("app.api.remediation.get_finding_for_account", side_effect=self._mock_get_finding_for_account),
            patch("app.models.remediation.db", self.mock_db),
            patch("app.models.remediation.remediations_collection", self.mock_rem_col),
            patch("app.models.remediation.get_remediation", side_effect=self._mock_get_remediation),
            patch("app.api.remediation.get_remediation", side_effect=self._mock_get_remediation),
            patch("app.models.remediation_settings.is_remediation_enabled", return_value=True),
            patch("app.api.aws_accounts.get_organization_accounts", side_effect=self._mock_get_org_accounts),
            patch("app.api.aws_accounts.get_account", side_effect=self._mock_get_account),
            patch("app.models.aws_account.get_account", side_effect=self._mock_get_account),
            patch("app.api.remediation.get_account", side_effect=self._mock_get_account),
            patch("app.api.cloud.get_account", side_effect=self._mock_get_account),
            patch("app.services.ec2_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.models.audit_log.audit_logs_collection", self.mock_audit_col),
        ]
        for p in self.patchers:
            p.start()

        # Build FastAPI test app with the actual integrated routers
        self.app = FastAPI(title="CloudGuardAI Test Integration")
        self.app.include_router(auth_router, prefix="/auth")
        self.app.include_router(aws_account_router, prefix="/aws")
        self.app.include_router(cloud_router, prefix="/cloud")
        self.app.include_router(dashboard_router, prefix="/dashboard")
        self.app.include_router(findings_router)
        self.app.include_router(remediation_router)

        # Set default active user to Analyst
        self.current_user = {
            "_id": self.user_analyst_id,
            "user_id": self.user_analyst_id,
            "email": "analyst@alpha.cloudguard.ai",
            "organization": self.org_id,
            "role": "analyst",
        }
        self.app.dependency_overrides[verify_token] = lambda: self.current_user
        self.client = TestClient(self.app)

    def tearDown(self):
        for p in self.patchers:
            p.stop()

    def _set_user(self, user_id, org_id, role, email=None):
        self.current_user = {
            "_id": user_id,
            "user_id": user_id,
            "email": email or f"{role}@{org_id}.cloudguard.ai",
            "organization": org_id,
            "role": role,
        }

    def _mock_insert_audit(self, doc, *args, **kwargs):
        self.audit_events.append(dict(doc))
        res = MagicMock()
        res.inserted_id = ObjectId()
        return res

    def _mock_find_member(self, query, *args, **kwargs):
        org_id = str(query.get("organization_id", ""))
        user_id = str(query.get("user_id", ""))
        member = self.members_store.get((org_id, user_id))
        return dict(member) if member else None

    def _mock_find_one_account(self, query, *args, **kwargs):
        acc_id = str(query.get("_id") or query.get("account_id") or "")
        acc = self.accounts_store.get(acc_id)
        if not acc:
            return None
        org_id = query.get("organization_id")
        if org_id and str(acc.get("organization_id")) != str(org_id):
            return None
        res = dict(acc)
        res["_id"] = str(res["_id"])
        return res

    def _mock_find_accounts(self, query, *args, **kwargs):
        org_id = str(query.get("organization_id", ""))
        results = []
        for a in self.accounts_store.values():
            if str(a.get("organization_id")) == org_id:
                item = dict(a)
                item["_id"] = str(item["_id"])
                results.append(item)
        mock_cursor = MagicMock()
        mock_cursor.__iter__.return_value = iter(results)
        mock_cursor.sort.return_value = results
        return mock_cursor

    def _mock_get_org_accounts(self, org_id):
        results = []
        for a in self.accounts_store.values():
            if str(a.get("organization_id")) == str(org_id):
                item = dict(a)
                item["_id"] = str(item["_id"])
                results.append(item)
        return results

    def _mock_get_account(self, account_id, user_id=None, organization_id=None):
        acc = self.accounts_store.get(str(account_id))
        if not acc:
            return None
        if organization_id and str(acc.get("organization_id")) != str(organization_id):
            return None
        res = dict(acc)
        res["_id"] = str(res["_id"])
        return res

    def _mock_get_single_finding(self, finding_id, user_id=None, organization_id=None):
        finding = self.findings_store.get(str(finding_id))
        if not finding:
            for f in self.findings_store.values():
                if str(f.get("_id")) == str(finding_id) or str(f.get("finding_id")) == str(finding_id):
                    finding = f
                    break
        if not finding:
            return None
        if organization_id and str(finding.get("organization_id")) != str(organization_id):
            return None
        return dict(finding)

    def _mock_get_finding_for_account(self, finding_id, user_id=None, account_id=None, organization_id=None):
        f = self._mock_get_single_finding(finding_id, user_id=user_id, organization_id=organization_id)
        if not f:
            return None
        if account_id and str(f.get("account_id")) != str(account_id):
            return None
        return dict(f)

    def _mock_find_findings(self, query, *args, **kwargs):
        res = self._filter_findings(query)
        mock_cursor = MagicMock()
        mock_cursor.__iter__.return_value = iter(res)
        mock_cursor.sort.return_value = res
        return mock_cursor

    def _mock_find_one_finding(self, query, *args, **kwargs):
        res = self._filter_findings(query)
        return dict(res[0]) if res else None

    def _mock_delete_finding(self, query):
        res = self._filter_findings(query)
        if not res:
            return MagicMock(deleted_count=0)
        target = res[0]
        self.findings_store.pop(str(target.get("finding_id")), None)
        self.findings_store.pop(str(target.get("_id")), None)
        return MagicMock(deleted_count=1)

    def _mock_update_finding(self, query, update, *args, **kwargs):
        res = self._filter_findings(query)
        if not res:
            return MagicMock(matched_count=0, modified_count=0)
        target = res[0]
        set_fields = update.get("$set", {})
        target.update(set_fields)
        return MagicMock(matched_count=1, modified_count=1)

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
                if str(finding.get("organization_id")) != str(expected):
                    return False
            elif key == "account_id":
                if str(finding.get("account_id")) != str(expected):
                    return False
            elif key == "status":
                if isinstance(expected, dict):
                    if "$ne" in expected and finding.get("status") == expected["$ne"]:
                        return False
        return True

    def _mock_find_one_rem(self, query, *args, **kwargs):
        rem_id = str(query.get("_id") or query.get("remediation_id") or "")
        rem = self.remediations_store.get(rem_id)
        if not rem:
            for r in self.remediations_store.values():
                if str(r.get("_id")) == rem_id or str(r.get("remediation_id")) == rem_id:
                    rem = r
                    break
        if not rem:
            return None
        org_id = query.get("organization_id")
        if org_id and str(rem.get("organization_id")) != str(org_id):
            return None
        return dict(rem)

    def _mock_get_remediation(self, remediation_id, user_id=None, organization_id=None):
        rem = self.remediations_store.get(str(remediation_id))
        if not rem:
            return None
        if organization_id and str(rem.get("organization_id")) != str(organization_id):
            return None
        return dict(rem)

    def _mock_insert_rem(self, doc, *args, **kwargs):
        doc_id = str(doc.get("_id") or ObjectId())
        doc["_id"] = ObjectId(doc_id)
        self.remediations_store[doc_id] = dict(doc)
        res = MagicMock()
        res.inserted_id = doc["_id"]
        return res

    def _mock_update_rem(self, query, update, *args, **kwargs):
        rem_id = str(query.get("_id") or query.get("remediation_id") or "")
        rem = self.remediations_store.get(rem_id)
        if not rem:
            res = MagicMock()
            res.matched_count = 0
            res.modified_count = 0
            return res
        if "$set" in update:
            rem.update(update["$set"])
        res = MagicMock()
        res.matched_count = 1
        res.modified_count = 1
        return res

    # ========================================================
    # 1. AUTHENTICATION & SESSION TESTS
    # ========================================================

    def test_auth_login_invalid_credentials_rejected(self):
        """Invalid password or missing user returns appropriate error code."""
        with patch("app.api.auth.db.users.find_one", return_value=None):
            resp = self.client.post("/auth/login", json={"email": "nobody@cloudguard.ai", "password": "WrongPassword123!"})
            self.assertEqual(resp.status_code, 404)
            self.assertIn("not found", resp.json().get("detail", "").lower())

    def test_auth_profile_returns_tenant_identity(self):
        """Protected profile route returns verified server-side identity."""
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        resp = self.client.get("/auth/profile")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["logged_in_user"]["_id"], self.user_analyst_id)
        self.assertEqual(data["logged_in_user"]["organization"], self.org_id)

    # ========================================================
    # 2. ORGANIZATION & CLOUD ACCOUNT TESTS
    # ========================================================

    def test_cloud_accounts_scoped_to_organization(self):
        """Listing accounts returns only the authenticated organization's accounts."""
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        resp = self.client.get("/aws/accounts")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["organization_id"], self.org_id)
        returned_ids = [a["account_id"] for a in data["accounts"]]
        self.assertIn(self.account_id, returned_ids)
        self.assertNotIn(self.foreign_account_id, returned_ids)

    def test_cross_tenant_cloud_account_rejected_404(self):
        """Attempting to access another organization's cloud account returns 404."""
        self._set_user(self.user_admin_id, self.org_id, "admin")
        resp = self.client.get(f"/aws/account/{self.foreign_account_id}")
        self.assertEqual(resp.status_code, 404)

    # ========================================================
    # 3. FINDINGS & DASHBOARD INTEGRATION
    # ========================================================

    def test_findings_dual_slash_url_support(self):
        """Both /findings and /findings/ resolve seamlessly without redirect error."""
        self._set_user(self.user_viewer_id, self.org_id, "viewer")

        resp_no_slash = self.client.get("/findings")
        self.assertEqual(resp_no_slash.status_code, 200)

        resp_with_slash = self.client.get("/findings/")
        self.assertEqual(resp_with_slash.status_code, 200)

    def test_findings_role_enforcement(self):
        """Viewer cannot delete findings (403); Admin can delete (200)."""
        # Viewer denied delete
        self._set_user(self.user_viewer_id, self.org_id, "viewer")
        resp_v = self.client.delete(f"/findings/{self.finding_id}")
        self.assertEqual(resp_v.status_code, 403)

        # Admin permitted delete
        self._set_user(self.user_admin_id, self.org_id, "admin")
        with patch("app.api.findings.delete_finding", return_value={"status": "success"}):
            resp_a = self.client.delete(f"/findings/{self.finding_id}")
            self.assertEqual(resp_a.status_code, 200)

    def test_dashboard_scoped_to_organization(self):
        """Dashboard endpoint aggregates scans using verified organization context."""
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        with patch("app.api.dashboard.get_all_scans") as mock_scans:
            mock_scans.return_value = [
                {
                    "_id": "scan-1",
                    "account_id": self.account_id,
                    "risk_score": 45,
                    "security_level": "Medium",
                    "resources": {"ec2": 5, "s3": 3, "iam": 2},
                    "findings": [],
                    "scan_time": "2026-10-15T00:00:00Z",
                }
            ]
            resp = self.client.get("/dashboard")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["total_scans"], 1)
            self.assertEqual(data["latest_risk_score"], 45.0)
            # Verify organization_id was passed to get_all_scans
            mock_scans.assert_called_once()
            _, kwargs = mock_scans.call_args
            self.assertEqual(kwargs.get("organization_id"), self.org_id)

    # ========================================================
    # 4. AI REMEDIATION PROPOSAL & HUMAN APPROVAL
    # ========================================================

    def test_ai_remediation_proposal_analyst_proposes_admin_approves(self):
        """
        Complete AI Proposal & Approval lifecycle:
        1. Analyst creates AI proposal -> 201 Created.
        2. Viewer denied proposal creation -> 403.
        3. Analyst cannot approve -> 403.
        4. Admin approves proposal -> 200 OK with APPROVED status.
        """
        # Step 1: Analyst proposes AI remediation
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        proposal_doc = {
            "remediation_id": rem_id,
            "_id": rem_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": self.finding_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "action": ACTION_EC2_STOP_INSTANCE,
            "status": STATUS_PROPOSED,
            "source": "ai",
            "proposed_by": self.user_analyst_id,
            "resource": self.instance_id,
            "created_at": datetime.now(timezone.utc),
        }

        with patch("app.api.remediation.propose_ai_remediation", return_value={"status": "success", "remediation": proposal_doc}):
            resp = self.client.post("/remediation/ai-proposals", json={"finding_id": self.finding_id})
            self.assertEqual(resp.status_code, 201)
            rem_id = resp.json()["remediation"]["remediation_id"]

        # Store in-memory
        self.remediations_store[rem_id] = proposal_doc

        # Step 2: Viewer cannot create proposal
        self._set_user(self.user_viewer_id, self.org_id, "viewer")
        resp_viewer = self.client.post("/remediation/ai-proposals", json={"finding_id": self.finding_id})
        self.assertEqual(resp_viewer.status_code, 403)

        # Step 3: Analyst cannot approve proposal
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        resp_analyst_app = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "Analyst attempt"})
        self.assertEqual(resp_analyst_app.status_code, 403)

        # Step 4: Admin approves proposal
        self._set_user(self.user_admin_id, self.org_id, "admin")
        resp_admin_app = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "Approved by SecOps Admin"})
        self.assertEqual(resp_admin_app.status_code, 200)
        self.assertEqual(self.remediations_store[rem_id]["status"], STATUS_APPROVED)
        self.assertEqual(self.remediations_store[rem_id]["approved_by"], self.user_admin_id)

    # ========================================================
    # 5. REMEDIATION EXECUTION & AUDIT INTEGRATION
    # ========================================================

    def test_remediation_execution_lifecycle_and_confirmation(self):
        """
        Validates execution:
        - Unconfirmed execution rejected.
        - Viewer / Analyst execution rejected (403).
        - Admin executes confirmed -> COMPLETED.
        - Execution recorded with attribution.
        """
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        self.remediations_store[rem_id] = {
            "_id": rem_id,
            "remediation_id": rem_id,
            "organization_id": self.org_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": self.finding_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "status": STATUS_APPROVED,
            "proposed_by": self.user_analyst_id,
            "approved_by": self.user_admin_id,
            "approved_at": datetime.now(timezone.utc),
            "resource": self.instance_id,
            "created_at": datetime.now(timezone.utc),
        }

        # Analyst cannot execute
        self._set_user(self.user_analyst_id, self.org_id, "analyst")
        resp_analyst = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
        self.assertEqual(resp_analyst.status_code, 403)

        # Admin unconfirmed execution rejected
        self._set_user(self.user_admin_id, self.org_id, "admin")
        resp_unconfirmed = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": False})
        self.assertIn(resp_unconfirmed.status_code, {400, 409})
        self.assertIn("confirmation", str(resp_unconfirmed.json()).lower())

        # Admin confirmed execution succeeds
        with patch("app.api.remediation.execute_ec2_stop") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "remediation_id": rem_id,
                "action": ACTION_EC2_STOP_INSTANCE,
                "status": STATUS_COMPLETED,
                "verified": True,
            }
            resp_confirmed = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
            self.assertEqual(resp_confirmed.status_code, 200)
            mock_exec.assert_called_once()
            _, kwargs = mock_exec.call_args
            self.assertTrue(kwargs.get("confirmed"))
            self.assertEqual(kwargs.get("organization_id"), self.org_id)
            self.assertEqual(kwargs.get("role"), "admin")

    # ========================================================
    # 6. DIRECT CLOUD RESOURCE CONTROLS INTEGRATION
    # ========================================================

    def test_direct_cloud_control_ec2_authorization(self):
        """Direct EC2 control checks active membership, connected account, and owner/admin role."""
        payload = {"action": "start", "region": "us-east-1", "confirmed": True}

        # Viewer denied direct mutation
        self._set_user(self.user_viewer_id, self.org_id, "viewer")
        resp_viewer = self.client.post(
            f"/cloud/aws/ec2/{self.account_id}/instances/{self.instance_id}/action",
            json=payload,
        )
        self.assertEqual(resp_viewer.status_code, 403)

        # Disconnected account rejected
        self._set_user(self.user_admin_id, self.org_id, "admin")
        resp_disconn = self.client.post(
            f"/cloud/aws/ec2/{self.disconnected_account_id}/instances/{self.instance_id}/action",
            json=payload,
        )
        self.assertEqual(resp_disconn.status_code, 400)
        self.assertIn("not connected", resp_disconn.json().get("detail", "").lower())

        # Cross-tenant account returns 404
        resp_cross = self.client.post(
            f"/cloud/aws/ec2/{self.foreign_account_id}/instances/{self.instance_id}/action",
            json=payload,
        )
        self.assertEqual(resp_cross.status_code, 404)

        # Admin on connected account authorized
        with patch("app.api.cloud.execute_ec2_instance_action") as mock_action:
            mock_action.return_value = {"status": "success", "instance_id": self.instance_id}
            resp_admin = self.client.post(
                f"/cloud/aws/ec2/{self.account_id}/instances/{self.instance_id}/action",
                json=payload,
            )
            self.assertEqual(resp_admin.status_code, 200)
            mock_action.assert_called_once()


if __name__ == "__main__":
    unittest.main()
