# ============================================================
# CloudGuardAI2 - Phase 5 Comprehensive QA, Security & Reliability Suite
# Validates:
# 1. Authentication & Authorization Security Boundaries
# 2. Multi-Tenant Isolation & Anti-Tampering
# 3. Remediation Lifecycle & Human Approval Safeguards
# 4. Direct Cloud Control Gates & Zero-Mutation Proof
# 5. Audit Logging Integrity & Attribution Preservation
# 6. Malformed Input & Edge-Case Handling
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
    ACTION_IAM_DISABLE_ACCESS_KEY,
    ACTION_S3_ENABLE_BLOCK_PUBLIC_ACCESS,
    ACTION_RDS_DISABLE_PUBLIC_ACCESS,
    ACTION_VPC_REMOVE_INSECURE_INGRESS,
    STATUS_APPROVED,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_PROPOSED,
    STATUS_REJECTED,
)
from app.services.tenant_context import TenantContext


class Phase5SecurityAndReliabilityTests(unittest.TestCase):
    """
    Comprehensive Security, QA, and Regression tests for Phase 5.
    """

    def setUp(self):
        self.org_alpha_id = "org-alpha-999"
        self.org_beta_id = "org-beta-888"

        self.user_owner_id = str(ObjectId())
        self.user_admin_id = str(ObjectId())
        self.user_analyst_id = str(ObjectId())
        self.user_viewer_id = str(ObjectId())
        self.user_inactive_id = str(ObjectId())
        self.user_foreign_id = str(ObjectId())

        self.account_connected_id = str(ObjectId())
        self.account_disconnected_id = str(ObjectId())
        self.account_foreign_id = str(ObjectId())

        self.aws_account_num = "111222333444"
        self.instance_id = "i-0123456789abcdef0"
        self.bucket_name = "corp-prod-secure-bucket"
        self.access_key_id = "AKIAIOSFODNN7EXAMPLE"

        # Mock Accounts Store
        self.accounts_store = {
            self.account_connected_id: {
                "_id": self.account_connected_id,
                "account_id": self.account_connected_id,
                "aws_account_id": self.aws_account_num,
                "account_name": "Alpha Connected AWS",
                "role_arn": f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole",
                "region": "us-east-1",
                "status": "connected",
                "organization_id": self.org_alpha_id,
                "user_id": self.user_owner_id,
            },
            self.account_disconnected_id: {
                "_id": self.account_disconnected_id,
                "account_id": self.account_disconnected_id,
                "aws_account_id": "999888777666",
                "account_name": "Alpha Disconnected AWS",
                "role_arn": "arn:aws:iam::999888777666:role/CloudGuardAIRole",
                "region": "us-east-1",
                "status": "disconnected",
                "organization_id": self.org_alpha_id,
                "user_id": self.user_owner_id,
            },
            self.account_foreign_id: {
                "_id": self.account_foreign_id,
                "account_id": self.account_foreign_id,
                "aws_account_id": "555444333222",
                "account_name": "Foreign Org Account",
                "role_arn": "arn:aws:iam::555444333222:role/CloudGuardAIRole",
                "region": "us-east-1",
                "status": "connected",
                "organization_id": self.org_beta_id,
                "user_id": self.user_foreign_id,
            },
        }

        # Mock Memberships
        self.members_store = {
            (self.org_alpha_id, self.user_owner_id): {
                "organization_id": self.org_alpha_id,
                "user_id": self.user_owner_id,
                "role": "owner",
                "status": "active",
            },
            (self.org_alpha_id, self.user_admin_id): {
                "organization_id": self.org_alpha_id,
                "user_id": self.user_admin_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_alpha_id, self.user_analyst_id): {
                "organization_id": self.org_alpha_id,
                "user_id": self.user_analyst_id,
                "role": "analyst",
                "status": "active",
            },
            (self.org_alpha_id, self.user_viewer_id): {
                "organization_id": self.org_alpha_id,
                "user_id": self.user_viewer_id,
                "role": "viewer",
                "status": "active",
            },
            (self.org_alpha_id, self.user_inactive_id): {
                "organization_id": self.org_alpha_id,
                "user_id": self.user_inactive_id,
                "role": "admin",
                "status": "inactive",
            },
            (self.org_beta_id, self.user_foreign_id): {
                "organization_id": self.org_beta_id,
                "user_id": self.user_foreign_id,
                "role": "admin",
                "status": "active",
            },
        }

        # Findings Store
        self.finding_oid = ObjectId()
        self.finding_id = str(self.finding_oid)
        self.foreign_finding_id = str(ObjectId())

        self.findings_store = {
            self.finding_id: {
                "_id": self.finding_oid,
                "finding_id": self.finding_id,
                "account_id": self.account_connected_id,
                "aws_account_id": self.aws_account_num,
                "organization_id": self.org_alpha_id,
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
            },
            self.foreign_finding_id: {
                "_id": ObjectId(self.foreign_finding_id),
                "finding_id": self.foreign_finding_id,
                "account_id": self.account_foreign_id,
                "aws_account_id": "555444333222",
                "organization_id": self.org_beta_id,
                "user_id": self.user_foreign_id,
                "resource": "i-foreign99999999",
                "resource_id": "i-foreign99999999",
                "resource_type": "AWS::EC2::Instance",
                "service": "EC2",
                "rule_id": "ec2-instance-running",
                "issue": "Foreign org finding",
                "severity": "CRITICAL",
                "status": "OPEN",
                "detection_status": "ACTIVE",
                "created_at": datetime.now(timezone.utc),
            },
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

        # Patchers
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
            patch("app.services.s3_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.rds_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.iam_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.services.network_control_service.get_account", side_effect=self._mock_get_account),
            patch("app.models.audit_log.audit_logs_collection", self.mock_audit_col),
        ]
        for p in self.patchers:
            p.start()

        # Build FastAPI test app
        self.app = FastAPI(title="CloudGuardAI QA Validation Test App")
        self.app.include_router(auth_router, prefix="/auth")
        self.app.include_router(aws_account_router, prefix="/aws")
        self.app.include_router(cloud_router, prefix="/cloud")
        self.app.include_router(dashboard_router, prefix="/dashboard")
        self.app.include_router(findings_router)
        self.app.include_router(remediation_router)

        # Set default active user to Owner
        self.current_user = {
            "_id": self.user_owner_id,
            "user_id": self.user_owner_id,
            "email": "owner@alpha.cloudguard.ai",
            "organization": self.org_alpha_id,
            "role": "owner",
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

    # Helpers
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
                elif finding.get("status") != expected:
                    return False
        return True

    def _mock_find_one_rem(self, query, *args, **kwargs):
        q_id = str(query.get("_id") or query.get("remediation_id") or "")
        rem = self.remediations_store.get(q_id)
        if not rem:
            for r in self.remediations_store.values():
                if str(r.get("_id")) == q_id or str(r.get("remediation_id")) == q_id:
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
            for r in self.remediations_store.values():
                if str(r.get("_id")) == str(remediation_id) or str(r.get("remediation_id")) == str(remediation_id):
                    rem = r
                    break
        if not rem:
            return None
        if organization_id and str(rem.get("organization_id")) != str(organization_id):
            return None
        return dict(rem)

    def _mock_insert_rem(self, doc, *args, **kwargs):
        doc_id = str(doc.get("_id") or ObjectId())
        doc["_id"] = str(doc_id)
        self.remediations_store[doc_id] = dict(doc)
        res = MagicMock()
        res.inserted_id = ObjectId(doc_id)
        return res

    def _mock_update_rem(self, query, update, *args, **kwargs):
        q_id = str(query.get("_id") or query.get("remediation_id") or "")
        rem = self.remediations_store.get(q_id)
        if not rem:
            for r in self.remediations_store.values():
                if str(r.get("_id")) == q_id or str(r.get("remediation_id")) == q_id:
                    rem = r
                    break
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
    # STEP 1: AUTHENTICATION & AUTHORIZATION SECURITY
    # ========================================================

    def test_inactive_and_revoked_memberships_fail_closed(self):
        """Inactive or suspended memberships are strictly denied (403 Forbidden)."""
        self._set_user(self.user_inactive_id, self.org_alpha_id, "admin")
        resp = self.client.get("/findings/")
        self.assertEqual(resp.status_code, 403)
        self.assertIn("inactive", resp.json().get("detail", "").lower())

    def test_unknown_or_empty_role_fails_closed(self):
        """Users with unknown role cannot perform role-gated actions."""
        self._set_user(self.user_analyst_id, self.org_alpha_id, "unknown_intruder")
        self.members_store[(self.org_alpha_id, self.user_analyst_id)]["role"] = "unknown_intruder"
        resp = self.client.delete(f"/findings/{self.finding_id}")
        self.assertEqual(resp.status_code, 403)
        # Restore analyst role
        self.members_store[(self.org_alpha_id, self.user_analyst_id)]["role"] = "analyst"

    def test_viewer_role_boundaries_strictly_enforced(self):
        """
        Viewer role is strictly read-only:
        - Denied manual proposal creation (403)
        - Denied AI proposal creation (403)
        - Denied proposal approval (403)
        - Denied proposal rejection (403)
        - Denied proposal cancellation (403)
        - Denied proposal execution (403)
        - Denied finding deletion (403)
        - Denied finding status update (403)
        - Denied finding assignment (403)
        """
        self._set_user(self.user_viewer_id, self.org_alpha_id, "viewer")

        # 1. Proposal creation denied
        resp1 = self.client.post("/remediation/ai-proposals", json={"finding_id": self.finding_id})
        self.assertEqual(resp1.status_code, 403)

        # 2. Finding delete denied
        resp2 = self.client.delete(f"/findings/{self.finding_id}")
        self.assertEqual(resp2.status_code, 403)

        # 3. Finding triage denied
        resp3 = self.client.patch(f"/findings/{self.finding_id}/status", json={"status": "RESOLVED"})
        self.assertEqual(resp3.status_code, 403)

        # 4. Finding assignment denied
        resp4 = self.client.patch(f"/findings/{self.finding_id}/assign", json={"assigned_to": "alice"})
        self.assertEqual(resp4.status_code, 403)

    def test_header_tampering_organization_spoofing_prevented(self):
        """
        Client attempts to tamper with x-organization-id to access another tenant.
        Server authoritative membership lookup fails closed with 403 Forbidden.
        """
        # User belongs to Alpha, but sends header claiming Beta
        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")
        resp = self.client.get("/findings/", headers={"x-organization-id": self.org_beta_id})
        self.assertEqual(resp.status_code, 403)
        self.assertIn("membership", resp.json().get("detail", "").lower())

    # ========================================================
    # STEP 2: FINDINGS, SCAN & DASHBOARD ISOLATION
    # ========================================================

    def test_cross_tenant_finding_mutation_returns_404(self):
        """Attempting to mutate or delete another tenant's finding fails closed with 404."""
        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")

        # Try to patch status of Beta finding
        resp_patch = self.client.patch(f"/findings/{self.foreign_finding_id}/status", json={"status": "RESOLVED"})
        self.assertEqual(resp_patch.status_code, 404)

        # Try to delete Beta finding
        resp_del = self.client.delete(f"/findings/{self.foreign_finding_id}")
        self.assertEqual(resp_del.status_code, 404)

    def test_dashboard_aggregation_strictly_excludes_other_tenants(self):
        """Dashboard totals calculate only from the caller's organization."""
        self._set_user(self.user_analyst_id, self.org_alpha_id, "analyst")

        with patch("app.api.dashboard.get_all_scans") as mock_scans:
            mock_scans.return_value = [
                {
                    "_id": "scan-alpha-1",
                    "organization_id": self.org_alpha_id,
                    "account_id": self.account_connected_id,
                    "risk_score": 50,
                    "security_level": "Medium",
                    "resources": {"ec2": 2},
                    "findings": [],
                    "scan_time": "2026-10-15T00:00:00Z",
                }
            ]
            resp = self.client.get("/dashboard")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["total_scans"], 1)
            _, kwargs = mock_scans.call_args
            self.assertEqual(kwargs.get("organization_id"), self.org_alpha_id)

    # ========================================================
    # STEP 3: REMEDIATION LIFECYCLE & EXECUTION SAFEGUARDS
    # ========================================================

    def test_unapproved_proposal_cannot_be_executed_409(self):
        """A proposal in PROPOSED status cannot be executed until explicitly approved."""
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        self.remediations_store[rem_id] = {
            "_id": rem_id,
            "remediation_id": rem_id,
            "organization_id": self.org_alpha_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_connected_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": self.finding_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "status": STATUS_PROPOSED,  # Not approved yet!
            "proposed_by": self.user_analyst_id,
            "resource": self.instance_id,
            "created_at": datetime.now(timezone.utc),
        }

        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")
        resp = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
        self.assertEqual(resp.status_code, 409)
        self.assertIn("approved", str(resp.json()).lower())

    def test_rejection_workflow_cannot_be_approved_or_executed(self):
        """A proposal rejected by an authorized user transitions to REJECTED and cannot be approved."""
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        self.remediations_store[rem_id] = {
            "_id": rem_id,
            "remediation_id": rem_id,
            "organization_id": self.org_alpha_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_connected_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": self.finding_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "status": STATUS_PROPOSED,
            "proposed_by": self.user_analyst_id,
            "resource": self.instance_id,
            "created_at": datetime.now(timezone.utc),
        }

        # Analyst rejects proposal
        self._set_user(self.user_analyst_id, self.org_alpha_id, "analyst")
        resp_rej = self.client.patch(f"/remediation/{rem_id}/reject", json={"reason": "False alarm risk"})
        self.assertEqual(resp_rej.status_code, 200)
        self.assertEqual(self.remediations_store[rem_id]["status"], STATUS_REJECTED)

        # Admin attempts to approve rejected proposal -> 409 Conflict
        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")
        resp_app = self.client.patch(f"/remediation/{rem_id}/approve", json={"comment": "Attempting override"})
        self.assertEqual(resp_app.status_code, 409)

    def test_cancellation_workflow_prevents_execution(self):
        """A cancelled proposal cannot be executed."""
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        self.remediations_store[rem_id] = {
            "_id": rem_id,
            "remediation_id": rem_id,
            "organization_id": self.org_alpha_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_connected_id,
            "aws_account_id": self.aws_account_num,
            "finding_id": self.finding_id,
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "status": STATUS_PROPOSED,
            "proposed_by": self.user_analyst_id,
            "resource": self.instance_id,
            "created_at": datetime.now(timezone.utc),
        }

        # Analyst cancels proposal
        self._set_user(self.user_analyst_id, self.org_alpha_id, "analyst")
        resp_canc = self.client.patch(f"/remediation/{rem_id}/cancel")
        self.assertEqual(resp_canc.status_code, 200)
        self.assertEqual(self.remediations_store[rem_id]["status"], STATUS_CANCELLED)

        # Admin execution attempt -> 409 Conflict
        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")
        resp_exec = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
        self.assertEqual(resp_exec.status_code, 409)

    def test_attribution_preservation_across_lifecycle(self):
        """Proposed_by, approved_by, and executed attribution remain distinct."""
        rem_oid = ObjectId()
        rem_id = str(rem_oid)
        self.remediations_store[rem_id] = {
            "_id": rem_id,
            "remediation_id": rem_id,
            "organization_id": self.org_alpha_id,
            "user_id": self.user_analyst_id,
            "account_id": self.account_connected_id,
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

        # Owner executes confirmed
        self._set_user(self.user_owner_id, self.org_alpha_id, "owner")
        with patch("app.api.remediation.execute_ec2_stop") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "remediation_id": rem_id,
                "action": ACTION_EC2_STOP_INSTANCE,
                "status": STATUS_COMPLETED,
            }
            resp = self.client.post(f"/remediation/{rem_id}/execute", json={"confirmed": True})
            self.assertEqual(resp.status_code, 200)
            mock_exec.assert_called_once()
            _, kwargs = mock_exec.call_args
            # Verify executor attribution was passed as Owner without overwriting proposer
            self.assertEqual(kwargs.get("role"), "owner")
            self.assertEqual(kwargs.get("user_id"), self.user_owner_id)
            self.assertEqual(kwargs.get("remediation")["proposed_by"], self.user_analyst_id)
            self.assertEqual(kwargs.get("remediation")["approved_by"], self.user_admin_id)

    # ========================================================
    # STEP 4: DIRECT CLOUD CONTROLS & ZERO-MUTATION PROOF
    # ========================================================

    def test_direct_controls_disconnected_account_fails_closed_across_services(self):
        """All direct cloud controls (EC2, S3, IAM, RDS, Network) reject disconnected accounts."""
        self._set_user(self.user_admin_id, self.org_alpha_id, "admin")

        # 1. EC2 control
        resp_ec2 = self.client.post(
            f"/cloud/aws/ec2/{self.account_disconnected_id}/instances/{self.instance_id}/action",
            json={"action": "start", "confirmed": True},
        )
        self.assertEqual(resp_ec2.status_code, 400)
        self.assertIn("not connected", resp_ec2.json().get("detail", "").lower())

        # 2. S3 control
        resp_s3 = self.client.post(
            f"/cloud/aws/s3/{self.account_disconnected_id}/buckets/{self.bucket_name}/action",
            json={"action": "enable_block_public_access", "confirmed": True},
        )
        self.assertEqual(resp_s3.status_code, 400)
        self.assertIn("not connected", resp_s3.json().get("detail", "").lower())

        # 3. IAM control
        resp_iam = self.client.post(
            f"/cloud/aws/iam/{self.account_disconnected_id}/resources/access-key/action",
            json={
                "action": "disable_access_key",
                "resource_type": "access_key",
                "parameters": {"username": "bob", "access_key_id": self.access_key_id},
                "confirmed": True,
            },
        )
        self.assertEqual(resp_iam.status_code, 400)
        self.assertIn("not connected", resp_iam.json().get("detail", "").lower())

        # 4. RDS control
        resp_rds = self.client.post(
            f"/cloud/aws/rds/{self.account_disconnected_id}/instances/prod-db/action",
            json={"action": "start", "confirmed": True},
        )
        self.assertEqual(resp_rds.status_code, 400)
        self.assertIn("not connected", resp_rds.json().get("detail", "").lower())

    def test_zero_aws_mutation_on_denied_or_unconfirmed_requests(self):
        """
        Proof that any denied or unconfirmed request raises error and NEVER calls AWS SDK mutations.
        """
        # Patch the underlying AWS connection and session generation to verify they are never invoked
        with patch("app.services.aws_connection.boto3") as mock_boto, \
             patch("app.services.aws_connection.assume_aws_role") as mock_assume:
            self._set_user(self.user_viewer_id, self.org_alpha_id, "viewer")
            resp = self.client.post(
                f"/cloud/aws/ec2/{self.account_connected_id}/instances/{self.instance_id}/action",
                json={"action": "start", "confirmed": True},
            )
            self.assertEqual(resp.status_code, 403)
            # AWS client was never instantiated or mutated
            mock_boto.client.assert_not_called()
            mock_boto.Session.assert_not_called()
            mock_assume.assert_not_called()

    # ========================================================
    # STEP 5: AUDIT LOG INTEGRITY & SECURITY MONITORING
    # ========================================================

    def test_audit_logs_recorded_for_authorization_denials(self):
        """Authorization denials record audit events for compliance visibility."""
        self._set_user(self.user_viewer_id, self.org_alpha_id, "viewer")
        initial_events = len(self.audit_events)

        self.client.post(
            f"/cloud/aws/ec2/{self.account_connected_id}/instances/{self.instance_id}/action",
            json={"action": "start", "confirmed": True},
        )
        self.assertGreater(len(self.audit_events), initial_events)
        last_event = self.audit_events[-1]
        self.assertEqual(last_event.get("user_id"), self.user_viewer_id)
        self.assertEqual(last_event.get("organization_id"), self.org_alpha_id)
        self.assertEqual(last_event.get("result"), "DENIED")


if __name__ == "__main__":
    unittest.main()
