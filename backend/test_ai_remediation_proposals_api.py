# ============================================================
# CloudGuardAI - Integration Tests for POST /remediation/ai-proposals
# Isolated testing: APP_ENV=test, cloudguardai_test DB, mocked Gemini/AWS
# ============================================================

import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import remediation as remediation_api
from app.middleware.auth_middleware import verify_token
from app.models.remediation import (
    ACTION_EC2_STOP_INSTANCE,
    ACTION_IAM_DISABLE_ACCESS_KEY,
    STATUS_PROPOSED,
)


def _make_app(user=None):
    app = FastAPI()
    app.include_router(remediation_api.router)
    if user is not None:
        app.dependency_overrides[verify_token] = lambda: user
    return app


class AIRemediationProposalsAPITests(unittest.TestCase):
    """Integration tests for the POST /remediation/ai-proposals endpoint."""

    def setUp(self):
        self.user_id = "user-api-test-1"
        self.org_id = "org-api-test-1"
        self.account_id = "acc-api-test-1"
        self.aws_account_id = "123456789012"

        self.user_owner = {
            "_id": self.user_id,
            "organization": self.org_id,
            "email": "owner@company.com",
        }
        self.user_viewer = {
            "_id": "user-viewer-1",
            "organization": self.org_id,
            "email": "viewer@company.com",
        }

        self.account = {
            "_id": self.account_id,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "aws_account_id": self.aws_account_id,
            "status": "connected",
        }

        self.ec2_finding = {
            "_id": "finding-ec2-api-1",
            "finding_id": "finding-ec2-api-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "service": "EC2",
            "resource_type": "EC2_INSTANCE",
            "resource": "i-0123456789abcdef0",
            "severity": "HIGH",
            "status": "OPEN",
            "detection_status": "ACTIVE",
            "issue": "EC2 instance communicates with known command-and-control server.",
            "description": "Outbound communication to malicious host detected.",
        }

        self.iam_finding = {
            "_id": "finding-iam-api-1",
            "finding_id": "finding-iam-api-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "service": "IAM",
            "resource_type": "IAM_ACCESS_KEY",
            "resource": "AKIAIOSFODNN7EXAMPLE",
            "user": "developer-dan",
            "severity": "CRITICAL",
            "status": "OPEN",
            "detection_status": "ACTIVE",
            "issue": "Exposed IAM credentials in public repository.",
            "description": "Active access key detected in public repository.",
        }

    def _setup_membership_mock(self, mock_db, user_id=None, role="owner"):
        membership = {
            "organization_id": self.org_id,
            "user_id": user_id or self.user_id,
            "status": "active",
            "role": role,
        }
        mock_db.organization_members = SimpleNamespace(
            find_one=Mock(return_value=membership)
        )

    # ============================================================
    # 1. Successful Proposal Creation & Lifecycle
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    @patch("app.services.ai_remediation_proposer.get_active_remediation")
    @patch("app.services.ai_remediation_proposer.create_remediation")
    @patch("app.services.ai_remediation_proposer.record_remediation_event")
    def test_create_ai_proposal_ec2_success_201(
        self, mock_audit, mock_create, mock_active, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "EC2_STOP_INSTANCE",
            "rationale": "Stop instance immediately to contain threat.",
            "confidence": 0.95,
            "risk_notes": "Temporary server downtime."
        }"""
        mock_active.return_value = None
        mock_create.return_value = {
            "_id": "rem-api-1",
            "status": STATUS_PROPOSED,
            "source": "ai",
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "resource": "i-0123456789abcdef0",
            "metadata": {
                "confidence": 0.95,
                "rationale": "Stop instance immediately to contain threat.",
                "risk_notes": "Temporary server downtime.",
            },
        }

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertTrue(data["created"])
        self.assertFalse(data["deduplicated"])
        self.assertEqual(data["remediation"]["status"], STATUS_PROPOSED)
        self.assertEqual(data["remediation"]["source"], "ai")
        self.assertEqual(data["remediation"]["resource"], "i-0123456789abcdef0")

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    @patch("app.services.ai_remediation_proposer.get_active_remediation")
    @patch("app.services.ai_remediation_proposer.create_remediation")
    @patch("app.services.ai_remediation_proposer.record_remediation_event")
    def test_create_ai_proposal_iam_masks_credentials_in_response(
        self, mock_audit, mock_create, mock_active, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.iam_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "IAM_DISABLE_ACCESS_KEY",
            "rationale": "Disable exposed access key.",
            "confidence": 0.98,
            "risk_notes": "Revokes access for key."
        }"""
        mock_active.return_value = None
        mock_create.return_value = {
            "_id": "rem-api-iam",
            "status": STATUS_PROPOSED,
            "source": "ai",
            "action_type": ACTION_IAM_DISABLE_ACCESS_KEY,
            "resource": "AKIAIOSFODNN7EXAMPLE",
            "operation": {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "username": "developer-dan"},
        }

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-iam-api-1"},
        )

        self.assertEqual(response.status_code, 201)
        data = response.json()
        operation = data["remediation"].get("operation", {})
        self.assertNotIn("access_key_id", operation)

    # ============================================================
    # 2. No Action & Deduplication Responses (200 OK)
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_create_ai_proposal_no_action_returns_200(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": null,
            "rationale": "No automated action applies to this finding.",
            "confidence": 0.85,
            "risk_notes": "Manual security review recommended."
        }"""

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "no_action")
        self.assertFalse(data["created"])
        self.assertIsNone(data["action_id"])
        self.assertEqual(data["confidence"], 0.85)

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    @patch("app.services.ai_remediation_proposer.get_active_remediation")
    def test_create_ai_proposal_deduplication_returns_200(
        self, mock_active, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "EC2_STOP_INSTANCE",
            "rationale": "Stop instance.",
            "confidence": 0.92,
            "risk_notes": "Downtime."
        }"""
        mock_active.return_value = {
            "_id": "rem-existing-1",
            "status": STATUS_PROPOSED,
            "source": "ai",
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "resource": "i-0123456789abcdef0",
        }

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertFalse(data["created"])
        self.assertTrue(data["deduplicated"])
        self.assertEqual(data["remediation"]["_id"], "rem-existing-1")

    # ============================================================
    # 3. RBAC & Tenant Isolation Gating
    # ============================================================

    def test_unauthenticated_request_rejected_401(self):
        client = TestClient(_make_app(user=None))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )
        self.assertIn(response.status_code, (401, 403))

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_viewer_role_propose_action_forbidden_403(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, user_id="user-viewer-1", role="viewer")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "EC2_STOP_INSTANCE",
            "rationale": "Stop instance.",
            "confidence": 0.90,
            "risk_notes": "None"
        }"""

        client = TestClient(_make_app(user=self.user_viewer))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("not authorized", response.json()["detail"])

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    def test_cross_tenant_finding_returns_404(
        self, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = None

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "other-tenant-finding-999"},
        )

        self.assertEqual(response.status_code, 404)
        self.assertIn("Finding not found", response.json()["detail"])

    # ============================================================
    # 4. Strict Validation Rejections (422)
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_low_confidence_rejected_422(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "EC2_STOP_INSTANCE",
            "rationale": "Maybe stop instance.",
            "confidence": 0.50,
            "risk_notes": "Uncertain."
        }"""

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("below minimum required threshold", response.json()["detail"])

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_extra_fields_in_ai_output_rejected_422(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "EC2_STOP_INSTANCE",
            "rationale": "Stop it.",
            "confidence": 0.95,
            "risk_notes": "None",
            "override_resource": "i-attacker"
        }"""

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("Unexpected extra fields", response.json()["detail"])

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_incompatible_action_rejected_422(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.return_value = """{
            "action_id": "S3_ENABLE_BLOCK_PUBLIC_ACCESS",
            "rationale": "Enable public access block.",
            "confidence": 0.95,
            "risk_notes": "None"
        }"""

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 422)
        self.assertIn("Finding service does not match S3 action", response.json()["detail"])

    # ============================================================
    # 5. Gemini Service Error Handling (503)
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.services.ai_remediation_proposer.get_finding")
    @patch("app.services.ai_remediation_proposer.get_account")
    @patch("app.services.ai_remediation_proposer.generate_raw_text")
    def test_gemini_missing_key_returns_503(
        self, mock_gemini, mock_account, mock_finding, mock_db
    ):
        self._setup_membership_mock(mock_db, role="owner")
        mock_finding.return_value = self.ec2_finding
        mock_account.return_value = self.account
        mock_gemini.side_effect = RuntimeError("GEMINI_API_KEY is not configured")

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals",
            json={"finding_id": "finding-ec2-api-1"},
        )

        self.assertEqual(response.status_code, 503)
        self.assertIn("unconfigured or unavailable", response.json()["detail"])

    # ============================================================
    # 6. Approval Lifecycle Protection (PROPOSED Cannot Execute)
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.api.remediation.get_remediation")
    def test_ai_proposal_cannot_be_executed_without_human_approval(
        self, mock_get_rem, mock_db
    ):
        """Verifies that an AI proposal (PROPOSED status) cannot bypass approval and cannot be executed."""
        self._setup_membership_mock(mock_db, role="owner")
        # Newly created AI proposal in initial status PROPOSED
        proposed_ai_rem = {
            "_id": "rem-ai-proposed-1",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "status": STATUS_PROPOSED,
            "source": "ai",
            "action_type": ACTION_EC2_STOP_INSTANCE,
            "resource": "i-0123456789abcdef0",
        }
        mock_get_rem.return_value = proposed_ai_rem

        client = TestClient(_make_app(user=self.user_owner))
        exec_response = client.post(
            "/remediation/rem-ai-proposed-1/execute",
            json={"confirmed": True},
        )

        self.assertEqual(exec_response.status_code, 409)
        detail = exec_response.json()["detail"]
        self.assertEqual(detail["code"], "APPROVAL_REQUIRED")
        self.assertIn("must be approved before execution", detail["message"])

    # ============================================================
    # 7. Batch AI Proposal Generation: POST /remediation/ai-proposals/batch
    # ============================================================

    @patch("app.api.remediation.db")
    @patch("app.api.remediation.batch_propose_ai_remediations")
    def test_batch_ai_proposals_success(self, mock_batch, mock_db):
        self._setup_membership_mock(mock_db, role="owner")
        mock_batch.return_value = {
            "total": 2,
            "successful": 2,
            "no_action": 0,
            "failed": 0,
            "results": [
                {
                    "finding_id": "f-1",
                    "status": "success",
                    "created": True,
                    "deduplicated": False,
                    "remediation": {"_id": "rem-1", "action_type": ACTION_EC2_STOP_INSTANCE},
                },
                {
                    "finding_id": "f-2",
                    "status": "success",
                    "created": False,
                    "deduplicated": True,
                    "remediation": {"_id": "rem-2", "action_type": ACTION_IAM_DISABLE_ACCESS_KEY},
                },
            ],
        }

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals/batch",
            json={"finding_ids": ["f-1", "f-2"]},
        )

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["successful"], 2)
        self.assertEqual(len(data["results"]), 2)
        self.assertEqual(data["results"][0]["finding_id"], "f-1")

    @patch("app.api.remediation.db")
    def test_batch_ai_proposals_viewer_forbidden(self, mock_db):
        self._setup_membership_mock(mock_db, user_id="user-viewer-1", role="viewer")
        client = TestClient(_make_app(user=self.user_viewer))
        response = client.post(
            "/remediation/ai-proposals/batch",
            json={"finding_ids": ["f-1", "f-2"]},
        )
        self.assertEqual(response.status_code, 403)

    @patch("app.api.remediation.db")
    def test_batch_ai_proposals_empty_list_rejected_422(self, mock_db):
        self._setup_membership_mock(mock_db, role="owner")
        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals/batch",
            json={"finding_ids": []},
        )
        self.assertEqual(response.status_code, 422)

    @patch("app.api.remediation.db")
    def test_batch_ai_proposals_exceeds_max_25_rejected_422(self, mock_db):
        self._setup_membership_mock(mock_db, role="owner")
        client = TestClient(_make_app(user=self.user_owner))
        excessive = [f"f-{i}" for i in range(26)]
        response = client.post(
            "/remediation/ai-proposals/batch",
            json={"finding_ids": excessive},
        )
        self.assertEqual(response.status_code, 422)

    @patch("app.api.remediation.db")
    @patch("app.api.remediation.batch_propose_ai_remediations")
    def test_batch_ai_proposals_partial_failure_isolation(self, mock_batch, mock_db):
        self._setup_membership_mock(mock_db, role="owner")
        mock_batch.return_value = {
            "total": 3,
            "successful": 1,
            "no_action": 1,
            "failed": 1,
            "results": [
                {
                    "finding_id": "f-success",
                    "status": "success",
                    "created": True,
                    "deduplicated": False,
                    "remediation": {"_id": "rem-ok"},
                },
                {
                    "finding_id": "f-noaction",
                    "status": "no_action",
                    "reason": "No registered action",
                    "confidence": 0.9,
                    "rationale": "Monitor",
                    "risk_notes": "None",
                },
                {
                    "finding_id": "f-missing",
                    "status": "error",
                    "error_code": "NOT_FOUND",
                    "error_message": "Finding not found for this tenant",
                },
            ],
        }

        client = TestClient(_make_app(user=self.user_owner))
        response = client.post(
            "/remediation/ai-proposals/batch",
            json={"finding_ids": ["f-success", "f-noaction", "f-missing"]},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 3)
        self.assertEqual(data["successful"], 1)
        self.assertEqual(data["no_action"], 1)
        self.assertEqual(data["failed"], 1)
        self.assertEqual(data["results"][2]["error_code"], "NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
