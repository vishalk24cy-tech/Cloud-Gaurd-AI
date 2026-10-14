# ============================================================
# CloudGuardAI - Unit & Integration Tests for Scan Jobs & Worker
# Phase 3B: Scan-Job Tenant Isolation & Authorization
# ============================================================

import contextlib
import io
import os
import sys
import unittest
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

from app.api.scan_jobs import router as scan_jobs_router
from app.api.scan_worker import optional_verify_token, router as scan_worker_router
from app.middleware.auth_middleware import verify_token


class TestScanJobsTenantIsolation(unittest.TestCase):
    """
    Focused test suite verifying tenant isolation, role enforcement,
    connected AWS account ownership, and worker endpoint security.
    """

    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_a_id = "org-alpha-123"
        self.org_b_id = "org-beta-456"
        self.email = "analyst@alpha.cloudguard.ai"

        self.account_a_id = str(ObjectId())
        self.account_b_id = str(ObjectId())

        self.valid_jwt_user_a = {
            "_id": self.user_id,
            "email": self.email,
            "organization": self.org_a_id,
            "role": "analyst",
        }

        # Connected AWS account in Org A
        self.mock_account_a = {
            "_id": self.account_a_id,
            "user_id": self.user_id,
            "organization_id": self.org_a_id,
            "account_name": "Production AWS",
            "aws_account_id": "111122223333",
            "status": "connected",
        }

        # Disconnected AWS account in Org A
        self.mock_account_a_disconnected = {
            "_id": str(ObjectId()),
            "user_id": self.user_id,
            "organization_id": self.org_a_id,
            "account_name": "Disconnected AWS",
            "aws_account_id": "111122223334",
            "status": "disconnected",
        }

        # Connected AWS account in Org B
        self.mock_account_b = {
            "_id": self.account_b_id,
            "user_id": str(ObjectId()),
            "organization_id": self.org_b_id,
            "account_name": "Org B AWS",
            "aws_account_id": "999988887777",
            "status": "connected",
        }

        # Membership record for User in Org A (analyst by default)
        self.mock_member_analyst = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "analyst",
            "status": "active",
            "email": self.email,
        }

        # Create FastAPI Test App
        self.app = FastAPI()
        self.app.include_router(scan_jobs_router)
        self.app.include_router(scan_worker_router)

        # Override verify_token dependency by default to return valid_jwt_user_a
        self.app.dependency_overrides[verify_token] = lambda: self.valid_jwt_user_a
        self.app.dependency_overrides[optional_verify_token] = lambda: self.valid_jwt_user_a
        self.client = TestClient(self.app)

    # ============================================================
    # 1. Authorized Scan Creation Tests
    # ============================================================

    @patch("app.api.scan_jobs.get_account")
    @patch("app.api.scan_jobs.create_scan_job")
    @patch("app.services.tenant_context.db")
    def test_analyst_can_create_scan_job_for_connected_account(
        self, mock_tenant_db, mock_create_scan_job, mock_get_account
    ):
        mock_tenant_db.organization_members.find_one.return_value = self.mock_member_analyst
        mock_get_account.return_value = self.mock_account_a
        mock_create_scan_job.return_value = {
            "_id": "job-101",
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "account_id": self.account_a_id,
            "aws_account_id": "111122223333",
            "status": "queued",
        }

        response = self.client.post(f"/scan-jobs?account_id={self.account_a_id}")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["job"]["_id"], "job-101")
        mock_get_account.assert_called_once_with(
            account_id=self.account_a_id,
            organization_id=self.org_a_id,
        )
        mock_create_scan_job.assert_called_once_with(
            organization_id=self.org_a_id,
            user_id=self.user_id,
            account_id=self.account_a_id,
            aws_account_id="111122223333",
        )

    @patch("app.api.scan_jobs.get_account")
    @patch("app.api.scan_jobs.create_scan_job")
    @patch("app.services.tenant_context.db")
    def test_owner_and_admin_can_create_scan_job(
        self, mock_tenant_db, mock_create_scan_job, mock_get_account
    ):
        mock_get_account.return_value = self.mock_account_a
        mock_create_scan_job.return_value = {"_id": "job-owner", "status": "queued"}

        for role in ["owner", "admin"]:
            mock_tenant_db.organization_members.find_one.return_value = {
                "organization_id": self.org_a_id,
                "user_id": self.user_id,
                "role": role,
                "status": "active",
            }
            response = self.client.post(f"/scan-jobs?account_id={self.account_a_id}")
            self.assertEqual(response.status_code, 200, f"Role {role} failed to create scan job")

    # ============================================================
    # 2. Viewer Role Denial
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_viewer_denied_scan_job_creation(self, mock_tenant_db):
        mock_tenant_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "viewer",
            "status": "active",
        }

        response = self.client.post(f"/scan-jobs?account_id={self.account_a_id}")

        self.assertEqual(response.status_code, 403)
        self.assertIn("Requires one of roles: admin, analyst, owner", response.json()["detail"])

    # ============================================================
    # 3. Inactive / Revoked / Suspended Membership Denial
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_inactive_and_revoked_memberships_denied(self, mock_tenant_db):
        for status in ["inactive", "revoked", "suspended", "removed"]:
            mock_tenant_db.organization_members.find_one.return_value = {
                "organization_id": self.org_a_id,
                "user_id": self.user_id,
                "role": "owner",
                "status": status,
            }

            response = self.client.post(f"/scan-jobs?account_id={self.account_a_id}")
            self.assertEqual(response.status_code, 403)
            self.assertIn(f"membership is {status}", response.json()["detail"])

    @patch("app.services.tenant_context.db")
    def test_missing_membership_document_denied(self, mock_tenant_db):
        mock_tenant_db.organization_members.find_one.return_value = None

        response = self.client.post(f"/scan-jobs?account_id={self.account_a_id}")
        self.assertEqual(response.status_code, 403)
        self.assertIn("Organization membership not found", response.json()["detail"])

    # ============================================================
    # 4. Cross-Tenant Account Rejection
    # ============================================================

    @patch("app.api.scan_jobs.get_account")
    @patch("app.services.tenant_context.db")
    def test_cross_tenant_account_id_rejected_404(
        self, mock_tenant_db, mock_get_account
    ):
        """User in Org A provides an account_id that belongs to Org B."""
        mock_tenant_db.organization_members.find_one.return_value = self.mock_member_analyst
        # get_account scoped to Org A returns None when account_id is in Org B
        mock_get_account.return_value = None

        response = self.client.post(f"/scan-jobs?account_id={self.account_b_id}")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Connected AWS account not found in organization", response.json()["detail"])
        mock_get_account.assert_called_once_with(
            account_id=self.account_b_id,
            organization_id=self.org_a_id,
        )

    # ============================================================
    # 5. Disconnected Account Rejection
    # ============================================================

    @patch("app.api.scan_jobs.get_account")
    @patch("app.services.tenant_context.db")
    def test_disconnected_account_rejected_400(
        self, mock_tenant_db, mock_get_account
    ):
        mock_tenant_db.organization_members.find_one.return_value = self.mock_member_analyst
        mock_get_account.return_value = self.mock_account_a_disconnected

        response = self.client.post(
            f"/scan-jobs?account_id={self.mock_account_a_disconnected['_id']}"
        )

        self.assertEqual(response.status_code, 400)
        self.assertIn("AWS account is not connected", response.json()["detail"])

    # ============================================================
    # 6. Tenant-Scoped Listing & Retrieval
    # ============================================================

    @patch("app.api.scan_jobs.get_scan_jobs")
    @patch("app.services.tenant_context.db")
    def test_list_jobs_scoped_to_organization(
        self, mock_tenant_db, mock_get_scan_jobs
    ):
        mock_tenant_db.organization_members.find_one.return_value = self.mock_member_analyst
        mock_get_scan_jobs.return_value = [
            {"_id": "job-1", "organization_id": self.org_a_id, "status": "completed"}
        ]

        response = self.client.get("/scan-jobs")

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["count"], 1)
        mock_get_scan_jobs.assert_called_once_with(
            organization_id=self.org_a_id,
            limit=50,
            status=None,
        )

    @patch("app.api.scan_jobs.get_scan_job")
    @patch("app.services.tenant_context.db")
    def test_get_job_cross_tenant_rejected_404(
        self, mock_tenant_db, mock_get_scan_job
    ):
        """Cross-tenant job query must return 404 without leaking existence."""
        mock_tenant_db.organization_members.find_one.return_value = self.mock_member_analyst
        mock_get_scan_job.return_value = None  # Not found in Org A

        response = self.client.get("/scan-jobs/job-belonging-to-org-b")

        self.assertEqual(response.status_code, 404)
        self.assertIn("Scan job not found", response.json()["detail"])
        mock_get_scan_job.assert_called_once_with(
            job_id="job-belonging-to-org-b",
            organization_id=self.org_a_id,
        )

    # ============================================================
    # 7. Worker Authentication & Processing Security Tests
    # ============================================================

    @patch("app.api.scan_worker.db")
    def test_worker_endpoint_unauthenticated_fails_closed(self, mock_worker_db):
        """Request without worker secret or auth header must fail closed (401)."""
        # Clear dependency override for verify_token to test raw auth requirement
        app_no_auth = FastAPI()
        app_no_auth.include_router(scan_worker_router)
        client_no_auth = TestClient(app_no_auth)

        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,
        }

        response = client_no_auth.post(f"/scan-worker/{valid_job_id}/process")
        self.assertEqual(response.status_code, 401)

    @patch("app.api.scan_worker.db")
    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": "top-secret-worker-key"})
    def test_worker_endpoint_invalid_worker_key_fails_closed(self, mock_worker_db):
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,
        }

        response = self.client.post(
            f"/scan-worker/{valid_job_id}/process",
            headers={"X-Internal-Worker-Key": "wrong-key"},
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid internal worker credentials", response.json()["detail"])

    @patch("app.api.scan_worker.process_scan_job")
    @patch("app.api.scan_worker.db")
    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": "top-secret-worker-key"})
    def test_worker_endpoint_valid_worker_key_succeeds(
        self, mock_worker_db, mock_process_scan_job
    ):
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,
        }
        mock_process_scan_job.return_value = {"status": "completed", "job_id": valid_job_id}

        response = self.client.post(
            f"/scan-worker/{valid_job_id}/process",
            headers={"X-Internal-Worker-Key": "top-secret-worker-key"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "completed")
        mock_process_scan_job.assert_called_once_with(
            job_id=valid_job_id,
            organization_id=self.org_a_id,
        )

    @patch("app.api.scan_worker.db")
    @patch.dict(os.environ, {"SCAN_WORKER_SECRET": "top-secret-worker-key"})
    def test_worker_key_cannot_select_arbitrary_organization(self, mock_worker_db):
        """Worker key request with mismatched X-Organization-ID must fail closed (403)."""
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,  # Job belongs to Org A
        }

        response = self.client.post(
            f"/scan-worker/{valid_job_id}/process",
            headers={
                "X-Internal-Worker-Key": "top-secret-worker-key",
                "X-Organization-ID": self.org_b_id,  # Caller tries to target Org B
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertIn("Target organization does not match scan job organization", response.json()["detail"])

    @patch("app.api.scan_worker.process_scan_job")
    @patch("app.services.tenant_context.db")
    @patch("app.api.scan_worker.db")
    def test_admin_jwt_can_trigger_worker_without_secret(
        self, mock_worker_db, mock_tenant_db, mock_process_scan_job
    ):
        """Human owner or admin can manually trigger processing for their org's job."""
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,
        }
        mock_tenant_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "admin",
            "status": "active",
        }
        mock_process_scan_job.return_value = {"status": "completed"}

        response = self.client.post(
            f"/scan-worker/{valid_job_id}/process",
            headers={"Authorization": "Bearer valid-admin-jwt"},
        )

        self.assertEqual(response.status_code, 200)
        mock_process_scan_job.assert_called_once_with(
            job_id=valid_job_id,
            organization_id=self.org_a_id,
        )

    @patch("app.services.tenant_context.db")
    @patch("app.api.scan_worker.db")
    def test_analyst_and_viewer_jwt_denied_worker_trigger(
        self, mock_worker_db, mock_tenant_db
    ):
        """Ordinary analysts and viewers cannot manually trigger scan worker processing."""
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_a_id,
        }

        for role in ["analyst", "viewer"]:
            mock_tenant_db.organization_members.find_one.return_value = {
                "organization_id": self.org_a_id,
                "user_id": self.user_id,
                "role": role,
                "status": "active",
            }

            response = self.client.post(
                f"/scan-worker/{valid_job_id}/process",
                headers={"Authorization": "Bearer user-jwt"},
            )

            self.assertEqual(response.status_code, 403)
            self.assertIn("Requires one of roles: admin, owner", response.json()["detail"])

    @patch("app.services.tenant_context.db")
    @patch("app.api.scan_worker.db")
    def test_admin_cannot_trigger_worker_for_cross_tenant_job(
        self, mock_worker_db, mock_tenant_db
    ):
        """Admin in Org A attempts to trigger worker for job belonging to Org B."""
        valid_job_id = str(ObjectId())
        mock_worker_db.scan_jobs.find_one.return_value = {
            "_id": ObjectId(valid_job_id),
            "organization_id": self.org_b_id,  # Job in Org B
        }
        # Admin has no membership in Org B
        mock_tenant_db.organization_members.find_one.return_value = None

        response = self.client.post(
            f"/scan-worker/{valid_job_id}/process",
            headers={"Authorization": "Bearer admin-jwt"},
        )

        # Fails closed (403 or 404, never allows execution)
        self.assertIn(response.status_code, [403, 404])


if __name__ == "__main__":
    unittest.main()
