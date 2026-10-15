# ============================================================
# CloudGuardAI - Phase 7B AWS Connection & Verification Tests
# Mocked security and regression tests for ExternalId handling,
# STS pre-flight verification, tenant isolation, and scan routes.
# ============================================================

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import ClientError, ConnectTimeoutError
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

from app.api.aws_accounts import router as aws_account_router
from app.api.cloud import router as cloud_router
from app.middleware.auth_middleware import verify_token
from app.models.aws_account import (
    generate_external_id,
    verify_external_id_binding,
    ensure_external_id,
    create_aws_account,
    update_account_verification,
)
from app.services.aws_connection import (
    assume_aws_role,
    verify_aws_role_connection,
    verify_aws_account,
)


class TestAWSConnectionVerification(unittest.TestCase):
    """
    Security and regression test suite for Phase 7B:
    - Secure ExternalId generation and cryptographic binding
    - Prevention of Confused Deputy and cross-tenant substitution
    - STS pre-flight verification handshake (AssumeRole + GetCallerIdentity)
    - Safe failure modes without leaking secrets or ExternalId
    - Tenant isolation and RBAC enforcement
    - Legacy account migration compatibility
    - Scan route alignment across /cloud/aws/scan and /aws/scan
    """

    def setUp(self):
        self.org_alpha = "org-alpha-777"
        self.org_beta = "org-beta-888"

        self.user_owner_id = str(ObjectId())
        self.user_admin_id = str(ObjectId())
        self.user_viewer_id = str(ObjectId())
        self.foreign_user_id = str(ObjectId())

        self.aws_account_num = "123456789012"
        self.role_arn = f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole"
        self.account_oid = ObjectId()
        self.account_id = str(self.account_oid)

        # ExternalId bound to org_alpha
        self.external_id_alpha = generate_external_id(self.org_alpha)

        # In-memory account document
        self.account_doc = {
            "_id": self.account_oid,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Alpha Production AWS",
            "role_arn": self.role_arn,
            "region": "us-east-1",
            "status": "pending_verification",
            "external_id": self.external_id_alpha,
            "organization_id": self.org_alpha,
            "user_id": self.user_owner_id,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
            "last_connected_at": None,
            "last_scan_at": None,
            "verification_error": None,
        }

        self.accounts_store = {
            self.account_id: self.account_doc,
        }

        self.members_store = {
            (self.org_alpha, self.user_owner_id): {
                "organization_id": self.org_alpha,
                "user_id": self.user_owner_id,
                "role": "owner",
                "status": "active",
            },
            (self.org_alpha, self.user_admin_id): {
                "organization_id": self.org_alpha,
                "user_id": self.user_admin_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_alpha, self.user_viewer_id): {
                "organization_id": self.org_alpha,
                "user_id": self.user_viewer_id,
                "role": "viewer",
                "status": "active",
            },
            (self.org_beta, self.foreign_user_id): {
                "organization_id": self.org_beta,
                "user_id": self.foreign_user_id,
                "role": "admin",
                "status": "active",
            },
        }

        # Mock database
        self.mock_db = MagicMock()
        self.mock_db.organization_members.find_one.side_effect = self._mock_find_member
        self.mock_db.aws_accounts.find_one.side_effect = self._mock_find_account
        self.mock_db.aws_accounts.update_one.side_effect = self._mock_update_account
        self.mock_db.aws_accounts.insert_one.side_effect = self._mock_insert_account

        self.patchers = [
            patch("app.database.connection.db", self.mock_db),
            patch("app.api.aws_accounts.db", self.mock_db),
            patch("app.models.aws_account.aws_accounts_collection", self.mock_db.aws_accounts),
            patch("app.api.aws_accounts.get_account", side_effect=self._mock_get_account),
            patch("app.models.aws_account.get_account", side_effect=self._mock_get_account),
            patch("app.api.cloud.get_account", side_effect=self._mock_get_account),
            patch("app.api.aws_accounts.enforce_quota", return_value={"allowed": True, "limit": 10}),
            patch("app.api.aws_accounts.reserve_usage", return_value={"reserved": True}),
            patch("app.api.aws_accounts.release_usage", return_value=True),
        ]
        for p in self.patchers:
            p.start()

        self.app = FastAPI(title="CloudGuardAI Phase 7B Tests")
        self.app.include_router(aws_account_router, prefix="/aws")
        self.app.include_router(cloud_router, prefix="/cloud")

        self.current_user = None

        def _mock_verify_token():
            if not self.current_user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            return self.current_user

        self.app.dependency_overrides[verify_token] = _mock_verify_token
        self.client = TestClient(self.app)

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()

    def _mock_find_member(self, query):
        org_id = query.get("organization_id")
        user_id = query.get("user_id")
        status = query.get("status")
        member = self.members_store.get((org_id, user_id))
        if member and (status is None or member.get("status") == status):
            return member
        return None

    def _mock_find_account(self, query):
        acc_id = str(query.get("_id", ""))
        org_id = query.get("organization_id")
        acc = self.accounts_store.get(acc_id)
        if acc and (org_id is None or acc.get("organization_id") == org_id):
            return dict(acc)
        return None

    def _mock_get_account(self, account_id, organization_id=None, user_id=None):
        acc = self.accounts_store.get(str(account_id))
        if acc and (organization_id is None or acc.get("organization_id") == organization_id):
            return dict(acc)
        return None

    def _mock_update_account(self, query, update):
        acc_id = str(query.get("_id", ""))
        acc = self.accounts_store.get(acc_id)
        if acc:
            set_vals = update.get("$set", {})
            acc.update(set_vals)
            res = MagicMock()
            res.modified_count = 1
            return res
        res = MagicMock()
        res.modified_count = 0
        return res

    def _mock_insert_account(self, doc):
        oid = ObjectId()
        doc["_id"] = oid
        self.accounts_store[str(oid)] = doc
        res = MagicMock()
        res.inserted_id = oid
        return res

    def _get_error_detail(self, response):
        body = response.json()
        return body.get("detail") or body.get("message") or ""

    # --------------------------------------------------------
    # STEP 1: ExternalId Generation & Binding Tests
    # --------------------------------------------------------

    def test_setup_intent_authorized_for_owner_and_admin(self):
        """Owners and Admins can obtain the organization-bound ExternalId."""
        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }
        res = self.client.get("/aws/setup-intent")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["organization_id"], self.org_alpha)
        self.assertTrue(data["external_id"].startswith(f"cg_{self.org_alpha[:8]}"))
        self.assertTrue(verify_external_id_binding(data["external_id"], self.org_alpha))
        self.assertIn("trust_policy_template", data)

    def test_setup_intent_rejected_for_viewer(self):
        """Viewers are rejected with 403 when requesting setup intent."""
        self.current_user = {
            "_id": self.user_viewer_id,
            "organization": self.org_alpha,
            "email": "viewer@alpha.com",
        }
        res = self.client.get("/aws/setup-intent")
        self.assertEqual(res.status_code, 403)
        detail = self._get_error_detail(res)
        self.assertIn("owners and admins", detail.lower())

    def test_setup_intent_rejected_unauthenticated(self):
        """Unauthenticated requests are rejected with 401."""
        self.current_user = None
        res = self.client.get("/aws/setup-intent")
        self.assertEqual(res.status_code, 401)

    def test_external_id_cross_tenant_substitution_prevented(self):
        """An ExternalId generated for Org Alpha is rejected when connecting Org Beta."""
        external_id_for_alpha = generate_external_id(self.org_alpha)
        # Verify valid for Alpha
        self.assertTrue(verify_external_id_binding(external_id_for_alpha, self.org_alpha))
        # Verify invalid for Beta
        self.assertFalse(verify_external_id_binding(external_id_for_alpha, self.org_beta))

        # Attempt to use Alpha's ExternalId on Beta
        self.current_user = {
            "_id": self.foreign_user_id,
            "organization": self.org_beta,
            "email": "admin@beta.com",
        }
        payload = {
            "account_name": "Beta AWS",
            "aws_account_id": "111222333444",
            "role_arn": "arn:aws:iam::111222333444:role/BetaRole",
            "region": "us-east-1",
            "external_id": external_id_for_alpha,
        }
        res = self.client.post("/aws/connect", json=payload)
        self.assertEqual(res.status_code, 400)
        detail = self._get_error_detail(res)
        self.assertIn("ExternalId does not match organization binding", detail)

    def test_connect_account_without_external_id_auto_generates_bound_id(self):
        """Connecting an account without an ExternalId auto-generates a valid, org-bound ExternalId."""
        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }
        payload = {
            "account_name": "Alpha New Account",
            "aws_account_id": "987654321098",
            "role_arn": "arn:aws:iam::987654321098:role/ScannerRole",
            "region": "ap-south-1",
        }
        res = self.client.post("/aws/connect", json=payload)
        self.assertEqual(res.status_code, 200)
        acc = res.json()["account"]
        self.assertEqual(acc["status"], "pending_verification")
        self.assertTrue(acc["external_id"].startswith(f"cg_{self.org_alpha[:8]}"))
        self.assertTrue(verify_external_id_binding(acc["external_id"], self.org_alpha))

    # --------------------------------------------------------
    # STEP 2: STS Pre-Flight Verification Tests
    # --------------------------------------------------------

    @patch("app.services.aws_connection.boto3.Session")
    @patch("app.services.aws_connection.boto3.client")
    def test_successful_verification_handshake(self, mock_boto_client, mock_boto_session):
        """
        Successful STS AssumeRole with exact stored ExternalId and matching
        GetCallerIdentity transitions account to 'connected'.
        """
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_MOCK_KEY",
                "SecretAccessKey": "MOCK_SECRET",
                "SessionToken": "MOCK_TOKEN",
            }
        }
        mock_sts.get_caller_identity.return_value = {
            "Account": self.aws_account_num,
            "Arn": f"arn:aws:sts::{self.aws_account_num}:assumed-role/CloudGuardAIRole/CloudGuardAI-PreflightVerification",
            "UserId": "AROA_MOCK_USER:CloudGuardAI-PreflightVerification",
        }
        mock_boto_client.return_value = mock_sts

        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_sts
        mock_boto_session.return_value = mock_session_instance

        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["verified"])
        self.assertEqual(data["account_status"], "connected")
        self.assertEqual(data["identity"]["account"], self.aws_account_num)

        # Assert STS was called with the exact stored ExternalId
        mock_sts.assume_role.assert_called_once()
        kwargs = mock_sts.assume_role.call_args[1]
        self.assertEqual(kwargs["ExternalId"], self.external_id_alpha)
        self.assertEqual(kwargs["RoleArn"], self.role_arn)

        # Verify DB store was updated to 'connected'
        self.assertEqual(self.accounts_store[self.account_id]["status"], "connected")
        self.assertIsNotNone(self.accounts_store[self.account_id]["last_connected_at"])
        self.assertIsNone(self.accounts_store[self.account_id]["verification_error"])

    @patch("app.services.aws_connection.boto3.client")
    def test_assume_role_access_denied_marks_account_failed(self, mock_boto_client):
        """
        STS AccessDenied (e.g. incorrect ExternalId or trust policy mismatch)
        marks status as failed closed and does not leak the ExternalId.
        """
        mock_sts = MagicMock()
        error_response = {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized to perform: sts:AssumeRole",
            }
        }
        mock_sts.assume_role.side_effect = ClientError(error_response, "AssumeRole")
        mock_boto_client.return_value = mock_sts

        self.current_user = {
            "_id": self.user_admin_id,
            "organization": self.org_alpha,
            "email": "admin@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 400)
        detail = self._get_error_detail(res)
        self.assertIn("assumerole access denied", detail.lower())
        # Confirm ExternalId value is NOT leaked in the response message
        self.assertNotIn(self.external_id_alpha, detail)

        # DB account status must be failed
        self.assertEqual(self.accounts_store[self.account_id]["status"], "failed")
        self.assertIn("access denied", self.accounts_store[self.account_id]["verification_error"].lower())

    @patch("app.services.aws_connection.boto3.Session")
    @patch("app.services.aws_connection.boto3.client")
    def test_aws_account_id_mismatch_fails_closed(self, mock_boto_client, mock_boto_session):
        """
        If STS returns an account ID different from the registered one,
        verification fails and status is marked failed.
        """
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_MOCK_KEY",
                "SecretAccessKey": "MOCK_SECRET",
                "SessionToken": "MOCK_TOKEN",
            }
        }
        mock_sts.get_caller_identity.return_value = {
            "Account": "999999999999",
            "Arn": "arn:aws:sts::999999999999:assumed-role/Role/Session",
            "UserId": "AROA_FOREIGN",
        }
        mock_boto_client.return_value = mock_sts

        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_sts
        mock_boto_session.return_value = mock_session_instance

        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 400)
        detail = self._get_error_detail(res)
        self.assertIn("identity mismatch", detail.lower())
        self.assertEqual(self.accounts_store[self.account_id]["status"], "failed")

    @patch("app.services.aws_connection.boto3.client")
    def test_network_timeout_during_verification(self, mock_boto_client):
        """Network/STS timeouts fail safely without breaking the server."""
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = ConnectTimeoutError(endpoint_url="https://sts.us-east-1.amazonaws.com")
        mock_boto_client.return_value = mock_sts

        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 400)
        detail = self._get_error_detail(res)
        self.assertIn("timed out", detail.lower())
        self.assertEqual(self.accounts_store[self.account_id]["status"], "failed")

    def test_invalid_role_arn_rejected(self):
        """Invalid role ARN format is rejected with 400 before STS is called."""
        self.accounts_store[self.account_id]["role_arn"] = "not-a-valid-arn"
        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 400)
        detail = self._get_error_detail(res)
        self.assertIn("Invalid AWS IAM role ARN", detail)

    def test_cross_tenant_test_connection_returns_404(self):
        """Tenant Beta attempting to verify Tenant Alpha's account receives 404."""
        self.current_user = {
            "_id": self.foreign_user_id,
            "organization": self.org_beta,
            "email": "admin@beta.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 404)
        detail = self._get_error_detail(res)
        self.assertIn("not found", detail.lower())

    def test_viewer_cannot_test_connection(self):
        """Viewers attempting to test connection receive 403 Forbidden."""
        self.current_user = {
            "_id": self.user_viewer_id,
            "organization": self.org_alpha,
            "email": "viewer@alpha.com",
        }

        res = self.client.post(f"/aws/account/{self.account_id}/test-connection")
        self.assertEqual(res.status_code, 403)

    # --------------------------------------------------------
    # STEP 3: Legacy Account Safe Migration
    # --------------------------------------------------------

    @patch("app.services.aws_connection.boto3.Session")
    @patch("app.services.aws_connection.boto3.client")
    def test_legacy_account_without_external_id_is_safely_migrated(self, mock_boto_client, mock_boto_session):
        """
        Legacy accounts missing external_id are automatically backfilled
        via ensure_external_id and can successfully verify.
        """
        # Create legacy account with missing external_id
        legacy_oid = ObjectId()
        legacy_id = str(legacy_oid)
        self.accounts_store[legacy_id] = {
            "_id": legacy_oid,
            "account_id": legacy_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Legacy Account",
            "role_arn": self.role_arn,
            "region": "us-east-1",
            "status": "pending_verification",
            "external_id": None,
            "organization_id": self.org_alpha,
            "user_id": self.user_owner_id,
        }

        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASIA_KEY",
                "SecretAccessKey": "SECRET",
                "SessionToken": "TOKEN",
            }
        }
        mock_sts.get_caller_identity.return_value = {
            "Account": self.aws_account_num,
            "Arn": f"arn:aws:sts::{self.aws_account_num}:assumed-role/Role/Session",
            "UserId": "AROA_USER",
        }
        mock_boto_client.return_value = mock_sts

        mock_session_instance = MagicMock()
        mock_session_instance.client.return_value = mock_sts
        mock_boto_session.return_value = mock_session_instance

        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.post(f"/aws/account/{legacy_id}/test-connection")
        self.assertEqual(res.status_code, 200)

        # Confirm external_id was populated and bound to org_alpha
        updated_acc = self.accounts_store[legacy_id]
        self.assertIsNotNone(updated_acc.get("external_id"))
        self.assertTrue(verify_external_id_binding(updated_acc["external_id"], self.org_alpha))
        self.assertEqual(updated_acc["status"], "connected")

    # --------------------------------------------------------
    # STEP 4: Scan Route Alignment & Compatibility Alias
    # --------------------------------------------------------

    @patch("app.api.cloud.scan_aws")
    def test_scan_alias_forwarding(self, mock_scan_aws):
        """
        The /aws/scan/{account_id} compatibility alias invokes the scan_aws
        handler without returning a 404 route error.
        """
        mock_scan_aws.return_value = {
            "status": "success",
            "message": "Scan completed via alias",
            "findings": [],
        }

        self.current_user = {
            "_id": self.user_owner_id,
            "organization": self.org_alpha,
            "email": "owner@alpha.com",
        }

        res = self.client.get(f"/aws/scan/{self.account_id}")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "success")
        mock_scan_aws.assert_called_once()


if __name__ == "__main__":
    unittest.main()
