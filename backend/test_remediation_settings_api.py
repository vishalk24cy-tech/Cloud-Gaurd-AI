# ============================================================
# CloudGuardAI - Unit & Integration Tests for Remediation Settings API
# Phase 10: Step 2 API Route Testing
# ============================================================

import unittest
from unittest.mock import MagicMock, patch
from bson import ObjectId
from fastapi import HTTPException
from pydantic import ValidationError

from app.api.remediation_settings import (
    RemediationSettingsUpdateRequest,
    _get_settings_handler,
    _update_settings_handler,
    get_settings_endpoint,
    update_settings_endpoint,
)
from app.models.remediation_settings import DEFAULT_SERVICES


class TestRemediationSettingsAPI(unittest.TestCase):
    """Integration and authorization tests for Remediation Settings API."""

    def setUp(self):
        self.org_id = "org-test-settings-001"
        self.owner_user_id = str(ObjectId())
        self.admin_user_id = str(ObjectId())
        self.viewer_user_id = str(ObjectId())
        self.account_id = str(ObjectId())
        self.aws_account_num = "138218764724"

        self.owner_jwt_user = {
            "_id": self.owner_user_id,
            "organization": self.org_id,
            "role": "owner",
            "email": "owner@cloudguard.ai",
        }

        self.admin_jwt_user = {
            "_id": self.admin_user_id,
            "organization": self.org_id,
            "role": "admin",
            "email": "admin@cloudguard.ai",
        }

        self.viewer_jwt_user = {
            "_id": self.viewer_user_id,
            "organization": self.org_id,
            "role": "viewer",
            "email": "viewer@cloudguard.ai",
        }

        self.mock_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Test AWS Account",
            "organization_id": self.org_id,
            "status": "connected",
        }

        # Mock database members
        self.members_db = {
            (self.org_id, self.owner_user_id): {
                "organization_id": self.org_id,
                "user_id": self.owner_user_id,
                "role": "owner",
                "status": "active",
            },
            (self.org_id, self.admin_user_id): {
                "organization_id": self.org_id,
                "user_id": self.admin_user_id,
                "role": "admin",
                "status": "active",
            },
            (self.org_id, self.viewer_user_id): {
                "organization_id": self.org_id,
                "user_id": self.viewer_user_id,
                "role": "viewer",
                "status": "active",
            },
        }

        self.settings_storage = {}

    def _mock_find_one_member(self, query):
        org = query.get("organization_id")
        uid = query.get("user_id")
        return self.members_db.get((org, uid))

    # --------------------------------------------------------
    # GET /api/remediation/settings/{account_id} Tests
    # --------------------------------------------------------

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.get_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_get_settings_defaults_when_missing(
        self, mock_db, mock_get_settings, mock_get_account
    ):
        """GET returns default disabled settings (all False) when not configured."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_get_settings.return_value = {
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "services": DEFAULT_SERVICES.copy(),
            "exists": False,
            "updated_at": None,
            "updated_by": None,
        }

        res = get_settings_endpoint(
            account_id=self.account_id,
            current_user=self.admin_jwt_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertEqual(res["organization_id"], self.org_id)
        self.assertEqual(res["account_id"], self.account_id)
        self.assertFalse(res["exists"])
        expected_services = {"ec2", "s3", "vpc", "rds", "iam", "cloudtrail"}
        self.assertEqual(set(res["services"].keys()), expected_services)
        for service in expected_services:
            self.assertFalse(res["services"][service], f"Service '{service}' must default to False.")

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.get_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_get_settings_allowed_for_active_viewer(
        self, mock_db, mock_get_settings, mock_get_account
    ):
        """Active organization Viewer can view current remediation settings."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_get_settings.return_value = {
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "services": {"ec2": True, "s3": False, "vpc": False, "rds": False, "iam": False, "cloudtrail": False},
            "exists": True,
            "updated_at": "2026-10-10T12:00:00Z",
            "updated_by": self.admin_user_id,
        }

        res = get_settings_endpoint(
            account_id=self.account_id,
            current_user=self.viewer_jwt_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["services"]["ec2"])
        self.assertFalse(res["services"]["s3"])

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.db")
    def test_get_settings_fails_when_account_not_in_organization(
        self, mock_db, mock_get_account
    ):
        """GET fails with 404 when requested account does not belong to user's organization."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = None  # Account not found in this org

        with self.assertRaises(HTTPException) as ctx:
            get_settings_endpoint(
                account_id="acc-cross-tenant-999",
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("not found for this organization", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.db")
    def test_get_settings_fails_for_inactive_membership(self, mock_db):
        """GET fails with 403 when user membership is inactive or removed."""
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_id,
            "user_id": self.admin_user_id,
            "role": "admin",
            "status": "removed",
        }

        with self.assertRaises(HTTPException) as ctx:
            get_settings_endpoint(
                account_id=self.account_id,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("removed", ctx.exception.detail.lower())

    # --------------------------------------------------------
    # PUT /api/remediation/settings/{account_id} Tests
    # --------------------------------------------------------

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.update_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_allowed_for_admin(
        self, mock_db, mock_update_settings, mock_get_account
    ):
        """Admin can update remediation settings."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_update_settings.return_value = {
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "services": {"ec2": True, "s3": True, "vpc": False, "rds": False, "iam": False, "cloudtrail": False},
            "updated_at": "2026-10-10T12:30:00Z",
            "updated_by": self.admin_user_id,
        }

        payload = RemediationSettingsUpdateRequest(ec2=True, s3=True)
        res = update_settings_endpoint(
            account_id=self.account_id,
            payload=payload,
            current_user=self.admin_jwt_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["services"]["ec2"])
        self.assertTrue(res["services"]["s3"])
        mock_update_settings.assert_called_once_with(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"ec2": True, "s3": True},
            user_id=self.admin_user_id,
        )

    @patch("app.api.remediation_settings.db")
    def test_put_settings_rejected_for_viewer(self, mock_db):
        """Viewer role is rejected with 403 when attempting to modify settings."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member

        payload = RemediationSettingsUpdateRequest(ec2=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.viewer_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("owners and admins", ctx.exception.detail.lower())

    def test_put_settings_rejects_unrecognized_keys(self):
        """Pydantic rejects unrecognized service keys with ValidationError."""
        with self.assertRaises(ValidationError):
            RemediationSettingsUpdateRequest(
                ec2=True,
                lambda_exec=True,  # Invalid extra key
            )

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_rejects_empty_payload(self, mock_db, mock_get_account):
        """Empty update payload is rejected with 400 Bad Request."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account

        payload = RemediationSettingsUpdateRequest()  # All None
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("at least one service setting", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_rejects_disconnected_account(self, mock_db, mock_get_account):
        """Updating settings on a disconnected account is rejected with 400."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        disconnected_account = self.mock_account.copy()
        disconnected_account["status"] = "disconnected"
        mock_get_account.return_value = disconnected_account

        payload = RemediationSettingsUpdateRequest(ec2=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("disconnected", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.db")
    def test_missing_organization_context_rejected(self, mock_db):
        """Missing organization context in JWT is rejected with 403."""
        user_no_org = {
            "_id": self.admin_user_id,
            "organization": None,
            "role": "admin",
        }

        payload = RemediationSettingsUpdateRequest(ec2=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=user_no_org,
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("organization context is required", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.update_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_allowed_for_owner(
        self, mock_db, mock_update_settings, mock_get_account
    ):
        """Organization Owner can update remediation settings."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_update_settings.return_value = {
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "services": {"ec2": False, "s3": False, "vpc": False, "rds": False, "iam": True, "cloudtrail": True},
            "updated_at": "2026-10-10T12:45:00Z",
            "updated_by": self.owner_user_id,
        }

        payload = RemediationSettingsUpdateRequest(iam=True, cloudtrail=True)
        res = update_settings_endpoint(
            account_id=self.account_id,
            payload=payload,
            current_user=self.owner_jwt_user,
        )

        self.assertEqual(res["status"], "success")
        self.assertTrue(res["services"]["iam"])
        self.assertTrue(res["services"]["cloudtrail"])
        mock_update_settings.assert_called_once_with(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"iam": True, "cloudtrail": True},
            user_id=self.owner_user_id,
        )

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.update_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_partial_update_preserves_unspecified(
        self, mock_db, mock_update_settings, mock_get_account
    ):
        """Partial update passes only specified keys to update handler."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_update_settings.return_value = {
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "services": {"ec2": False, "s3": True, "vpc": False, "rds": False, "iam": False, "cloudtrail": False},
            "updated_at": "2026-10-10T12:50:00Z",
            "updated_by": self.admin_user_id,
        }

        payload = RemediationSettingsUpdateRequest(s3=True)
        res = update_settings_endpoint(
            account_id=self.account_id,
            payload=payload,
            current_user=self.admin_jwt_user,
        )

        self.assertEqual(res["status"], "success")
        # Ensure only 's3' was passed in service_toggles, unspecified services omitted from patch dict
        mock_update_settings.assert_called_once_with(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"s3": True},
            user_id=self.admin_user_id,
        )

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_fails_when_account_not_in_organization(
        self, mock_db, mock_get_account
    ):
        """PUT fails with 404 when requested account does not belong to user's organization."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = None  # Cross-tenant account

        payload = RemediationSettingsUpdateRequest(ec2=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id="acc-other-org-999",
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("not found for this organization", ctx.exception.detail.lower())

    def test_put_settings_rejects_non_boolean_values(self):
        """Pydantic rejects non-boolean values in strict mode with ValidationError."""
        invalid_values = ["true", "false", 1, 0, "yes", "no", [], {}]
        for val in invalid_values:
            with self.assertRaises(ValidationError, msg=f"Should reject {val}"):
                RemediationSettingsUpdateRequest(ec2=val)

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.db")
    def test_get_settings_database_error_on_account_lookup(
        self, mock_db, mock_get_account
    ):
        """GET fails closed with 500 when account database lookup fails."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.side_effect = Exception("Mongo connection timeout")

        with self.assertRaises(HTTPException) as ctx:
            get_settings_endpoint(
                account_id=self.account_id,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("internal error validating aws account", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.get_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_get_settings_database_error_on_settings_lookup(
        self, mock_db, mock_get_settings, mock_get_account
    ):
        """GET fails closed with 500 when settings retrieval encounters unexpected DB exception."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_get_settings.side_effect = Exception("Database read error")

        with self.assertRaises(HTTPException) as ctx:
            get_settings_endpoint(
                account_id=self.account_id,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("internal error retrieving remediation settings", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.update_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_database_error_on_update(
        self, mock_db, mock_update_settings, mock_get_account
    ):
        """PUT fails closed with 500 when database update raises exception."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_update_settings.side_effect = Exception("Write concern error")

        payload = RemediationSettingsUpdateRequest(rds=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("internal error updating remediation settings", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.get_account")
    @patch("app.api.remediation_settings.update_remediation_settings")
    @patch("app.api.remediation_settings.db")
    def test_put_settings_fails_when_update_returns_none(
        self, mock_db, mock_update_settings, mock_get_account
    ):
        """PUT fails closed with 500 when update_remediation_settings returns None."""
        mock_db.organization_members.find_one.side_effect = self._mock_find_one_member
        mock_get_account.return_value = self.mock_account
        mock_update_settings.return_value = None

        payload = RemediationSettingsUpdateRequest(vpc=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("failed to update remediation settings", ctx.exception.detail.lower())

    @patch("app.api.remediation_settings.db")
    def test_membership_lookup_database_error(self, mock_db):
        """Endpoint fails closed with 500 when membership lookup encounters database error."""
        mock_db.organization_members.find_one.side_effect = Exception("DB cluster unavailable")

        payload = RemediationSettingsUpdateRequest(ec2=True)
        with self.assertRaises(HTTPException) as ctx:
            update_settings_endpoint(
                account_id=self.account_id,
                payload=payload,
                current_user=self.admin_jwt_user,
            )
        self.assertEqual(ctx.exception.status_code, 500)
        self.assertIn("internal error resolving organization membership", ctx.exception.detail.lower())


if __name__ == "__main__":
    unittest.main()
