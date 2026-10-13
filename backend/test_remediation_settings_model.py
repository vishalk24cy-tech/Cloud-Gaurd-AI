# ============================================================
# CloudGuardAI - Offline Unit Tests for Remediation Settings Data Model
# Phase 10: Step 1 Isolated Model Validation
# ============================================================

import sys
import unittest
from unittest.mock import MagicMock, patch
from bson import ObjectId

# 1. Mock PyMongo client in sys.modules to prevent live Atlas connection during import
mock_pymongo = MagicMock()
mock_db_inst = MagicMock()
mock_pymongo.MongoClient.return_value.__getitem__.return_value = mock_db_inst
mock_pymongo.MongoClient.return_value.admin.command.return_value = {"ok": 1}
sys.modules["pymongo"] = mock_pymongo

# 2. Import remediation_settings model
from app.models.remediation_settings import (
    DEFAULT_SERVICES,
    get_remediation_settings,
    is_remediation_enabled,
    update_remediation_settings,
)


class TestRemediationSettingsModel(unittest.TestCase):
    """Unit and mock regression tests for Remediation Settings model and fail-closed logic."""

    def setUp(self):
        self.org_id = "org-enterprise-101"
        self.user_id = str(ObjectId())
        self.account_id = str(ObjectId())
        self.aws_account_id = "138218764724"

        self.mock_account = {
            "_id": ObjectId(self.account_id),
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "account_name": "Prod Account",
            "organization_id": self.org_id,
            "status": "connected",
        }

        # In-memory storage for mock DB collection
        self.db_storage = {}

        def mock_find_one(query):
            key = (query.get("organization_id"), query.get("account_id"))
            return self.db_storage.get(key)

        def mock_update_one(query, update, upsert=False):
            key = (query.get("organization_id"), query.get("account_id"))
            existing = self.db_storage.get(key, {})
            set_data = update.get("$set", {})
            set_on_insert = update.get("$setOnInsert", {})

            if not existing and set_on_insert:
                existing.update(set_on_insert)

            existing.update(set_data)
            existing["_id"] = existing.get("_id", ObjectId())
            self.db_storage[key] = existing

        patcher_col = patch("app.models.remediation_settings.remediation_settings_collection")
        self.mock_col = patcher_col.start()
        self.mock_col.find_one.side_effect = mock_find_one
        self.mock_col.update_one.side_effect = mock_update_one
        self.addCleanup(patcher_col.stop)

    @patch("app.models.remediation_settings.get_account")
    def test_default_settings_all_services_disabled(self, mock_get_account):
        """Newly requested accounts default all 6 service remediations to False."""
        mock_get_account.return_value = self.mock_account

        settings = get_remediation_settings(self.org_id, self.account_id)

        self.assertFalse(settings["exists"])
        self.assertEqual(settings["organization_id"], self.org_id)
        self.assertEqual(settings["account_id"], self.account_id)

        for service, enabled in settings["services"].items():
            self.assertFalse(enabled, f"Service '{service}' should default to False.")

    @patch("app.models.remediation_settings.get_account")
    def test_is_remediation_enabled_defaults_to_false(self, mock_get_account):
        """is_remediation_enabled returns False for all services by default."""
        mock_get_account.return_value = self.mock_account

        for service in ["ec2", "s3", "vpc", "rds", "iam", "cloudtrail"]:
            self.assertFalse(
                is_remediation_enabled(self.org_id, self.account_id, service),
                f"is_remediation_enabled('{service}') should return False by default.",
            )

    @patch("app.models.remediation_settings.get_account")
    def test_update_and_persist_remediation_settings(self, mock_get_account):
        """Updating remediation settings persists toggle states."""
        mock_get_account.return_value = self.mock_account

        updated = update_remediation_settings(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"ec2": True, "s3": True},
            user_id=self.user_id,
        )

        self.assertIsNotNone(updated)
        self.assertTrue(updated["exists"])
        self.assertTrue(updated["services"]["ec2"])
        self.assertTrue(updated["services"]["s3"])
        self.assertFalse(updated["services"]["vpc"])
        self.assertFalse(updated["services"]["rds"])

        # Verify through is_remediation_enabled
        self.assertTrue(is_remediation_enabled(self.org_id, self.account_id, "ec2"))
        self.assertTrue(is_remediation_enabled(self.org_id, self.account_id, "s3"))
        self.assertFalse(is_remediation_enabled(self.org_id, self.account_id, "vpc"))

    @patch("app.models.remediation_settings.get_account")
    def test_partial_update_preserves_unspecified_services(self, mock_get_account):
        """Updating one service does not reset or overwrite other service states."""
        mock_get_account.return_value = self.mock_account

        # Step 1: Enable EC2 and S3
        update_remediation_settings(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"ec2": True, "s3": True},
            user_id=self.user_id,
        )

        # Step 2: Partial update to enable RDS
        updated = update_remediation_settings(
            organization_id=self.org_id,
            account_id=self.account_id,
            service_toggles={"rds": True},
            user_id=self.user_id,
        )

        self.assertTrue(updated["services"]["ec2"], "EC2 toggle should remain True.")
        self.assertTrue(updated["services"]["s3"], "S3 toggle should remain True.")
        self.assertTrue(updated["services"]["rds"], "RDS toggle should be True.")
        self.assertFalse(updated["services"]["iam"], "IAM toggle should remain False.")

    @patch("app.models.remediation_settings.get_account")
    def test_cross_organization_access_fails_closed(self, mock_get_account):
        """Accessing settings for an account that does not belong to the org returns default disabled."""
        mock_get_account.return_value = None

        other_org_id = "org-unauthorized-999"
        settings = get_remediation_settings(other_org_id, self.account_id)

        self.assertFalse(settings["exists"])
        for service, enabled in settings["services"].items():
            self.assertFalse(enabled)

        # is_remediation_enabled must return False
        self.assertFalse(is_remediation_enabled(other_org_id, self.account_id, "ec2"))

        # Update attempt must return None
        update_res = update_remediation_settings(
            organization_id=other_org_id,
            account_id=self.account_id,
            service_toggles={"ec2": True},
            user_id=self.user_id,
        )
        self.assertIsNone(update_res)

    def test_invalid_service_key_fails_closed(self):
        """Unrecognized service keys return False without throwing exceptions."""
        invalid_keys = ["lambda", "dynamodb", "root_admin", "eval()", ""]
        for bad_key in invalid_keys:
            self.assertFalse(
                is_remediation_enabled(self.org_id, self.account_id, bad_key),
                f"Invalid key '{bad_key}' must return False.",
            )


if __name__ == "__main__":
    unittest.main()
