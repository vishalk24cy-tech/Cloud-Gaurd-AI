import unittest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from bson import ObjectId

from app.models.audit_log import EVENT_FINDING_RESOLVED
from app.models.finding import (
    WORKFLOW_OPEN,
    WORKFLOW_IN_PROGRESS,
    WORKFLOW_RESOLVED,
)
from app.models.remediation import (
    STATUS_COMPLETED,
    STATUS_PROPOSED,
)
from app.services.scan_remediation_reconciler import reconcile_scan_remediations


class ScanRemediationResolutionTests(unittest.TestCase):
    def setUp(self):
        self.user_id = "user-test-1"
        self.org_id = "org-test-1"
        self.account_id = "acc-test-1"
        self.aws_account_id = "123456789012"
        self.finding_id = "CG-1234ABCD5678EF90"
        self.scan_id = "scan-test-1"

        self.base_time = datetime(2026, 10, 9, 10, 0, 0)
        self.scan_started_at = self.base_time + timedelta(minutes=15)
        self.scan_completed_at = self.base_time + timedelta(minutes=20)

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_successful_remediation_resolved_by_authoritative_scan(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """Authoritative scan that started after execution resolves the finding."""
        finding_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "finding_id": self.finding_id,
            "service": "S3",
            "resource": "my-bucket",
            "status": WORKFLOW_OPEN,
            "workflow_status": WORKFLOW_OPEN,
        }
        remediation_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "status": STATUS_COMPLETED,
            "executed_at": self.base_time,  # 10:00 AM (executed before scan start 10:15 AM)
        }

        mock_findings_col.find.return_value = [finding_doc]
        mock_rem_col.find_one.return_value = remediation_doc

        update_result_mock = Mock()
        update_result_mock.modified_count = 1
        mock_findings_col.update_one.return_value = update_result_mock

        rem_update_mock = Mock()
        rem_update_mock.modified_count = 1
        mock_rem_col.update_one.return_value = rem_update_mock

        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            organization_id=self.org_id,
            aws_account_id=self.aws_account_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_started_at,
            scan_completed_at=self.scan_completed_at,
            detected_finding_ids=set(),  # Finding is NOT detected in scan
            evaluated_services={"S3", "EC2"},
        )

        self.assertEqual(result["resolved_count"], 1)
        self.assertIn(self.finding_id, result["resolved_findings"])

        # Check finding update call
        mock_findings_col.update_one.assert_called_once()
        args, kwargs = mock_findings_col.update_one.call_args
        self.assertEqual(args[0]["_id"], finding_doc["_id"])
        self.assertEqual(args[1]["$set"]["status"], WORKFLOW_RESOLVED)
        self.assertEqual(args[1]["$set"]["verifying_scan_id"], self.scan_id)
        self.assertEqual(args[1]["$set"]["resolved_at"], self.scan_completed_at)

        # Check remediation update call
        mock_rem_col.update_one.assert_called_once()
        rem_args, _ = mock_rem_col.update_one.call_args
        self.assertEqual(rem_args[0]["_id"], remediation_doc["_id"])
        self.assertTrue(rem_args[1]["$set"]["verification.scan_verified"])
        self.assertEqual(rem_args[1]["$set"]["verification.scan_id"], self.scan_id)

        # Check audit event
        mock_record_event.assert_called_once()
        event_kwargs = mock_record_event.call_args[1]
        self.assertEqual(event_kwargs["event_type"], EVENT_FINDING_RESOLVED)
        self.assertEqual(event_kwargs["finding_id"], self.finding_id)
        self.assertEqual(event_kwargs["account_id"], self.account_id)

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_finding_still_detected_remains_open(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """If the scan still detects the finding, it must NOT be resolved."""
        finding_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "service": "S3",
            "status": WORKFLOW_OPEN,
        }
        remediation_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "status": STATUS_COMPLETED,
            "executed_at": self.base_time,
        }

        mock_findings_col.find.return_value = [finding_doc]
        mock_rem_col.find_one.return_value = remediation_doc

        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_started_at,
            scan_completed_at=self.scan_completed_at,
            detected_finding_ids={self.finding_id},  # Still detected!
            evaluated_services={"S3"},
        )

        self.assertEqual(result["resolved_count"], 0)
        mock_findings_col.update_one.assert_not_called()
        mock_record_event.assert_not_called()

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_stale_scan_does_not_resolve_newer_remediation(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """If scan started BEFORE remediation executed, it must NOT resolve the finding."""
        finding_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "service": "S3",
            "status": WORKFLOW_OPEN,
        }
        # Remediation was executed at 10:25 AM
        remediation_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "status": STATUS_COMPLETED,
            "executed_at": self.base_time + timedelta(minutes=25),
        }

        mock_findings_col.find.return_value = [finding_doc]
        mock_rem_col.find_one.return_value = remediation_doc

        # Scan started at 10:15 AM (before 10:25 AM execution)
        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_started_at,
            scan_completed_at=self.scan_completed_at,
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )

        self.assertEqual(result["resolved_count"], 0)
        mock_findings_col.update_one.assert_not_called()
        mock_record_event.assert_not_called()

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_unremediated_missing_finding_not_resolved(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """Missing findings without COMPLETED remediation are never resolved automatically."""
        finding_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "service": "S3",
            "status": WORKFLOW_OPEN,
        }

        mock_findings_col.find.return_value = [finding_doc]
        # No completed remediation
        mock_rem_col.find_one.return_value = None

        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_started_at,
            scan_completed_at=self.scan_completed_at,
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )

        self.assertEqual(result["resolved_count"], 0)
        mock_findings_col.update_one.assert_not_called()
        mock_record_event.assert_not_called()

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_service_not_evaluated_in_scan_not_resolved(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """If a service was not evaluated in this scan, its findings are not resolved."""
        finding_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "service": "RDS",  # RDS finding
            "status": WORKFLOW_OPEN,
        }
        remediation_doc = {
            "_id": ObjectId(),
            "user_id": self.user_id,
            "account_id": self.account_id,
            "finding_id": self.finding_id,
            "status": STATUS_COMPLETED,
            "executed_at": self.base_time,
        }

        mock_findings_col.find.return_value = [finding_doc]
        mock_rem_col.find_one.return_value = remediation_doc

        # Scan only evaluated S3 and EC2, not RDS
        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_started_at,
            scan_completed_at=self.scan_completed_at,
            detected_finding_ids=set(),
            evaluated_services={"S3", "EC2"},
        )

        self.assertEqual(result["resolved_count"], 0)
        mock_findings_col.update_one.assert_not_called()
        mock_record_event.assert_not_called()

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_inverted_timestamps_fail_closed(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        """Inverted or invalid timestamps fail closed immediately."""
        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.user_id,
            scan_id=self.scan_id,
            scan_started_at=self.scan_completed_at,  # Inverted!
            scan_completed_at=self.scan_started_at,
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )

        self.assertEqual(result["resolved_count"], 0)
        mock_findings_col.find.assert_not_called()
        mock_findings_col.update_one.assert_not_called()


if __name__ == "__main__":
    unittest.main()
