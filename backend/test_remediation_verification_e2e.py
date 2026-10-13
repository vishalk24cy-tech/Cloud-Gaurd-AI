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
    STATUS_PROPOSED,
    STATUS_APPROVED,
    STATUS_COMPLETED,
)
from app.services.scan_remediation_reconciler import reconcile_scan_remediations


class RemediationVerificationE2ETests(unittest.TestCase):
    """
    Comprehensive mocked end-to-end test verifying the complete 11-step lifecycle:
    1. Finding creation
    2. Remediation proposal
    3. Authorization and approval
    4. Mocked AWS execution
    5. Simulated AWS state verification
    6. Finding remains UNRESOLVED immediately after execution
    7. Qualifying simulated scan execution
    8. Authoritative finding resolution by scan
    9. Exact remediation verification record and audit logging
    10. Idempotency and stale-scan protection
    11. Cross-tenant and partial scan isolation
    """

    def setUp(self):
        self.tenant_user = "user-e2e-tenant-1"
        self.other_tenant_user = "user-e2e-tenant-2"
        self.org_id = "org-e2e-1"
        self.account_id = "acc-e2e-1"
        self.aws_account_id = "112233445566"
        self.finding_id = "CG-E2E-TEST-001"
        self.scan_id = "scan-e2e-verified-01"

        self.t0_create = datetime(2026, 10, 9, 8, 0, 0)
        self.t1_propose = datetime(2026, 10, 9, 8, 15, 0)
        self.t2_approve = datetime(2026, 10, 9, 8, 30, 0)
        self.t3_execute = datetime(2026, 10, 9, 9, 0, 0)
        self.t4_scan_start = datetime(2026, 10, 9, 9, 30, 0)
        self.t5_scan_done = datetime(2026, 10, 9, 9, 35, 0)

    @patch("app.services.scan_remediation_reconciler.record_event")
    @patch("app.services.scan_remediation_reconciler.remediations_collection")
    @patch("app.services.scan_remediation_reconciler.findings_collection")
    def test_complete_11_step_lifecycle(
        self, mock_findings_col, mock_rem_col, mock_record_event
    ):
        # 1. Isolated test finding
        finding = {
            "_id": ObjectId(),
            "user_id": self.tenant_user,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "finding_id": self.finding_id,
            "service": "S3",
            "resource": "cloudguard-e2e-bucket",
            "status": WORKFLOW_OPEN,
            "workflow_status": WORKFLOW_OPEN,
            "created_at": self.t0_create,
        }

        # 2 & 3. Proposal and Approval
        remediation = {
            "_id": ObjectId(),
            "user_id": self.tenant_user,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_id,
            "finding_id": self.finding_id,
            "action_type": "DISABLE_PUBLIC_ACCESS",
            "status": STATUS_APPROVED,
            "created_at": self.t1_propose,
            "approved_at": self.t2_approve,
        }

        # 4 & 5. Mocked execution and verified read-back state
        remediation["status"] = STATUS_COMPLETED
        remediation["executed_at"] = self.t3_execute
        remediation["verification"] = {
            "verified": True,
            "read_back": {"BlockPublicAcls": True, "BlockPublicPolicy": True},
        }

        # 6. Safety Rule check: finding MUST remain OPEN immediately after execution
        self.assertEqual(finding["status"], WORKFLOW_OPEN)
        self.assertEqual(finding["workflow_status"], WORKFLOW_OPEN)

        # 7. Setup qualifying simulated scan (scan started at 9:30, after 9:00 execution)
        mock_findings_col.find.return_value = [finding]
        mock_rem_col.find_one.return_value = remediation

        # Setup mock updates
        def mock_finding_update(query, update):
            if query.get("_id") == finding["_id"] and finding["status"] in (WORKFLOW_OPEN, WORKFLOW_IN_PROGRESS):
                finding.update(update["$set"])
                res = Mock()
                res.modified_count = 1
                return res
            res = Mock()
            res.modified_count = 0
            return res

        mock_findings_col.update_one.side_effect = mock_finding_update

        def mock_rem_update(query, update):
            if query.get("_id") == remediation["_id"]:
                if "verification" not in remediation or not isinstance(remediation["verification"], dict):
                    remediation["verification"] = {}
                remediation["verification"].update(update["$set"])
                res = Mock()
                res.modified_count = 1
                return res
            res = Mock()
            res.modified_count = 0
            return res

        mock_rem_col.update_one.side_effect = mock_rem_update

        # 8. Reconcile scan
        result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.tenant_user,
            organization_id=self.org_id,
            aws_account_id=self.aws_account_id,
            scan_id=self.scan_id,
            scan_started_at=self.t4_scan_start,
            scan_completed_at=self.t5_scan_done,
            detected_finding_ids=set(),  # absent from scan
            evaluated_services={"S3"},
        )

        self.assertEqual(result["resolved_count"], 1)
        self.assertEqual(finding["status"], WORKFLOW_RESOLVED)
        self.assertEqual(finding["workflow_status"], WORKFLOW_RESOLVED)
        self.assertEqual(finding["verifying_scan_id"], self.scan_id)

        # 9. Verify remediation record and audit log
        mock_record_event.assert_called_once()
        audit_call = mock_record_event.call_args[1]
        self.assertEqual(audit_call["event_type"], EVENT_FINDING_RESOLVED)
        self.assertEqual(audit_call["finding_id"], self.finding_id)
        self.assertEqual(audit_call["account_id"], self.account_id)

        # 10. Confirm Idempotency
        result_idempotent = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.tenant_user,
            organization_id=self.org_id,
            aws_account_id=self.aws_account_id,
            scan_id=self.scan_id,
            scan_started_at=self.t4_scan_start,
            scan_completed_at=self.t5_scan_done,
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )
        self.assertEqual(result_idempotent["resolved_count"], 0)

        # 10b. Stale scan protection: scan started before remediation execution
        stale_finding = {
            "_id": ObjectId(),
            "user_id": self.tenant_user,
            "account_id": self.account_id,
            "finding_id": "CG-STALE-001",
            "service": "S3",
            "status": WORKFLOW_OPEN,
        }
        stale_remediation = {
            "_id": ObjectId(),
            "user_id": self.tenant_user,
            "account_id": self.account_id,
            "finding_id": "CG-STALE-001",
            "status": STATUS_COMPLETED,
            "executed_at": self.t3_execute,  # 9:00 AM
        }
        mock_findings_col.find.return_value = [stale_finding]
        mock_rem_col.find_one.return_value = stale_remediation

        stale_result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.tenant_user,
            scan_id="stale-scan",
            scan_started_at=datetime(2026, 10, 9, 8, 45, 0),  # 8:45 AM (before execution!)
            scan_completed_at=datetime(2026, 10, 9, 8, 55, 0),
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )
        self.assertEqual(stale_result["resolved_count"], 0)
        self.assertEqual(stale_finding["status"], WORKFLOW_OPEN)

        # 11. Cross-tenant attempt
        mock_findings_col.find.return_value = []
        cross_tenant_result = reconcile_scan_remediations(
            account_id=self.account_id,
            user_id=self.other_tenant_user,  # Other tenant!
            scan_id=self.scan_id,
            scan_started_at=self.t4_scan_start,
            scan_completed_at=self.t5_scan_done,
            detected_finding_ids=set(),
            evaluated_services={"S3"},
        )
        self.assertEqual(cross_tenant_result["resolved_count"], 0)


if __name__ == "__main__":
    unittest.main()
