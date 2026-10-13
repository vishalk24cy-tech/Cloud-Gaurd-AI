# ============================================================
# CloudGuardAI - S3 Checker & Finding Accuracy Tests
# Unit Tests with Isolated Mocks (Zero AWS Live Changes)
# ============================================================

from datetime import datetime, timedelta
import unittest
from unittest.mock import MagicMock, patch
from botocore.exceptions import ClientError, EndpointConnectionError

from app.services.s3_checker import (
    S3DiscoveryError,
    S3RegionResolutionError,
    check_s3,
    inspect_s3_inventory,
    resolve_bucket_region,
)
from app.services.scan_remediation_reconciler import reconcile_scan_remediations
from app.models.finding import (
    WORKFLOW_OPEN,
    WORKFLOW_RESOLVED,
    findings_collection,
)
from app.models.remediation import (
    STATUS_COMPLETED,
    remediations_collection,
)


class TestS3CheckerAccuracy(unittest.TestCase):
    """Authoritative unit test suite for S3 discovery, inspection, and finding accuracy."""

    def setUp(self):
        self.mock_s3 = MagicMock()
        self.account_id = "138218764724"
        self.user_id = "test-user-s3-100"
        self.org_id = "test-org-s3-100"
        self.test_bucket_name = "cloudguard-test-verify-138218764724-1945361064"
        self.app_bucket_name = "srishakthibucket"

    # ========================================================
    # 1. REGION RESOLUTION TESTS (Fix A)
    # ========================================================

    def test_region_resolution_null_constraint_maps_to_us_east_1(self):
        """1. Null or empty LocationConstraint resolves to us-east-1."""
        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        region = resolve_bucket_region(self.mock_s3, self.test_bucket_name)
        self.assertEqual(region, "us-east-1")

        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": ""}
        region_empty = resolve_bucket_region(self.mock_s3, self.test_bucket_name)
        self.assertEqual(region_empty, "us-east-1")

    def test_region_resolution_non_default_region(self):
        """2. Non-default regions resolve correctly (EU -> eu-west-1, ap-south-1)."""
        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": "EU"}
        region_eu = resolve_bucket_region(self.mock_s3, "eu-bucket")
        self.assertEqual(region_eu, "eu-west-1")

        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}
        region_ap = resolve_bucket_region(self.mock_s3, self.app_bucket_name)
        self.assertEqual(region_ap, "ap-south-1")

    def test_region_lookup_fails_due_to_access_denied(self):
        """3. Region lookup failing due to AccessDenied raises S3RegionResolutionError and does not return default region."""
        self.mock_s3.get_bucket_location.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetBucketLocation",
        )
        with self.assertRaises(S3RegionResolutionError) as ctx:
            resolve_bucket_region(self.mock_s3, "forbidden-bucket")
        self.assertEqual(ctx.exception.error_code, "AccessDenied")

        # In check_s3, it records Unknown finding and stops inspection for that bucket
        self.mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "forbidden-bucket"}]}
        findings = check_s3(self.mock_s3, account_id=self.account_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "Unknown")
        self.assertEqual(findings[0]["region"], "UNKNOWN")
        self.assertIn("could not resolve region", findings[0]["issue"])

    def test_region_lookup_fails_due_to_network_error(self):
        """4. Region lookup failing due to network error raises S3RegionResolutionError and marks inventory as PARTIAL."""
        self.mock_s3.get_bucket_location.side_effect = EndpointConnectionError(
            endpoint_url="https://s3.amazonaws.com"
        )
        with self.assertRaises(S3RegionResolutionError) as ctx:
            resolve_bucket_region(self.mock_s3, "net-err-bucket")
        self.assertEqual(ctx.exception.error_code, "EndpointConnectionError")

        self.mock_s3.list_buckets.return_value = {"Buckets": [{"Name": "net-err-bucket"}]}
        inv = inspect_s3_inventory(self.mock_s3, account_id=self.account_id)
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["security_posture"], "UNKNOWN")
        self.assertEqual(inv[0]["coverage"], "PARTIAL")
        self.assertEqual(inv[0]["inspection_error"]["stage"], "REGION_RESOLUTION")

    # ========================================================
    # 2. INVENTORY DISCOVERY FAILURES (Fix B)
    # ========================================================

    def test_bucket_enumeration_fails_raises_discovery_error(self):
        """5. Bucket enumeration failure raises S3DiscoveryError and is distinguishable from empty account."""
        self.mock_s3.list_buckets.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "ListBuckets",
        )
        # raise_on_error=True raises S3DiscoveryError
        with self.assertRaises(S3DiscoveryError) as ctx:
            inspect_s3_inventory(self.mock_s3, account_id=self.account_id, raise_on_error=True)
        self.assertEqual(ctx.exception.error_code, "AccessDenied")

        # check_s3 produces an Unknown finding for the s3 service
        findings = check_s3(self.mock_s3, account_id=self.account_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "Unknown")
        self.assertEqual(findings[0]["resource"], "s3")

    def test_account_genuinely_zero_buckets(self):
        """6. Account genuinely having zero buckets returns empty list without error."""
        self.mock_s3.list_buckets.return_value = {"Buckets": []}
        findings = check_s3(self.mock_s3, account_id=self.account_id)
        inventory = inspect_s3_inventory(self.mock_s3, account_id=self.account_id, raise_on_error=True)
        self.assertEqual(findings, [])
        self.assertEqual(inventory, [])

    # ========================================================
    # 3. PER-BUCKET INSPECTION COVERAGE & FAILURES (Fix C)
    # ========================================================

    def test_policy_acl_encryption_bpa_inspection_failures(self):
        """7. Individual check inspection failures are explicitly represented and never swallowed."""
        self.mock_s3.list_buckets.return_value = {"Buckets": [{"Name": self.app_bucket_name}]}
        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": "ap-south-1"}

        # BPA has NoSuchPublicAccessBlockConfiguration (configuration absence -> verified High Risk)
        self.mock_s3.get_public_access_block.side_effect = ClientError(
            {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration", "Message": "Not found"}},
            "GetPublicAccessBlock",
        )
        # PolicyStatus has NoSuchBucketPolicy (policy absence -> verified safe absence)
        self.mock_s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "Not found"}},
            "GetBucketPolicyStatus",
        )
        # ACL has AccessDenied (authorization failure -> Unknown)
        self.mock_s3.get_bucket_acl.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetBucketAcl",
        )
        # Encryption has unexpected network error
        self.mock_s3.get_bucket_encryption.side_effect = EndpointConnectionError(
            endpoint_url="https://s3.amazonaws.com"
        )

        findings = check_s3(self.mock_s3, account_id=self.account_id)
        inv = inspect_s3_inventory(self.mock_s3, account_id=self.account_id)

        # check_s3 must contain:
        # 1. High Risk BPA finding (not configured)
        # 2. Medium Unknown ACL finding (AccessDenied)
        # 3. Low Unknown Encryption finding (Network error)
        # And ZERO false finding for NoSuchBucketPolicy
        bpa_findings = [f for f in findings if "Block Public Access" in f["issue"]]
        acl_findings = [f for f in findings if "ACL" in f["issue"]]
        enc_findings = [f for f in findings if "encryption" in f["issue"]]
        pol_findings = [f for f in findings if "policy" in f["issue"]]

        self.assertEqual(len(bpa_findings), 1)
        self.assertEqual(bpa_findings[0]["severity"], "HIGH")
        self.assertEqual(bpa_findings[0]["status"], "Risk")

        self.assertEqual(len(acl_findings), 1)
        self.assertEqual(acl_findings[0]["status"], "Unknown")

        self.assertEqual(len(enc_findings), 1)
        self.assertEqual(enc_findings[0]["status"], "Unknown")

        self.assertEqual(len(pol_findings), 0)

        # In inventory: ACL and encryption are verified=False
        item = inv[0]
        self.assertFalse(item["acl"]["verified"])
        self.assertEqual(item["acl"]["status"], "ACCESS_DENIED")
        self.assertFalse(item["encryption"]["verified"])
        self.assertEqual(item["encryption"]["status"], "ERROR")
        self.assertEqual(item["coverage"], "PARTIAL")

    def test_secure_bucket_classified_secure_only_with_sufficient_evidence(self):
        """8. A secure bucket is classified as SECURE only when all 4 checks are verified with positive evidence."""
        self.mock_s3.list_buckets.return_value = {"Buckets": [{"Name": self.test_bucket_name}]}
        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        self.mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        self.mock_s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucketPolicy", "Message": "No policy"}},
            "GetBucketPolicyStatus",
        )
        self.mock_s3.get_bucket_acl.return_value = {"Grants": [{"Grantee": {"DisplayName": "owner"}}]}
        self.mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        findings = check_s3(self.mock_s3, account_id=self.account_id)
        inv = inspect_s3_inventory(self.mock_s3, account_id=self.account_id)

        self.assertEqual(findings, [])
        self.assertEqual(len(inv), 1)
        self.assertEqual(inv[0]["security_posture"], "SECURE")
        self.assertEqual(inv[0]["coverage"], "COMPLETE")
        self.assertTrue(inv[0]["block_public_access"]["verified"])
        self.assertTrue(inv[0]["bucket_policy"]["verified"])
        self.assertTrue(inv[0]["acl"]["verified"])
        self.assertTrue(inv[0]["encryption"]["verified"])

    def test_incomplete_inspection_never_falsely_reports_bucket_as_secure(self):
        """9. Incomplete inspection (e.g. AccessDenied on ACL or Policy) never falsely classifies a bucket as SECURE."""
        self.mock_s3.list_buckets.return_value = {"Buckets": [{"Name": self.test_bucket_name}]}
        self.mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        # BPA is fully enabled
        self.mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        # BUT Policy check fails with AccessDenied!
        self.mock_s3.get_bucket_policy_status.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}},
            "GetBucketPolicyStatus",
        )
        self.mock_s3.get_bucket_acl.return_value = {"Grants": []}
        self.mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        inv = inspect_s3_inventory(self.mock_s3, account_id=self.account_id)
        self.assertEqual(len(inv), 1)
        # MUST NOT be SECURE or EVALUATED!
        self.assertNotEqual(inv[0]["security_posture"], "SECURE")
        self.assertNotEqual(inv[0]["security_posture"], "EVALUATED")
        self.assertEqual(inv[0]["security_posture"], "UNKNOWN")
        self.assertEqual(inv[0]["coverage"], "PARTIAL")

    # ========================================================
    # 4. SCAN RECONCILIATION INTEGRATION (Fix D)
    # ========================================================

    def test_failed_or_partial_scans_do_not_resolve_findings(self):
        """10. Failed or partial scans do not resolve existing findings."""
        scan_id = "test-scan-reconcile-001"
        scan_start = datetime.utcnow() - timedelta(minutes=5)
        scan_end = datetime.utcnow()
        fid = "CG-TEST-RECONCILE-S3"

        # Setup test finding and completed remediation
        findings_collection.delete_many({"finding_id": fid})
        remediations_collection.delete_many({"finding_id": fid})

        findings_collection.insert_one({
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "finding_id": fid,
            "service": "S3",
            "resource": self.test_bucket_name,
            "status": WORKFLOW_OPEN,
            "workflow_status": WORKFLOW_OPEN,
        })
        remediations_collection.insert_one({
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_id": self.account_id,
            "finding_id": fid,
            "status": STATUS_COMPLETED,
            "executed_at": scan_start - timedelta(minutes=2),
            "completed_at": scan_start - timedelta(minutes=1),
        })

        try:
            # Scenario A: S3 service was NOT evaluated (discovery failed)
            res_a = reconcile_scan_remediations(
                account_id=self.account_id,
                user_id=self.user_id,
                organization_id=self.org_id,
                scan_id=scan_id,
                scan_started_at=scan_start,
                scan_completed_at=scan_end,
                detected_finding_ids=set(),
                evaluated_services={"EC2", "IAM"},  # S3 omitted!
            )
            self.assertEqual(res_a["resolved_count"], 0)
            doc_a = findings_collection.find_one({"finding_id": fid})
            self.assertEqual(doc_a["status"], WORKFLOW_OPEN)

            # Scenario B: S3 in evaluated_services, but target bucket in uninspected_resources (partial coverage)
            res_b = reconcile_scan_remediations(
                account_id=self.account_id,
                user_id=self.user_id,
                organization_id=self.org_id,
                scan_id=scan_id,
                scan_started_at=scan_start,
                scan_completed_at=scan_end,
                detected_finding_ids=set(),
                evaluated_services={"EC2", "S3", "IAM"},
                uninspected_resources={self.test_bucket_name},  # Bucket was partial/uninspected!
            )
            self.assertEqual(res_b["resolved_count"], 0)
            doc_b = findings_collection.find_one({"finding_id": fid})
            self.assertEqual(doc_b["status"], WORKFLOW_OPEN)

            # Scenario C: S3 fully evaluated, bucket inspected, finding not in detected_ids -> authoritatively resolved
            res_c = reconcile_scan_remediations(
                account_id=self.account_id,
                user_id=self.user_id,
                organization_id=self.org_id,
                scan_id=scan_id,
                scan_started_at=scan_start,
                scan_completed_at=scan_end,
                detected_finding_ids=set(),
                evaluated_services={"EC2", "S3", "IAM"},
                uninspected_resources=set(),
            )
            self.assertEqual(res_c["resolved_count"], 1)
            doc_c = findings_collection.find_one({"finding_id": fid})
            self.assertEqual(doc_c["status"], WORKFLOW_RESOLVED)

        finally:
            findings_collection.delete_many({"finding_id": fid})
            remediations_collection.delete_many({"finding_id": fid})


class TestScanHistoryAndInspectionAPI(unittest.TestCase):
    """Tests for scan history inspection API and S3 inventory/coverage persistence."""

    def setUp(self):
        self.user_id = "test-history-user-1"
        self.org_id = "test-history-org-1"
        self.current_user = {
            "_id": self.user_id,
            "organization": self.org_id,
        }

    @patch("app.api.cloud.get_scan")
    def test_history_details_historical_scan_without_inventory_returns_unavailable(self, mock_get_scan):
        """Historical scans without s3_coverage/s3_inventory return UNAVAILABLE status without fabricating data."""
        from app.api.cloud import history_details

        mock_get_scan.return_value = {
            "_id": "scan-historical-oct9",
            "aws_account_id": "138218764724",
            "risk_score": 57.22,
            "resources": {"s3": 2, "ec2": 4},
            "findings": [{"finding_id": "f1", "service": "S3"}],
            # s3_coverage and s3_inventory are intentionally omitted as in older scans
        }

        result = history_details(
            scan_id="scan-historical-oct9",
            current_user=self.current_user,
        )

        self.assertIsNotNone(result)
        self.assertIn("s3_coverage", result)
        self.assertEqual(result["s3_coverage"]["status"], "UNAVAILABLE")
        self.assertFalse(result["s3_coverage"]["evaluated"])
        self.assertEqual(result["s3_coverage"]["total_buckets"], 2)
        self.assertIn("not captured", result["s3_coverage"]["message"].lower())
        self.assertIsNone(result["s3_inventory"])

    @patch("app.api.cloud.get_scan")
    def test_history_details_historical_scan_with_inventory_computes_complete(self, mock_get_scan):
        """Historical scans that recorded s3_inventory but lacked s3_coverage compute COMPLETE coverage."""
        from app.api.cloud import history_details

        mock_get_scan.return_value = {
            "_id": "scan-historical-with-inv",
            "aws_account_id": "138218764724",
            "s3_inventory": [
                {
                    "bucket_name": "prod-data-bucket",
                    "region": "us-east-1",
                    "security_posture": "SECURE",
                    "coverage": "COMPLETE",
                }
            ],
        }

        result = history_details(
            scan_id="scan-historical-with-inv",
            current_user=self.current_user,
        )

        self.assertIn("s3_coverage", result)
        self.assertEqual(result["s3_coverage"]["status"], "COMPLETE")
        self.assertTrue(result["s3_coverage"]["evaluated"])
        self.assertEqual(result["s3_coverage"]["total_buckets"], 1)
        self.assertEqual(len(result["s3_inventory"]), 1)
        self.assertEqual(result["s3_inventory"][0]["bucket_name"], "prod-data-bucket")

    @patch("app.api.cloud.get_scan")
    def test_history_details_failed_s3_discovery_preserves_error(self, mock_get_scan):
        """Scans with failed S3 discovery return FAILED status, error details, and empty inventory."""
        from app.api.cloud import history_details

        mock_get_scan.return_value = {
            "_id": "scan-failed-s3",
            "aws_account_id": "138218764724",
            "s3_inventory": [],
            "s3_coverage": {
                "status": "FAILED",
                "total_buckets": 0,
                "evaluated": False,
                "error": "ClientError: AccessDenied listing buckets",
                "uninspected_buckets": [],
            },
            "findings": [{"finding_id": "f-s3-1", "service": "S3", "status": "Unknown"}],
        }

        result = history_details(
            scan_id="scan-failed-s3",
            current_user=self.current_user,
        )

        self.assertEqual(result["s3_coverage"]["status"], "FAILED")
        self.assertFalse(result["s3_coverage"]["evaluated"])
        self.assertIn("AccessDenied", result["s3_coverage"]["error"])
        self.assertEqual(result["s3_inventory"], [])

    @patch("app.api.cloud.get_scan")
    def test_history_details_zero_discovered_buckets(self, mock_get_scan):
        """Accounts with genuinely zero discovered buckets return ZERO_DISCOVERED status."""
        from app.api.cloud import history_details

        mock_get_scan.return_value = {
            "_id": "scan-zero-s3",
            "aws_account_id": "138218764724",
            "s3_inventory": [],
            "s3_coverage": {
                "status": "ZERO_DISCOVERED",
                "total_buckets": 0,
                "evaluated": True,
                "error": None,
                "uninspected_buckets": [],
            },
        }

        result = history_details(
            scan_id="scan-zero-s3",
            current_user=self.current_user,
        )

        self.assertEqual(result["s3_coverage"]["status"], "ZERO_DISCOVERED")
        self.assertTrue(result["s3_coverage"]["evaluated"])
        self.assertEqual(result["s3_coverage"]["total_buckets"], 0)

    @patch("app.api.cloud.ask_gemini")
    @patch("app.api.cloud.explain")
    @patch("app.api.cloud.save_scan")
    @patch("app.api.cloud.upsert_finding")
    @patch("app.api.cloud.reserve_quota")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.get_account")
    def test_scan_aws_persists_s3_inventory_and_coverage(
        self,
        mock_get_account,
        mock_get_clients,
        mock_assume_role,
        mock_reserve_quota,
        mock_upsert,
        mock_save_scan,
        mock_explain,
        mock_ask_gemini,
    ):
        """scan_aws builds and persists s3_inventory and structured s3_coverage."""
        from bson import ObjectId
        from app.api.cloud import scan_aws

        acc_oid = ObjectId()
        mock_get_account.return_value = {
            "_id": acc_oid,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_name": "Test Account",
            "account": "138218764724",
            "aws_account_id": "138218764724",
            "role_arn": "arn:aws:iam::138218764724:role/CloudGuardRole",
            "region": "us-east-1",
        }
        mock_reserve_quota.return_value = True

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [{"Name": "test-persisted-bucket", "CreationDate": datetime.utcnow()}]
        }
        mock_s3.get_bucket_location.return_value = {"LocationConstraint": None}
        mock_s3.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        mock_s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_encryption.return_value = {
            "ServerSideEncryptionConfiguration": {
                "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
            }
        }

        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_assume_role.return_value = mock_session

        # Mock AWS clients
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "138218764724",
            "Arn": "arn:aws:sts::138218764724:assumed-role/CloudGuardRole/scan",
        }

        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}


        mock_iam = MagicMock()
        mock_iam.list_users.return_value = {"Users": []}

        mock_cloudtrail = MagicMock()
        mock_cloudtrail.describe_trails.return_value = {"trailList": []}

        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {"DBInstances": []}

        mock_lambda = MagicMock()
        mock_lambda.list_functions.return_value = {"Functions": []}

        mock_kms = MagicMock()
        mock_kms.list_keys.return_value = {"Keys": []}

        mock_get_clients.return_value = {
            "sts": mock_sts,
            "ec2": mock_ec2,
            "s3": mock_s3,
            "iam": mock_iam,
            "cloudtrail": mock_cloudtrail,
            "rds": mock_rds,
            "lambda": mock_lambda,
            "kms": mock_kms,
        }

        mock_save_scan.return_value = {"_id": "saved-scan-123"}

        res = scan_aws(
            account_id=str(acc_oid),
            current_user=self.current_user,
        )

        self.assertIsNotNone(res)
        # Verify save_scan was called with s3_inventory and s3_coverage
        self.assertTrue(mock_save_scan.called)
        saved_scan = mock_save_scan.call_args[0][0]
        self.assertIn("s3_inventory", saved_scan)
        self.assertIn("s3_coverage", saved_scan)
        self.assertEqual(saved_scan["s3_coverage"]["status"], "COMPLETE")
        self.assertTrue(saved_scan["s3_coverage"]["evaluated"])
        self.assertEqual(len(saved_scan["s3_inventory"]), 1)
        self.assertEqual(saved_scan["s3_inventory"][0]["bucket_name"], "test-persisted-bucket")
        self.assertEqual(saved_scan["s3_inventory"][0]["region"], "us-east-1")
        self.assertEqual(saved_scan["s3_inventory"][0]["security_posture"], "SECURE")

    @patch("app.api.cloud.get_scan")
    @patch("app.api.cloud.get_all_scans")
    def test_history_list_new_scan_returns_s3_inventory_and_coverage(
        self,
        mock_get_all_scans,
        mock_get_scan,
    ):
        """history_list returns s3_inventory and s3_coverage for newly created scans."""
        from app.api.cloud import history_list

        mock_get_all_scans.return_value = [
            {
                "_id": "scan-fresh-001",
                "user_id": self.user_id,
                "organization_id": self.org_id,
                "account": "138218764724",
                "risk_score": 25.0,
                "status": "completed",
                "resources": {"s3": 2, "ec2": 4},
                "s3_inventory": [
                    {
                        "bucket_name": "app-assets",
                        "region": "us-east-1",
                        "security_posture": "SECURE",
                        "coverage": "COMPLETE",
                    },
                    {
                        "bucket_name": "db-backups",
                        "region": "ap-south-1",
                        "security_posture": "RISK",
                        "coverage": "COMPLETE",
                    },
                ],
                "s3_coverage": {
                    "status": "COMPLETE",
                    "total_buckets": 2,
                    "evaluated": True,
                    "error": None,
                    "uninspected_buckets": [],
                },
            }
        ]
        mock_get_scan.return_value = None

        results = history_list(current_user=self.current_user)

        self.assertEqual(len(results), 1)
        scan = results[0]
        self.assertIn("s3_inventory", scan)
        self.assertIn("s3_coverage", scan)
        self.assertEqual(len(scan["s3_inventory"]), 2)
        self.assertEqual(scan["s3_inventory"][0]["bucket_name"], "app-assets")
        self.assertEqual(scan["s3_coverage"]["status"], "COMPLETE")
        self.assertTrue(scan["s3_coverage"]["evaluated"])

    @patch("app.api.cloud.get_scan")
    @patch("app.api.cloud.get_all_scans")
    def test_history_list_historical_scan_normalized_as_unavailable(
        self,
        mock_get_all_scans,
        mock_get_scan,
    ):
        """history_list normalizes older historical scans as UNAVAILABLE without fabricating inventory."""
        from app.api.cloud import history_list

        mock_get_all_scans.return_value = [
            {
                "_id": "6ac8da71f0bfb2006e4b3ffc",  # Real historical scan ID
                "user_id": self.user_id,
                "organization_id": self.org_id,
                "account": "138218764724",
                "risk_score": 57.22,
                "status": "completed",
                "resources": {"s3": 3, "ec2": 8},
                # Note: No s3_inventory or s3_coverage
            }
        ]
        mock_get_scan.return_value = None

        results = history_list(current_user=self.current_user)

        self.assertEqual(len(results), 1)
        scan = results[0]
        self.assertIn("s3_coverage", scan)
        self.assertIsNone(scan["s3_inventory"])  # Do NOT fabricate bucket inventory
        self.assertEqual(scan["s3_coverage"]["status"], "UNAVAILABLE")
        self.assertFalse(scan["s3_coverage"]["evaluated"])
        self.assertEqual(scan["s3_coverage"]["total_buckets"], 3)
        self.assertIn("historical", scan["s3_coverage"]["message"].lower())

    @patch("app.api.cloud.get_scan")
    def test_history_details_new_scan_preserves_persisted_inventory(
        self,
        mock_get_scan,
    ):
        """history_details returns exact persisted inventory for inspection."""
        from app.api.cloud import history_details

        mock_get_scan.return_value = {
            "_id": "scan-fresh-detail",
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account": "138218764724",
            "risk_score": 10.0,
            "status": "completed",
            "resources": {"s3": 1},
            "s3_inventory": [
                {
                    "bucket_name": "production-logs",
                    "region": "us-east-1",
                    "security_posture": "SECURE",
                    "coverage": "COMPLETE",
                    "block_public_access": {"all_protected": True},
                    "bucket_policy": {"is_public": False, "status": "RESTRICTED"},
                    "acl": {"public": False, "status": "PRIVATE"},
                    "encryption": {"enabled": True, "algorithm": "AES256"},
                }
            ],
            "s3_coverage": {
                "status": "COMPLETE",
                "total_buckets": 1,
                "evaluated": True,
                "error": None,
                "uninspected_buckets": [],
            },
        }

        result = history_details(
            scan_id="scan-fresh-detail",
            current_user=self.current_user,
        )

        self.assertEqual(result["s3_coverage"]["status"], "COMPLETE")
        self.assertTrue(result["s3_coverage"]["evaluated"])
        self.assertIsNotNone(result["s3_inventory"])
        self.assertEqual(len(result["s3_inventory"]), 1)
        b = result["s3_inventory"][0]
        self.assertEqual(b["bucket_name"], "production-logs")
        self.assertEqual(b["region"], "us-east-1")
        self.assertEqual(b["security_posture"], "SECURE")
        self.assertTrue(b["block_public_access"]["all_protected"])

    @patch("app.api.cloud.ask_gemini")
    @patch("app.api.cloud.explain")
    @patch("app.api.cloud.save_scan")
    @patch("app.api.cloud.upsert_finding")
    @patch("app.api.cloud.reserve_quota")
    @patch("app.api.cloud.assume_aws_role")
    @patch("app.api.cloud.get_aws_clients")
    @patch("app.api.cloud.get_account")
    def test_complete_fresh_scan_data_flow_to_inspection(
        self,
        mock_get_account,
        mock_get_clients,
        mock_assume_role,
        mock_reserve_quota,
        mock_upsert,
        mock_save_scan,
        mock_explain,
        mock_ask_gemini,
    ):
        """End-to-end test: scan_aws -> save_scan -> history_details returns discovered S3 inventory."""
        from bson import ObjectId
        from app.api.cloud import scan_aws, history_details

        mock_ask_gemini.return_value = "Mocked AI analysis"
        mock_explain.return_value = {"explanations": []}

        acc_oid = ObjectId()
        mock_get_account.return_value = {
            "_id": acc_oid,
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "account_name": "Prod Account",
            "account": "138218764724",
            "aws_account_id": "138218764724",
            "role_arn": "arn:aws:iam::138218764724:role/CloudGuardRole",
            "region": "us-east-1",
        }
        mock_reserve_quota.return_value = True

        mock_s3 = MagicMock()
        mock_s3.list_buckets.return_value = {
            "Buckets": [
                {"Name": "corp-finance-vault", "CreationDate": datetime.utcnow()},
                {"Name": "corp-public-assets", "CreationDate": datetime.utcnow()},
            ]
        }
        def fake_get_bucket_location(Bucket=None, **kwargs):
            if Bucket == "corp-finance-vault":
                return {"LocationConstraint": None}
            return {"LocationConstraint": "eu-west-1"}

        def fake_get_pab(Bucket=None, **kwargs):
            if Bucket == "corp-finance-vault":
                return {
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True,
                    }
                }
            return {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                }
            }

        def fake_policy_status(Bucket=None, **kwargs):
            if Bucket == "corp-finance-vault":
                return {"PolicyStatus": {"IsPublic": False}}
            return {"PolicyStatus": {"IsPublic": True}}

        def fake_encryption(Bucket=None, **kwargs):
            if Bucket == "corp-finance-vault":
                return {
                    "ServerSideEncryptionConfiguration": {
                        "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]
                    }
                }
            return {
                "ServerSideEncryptionConfiguration": {
                    "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
                }
            }

        mock_s3.get_bucket_location.side_effect = fake_get_bucket_location
        mock_s3.get_public_access_block.side_effect = fake_get_pab
        mock_s3.get_bucket_policy_status.side_effect = fake_policy_status
        mock_s3.get_bucket_acl.return_value = {"Grants": []}
        mock_s3.get_bucket_encryption.side_effect = fake_encryption

        mock_session = MagicMock()
        mock_session.client.return_value = mock_s3
        mock_assume_role.return_value = mock_session

        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {
            "Account": "138218764724",
            "Arn": "arn:aws:sts::138218764724:assumed-role/CloudGuardRole/scan",
        }
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_iam = MagicMock()
        mock_iam.list_users.return_value = {"Users": []}
        mock_cloudtrail = MagicMock()
        mock_cloudtrail.describe_trails.return_value = {"trailList": []}
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {"DBInstances": []}
        mock_lambda = MagicMock()
        mock_lambda.list_functions.return_value = {"Functions": []}
        mock_kms = MagicMock()
        mock_kms.list_keys.return_value = {"Keys": []}

        mock_get_clients.return_value = {
            "sts": mock_sts,
            "ec2": mock_ec2,
            "s3": mock_s3,
            "iam": mock_iam,
            "cloudtrail": mock_cloudtrail,
            "rds": mock_rds,
            "lambda": mock_lambda,
            "kms": mock_kms,
        }

        persisted_document = {}
        def fake_save_scan(scan_doc, user_id, account_id=None):
            persisted_document.update(scan_doc)
            persisted_document["_id"] = "e2e-scan-789"
            return "e2e-scan-789"

        mock_save_scan.side_effect = fake_save_scan

        # 1. Trigger scan_aws
        scan_result = scan_aws(
            account_id=str(acc_oid),
            current_user=self.current_user,
        )

        self.assertIsNotNone(scan_result)
        self.assertEqual(scan_result["status"], "success")

        # 2. Verify MongoDB persisted document has S3 inventory & coverage
        self.assertIn("s3_inventory", persisted_document)
        self.assertIn("s3_coverage", persisted_document)
        self.assertEqual(persisted_document["s3_coverage"]["status"], "COMPLETE")
        self.assertEqual(len(persisted_document["s3_inventory"]), 2)

        # 3. Verify history_details retrieves this exact document for Scan Inspection
        with patch("app.api.cloud.get_scan") as mock_get_scan:
            mock_get_scan.return_value = persisted_document

            details = history_details(
                scan_id="e2e-scan-789",
                current_user=self.current_user,
            )

            self.assertEqual(details["_id"], "e2e-scan-789")
            self.assertEqual(details["s3_coverage"]["status"], "COMPLETE")
            self.assertEqual(len(details["s3_inventory"]), 2)
            bucket_names = [b["bucket_name"] for b in details["s3_inventory"]]
            self.assertIn("corp-finance-vault", bucket_names)
            self.assertIn("corp-public-assets", bucket_names)

            # Check individual bucket posture
            b1 = next(b for b in details["s3_inventory"] if b["bucket_name"] == "corp-finance-vault")
            self.assertEqual(b1["region"], "us-east-1")
            self.assertEqual(b1["security_posture"], "SECURE")

            b2 = next(b for b in details["s3_inventory"] if b["bucket_name"] == "corp-public-assets")
            self.assertEqual(b2["region"], "eu-west-1")
            self.assertEqual(b2["security_posture"], "CRITICAL")


if __name__ == "__main__":
    unittest.main()

