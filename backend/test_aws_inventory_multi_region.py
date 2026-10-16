# ============================================================
# CloudGuardAI - Phase 7C: AWS Multi-Region Inventory Tests
# Strictly mocked tests for EC2, RDS, Network, S3, and IAM
# read-only inventory, bounded multi-region discovery, partial
# failure reporting, tenant isolation, and disconnected checks.
# ============================================================

import os
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from bson import ObjectId
from botocore.exceptions import ClientError
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

from app.api.cloud import router as cloud_router
from app.middleware.auth_middleware import verify_token
from app.services.ec2_inventory_service import (
    discover_multi_region_ec2_inventory,
    STANDARD_AWS_REGIONS as EC2_STANDARD_REGIONS,
)
from app.services.rds_control_service import (
    discover_multi_region_rds_inventory,
    discover_multi_region_rds_clusters,
    STANDARD_AWS_REGIONS as RDS_STANDARD_REGIONS,
)
from app.services.network_control_service import (
    discover_multi_region_vpcs,
    discover_multi_region_security_groups,
    STANDARD_AWS_REGIONS as NET_STANDARD_REGIONS,
)


class TestAWSInventoryMultiRegion(unittest.TestCase):
    """
    Phase 7C Multi-Region Discovery and Read-Only Inventory Tests:
    - Bounded multi-region discovery (ThreadPoolExecutor max_workers=5)
    - EC2, RDS, Network (VPCs, Security Groups) multi-region flows
    - Partial failure handling and coverage reporting (coverage='PARTIAL')
    - Full failure handling (ClientError / 403 on AccessDenied across all regions)
    - Tenant isolation: cross-tenant access blocked (404/403)
    - Disconnected account fail-fast check (HTTP 400)
    - STS account identity mismatch rejection (HTTP 403)
    - Strictly read-only calls (no create/delete/modify mutations)
    - S3 global and regional bucket listing
    - IAM inventory read-only querying and error mapping
    """

    def setUp(self):
        self.org_alpha = "org-alpha-123"
        self.org_beta = "org-beta-456"

        self.user_alpha_id = str(ObjectId())
        self.user_beta_id = str(ObjectId())

        self.aws_account_num = "123456789012"
        self.role_arn = f"arn:aws:iam::{self.aws_account_num}:role/CloudGuardAIRole"
        self.account_oid = ObjectId()
        self.account_id = str(self.account_oid)

        self.account_doc = {
            "_id": self.account_oid,
            "account_id": self.account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Production Account",
            "role_arn": self.role_arn,
            "region": "us-east-1",
            "status": "connected",
            "external_id": f"cgai-ext-{self.org_alpha}-secret123",
            "organization_id": self.org_alpha,
            "user_id": self.user_alpha_id,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        self.disconnected_account_oid = ObjectId()
        self.disconnected_account_id = str(self.disconnected_account_oid)
        self.disconnected_account_doc = {
            "_id": self.disconnected_account_oid,
            "account_id": self.disconnected_account_id,
            "aws_account_id": self.aws_account_num,
            "account_name": "Disconnected Account",
            "role_arn": self.role_arn,
            "region": "us-east-1",
            "status": "disconnected",
            "external_id": f"cgai-ext-{self.org_alpha}-secret456",
            "organization_id": self.org_alpha,
            "user_id": self.user_alpha_id,
            "created_at": datetime.now(timezone.utc),
            "updated_at": datetime.now(timezone.utc),
        }

        self.accounts_store = {
            self.account_id: self.account_doc,
            self.disconnected_account_id: self.disconnected_account_doc,
        }

        self.current_user = {
            "_id": self.user_alpha_id,
            "organization": self.org_alpha,
            "role": "owner",
        }

        # Mock assume role and STS
        self.mock_session = MagicMock()
        self.mock_sts = MagicMock()
        self.mock_sts.get_caller_identity.return_value = {"Account": self.aws_account_num}

        # Setup FastAPI app
        self.app = FastAPI(title="Phase 7C Tests")
        self.app.include_router(cloud_router, prefix="/cloud")

        def _mock_verify_token():
            if not self.current_user:
                raise HTTPException(status_code=401, detail="Unauthorized")
            return self.current_user

        self.app.dependency_overrides[verify_token] = _mock_verify_token
        self.client = TestClient(self.app)

        self.patchers = [
            patch("app.api.cloud.get_account", side_effect=self._mock_get_account),
            patch("app.api.cloud.assume_aws_role", return_value=self.mock_session),
            patch("app.api.cloud.verify_aws_account", side_effect=self._mock_verify_aws_account),
            patch("app.api.cloud.get_aws_clients", return_value=self._mock_clients_dict()),
        ]
        for p in self.patchers:
            p.start()

    def tearDown(self):
        for p in reversed(self.patchers):
            p.stop()

    def _mock_get_account(self, account_id, organization_id=None):
        acc = self.accounts_store.get(str(account_id))
        if not acc:
            return None
        if organization_id and acc.get("organization_id") != organization_id:
            return None
        return acc

    def _mock_verify_aws_account(self, session, stored_account_id):
        if stored_account_id != self.aws_account_num:
            raise PermissionError(f"Account ID mismatch: {stored_account_id} != {self.aws_account_num}")
        return True

    def _mock_clients_dict(self):
        return {
            "ec2": MagicMock(),
            "rds": MagicMock(),
            "s3": MagicMock(),
            "iam": MagicMock(),
        }

    # ============================================================
    # 1. EC2 MULTI-REGION DISCOVERY TESTS
    # ============================================================

    def test_ec2_multi_region_service_full_success(self):
        """EC2 multi-region discovery across regions aggregates results deterministically."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            client.describe_instances.return_value = {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": f"i-{region_name}-01",
                                "InstanceType": "t3.micro",
                                "State": {"Name": "running"},
                                "Placement": {"AvailabilityZone": f"{region_name}a"},
                                "LaunchTime": datetime.now(timezone.utc),
                                "Tags": [{"Key": "Name", "Value": f"server-{region_name}"}],
                            }
                        ]
                    }
                ]
            }
            return client

        session.client.side_effect = make_client

        test_regions = ["us-east-1", "us-west-2", "eu-west-1"]
        result = discover_multi_region_ec2_inventory(session, regions=test_regions, max_workers=3)

        self.assertEqual(result["coverage"], "COMPLETE")
        self.assertEqual(result["total_count"], 3)
        self.assertEqual(len(result["instances"]), 3)
        self.assertEqual(result["regional_failures"], [])
        self.assertEqual(len(result["successful_regions"]), 3)
        found_regions = {inst["region"] for inst in result["instances"]}
        self.assertEqual(found_regions, set(test_regions))

    def test_ec2_multi_region_service_partial_failure(self):
        """When one region fails (AccessDenied / OptInRequired), discovery continues with PARTIAL coverage."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            if region_name == "sa-east-1":
                error_response = {
                    "Error": {
                        "Code": "AuthFailure",
                        "Message": "AWS was not able to validate the provided access credentials",
                    }
                }
                client.describe_instances.side_effect = ClientError(error_response, "DescribeInstances")
            else:
                client.describe_instances.return_value = {
                    "Reservations": [
                        {
                            "Instances": [
                                {
                                    "InstanceId": f"i-{region_name}-01",
                                    "InstanceType": "t3.small",
                                    "State": {"Name": "running"},
                                    "Placement": {"AvailabilityZone": f"{region_name}a"},
                                    "LaunchTime": datetime.now(timezone.utc),
                                }
                            ]
                        }
                    ]
                }
            return client

        session.client.side_effect = make_client

        test_regions = ["us-east-1", "sa-east-1"]
        result = discover_multi_region_ec2_inventory(session, regions=test_regions, max_workers=2)

        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["total_count"], 1)
        self.assertEqual(len(result["regional_failures"]), 1)
        self.assertEqual(result["regional_failures"][0]["region"], "sa-east-1")
        self.assertEqual(result["regional_failures"][0]["code"], "AuthFailure")
        self.assertEqual(result["successful_regions"], ["us-east-1"])

    def test_ec2_multi_region_service_all_access_denied(self):
        """When all regions fail with AccessDenied, service raises ClientError."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            error_response = {
                "Error": {
                    "Code": "UnauthorizedOperation",
                    "Message": "You are not authorized to perform this operation.",
                }
            }
            client.describe_instances.side_effect = ClientError(error_response, "DescribeInstances")
            return client

        session.client.side_effect = make_client

        with self.assertRaises(ClientError):
            discover_multi_region_ec2_inventory(session, regions=["us-east-1", "us-west-2"], max_workers=2)

    def test_ec2_inventory_endpoint_multi_region(self):
        """GET /cloud/aws/ec2/{account_id}/instances?region=all invokes multi-region discovery."""
        with patch("app.api.cloud.discover_multi_region_ec2_inventory") as mock_disc:
            mock_disc.return_value = {
                "total_count": 2,
                "summary": {"total_instances": 2, "running": 2, "stopped": 0, "region": "all"},
                "instances": [
                    {"instance_id": "i-111", "region": "us-east-1", "state": "running"},
                    {"instance_id": "i-222", "region": "eu-central-1", "state": "running"},
                ],
                "coverage": "COMPLETE",
                "regional_failures": [],
                "successful_regions": ["us-east-1", "eu-central-1"],
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }

            resp = self.client.get(f"/cloud/aws/ec2/{self.account_id}/instances?region=all")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["region"], "all")
            self.assertEqual(data["total_count"], 2)
            self.assertEqual(data["coverage"], "COMPLETE")
            self.assertIn("retrieved_at", data)
            mock_disc.assert_called_once()

    # ============================================================
    # 2. RDS MULTI-REGION DISCOVERY TESTS
    # ============================================================

    def test_rds_multi_region_service_instances_and_clusters(self):
        """RDS multi-region discovery aggregates DB instances and clusters with honest coverage."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            client.describe_db_instances.return_value = {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": f"db-{region_name}-prod",
                        "DBInstanceClass": "db.t3.medium",
                        "Engine": "postgres",
                        "DBInstanceStatus": "available",
                        "PubliclyAccessible": False,
                        "StorageEncrypted": True,
                        "AvailabilityZone": f"{region_name}a",
                    }
                ]
            }
            client.describe_db_clusters.return_value = {
                "DBClusters": [
                    {
                        "DBClusterIdentifier": f"aurora-{region_name}-cluster",
                        "Engine": "aurora-postgresql",
                        "Status": "available",
                        "StorageEncrypted": True,
                    }
                ]
            }
            return client

        session.client.side_effect = make_client

        test_regions = ["us-east-1", "ap-south-1"]
        inst_res = discover_multi_region_rds_inventory(session, regions=test_regions, max_workers=2)
        self.assertEqual(inst_res["coverage"], "COMPLETE")
        self.assertEqual(inst_res["total_count"], 2)

        clust_res = discover_multi_region_rds_clusters(session, regions=test_regions, max_workers=2)
        self.assertEqual(clust_res["coverage"], "COMPLETE")
        self.assertEqual(clust_res["total_count"], 2)

    def test_rds_multi_region_partial_failure(self):
        """RDS multi-region discovery handles a single regional failure without breaking others."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            if region_name == "eu-west-1":
                error_response = {
                    "Error": {
                        "Code": "AccessDenied",
                        "Message": "User is not authorized to perform rds:DescribeDBInstances in eu-west-1",
                    }
                }
                client.describe_db_instances.side_effect = ClientError(error_response, "DescribeDBInstances")
            else:
                client.describe_db_instances.return_value = {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": f"db-{region_name}-test",
                            "DBInstanceClass": "db.t3.micro",
                            "Engine": "mysql",
                            "DBInstanceStatus": "available",
                        }
                    ]
                }
            return client

        session.client.side_effect = make_client

        test_regions = ["us-east-1", "eu-west-1"]
        result = discover_multi_region_rds_inventory(session, regions=test_regions, max_workers=2)
        self.assertEqual(result["coverage"], "PARTIAL")
        self.assertEqual(result["total_count"], 1)
        self.assertEqual(len(result["regional_failures"]), 1)
        self.assertEqual(result["regional_failures"][0]["region"], "eu-west-1")

    def test_rds_inventory_endpoint_multi_region(self):
        """GET /cloud/aws/rds/{account_id}/instances?region=all invokes multi-region RDS discovery."""
        with patch("app.api.cloud.discover_multi_region_rds_inventory") as mock_disc:
            mock_disc.return_value = {
                "total_count": 1,
                "summary": {"total_instances": 1, "available": 1},
                "instances": [
                    {"db_instance_id": "db-1", "region": "us-east-1", "status": "available"}
                ],
                "coverage": "COMPLETE",
                "regional_failures": [],
                "successful_regions": ["us-east-1"],
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }

            resp = self.client.get(f"/cloud/aws/rds/{self.account_id}/instances?region=all")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["region"], "all")
            self.assertEqual(data["coverage"], "COMPLETE")

    # ============================================================
    # 3. NETWORK (VPC & SECURITY GROUP) MULTI-REGION DISCOVERY
    # ============================================================

    def test_network_multi_region_vpcs_and_sgs(self):
        """VPCs and Security Groups multi-region discovery runs across regions with safe defaults."""
        session = MagicMock()

        def make_client(service_name, region_name=None, *args, **kwargs):
            client = MagicMock()
            client.describe_vpcs.return_value = {
                "Vpcs": [
                    {
                        "VpcId": f"vpc-{region_name}-01",
                        "CidrBlock": "10.0.0.0/16",
                        "IsDefault": False,
                        "State": "available",
                        "Tags": [{"Key": "Name", "Value": f"vpc-{region_name}"}],
                    }
                ]
            }
            client.describe_security_groups.return_value = {
                "SecurityGroups": [
                    {
                        "GroupId": f"sg-{region_name}-01",
                        "GroupName": f"sg-{region_name}",
                        "Description": "Test SG",
                        "VpcId": f"vpc-{region_name}-01",
                        "IpPermissions": [],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
            return client

        session.client.side_effect = make_client

        test_regions = ["us-east-1", "ap-southeast-1"]
        vpc_res = discover_multi_region_vpcs(session, regions=test_regions, max_workers=2)
        self.assertEqual(vpc_res["coverage"], "COMPLETE")
        self.assertEqual(vpc_res["total_count"], 2)

        sg_res = discover_multi_region_security_groups(session, regions=test_regions, max_workers=2)
        self.assertEqual(sg_res["coverage"], "COMPLETE")
        self.assertEqual(sg_res["total_count"], 2)

    def test_network_multi_region_vpcs_endpoint(self):
        """GET /cloud/aws/network/{account_id}/vpcs?region=all calls discover_multi_region_vpcs."""
        with patch("app.api.cloud.discover_multi_region_vpcs") as mock_disc:
            mock_disc.return_value = {
                "total_count": 1,
                "summary": {"total_vpcs": 1, "custom_vpcs": 1, "default_vpcs": 0},
                "vpcs": [{"vpc_id": "vpc-1", "region": "us-east-1"}],
                "coverage": "COMPLETE",
                "regional_failures": [],
                "successful_regions": ["us-east-1"],
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }

            resp = self.client.get(f"/cloud/aws/network/{self.account_id}/vpcs?region=all")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertEqual(data["region"], "all")
            self.assertEqual(data["coverage"], "COMPLETE")

    # ============================================================
    # 4. S3 READ-ONLY INVENTORY & REGION HANDLING
    # ============================================================

    def test_s3_inventory_all_regions(self):
        """GET /cloud/aws/s3/{account_id}/buckets?region=all accepts global bucket inventory."""
        with patch("app.api.cloud.fetch_s3_buckets_inventory") as mock_fetch:
            mock_fetch.return_value = {
                "total_count": 2,
                "summary": {"total_buckets": 2, "public_count": 0, "encrypted_count": 2},
                "buckets": [
                    {"name": "bucket-east", "region": "us-east-1"},
                    {"name": "bucket-west", "region": "us-west-2"},
                ],
                "next_token": None,
                "coverage": "COMPLETE",
            }

            resp = self.client.get(f"/cloud/aws/s3/{self.account_id}/buckets?region=all")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "success")
            self.assertIn("retrieved_at", data)
            self.assertEqual(data["total_count"], 2)

    # ============================================================
    # 5. IAM READ-ONLY INVENTORY & PERMISSION DENIED HANDLING
    # ============================================================

    def test_iam_inventory_permission_denied_mapping(self):
        """GET /cloud/aws/iam/{account_id}/inventory maps ClientError AccessDenied to HTTP 403."""
        with patch("app.api.cloud.fetch_iam_inventory") as mock_fetch:
            error_response = {
                "Error": {
                    "Code": "AccessDenied",
                    "Message": "User is not authorized to perform iam:ListUsers",
                }
            }
            mock_fetch.side_effect = ClientError(error_response, "ListUsers")

            resp = self.client.get(f"/cloud/aws/iam/{self.account_id}/inventory")
            self.assertEqual(resp.status_code, 403)
            self.assertIn("AWS AccessDenied", resp.json()["detail"])

    # ============================================================
    # 6. DISCONNECTED ACCOUNT FAIL-FAST CHECK
    # ============================================================

    def test_disconnected_account_rejected_across_all_inventory_routes(self):
        """All inventory endpoints immediately return HTTP 400 when account status is 'disconnected'."""
        routes = [
            f"/cloud/aws/ec2/{self.disconnected_account_id}/instances",
            f"/cloud/aws/rds/{self.disconnected_account_id}/instances",
            f"/cloud/aws/rds/{self.disconnected_account_id}/clusters",
            f"/cloud/aws/network/{self.disconnected_account_id}/vpcs",
            f"/cloud/aws/network/{self.disconnected_account_id}/security-groups",
            f"/cloud/aws/s3/{self.disconnected_account_id}/buckets",
            f"/cloud/aws/iam/{self.disconnected_account_id}/inventory",
        ]

        for route in routes:
            with self.subTest(route=route):
                resp = self.client.get(route)
                self.assertEqual(
                    resp.status_code,
                    400,
                    f"Route {route} did not return 400 for disconnected account, got {resp.status_code}: {resp.text}",
                )
                self.assertIn("disconnected", resp.json()["detail"].lower())

    # ============================================================
    # 7. TENANT ISOLATION & ACCOUNT VERIFICATION
    # ============================================================

    def test_tenant_isolation_cross_organization_blocked(self):
        """User from Org Beta cannot query inventory of an account belonging to Org Alpha."""
        self.current_user = {
            "_id": self.user_beta_id,
            "organization": self.org_beta,
            "role": "admin",
        }

        resp = self.client.get(f"/cloud/aws/ec2/{self.account_id}/instances")
        self.assertEqual(resp.status_code, 404)
        self.assertIn("not found", resp.json()["detail"].lower())

    def test_account_id_mismatch_raises_403(self):
        """If STS GetCallerIdentity returns an account ID different from database, returns 403."""
        with patch("app.api.cloud.verify_aws_account") as mock_verify:
            mock_verify.side_effect = PermissionError("AWS account identity mismatch.")

            resp = self.client.get(f"/cloud/aws/ec2/{self.account_id}/instances")
            self.assertEqual(resp.status_code, 403)
            self.assertIn("mismatch", resp.json()["detail"].lower())

    # ============================================================
    # 8. STRICT READ-ONLY GUARANTEE (NO MUTATION CALLS)
    # ============================================================

    def test_inventory_strictly_read_only_no_mutations(self):
        """Verify that multi-region inventory execution never calls mutate/modify/delete boto3 methods."""
        session = MagicMock()
        client = MagicMock()
        session.client.return_value = client

        client.describe_instances.return_value = {"Reservations": []}
        discover_multi_region_ec2_inventory(session, regions=["us-east-1"], max_workers=1)

        # Ensure no write methods were touched
        forbidden_calls = [
            "run_instances",
            "terminate_instances",
            "stop_instances",
            "start_instances",
            "reboot_instances",
            "modify_instance_attribute",
        ]
        for forbidden in forbidden_calls:
            self.assertFalse(
                getattr(client, forbidden).called,
                f"Forbidden mutation call '{forbidden}' was invoked during read-only EC2 discovery!",
            )


if __name__ == "__main__":
    unittest.main()
