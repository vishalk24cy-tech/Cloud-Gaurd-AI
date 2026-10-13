# ============================================================
# CloudGuardAI - Unit & Regression Tests for Network Resource Controls
# Phase 5: AWS VPC, Network Inventory, Security Groups & Remediation
# ============================================================

from datetime import datetime, timezone
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from bson import ObjectId
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException

from app.api.cloud import (
    control_security_group,
    list_gateways,
    list_route_tables,
    list_security_groups,
    list_subnets,
    list_vpc_endpoints,
    list_vpcs,
    SecurityGroupActionPayload,
)
from app.models.audit_log import (
    EVENT_REMEDIATION_AUTHORIZATION,
    EVENT_RESOURCE_CONTROL_COMPLETED,
    EVENT_RESOURCE_CONTROL_EXECUTION_STARTED,
    EVENT_RESOURCE_CONTROL_FAILED,
    RESULT_DENIED,
    RESULT_FAILURE,
    RESULT_SUCCESS,
)
from app.services.network_control_service import (
    ALLOWED_NETWORK_MUTATION_ACTIONS,
    NetworkControlExecutionError,
    execute_security_group_control,
    is_valid_gateway_id,
    is_valid_route_table_id,
    is_valid_security_group_id,
    is_valid_subnet_id,
    is_valid_vpc_endpoint_id,
    is_valid_vpc_id,
    normalize_gateway,
    normalize_route_table,
    normalize_security_group,
    normalize_subnet,
    normalize_vpc,
    normalize_vpc_endpoint,
    query_gateways,
    query_route_tables,
    query_security_groups,
    query_subnets,
    query_vpc_endpoints,
    query_vpcs,
    validate_aws_region,
)


class TestNetworkValidationAndNormalizationUnit(unittest.TestCase):
    """Unit tests for Network identifier validation and resource normalization."""

    def test_validators(self):
        """Test VPC, Subnet, SG, Route Table, Gateway, VPCE and Region validators."""
        self.assertTrue(validate_aws_region("us-east-1"))
        self.assertTrue(validate_aws_region("ap-south-1"))
        self.assertFalse(validate_aws_region("invalid-region"))
        self.assertFalse(validate_aws_region(""))

        self.assertTrue(is_valid_vpc_id("vpc-12345678"))
        self.assertTrue(is_valid_vpc_id("vpc-0123456789abcdef0"))
        self.assertFalse(is_valid_vpc_id("invalid-vpc"))

        self.assertTrue(is_valid_subnet_id("subnet-12345678"))
        self.assertFalse(is_valid_subnet_id("invalid-subnet"))

        self.assertTrue(is_valid_security_group_id("sg-12345678"))
        self.assertFalse(is_valid_security_group_id("invalid-sg"))

        self.assertTrue(is_valid_route_table_id("rtb-12345678"))
        self.assertFalse(is_valid_route_table_id("invalid-rtb"))

        self.assertTrue(is_valid_gateway_id("igw-12345678"))
        self.assertTrue(is_valid_gateway_id("nat-12345678"))
        self.assertFalse(is_valid_gateway_id("gw-12345678"))

        self.assertTrue(is_valid_vpc_endpoint_id("vpce-12345678"))
        self.assertFalse(is_valid_vpc_endpoint_id("invalid-vpce"))

    def test_normalize_vpc(self):
        """Test VPC normalization with CIDRs and tags."""
        raw_vpc = {
            "VpcId": "vpc-01234567",
            "State": "available",
            "CidrBlock": "10.0.0.0/16",
            "DhcpOptionsId": "dopt-12345678",
            "IsDefault": False,
            "InstanceTenancy": "default",
            "CidrBlockAssociationSet": [{"CidrBlock": "10.0.0.0/16"}, {"CidrBlock": "10.1.0.0/16"}],
            "Tags": [{"Key": "Name", "Value": "Production-VPC"}],
        }
        res = normalize_vpc(raw_vpc, fallback_region="us-east-1")
        self.assertEqual(res["vpc_id"], "vpc-01234567")
        self.assertEqual(res["name"], "Production-VPC")
        self.assertEqual(res["cidr_block"], "10.0.0.0/16")
        self.assertEqual(res["secondary_cidrs"], ["10.1.0.0/16"])
        self.assertEqual(res["security_posture"], "SECURE")
        self.assertFalse(res["is_default"])

    def test_normalize_subnet(self):
        """Test Subnet normalization and posture evaluation."""
        raw_public_subnet = {
            "SubnetId": "subnet-01234567",
            "VpcId": "vpc-01234567",
            "State": "available",
            "CidrBlock": "10.0.1.0/24",
            "AvailabilityZone": "us-east-1a",
            "AvailableIpAddressCount": 250,
            "MapPublicIpOnLaunch": True,
            "Tags": [{"Key": "Name", "Value": "Public-Subnet-1"}],
        }
        res = normalize_subnet(raw_public_subnet, fallback_region="us-east-1")
        self.assertEqual(res["subnet_id"], "subnet-01234567")
        self.assertEqual(res["security_posture"], "RISK")
        self.assertTrue(res["map_public_ip_on_launch"])
        self.assertEqual(res["region"], "us-east-1")

    def test_normalize_security_group_critical_ssh_rdp(self):
        """Test Security Group posture with open SSH and RDP rules."""
        raw_sg = {
            "GroupId": "sg-01234567",
            "GroupName": "web-servers",
            "Description": "Public web and ssh",
            "VpcId": "vpc-01234567",
            "OwnerId": "123456789012",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                },
            ],
            "IpPermissionsEgress": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
        res = normalize_security_group(raw_sg, fallback_region="us-east-1")
        self.assertEqual(res["group_id"], "sg-01234567")
        self.assertEqual(res["security_posture"], "HIGH_RISK")
        self.assertTrue(res["has_open_ssh"])
        self.assertTrue(res["has_open_rdp"])
        self.assertEqual(res["ingress_rule_count"], 2)

    def test_normalize_security_group_critical_all_traffic(self):
        """Test Security Group posture with unrestricted all traffic (-1)."""
        raw_sg = {
            "GroupId": "sg-openall",
            "GroupName": "wide-open",
            "Description": "All open",
            "VpcId": "vpc-01234567",
            "IpPermissions": [
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        }
        res = normalize_security_group(raw_sg, fallback_region="us-east-1")
        self.assertEqual(res["security_posture"], "CRITICAL")
        self.assertTrue(res["has_all_traffic_open"])

    def test_normalize_route_table(self):
        """Test Route Table normalization and internet route detection."""
        raw_rt = {
            "RouteTableId": "rtb-01234567",
            "VpcId": "vpc-01234567",
            "Routes": [
                {"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local", "State": "active"},
                {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-01234567", "State": "active"},
            ],
            "Associations": [{"RouteTableAssociationId": "rtbassoc-123", "SubnetId": "subnet-123", "Main": False}],
        }
        res = normalize_route_table(raw_rt, fallback_region="us-east-1")
        self.assertEqual(res["route_table_id"], "rtb-01234567")
        self.assertTrue(res["has_direct_internet_route"])
        self.assertEqual(res["security_posture"], "PUBLIC_ROUTE")


class TestNetworkInventoryQueries(unittest.TestCase):
    """Unit tests for read-only inventory query methods."""

    def test_query_vpcs_success(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.return_value = {
            "Vpcs": [
                {"VpcId": "vpc-001", "CidrBlock": "10.0.0.0/16", "IsDefault": True, "State": "available"},
                {"VpcId": "vpc-002", "CidrBlock": "172.31.0.0/16", "IsDefault": False, "State": "available"},
            ]
        }
        res = query_vpcs(mock_ec2, region="us-east-1", search="vpc-001")
        self.assertEqual(res["total_count"], 1)
        self.assertEqual(res["vpcs"][0]["vpc_id"], "vpc-001")

    def test_query_vpcs_access_denied(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_vpcs.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "DescribeVpcs"
        )
        with self.assertRaises(NetworkControlExecutionError) as cm:
            query_vpcs(mock_ec2, region="us-east-1")
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "AWS_ACCESS_DENIED")

    def test_query_security_groups_with_posture_filter(self):
        mock_ec2 = MagicMock()
        mock_ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-critical",
                    "GroupName": "crit-sg",
                    "IpPermissions": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                },
                {
                    "GroupId": "sg-secure",
                    "GroupName": "sec-sg",
                    "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}],
                },
            ]
        }
        res = query_security_groups(mock_ec2, region="us-east-1", posture_filter="CRITICAL")
        self.assertEqual(len(res["security_groups"]), 1)
        self.assertEqual(res["security_groups"][0]["group_id"], "sg-critical")


class TestSecurityGroupMutationControls(unittest.TestCase):
    """Unit and mock tests for Security Group rule mutation safety."""

    def setUp(self):
        self.mock_account = {
            "_id": ObjectId("66e000000000000000000001"),
            "aws_account_id": "123456789012",
            "account_name": "Test AWS Account",
            "role_arn": "arn:aws:iam::123456789012:role/CloudGuardAIRole",
            "region": "us-east-1",
            "status": "connected",
            "organization_id": "org-123",
        }

        from app.database.connection import db
        db.aws_accounts.insert_one(dict(self.mock_account))
        db.remediation_settings.insert_one({
            "organization_id": "org-123",
            "account_id": str(self.mock_account["_id"]),
            "aws_account_id": "123456789012",
            "services": {
                "ec2": True,
                "s3": True,
                "vpc": True,
                "rds": True,
                "iam": True,
                "cloudtrail": True,
            },
        })

    def tearDown(self):
        from app.database.connection import db
        db.aws_accounts.delete_many({"organization_id": "org-123"})
        db.remediation_settings.delete_many({"organization_id": "org-123"})

    @patch("app.services.network_control_service.record_event")
    def test_unauthorized_role_rejected(self, mock_record_event):
        """Viewer or member roles must be rejected with 403 and audit log recorded."""
        with self.assertRaises(NetworkControlExecutionError) as cm:
            execute_security_group_control(
                account_id="acc-123",
                group_id="sg-01234567",
                user_id="user-123",
                organization_id="org-123",
                user_role="viewer",
                action="revoke_ssh_ingress",
                confirmed=True,
            )
        self.assertEqual(cm.exception.status_code, 403)
        self.assertEqual(cm.exception.code, "ROLE_NOT_AUTHORIZED")
        mock_record_event.assert_called_once()
        self.assertEqual(mock_record_event.call_args[1]["event_type"], EVENT_REMEDIATION_AUTHORIZATION)

    def test_unconfirmed_request_rejected(self):
        """Requests without explicit confirmed=True must be rejected."""
        with self.assertRaises(NetworkControlExecutionError) as cm:
            execute_security_group_control(
                account_id="acc-123",
                group_id="sg-01234567",
                user_id="user-123",
                organization_id="org-123",
                user_role="admin",
                action="revoke_ssh_ingress",
                confirmed=False,
            )
        self.assertEqual(cm.exception.status_code, 409)
        self.assertEqual(cm.exception.code, "CONFIRMATION_REQUIRED")

    @patch("app.services.network_control_service.record_event")
    @patch("app.services.network_control_service.get_aws_clients")
    @patch("app.services.network_control_service.verify_aws_account")
    @patch("app.services.network_control_service.assume_aws_role")
    @patch("app.services.network_control_service.get_account")
    def test_revoke_ssh_ingress_success_and_post_verification(
        self, mock_get_account, mock_assume, mock_verify_aws, mock_clients, mock_record_event
    ):
        """Test successful SSH rule revocation, audit events, and post-action verification."""
        mock_get_account.return_value = self.mock_account
        mock_session = MagicMock()
        mock_assume.return_value = mock_session
        mock_ec2 = MagicMock()
        mock_clients.return_value = {"ec2": mock_ec2}

        # Initial describe returns open SSH rule
        initial_sg = {
            "GroupId": "sg-01234567",
            "GroupName": "ssh-sg",
            "OwnerId": "123456789012",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
            "IpPermissionsEgress": [],
        }
        # Post-action describe returns empty rules (verified)
        verified_sg = {
            "GroupId": "sg-01234567",
            "GroupName": "ssh-sg",
            "OwnerId": "123456789012",
            "IpPermissions": [],
            "IpPermissionsEgress": [],
        }

        mock_ec2.describe_security_groups.side_effect = [
            {"SecurityGroups": [initial_sg]},
            {"SecurityGroups": [verified_sg]},
        ]
        mock_ec2.revoke_security_group_ingress.return_value = {"Return": True}

        res = execute_security_group_control(
            account_id=str(self.mock_account["_id"]),
            group_id="sg-01234567",
            user_id="user-123",
            organization_id="org-123",
            user_role="admin",
            action="revoke_ssh_ingress",
            confirmed=True,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "revoke_ssh_ingress")
        mock_ec2.revoke_security_group_ingress.assert_called_once()
        self.assertEqual(mock_record_event.call_count, 2)
        # Check start and completion audit logs
        event_types = [call[1]["event_type"] for call in mock_record_event.call_args_list]
        self.assertIn(EVENT_RESOURCE_CONTROL_EXECUTION_STARTED, event_types)
        self.assertIn(EVENT_RESOURCE_CONTROL_COMPLETED, event_types)


class TestSecurityGroupEndpointAPI(unittest.TestCase):
    """Integration tests for Security Group FastAPI route endpoint authorization."""

    def setUp(self):
        self.account_id = str(ObjectId())
        self.user_id = str(ObjectId())
        self.org_id = "org-test-sg-endpoints"
        self.user_context = {
            "_id": self.user_id,
            "organization": self.org_id,
            "role": "admin",
        }
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})
        db.organization_members.insert_one({
            "user_id": self.user_id,
            "organization_id": self.org_id,
            "role": "admin",
            "status": "active",
        })

    def tearDown(self):
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})

    @patch("app.api.cloud.execute_security_group_control")
    def test_control_security_group_endpoint_success(self, mock_execute):
        """control_security_group endpoint delegates to service when authorized."""
        mock_execute.return_value = {
            "success": True,
            "action": "revoke_ssh_ingress",
            "group_id": "sg-01234567",
        }

        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )

        resp = control_security_group(
            account_id=self.account_id,
            group_id="sg-01234567",
            payload=payload,
            current_user=self.user_context,
        )

        self.assertTrue(resp["success"])
        self.assertEqual(resp["action"], "revoke_ssh_ingress")

    def test_control_security_group_viewer_denied(self):
        """Viewer role in organization_members must be denied with 403."""
        from app.database.connection import db
        db.organization_members.update_one(
            {"user_id": self.user_id, "organization_id": self.org_id},
            {"$set": {"role": "viewer"}}
        )
        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_security_group(
                account_id=self.account_id,
                group_id="sg-01234567",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)

    def test_control_security_group_missing_membership_denied(self):
        """Missing organization membership must raise 403."""
        from app.database.connection import db
        db.organization_members.delete_many({"organization_id": self.org_id})
        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_security_group(
                account_id=self.account_id,
                group_id="sg-01234567",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)

    def test_control_security_group_inactive_membership_denied(self):
        """Inactive membership status must raise 403."""
        from app.database.connection import db
        db.organization_members.update_one(
            {"user_id": self.user_id, "organization_id": self.org_id},
            {"$set": {"status": "inactive"}}
        )
        payload = SecurityGroupActionPayload(
            action="revoke_ssh_ingress",
            region="us-east-1",
            confirmed=True,
        )
        with self.assertRaises(HTTPException) as cm:
            control_security_group(
                account_id=self.account_id,
                group_id="sg-01234567",
                payload=payload,
                current_user=self.user_context,
            )
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()

