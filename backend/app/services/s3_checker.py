# ============================================================
# CloudGuardAI - AWS S3 Security Checker & Inventory Service
# Production / Verified Version
# ============================================================

from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError, BotoCoreError

from app.services.aws_connection import AWS_CONFIG


class S3RegionResolutionError(Exception):
    """Raised when an S3 bucket's home region cannot be authoritatively determined."""

    def __init__(self, bucket: str, error_code: str, message: str):
        super().__init__(
            f"Failed to resolve region for S3 bucket '{bucket}': [{error_code}] {message}"
        )
        self.bucket = bucket
        self.error_code = error_code
        self.message = message


class S3DiscoveryError(Exception):
    """Raised when S3 bucket enumeration fails."""

    def __init__(self, error_code: str, message: str, original_error: Optional[Exception] = None):
        super().__init__(f"S3 bucket enumeration failed: [{error_code}] {message}")
        self.error_code = error_code
        self.message = message
        self.original_error = original_error


def resolve_bucket_region(
    s3_client: Any,
    bucket_name: str,
) -> str:
    """
    Authoritatively resolve an S3 bucket's home region.

    AWS behavior:
    - GetBucketLocation returning None or empty string indicates 'us-east-1'.
    - 'EU' represents 'eu-west-1'.
    - Other strings represent the exact region identifier (e.g. 'ap-south-1').
    - If region lookup fails, this function raises S3RegionResolutionError explicitly
      to prevent inspection from proceeding with an unverified default region.
    """
    try:
        response = s3_client.get_bucket_location(Bucket=bucket_name)
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = error.response.get("Error", {}).get("Message", str(error))
        raise S3RegionResolutionError(bucket_name, code, msg) from error
    except Exception as error:
        raise S3RegionResolutionError(bucket_name, type(error).__name__, str(error)) from error

    location = response.get("LocationConstraint")
    if not location:
        return "us-east-1"
    if location == "EU":
        return "eu-west-1"
    return str(location).strip()


def get_regional_s3_client(
    fallback_client: Any,
    bucket_region: str,
    session: Optional[Any] = None,
) -> Any:
    """
    Obtain a regional S3 client for bucket-specific configuration inspection.
    """
    if session is not None and hasattr(session, "client"):
        try:
            return session.client("s3", region_name=bucket_region, config=AWS_CONFIG)
        except Exception:
            pass
    return fallback_client


def check_s3(
    s3_client: Any,
    session: Optional[Any] = None,
    account_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Inspect S3 buckets for security posture and misconfigurations.

    Args:
        s3_client: Authenticated boto3 S3 client.
        session: Optional temporary boto3 Session for regional routing.
        account_id: Expected AWS account ID for ExpectedBucketOwner validation.

    Returns:
        List of CloudGuardAI finding dictionaries.
    """
    findings: List[Dict[str, Any]] = []

    # ========================================================
    # 1. ENUMERATE S3 BUCKETS
    # ========================================================
    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "")
        if code in ("AccessDenied", "UnauthorizedOperation", "Forbidden"):
            return [{
                "resource_type": "S3 Service",
                "resource": "s3",
                "service": "S3",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": "CloudGuardAI could not list S3 buckets due to permission denial.",
                "recommendation": "Grant the scanner role permission to call s3:ListAllMyBuckets.",
                "account_id": account_id or "",
                "evidence": {"error": code},
            }]
        return [{
            "resource_type": "S3 Service",
            "resource": "s3",
            "service": "S3",
            "severity": "MEDIUM",
            "status": "Unknown",
            "issue": f"S3 bucket discovery failed ({code or type(error).__name__}).",
            "recommendation": "Verify S3 service connectivity and scanner permissions.",
            "account_id": account_id or "",
            "evidence": {"error": code or str(error)},
        }]
    except Exception as error:
        return [{
            "resource_type": "S3 Service",
            "resource": "s3",
            "service": "S3",
            "severity": "MEDIUM",
            "status": "Unknown",
            "issue": f"S3 bucket discovery encountered an unexpected error ({type(error).__name__}).",
            "recommendation": "Check scanner network connectivity to AWS S3.",
            "account_id": account_id or "",
            "evidence": {"error": str(error)},
        }]

    # ========================================================
    # 2. CHECK EACH BUCKET INDEPENDENTLY
    # ========================================================
    owner_kwargs = {"ExpectedBucketOwner": account_id} if account_id else {}

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue

        # ----------------------------------------------------
        # Authoritative Region Resolution
        # ----------------------------------------------------
        try:
            bucket_region = resolve_bucket_region(s3_client, bucket_name)
        except S3RegionResolutionError as reg_err:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource": bucket_name,
                "bucket": bucket_name,
                "service": "S3",
                "region": "UNKNOWN",
                "account_id": account_id or "",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": f"CloudGuardAI could not resolve region for S3 bucket {bucket_name}.",
                "recommendation": "Grant the scanner role s3:GetBucketLocation permission and verify network routing.",
                "evidence": {
                    "error_code": reg_err.error_code,
                    "detail": reg_err.message,
                    "reason": "REGION_RESOLUTION_FAILED",
                },
            })
            # Prevent inspection from proceeding with an unverified region
            continue

        regional_client = get_regional_s3_client(s3_client, bucket_region, session=session)

        # ----------------------------------------------------
        # 2A. BUCKET-LEVEL BLOCK PUBLIC ACCESS
        # ----------------------------------------------------
        try:
            public_access = regional_client.get_public_access_block(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            config = public_access.get("PublicAccessBlockConfiguration", {})
            block_public_acls = config.get("BlockPublicAcls", False)
            ignore_public_acls = config.get("IgnorePublicAcls", False)
            block_public_policy = config.get("BlockPublicPolicy", False)
            restrict_public_buckets = config.get("RestrictPublicBuckets", False)

            all_protected = (
                block_public_acls
                and ignore_public_acls
                and block_public_policy
                and restrict_public_buckets
            )

            if not all_protected:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "HIGH",
                    "status": "Risk",
                    "issue": "S3 Block Public Access is not fully enabled.",
                    "recommendation": (
                        "Enable all four S3 Block Public Access settings: "
                        "BlockPublicAcls, IgnorePublicAcls, "
                        "BlockPublicPolicy and RestrictPublicBuckets."
                    ),
                    "evidence": {
                        "block_public_acls": block_public_acls,
                        "ignore_public_acls": ignore_public_acls,
                        "block_public_policy": block_public_policy,
                        "restrict_public_buckets": restrict_public_buckets,
                    },
                })

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "")
            if error_code == "NoSuchPublicAccessBlockConfiguration":
                # Explicit evidence that bucket-level Block Public Access is not configured
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "HIGH",
                    "status": "Risk",
                    "issue": "S3 Block Public Access is not fully enabled.",
                    "recommendation": (
                        "Enable all four S3 Block Public Access settings: "
                        "BlockPublicAcls, IgnorePublicAcls, "
                        "BlockPublicPolicy and RestrictPublicBuckets."
                    ),
                    "evidence": {
                        "block_public_acls": False,
                        "ignore_public_acls": False,
                        "block_public_policy": False,
                        "restrict_public_buckets": False,
                        "configured": False,
                        "error_code": "NoSuchPublicAccessBlockConfiguration",
                    },
                })
            elif error_code in ("AccessDenied", "Forbidden", "AccessDeniedException"):
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": "CloudGuardAI could not verify the S3 Public Access Block configuration.",
                    "recommendation": "Grant the scanner role permission to call s3:GetPublicAccessBlock and verify the bucket configuration.",
                    "evidence": {"error_code": error_code},
                })
            else:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": f"S3 Block Public Access inspection encountered an error ({error_code}).",
                    "recommendation": "Verify bucket permissions and configuration.",
                    "evidence": {"error_code": error_code, "detail": str(error)},
                })
        except Exception as error:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource": bucket_name,
                "bucket": bucket_name,
                "service": "S3",
                "region": bucket_region,
                "account_id": account_id or "",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": "S3 Block Public Access configuration could not be verified due to an inspection error.",
                "recommendation": "Verify bucket status and scanner network connection.",
                "evidence": {"error": str(error)},
            })

        # ----------------------------------------------------
        # 2B. BUCKET POLICY PUBLIC ACCESS STATUS
        # ----------------------------------------------------
        try:
            policy_status = regional_client.get_bucket_policy_status(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            policy = policy_status.get("PolicyStatus", {})
            is_public = policy.get("IsPublic", False)

            if is_public:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "CRITICAL",
                    "status": "Public",
                    "issue": "S3 bucket policy allows public access.",
                    "recommendation": (
                        "Review the bucket policy and remove unnecessary public Allow statements. "
                        "Keep access restricted to trusted principals."
                    ),
                    "evidence": {"is_public": True},
                })

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
                # Normal absence of policy - not a vulnerability
                pass
            elif error_code in ("AccessDenied", "Forbidden", "AccessDeniedException"):
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": "CloudGuardAI could not verify the S3 bucket policy public status.",
                    "recommendation": (
                        "Grant the scanner role permission to call s3:GetBucketPolicyStatus "
                        "and verify that the bucket is not publicly accessible."
                    ),
                    "evidence": {"error_code": error_code},
                })
            else:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": f"S3 bucket policy verification encountered an error ({error_code}).",
                    "recommendation": "Check bucket policy configuration and scanner permissions.",
                    "evidence": {"error_code": error_code, "detail": str(error)},
                })
        except Exception as error:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource": bucket_name,
                "bucket": bucket_name,
                "service": "S3",
                "region": bucket_region,
                "account_id": account_id or "",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": "S3 bucket policy could not be verified due to an inspection error.",
                "recommendation": "Verify scanner network connectivity and S3 service availability.",
                "evidence": {"error": str(error)},
            })

        # ----------------------------------------------------
        # 2C. BUCKET ACL PUBLIC ACCESS
        # ----------------------------------------------------
        try:
            acl_response = regional_client.get_bucket_acl(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            grants = acl_response.get("Grants", [])
            public_acl = False

            for grant in grants:
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_acl = True
                    break

            if public_acl:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "CRITICAL",
                    "status": "Public",
                    "issue": "S3 bucket ACL grants access to public or authenticated AWS users.",
                    "recommendation": (
                        "Remove public ACL grants and use IAM policies or bucket policies "
                        "for controlled access."
                    ),
                    "evidence": {"public_acl": True},
                })

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "")
            if error_code in ("AccessDenied", "Forbidden", "AccessDeniedException"):
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": "CloudGuardAI could not verify the S3 bucket ACL.",
                    "recommendation": "Grant the scanner role permission to call s3:GetBucketAcl.",
                    "evidence": {"error_code": error_code},
                })
            else:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Unknown",
                    "issue": f"S3 bucket ACL verification encountered an error ({error_code}).",
                    "recommendation": "Verify bucket permissions and configuration.",
                    "evidence": {"error_code": error_code, "detail": str(error)},
                })
        except Exception as error:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource": bucket_name,
                "bucket": bucket_name,
                "service": "S3",
                "region": bucket_region,
                "account_id": account_id or "",
                "severity": "MEDIUM",
                "status": "Unknown",
                "issue": "S3 bucket ACL could not be verified due to an inspection error.",
                "recommendation": "Verify scanner network connectivity.",
                "evidence": {"error": str(error)},
            })

        # ----------------------------------------------------
        # 2D. SERVER-SIDE ENCRYPTION
        # ----------------------------------------------------
        try:
            encryption = regional_client.get_bucket_encryption(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            rules = (
                encryption.get("ServerSideEncryptionConfiguration", {})
                .get("Rules", [])
            )
            if not rules:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Risk",
                    "issue": "S3 bucket does not have a server-side encryption configuration.",
                    "recommendation": "Enable default server-side encryption for the S3 bucket.",
                })

        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code", "")
            if (
                error_code == "ServerSideEncryptionConfigurationNotFoundError"
                or error_code == "NoSuchBucket"
                or "not found" in str(error).lower()
            ):
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "MEDIUM",
                    "status": "Risk",
                    "issue": "S3 bucket does not have default server-side encryption enabled.",
                    "recommendation": "Enable default server-side encryption for the S3 bucket.",
                    "evidence": {"error_code": error_code},
                })
            elif error_code in ("AccessDenied", "Forbidden", "AccessDeniedException"):
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "LOW",
                    "status": "Unknown",
                    "issue": "CloudGuardAI could not verify the S3 encryption configuration.",
                    "recommendation": "Grant the scanner role permission to verify S3 bucket encryption.",
                    "evidence": {"error_code": error_code},
                })
            else:
                findings.append({
                    "resource_type": "S3 Bucket",
                    "resource": bucket_name,
                    "bucket": bucket_name,
                    "service": "S3",
                    "region": bucket_region,
                    "account_id": account_id or "",
                    "severity": "LOW",
                    "status": "Unknown",
                    "issue": f"S3 encryption verification encountered an error ({error_code}).",
                    "recommendation": "Verify bucket permissions and encryption configuration.",
                    "evidence": {"error_code": error_code, "detail": str(error)},
                })
        except Exception as error:
            findings.append({
                "resource_type": "S3 Bucket",
                "resource": bucket_name,
                "bucket": bucket_name,
                "service": "S3",
                "region": bucket_region,
                "account_id": account_id or "",
                "severity": "LOW",
                "status": "Unknown",
                "issue": "S3 encryption could not be verified due to an inspection error.",
                "recommendation": "Verify scanner network connectivity.",
                "evidence": {"error": str(error)},
            })

    return findings


def inspect_s3_inventory(
    s3_client: Any,
    session: Optional[Any] = None,
    account_id: Optional[str] = None,
    raise_on_error: bool = True,
) -> List[Dict[str, Any]]:
    """
    Produce an authoritative, complete resource inventory of all discovered S3 buckets,
    regardless of whether they have security findings.

    Args:
        s3_client: Authenticated boto3 S3 client.
        session: Optional temporary boto3 Session.
        account_id: Expected AWS account ID.
        raise_on_error: If True, raises S3DiscoveryError when list_buckets fails.

    Returns:
        List of structured bucket inventory records.

    Raises:
        S3DiscoveryError: When list_buckets fails and raise_on_error is True.
    """
    inventory: List[Dict[str, Any]] = []

    try:
        response = s3_client.list_buckets()
        buckets = response.get("Buckets", [])
    except ClientError as error:
        code = error.response.get("Error", {}).get("Code", "AWS_CLIENT_ERROR")
        msg = error.response.get("Error", {}).get("Message", str(error))
        if raise_on_error:
            raise S3DiscoveryError(code, msg, original_error=error) from error
        return inventory
    except Exception as error:
        if raise_on_error:
            raise S3DiscoveryError(type(error).__name__, str(error), original_error=error) from error
        return inventory

    owner_kwargs = {"ExpectedBucketOwner": account_id} if account_id else {}

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue

        creation_date = bucket.get("CreationDate")
        created_str = (
            creation_date.isoformat()
            if hasattr(creation_date, "isoformat")
            else str(creation_date or "")
        )

        # ----------------------------------------------------
        # Authoritative Region Resolution
        # ----------------------------------------------------
        try:
            bucket_region = resolve_bucket_region(s3_client, bucket_name)
        except S3RegionResolutionError as reg_err:
            # Region could not be verified; prevent inspection with unverified region
            inventory.append({
                "bucket_name": bucket_name,
                "resource": bucket_name,
                "resource_id": bucket_name,
                "resource_arn": f"arn:aws:s3:::{bucket_name}",
                "resource_type": "S3 Bucket",
                "service": "S3",
                "region": "UNKNOWN",
                "account_id": account_id or "",
                "creation_date": created_str,
                "block_public_access": {"status": "UNVERIFIED", "all_protected": False, "verified": False},
                "bucket_policy": {"status": "UNVERIFIED", "exists": False, "is_public": False, "verified": False},
                "acl": {"status": "UNVERIFIED", "public": False, "verified": False},
                "encryption": {"status": "UNVERIFIED", "enabled": False, "verified": False},
                "security_posture": "UNKNOWN",
                "coverage": "PARTIAL",
                "inspection_error": {
                    "stage": "REGION_RESOLUTION",
                    "error_code": reg_err.error_code,
                    "message": reg_err.message,
                },
            })
            continue

        regional_client = get_regional_s3_client(s3_client, bucket_region, session=session)

        # ----------------------------------------------------
        # BPA evaluation
        # ----------------------------------------------------
        bpa_record = {
            "configured": False,
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
            "all_protected": False,
            "status": "UNCONFIGURED",
            "verified": False,
        }
        try:
            bpa_resp = regional_client.get_public_access_block(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            cfg = bpa_resp.get("PublicAccessBlockConfiguration", {})
            bpa_protected = bool(
                cfg.get("BlockPublicAcls")
                and cfg.get("IgnorePublicAcls")
                and cfg.get("BlockPublicPolicy")
                and cfg.get("RestrictPublicBuckets")
            )
            bpa_record = {
                "configured": True,
                "BlockPublicAcls": bool(cfg.get("BlockPublicAcls")),
                "IgnorePublicAcls": bool(cfg.get("IgnorePublicAcls")),
                "BlockPublicPolicy": bool(cfg.get("BlockPublicPolicy")),
                "RestrictPublicBuckets": bool(cfg.get("RestrictPublicBuckets")),
                "all_protected": bpa_protected,
                "status": "PROTECTED" if bpa_protected else "PARTIAL",
                "verified": True,
            }
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code == "NoSuchPublicAccessBlockConfiguration":
                bpa_record["status"] = "NOT_CONFIGURED"
                bpa_record["configured"] = False
                bpa_record["verified"] = True
                bpa_record["all_protected"] = False
            elif err_code in ("AccessDenied", "Forbidden"):
                bpa_record["status"] = "ACCESS_DENIED"
                bpa_record["verified"] = False
            else:
                bpa_record["status"] = "ERROR"
                bpa_record["verified"] = False
                bpa_record["error"] = err_code
        except Exception as err:
            bpa_record["status"] = "ERROR"
            bpa_record["verified"] = False
            bpa_record["error"] = str(err)

        # ----------------------------------------------------
        # Policy evaluation
        # ----------------------------------------------------
        policy_record = {"exists": False, "is_public": False, "status": "NONE", "verified": False}
        try:
            pol_resp = regional_client.get_bucket_policy_status(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            is_pub = bool(pol_resp.get("PolicyStatus", {}).get("IsPublic", False))
            policy_record = {
                "exists": True,
                "is_public": is_pub,
                "status": "PUBLIC" if is_pub else "RESTRICTED",
                "verified": True,
            }
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("NoSuchBucketPolicy", "NoSuchPolicy"):
                policy_record = {"exists": False, "is_public": False, "status": "NO_POLICY", "verified": True}
            elif err_code in ("AccessDenied", "Forbidden"):
                policy_record["status"] = "ACCESS_DENIED"
                policy_record["verified"] = False
            else:
                policy_record["status"] = "ERROR"
                policy_record["verified"] = False
                policy_record["error"] = err_code
        except Exception as err:
            policy_record["status"] = "ERROR"
            policy_record["verified"] = False
            policy_record["error"] = str(err)

        # ----------------------------------------------------
        # ACL evaluation
        # ----------------------------------------------------
        acl_record = {"public": False, "grants_count": 0, "status": "PRIVATE", "verified": False}
        try:
            acl_resp = regional_client.get_bucket_acl(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            grants = acl_resp.get("Grants", [])
            acl_record["grants_count"] = len(grants)
            is_public_acl = False
            for g in grants:
                uri = g.get("Grantee", {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public_acl = True
                    break
            acl_record["public"] = is_public_acl
            acl_record["status"] = "PUBLIC" if is_public_acl else "PRIVATE"
            acl_record["verified"] = True
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("AccessDenied", "Forbidden"):
                acl_record["status"] = "ACCESS_DENIED"
                acl_record["verified"] = False
            else:
                acl_record["status"] = "ERROR"
                acl_record["verified"] = False
                acl_record["error"] = err_code
        except Exception as err:
            acl_record["status"] = "ERROR"
            acl_record["verified"] = False
            acl_record["error"] = str(err)

        # ----------------------------------------------------
        # Encryption evaluation
        # ----------------------------------------------------
        enc_record = {"enabled": False, "algorithm": None, "status": "DISABLED", "verified": False}
        try:
            enc_resp = regional_client.get_bucket_encryption(
                Bucket=bucket_name,
                **owner_kwargs,
            )
            rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if rules:
                algo = (
                    rules[0]
                    .get("ApplyServerSideEncryptionByDefault", {})
                    .get("SSEAlgorithm")
                )
                enc_record = {"enabled": True, "algorithm": algo, "status": "ENABLED", "verified": True}
            else:
                enc_record = {"enabled": False, "algorithm": None, "status": "DISABLED", "verified": True}
        except ClientError as err:
            err_code = err.response.get("Error", {}).get("Code", "")
            if err_code in ("ServerSideEncryptionConfigurationNotFoundError", "NoSuchBucket") or "not found" in str(err).lower():
                enc_record = {"enabled": False, "algorithm": None, "status": "NOT_CONFIGURED", "verified": True}
            elif err_code in ("AccessDenied", "Forbidden"):
                enc_record["status"] = "ACCESS_DENIED"
                enc_record["verified"] = False
            else:
                enc_record["status"] = "ERROR"
                enc_record["verified"] = False
                enc_record["error"] = err_code
        except Exception as err:
            enc_record["status"] = "ERROR"
            enc_record["verified"] = False
            enc_record["error"] = str(err)

        # ----------------------------------------------------
        # Overall bucket posture classification
        # ----------------------------------------------------
        all_checks_verified = (
            bpa_record.get("verified", False)
            and policy_record.get("verified", False)
            and acl_record.get("verified", False)
            and enc_record.get("verified", False)
        )

        has_critical = (
            policy_record.get("is_public", False)
            or acl_record.get("public", False)
        )

        has_risk = (
            not bpa_record.get("all_protected", False)
            or not enc_record.get("enabled", False)
        )

        if not all_checks_verified:
            # When required security checks remain unverified, NEVER classify as SECURE or EVALUATED!
            if has_critical:
                overall_posture = "CRITICAL"
            elif has_risk:
                overall_posture = "RISK"
            else:
                overall_posture = "UNKNOWN"
            coverage_status = "PARTIAL"
        else:
            coverage_status = "COMPLETE"
            if bpa_record["all_protected"] and not policy_record["is_public"] and not acl_record["public"] and enc_record["enabled"]:
                overall_posture = "SECURE"
            elif has_critical:
                overall_posture = "CRITICAL"
            elif has_risk:
                overall_posture = "RISK"
            else:
                overall_posture = "EVALUATED"

        inventory.append({
            "bucket_name": bucket_name,
            "resource": bucket_name,
            "resource_id": bucket_name,
            "resource_arn": f"arn:aws:s3:::{bucket_name}",
            "resource_type": "S3 Bucket",
            "service": "S3",
            "region": bucket_region,
            "account_id": account_id or "",
            "creation_date": created_str,
            "block_public_access": bpa_record,
            "bucket_policy": policy_record,
            "acl": acl_record,
            "encryption": enc_record,
            "security_posture": overall_posture,
            "coverage": coverage_status,
        })

    return inventory