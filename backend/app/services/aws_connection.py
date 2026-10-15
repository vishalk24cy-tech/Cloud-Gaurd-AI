import boto3

from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_REGION = "ap-south-1"

# Production-friendly boto configuration.
AWS_CONFIG = Config(
    retries={
        "max_attempts": 3,
        "mode": "standard",
    },
    connect_timeout=10,
    read_timeout=30,
)


# ============================================================
# AWS ROLE ASSUMPTION
# ============================================================

def assume_aws_role(
    role_arn: str,
    region: str = DEFAULT_REGION,
    session_name: str = "CloudGuardAI-Scanner",
    external_id: str = None,
):
    """
    Assume an AWS IAM role and return a temporary boto3 Session.

    CloudGuardAI never stores long-lived AWS credentials.
    The returned session uses temporary STS credentials.

    Args:
        role_arn: IAM Role ARN to assume.
        region: Default AWS region.
        session_name: STS session name.
        external_id: Cryptographic ExternalId to guard against confused deputy attacks.

    Returns:
        boto3.Session

    Raises:
        ValueError: Invalid role ARN.
        Exception: AWS AssumeRole failure.
    """

    if not role_arn or not isinstance(role_arn, str):
        raise ValueError("AWS role ARN is required.")

    role_arn = role_arn.strip()

    if not role_arn.startswith("arn:aws:iam::"):
        raise ValueError("Invalid AWS IAM role ARN.")

    try:
        # ----------------------------------------------------
        # Base STS client
        # ----------------------------------------------------

        sts_client = boto3.client(
            "sts",
            region_name=region,
            config=AWS_CONFIG,
        )

        # ----------------------------------------------------
        # Assume customer role with ExternalId condition
        # ----------------------------------------------------

        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": 3600,
        }

        if external_id and str(external_id).strip():
            assume_kwargs["ExternalId"] = str(external_id).strip()

        response = sts_client.assume_role(**assume_kwargs)

        credentials = response.get("Credentials")

        if not credentials:
            raise RuntimeError(
                "AWS AssumeRole succeeded but no temporary credentials were returned."
            )

        # ----------------------------------------------------
        # Temporary boto3 session
        # ----------------------------------------------------

        session = boto3.Session(
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=region,
        )

        return session

    except (ClientError, BotoCoreError) as exc:

        error_code = "AWS_ERROR"

        if isinstance(exc, ClientError):
            error_code = (
                exc.response
                .get("Error", {})
                .get("Code", "AWS_ERROR")
            )

        raise RuntimeError(
            f"AWS role assumption failed ({error_code})."
        ) from exc

    except Exception:
        raise


# ============================================================
# AWS CLIENT FACTORY
# ============================================================

def get_aws_clients(session):
    """
    Create AWS service clients from an already authenticated
    temporary boto3 session.

    The same assumed-role session can be reused for scanning
    and approved remediation operations.
    """

    if session is None:
        raise ValueError("AWS session is required.")

    clients = {
        "sts": session.client(
            "sts",
            config=AWS_CONFIG,
        ),

        "ec2": session.client(
            "ec2",
            config=AWS_CONFIG,
        ),

        "s3": session.client(
            "s3",
            config=AWS_CONFIG,
        ),

        "iam": session.client(
            "iam",
            config=AWS_CONFIG,
        ),

        "cloudtrail": session.client(
            "cloudtrail",
            config=AWS_CONFIG,
        ),

        "rds": session.client(
            "rds",
            config=AWS_CONFIG,
        ),

        "lambda": session.client(
            "lambda",
            config=AWS_CONFIG,
        ),

        "kms": session.client(
            "kms",
            config=AWS_CONFIG,
        ),

        # ----------------------------------------------------
        # AWS Cost Explorer
        #
        # Cost Explorer is region-specific and normally uses
        # the us-east-1 endpoint.
        # ----------------------------------------------------

        "ce": session.client(
            "ce",
            region_name="us-east-1",
            config=AWS_CONFIG,
        ),
    }

    return clients


# ============================================================
# AWS IDENTITY
# ============================================================

def get_aws_identity(session):
    """
    Return the AWS identity associated with the current
    temporary session.

    This is useful for verifying that CloudGuardAI is operating
    against the expected AWS account.
    """

    if session is None:
        raise ValueError("AWS session is required.")

    try:
        sts_client = session.client(
            "sts",
            config=AWS_CONFIG,
        )

        return sts_client.get_caller_identity()

    except (ClientError, BotoCoreError) as exc:

        raise RuntimeError(
            "Unable to verify AWS session identity."
        ) from exc


# ============================================================
# AWS ACCOUNT ID
# ============================================================

def get_aws_account_id(session):
    """
    Return the AWS account ID associated with the session.
    """

    identity = get_aws_identity(session)

    account_id = identity.get("Account")

    if not account_id:
        raise RuntimeError(
            "AWS identity did not contain an account ID."
        )

    return str(account_id)


# ============================================================
# VERIFY EXPECTED AWS ACCOUNT
# ============================================================

def verify_aws_account(
    session,
    expected_account_id: str,
):
    """
    Security boundary:
    Verify that the assumed role belongs to the AWS account
    CloudGuardAI intended to operate on.

    Returns:
        AWS identity dictionary.
    """

    if not expected_account_id:
        raise ValueError(
            "Expected AWS account ID is required."
        )

    expected_account_id = str(
        expected_account_id
    ).strip()

    identity = get_aws_identity(session)

    actual_account_id = str(
        identity.get("Account", "")
    ).strip()

    if not actual_account_id:
        raise RuntimeError(
            "Unable to determine AWS account ID."
        )

    if actual_account_id != expected_account_id:
        raise PermissionError(
            "AWS account identity mismatch. "
            "The assumed role does not belong to the expected account."
        )

    return identity


# ============================================================
# VERIFY AWS ROLE CONNECTION (PRE-FLIGHT STS HANDSHAKE)
# ============================================================

def verify_aws_role_connection(
    role_arn: str,
    expected_account_id: str,
    external_id: str = None,
    region: str = DEFAULT_REGION,
) -> dict:
    """
    Perform a secure pre-flight verification of an AWS role connection:
    1. Validates role_arn format.
    2. Validates expected_account_id format.
    3. Assumes the role via STS AssumeRole using the external_id.
    4. Calls STS GetCallerIdentity.
    5. Confirms caller identity account matches expected_account_id.
    6. Returns sanitized identity metadata without exposing credentials or internal secrets.
    """
    if not role_arn or not isinstance(role_arn, str) or not role_arn.strip().startswith("arn:aws:iam::"):
        raise ValueError("Invalid AWS IAM role ARN. Must start with 'arn:aws:iam::'.")

    expected_acc = str(expected_account_id or "").strip()
    if not expected_acc or len(expected_acc) != 12 or not expected_acc.isdigit():
        raise ValueError("Invalid AWS account ID. Must be a 12-digit number.")

    try:
        session = assume_aws_role(
            role_arn=role_arn,
            region=region,
            session_name="CloudGuardAI-PreflightVerification",
            external_id=external_id,
        )
    except Exception as exc:
        cause = getattr(exc, "__cause__", None) or exc
        code = ""
        if isinstance(cause, ClientError):
            code = cause.response.get("Error", {}).get("Code", "")
        elif isinstance(exc, ClientError):
            code = exc.response.get("Error", {}).get("Code", "")
        elif "AccessDenied" in str(exc):
            code = "AccessDenied"
        elif "InvalidParameter" in str(exc) or "ValidationError" in str(exc):
            code = "InvalidParameter"
        elif "ExpiredToken" in str(exc):
            code = "ExpiredToken"

        if code in ("AccessDenied", "AccessDeniedException"):
            raise PermissionError(
                "AWS STS AssumeRole access denied. Verify that the IAM role trust policy grants "
                "sts:AssumeRole to CloudGuardAI and requires the matching ExternalId condition."
            ) from exc
        if code in ("InvalidParameter", "InvalidParameterValue", "ValidationError"):
            raise ValueError("Invalid IAM role ARN or parameter configuration.") from exc
        if code in ("ExpiredToken", "ExpiredTokenException"):
            raise PermissionError("AWS credentials or STS session token expired.") from exc

        exc_str = f"{str(exc)} {str(cause)}".lower()
        if "timeout" in exc_str or "timed out" in exc_str:
            raise TimeoutError("AWS STS connection timed out. Check network connectivity and region.") from exc
        if isinstance(exc, (ValueError, PermissionError)):
            raise
        raise RuntimeError("AWS STS role assumption failed. Verify role ARN and permissions.") from exc

    try:
        identity = verify_aws_account(session, expected_acc)
    except PermissionError:
        raise
    except Exception as exc:
        raise RuntimeError("Unable to verify AWS account identity via STS GetCallerIdentity.") from exc

    return {
        "verified": True,
        "account_id": identity.get("Account"),
        "arn": identity.get("Arn"),
        "user_id": identity.get("UserId"),
    }
