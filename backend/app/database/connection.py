from pymongo import MongoClient
from dotenv import load_dotenv
import os


# ============================================================
# Environment
# ============================================================

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "cloudguardai")

# Optional full mongodb:// URI (with credentials) used ONLY if the
# SRV connection fails. Keep it in .env - never hardcode hosts or
# credentials in source.
MONGODB_DIRECT_URL = os.getenv("MONGODB_DIRECT_URL")


if not MONGODB_URL:
    raise RuntimeError(
        "MONGODB_URL is not configured in the environment"
    )


# ============================================================
# Test-mode safety guard
# ============================================================
# Tests set APP_ENV=test (see backend/conftest.py). In that mode we
# refuse to connect unless the database name clearly looks like a
# test database, so a test run can never touch production data.

if os.getenv("APP_ENV", "").strip().lower() == "test":
    if "test" not in DATABASE_NAME.lower():
        raise RuntimeError(
            "Refusing to connect: APP_ENV=test but DATABASE_NAME "
            f"'{DATABASE_NAME}' does not look like a test database."
        )


# ============================================================
# MongoDB Configuration
# ============================================================

COMMON_OPTIONS = {
    "serverSelectionTimeoutMS": 15000,
    "connectTimeoutMS": 10000,
    "socketTimeoutMS": 15000,
    "tls": True,
    "tlsAllowInvalidCertificates": False,
    "retryWrites": True,
    "retryReads": True,
    "w": "majority",
    "maxPoolSize": 50,
    "maxIdleTimeMS": 60000,
}


def create_primary_client():
    """
    Create MongoDB client using the Atlas SRV connection.
    """

    return MongoClient(
        MONGODB_URL,
        **COMMON_OPTIONS
    )


def create_direct_client():
    """
    Create a direct multi-host MongoDB connection.

    Used only when SRV DNS discovery fails. The URI comes from the
    MONGODB_DIRECT_URL environment variable (standard mongodb:// form,
    including credentials, replicaSet and authSource). It keeps the
    replica-set semantics required by MongoDB transactions.
    """

    if not MONGODB_DIRECT_URL:
        raise RuntimeError(
            "MONGODB_DIRECT_URL is not configured; "
            "no direct fallback is available"
        )

    return MongoClient(
        MONGODB_DIRECT_URL,
        **COMMON_OPTIONS
    )


# ============================================================
# Connection Initialization
# ============================================================

try:

    # --------------------------------------------------------
    # Primary Atlas SRV connection
    # --------------------------------------------------------

    client = create_primary_client()

    client.admin.command("ping")

    print(
        "[OK] Connected to MongoDB Atlas (Primary SRV)"
    )


except Exception as primary_error:

    print(
        "[WARN] MongoDB Primary SRV failed "
        f"({primary_error}), trying direct replica set..."
    )

    try:

        # ----------------------------------------------------
        # Direct replica-set fallback
        # ----------------------------------------------------

        client = create_direct_client()

        client.admin.command("ping")

        print(
            "[OK] Connected to MongoDB Atlas "
            "(Direct Replica Set Fallback)"
        )

    except Exception as fallback_error:

        print(
            "[ERROR] MongoDB connection failed."
        )

        print(
            f"[ERROR] Primary connection: {primary_error}"
        )

        print(
            f"[ERROR] Direct fallback: {fallback_error}"
        )

        raise RuntimeError(
            "Unable to connect to MongoDB Atlas"
        ) from fallback_error


# ============================================================
# Database
# ============================================================

db = client[DATABASE_NAME]