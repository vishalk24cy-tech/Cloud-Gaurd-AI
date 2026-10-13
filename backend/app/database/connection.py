from pymongo import MongoClient
from dotenv import load_dotenv
import os


# ============================================================
# Environment
# ============================================================

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DATABASE_NAME = os.getenv("DATABASE_NAME", "cloudguardai")


if not MONGODB_URL:
    raise RuntimeError(
        "MONGODB_URL is not configured in the environment"
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

    This is used only when SRV DNS discovery fails.
    It keeps replica-set semantics required by
    MongoDB transactions.
    """

    direct_url = (
        "mongodb://"
        "ac-wnnoswe-shard-00-00.gf7jzxl.mongodb.net:27017,"
        "ac-wnnoswe-shard-00-01.gf7jzxl.mongodb.net:27017,"
        "ac-wnnoswe-shard-00-02.gf7jzxl.mongodb.net:27017/"
        f"{DATABASE_NAME}"
        "?ssl=true"
        "&authSource=admin"
        "&replicaSet=atlas-xxxxx-shard-0"
        "&retryWrites=true"
        "&w=majority"
    )

    return MongoClient(
        direct_url,
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