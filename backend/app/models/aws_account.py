import hashlib
import hmac
import os
import secrets
from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


aws_accounts_collection = db["aws_accounts"]

EXTERNAL_ID_SALT = os.getenv("EXTERNAL_ID_SALT", "cloudguardai-external-id-secret-salt")


def generate_external_id(organization_id: str) -> str:
    """
    Generate a cryptographically secure, unguessable ExternalId strictly bound
    to the organization to defend against AWS Confused Deputy attacks.
    """
    org_clean = str(organization_id or "").strip()
    nonce = secrets.token_hex(12)
    sig = hmac.new(
        EXTERNAL_ID_SALT.encode("utf-8"),
        f"{org_clean}:{nonce}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:16]
    return f"cg_{org_clean[:8]}_{nonce}_{sig}"


def verify_external_id_binding(external_id: str, organization_id: str) -> bool:
    """
    Verify that an ExternalId was generated for this specific organization,
    preventing cross-tenant reuse, spoofing, or substitution.
    """
    if not external_id or not organization_id:
        return False
    parts = str(external_id).strip().split("_")
    if len(parts) != 4 or parts[0] != "cg":
        return False
    org_prefix, nonce, sig = parts[1], parts[2], parts[3]
    org_clean = str(organization_id).strip()
    if not org_clean.startswith(org_prefix):
        return False
    expected_sig = hmac.new(
        EXTERNAL_ID_SALT.encode("utf-8"),
        f"{org_clean}:{nonce}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()[:16]
    return hmac.compare_digest(sig, expected_sig)


def _to_object_id(account_id):
    try:
        return ObjectId(str(account_id))
    except (InvalidId, TypeError):
        return None


def create_aws_account(data):
    now = datetime.utcnow()

    organization_id = data.get("organization_id")

    if organization_id is not None:
        organization_id = str(organization_id).strip()

    # Tenant-safe ExternalId handling:
    supplied_external_id = data.get("external_id")
    if supplied_external_id and str(supplied_external_id).strip():
        supplied_external_id = str(supplied_external_id).strip()
        if not verify_external_id_binding(supplied_external_id, organization_id):
            raise ValueError("ExternalId does not match organization binding or is invalid.")
        external_id = supplied_external_id
    else:
        external_id = generate_external_id(organization_id)

    status = data.get("status") or "pending_verification"
    is_connected = status == "connected"

    account = {
        "user_id": str(data["user_id"]),
        "organization_id": organization_id,
        "account_name": data["account_name"].strip(),
        "aws_account_id": str(data["aws_account_id"]).strip(),
        "role_arn": data["role_arn"].strip(),
        "region": data.get("region", "ap-south-1").strip(),
        "status": status,
        "external_id": external_id,
        "verified_at": now if is_connected else None,
        "verification_error": None,
        "created_at": now,
        "updated_at": now,
        "last_connected_at": now if is_connected else None,
        "last_scan_at": None,
    }

    result = aws_accounts_collection.insert_one(account)

    account["_id"] = str(result.inserted_id)

    return account



def get_user_accounts(user_id):

    accounts = list(
        aws_accounts_collection.find(
            {
                "user_id": str(user_id)
            }
        ).sort(
            "created_at",
            -1
        )
    )

    for account in accounts:
        account["_id"] = str(account["_id"])

    return accounts


def get_organization_accounts(organization_id):

    organization_id = str(
        organization_id
    ).strip()

    if not organization_id:
        return []

    accounts = list(
        aws_accounts_collection.find(
            {
                "organization_id": organization_id
            }
        ).sort(
            "created_at",
            -1
        )
    )

    for account in accounts:

        account["_id"] = str(
            account["_id"]
        )

        account["user_id"] = str(
            account["user_id"]
        )

        if account.get("organization_id") is not None:

            account["organization_id"] = str(
                account["organization_id"]
            )

    return accounts


def get_all_connected_accounts():

    accounts = list(
        aws_accounts_collection.find(
            {
                "status": "connected"
            }
        ).sort(
            "created_at",
            -1
        )
    )

    for account in accounts:

        account["_id"] = str(
            account["_id"]
        )

        account["user_id"] = str(
            account["user_id"]
        )

        if account.get("organization_id") is not None:

            account["organization_id"] = str(
                account["organization_id"]
            )

    return accounts


def get_account(
    account_id,
    user_id=None,
    organization_id=None
):

    object_id = _to_object_id(
        account_id
    )

    if object_id is None:
        return None

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    account = aws_accounts_collection.find_one(
        query
    )

    if account:
        account["_id"] = str(account["_id"])

    return account


def get_account_by_aws_id(
    aws_account_id,
    user_id=None,
    organization_id=None
):

    query = {
        "aws_account_id": str(
            aws_account_id
        )
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    account = aws_accounts_collection.find_one(
        query
    )

    if account:
        account["_id"] = str(account["_id"])

    return account


def update_account_status(
    account_id,
    status,
    user_id=None,
    organization_id=None
):

    object_id = _to_object_id(
        account_id
    )

    if object_id is None:
        return False

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    result = aws_accounts_collection.update_one(
        query,
        {
            "$set": {
                "status": status,
                "updated_at": datetime.utcnow()
            }
        }
    )

    return result.modified_count > 0


def update_last_connected(
    account_id,
    user_id=None,
    organization_id=None
):

    object_id = _to_object_id(
        account_id
    )

    if object_id is None:
        return False

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    now = datetime.utcnow()

    result = aws_accounts_collection.update_one(
        query,
        {
            "$set": {
                "status": "connected",
                "last_connected_at": now,
                "updated_at": now
            }
        }
    )

    return result.modified_count > 0


def update_last_scan(
    account_id,
    user_id=None,
    organization_id=None
):

    object_id = _to_object_id(
        account_id
    )

    if object_id is None:
        return False

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    now = datetime.utcnow()

    result = aws_accounts_collection.update_one(
        query,
        {
            "$set": {
                "last_scan_at": now,
                "updated_at": now
            }
        }
    )

    return result.modified_count > 0


def delete_account(
    account_id,
    user_id=None,
    organization_id=None
):

    object_id = _to_object_id(
        account_id
    )

    if object_id is None:
        return False

    query = {
        "_id": object_id
    }

    if user_id is not None:
        query["user_id"] = str(user_id)

    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    result = aws_accounts_collection.delete_one(
        query
    )

    return result.deleted_count > 0


def update_account_verification(
    account_id,
    status: str,
    verified_at=None,
    verification_error: str = None,
    user_id=None,
    organization_id=None,
):
    """
    Update verification status, timestamps, and safe verification error details.
    """
    object_id = _to_object_id(account_id)
    if object_id is None:
        return False

    query = {"_id": object_id}
    if user_id is not None:
        query["user_id"] = str(user_id)
    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    now = datetime.utcnow()
    update_doc = {
        "status": status,
        "verification_error": verification_error,
        "updated_at": now,
    }
    if status == "connected":
        update_doc["verified_at"] = verified_at or now
        update_doc["last_connected_at"] = now
        update_doc["verification_error"] = None
    elif verified_at is not None:
        update_doc["verified_at"] = verified_at

    result = aws_accounts_collection.update_one(
        query,
        {"$set": update_doc}
    )
    return result.modified_count > 0


def ensure_external_id(account_id, organization_id=None):
    """
    Ensure an account document has a tenant-bound ExternalId.
    For legacy accounts created before Phase 7B, generates and persists one.
    """
    object_id = _to_object_id(account_id)
    if object_id is None:
        return None

    query = {"_id": object_id}
    if organization_id is not None:
        query["organization_id"] = str(organization_id)

    account = aws_accounts_collection.find_one(query)
    if not account:
        return None

    existing_id = account.get("external_id")
    if existing_id and str(existing_id).strip():
        return str(existing_id).strip()

    org_id = str(account.get("organization_id") or organization_id or "")
    new_external_id = generate_external_id(org_id)
    aws_accounts_collection.update_one(
        {"_id": object_id},
        {"$set": {"external_id": new_external_id, "updated_at": datetime.utcnow()}}
    )
    return new_external_id
