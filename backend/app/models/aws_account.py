from datetime import datetime

from bson import ObjectId
from bson.errors import InvalidId

from app.database.connection import db


aws_accounts_collection = db["aws_accounts"]


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

    account = {
        "user_id": str(data["user_id"]),
        "organization_id": organization_id,
        "account_name": data["account_name"].strip(),
        "aws_account_id": str(data["aws_account_id"]).strip(),
        "role_arn": data["role_arn"].strip(),
        "region": data.get("region", "ap-south-1").strip(),
        "status": "connected",
        "created_at": now,
        "updated_at": now,
        "last_connected_at": now,
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