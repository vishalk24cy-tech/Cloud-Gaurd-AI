from dotenv import load_dotenv

from app.database.connection import db


load_dotenv()


# =========================================================
# EXISTING SIET ORGANIZATION
# =========================================================

ORGANIZATION_ID = "6aa28ae9e8236f1222f6709a"

USER_ID = "6a92586562d364eaa3bb9b49"

ACCOUNT_ID = "6a9284137cb6ac34f431b722"


# =========================================================
# FIND EXISTING SCANS
# =========================================================

query = {
    "user_id": USER_ID,
    "account_id": ACCOUNT_ID,
}


total_before = db.scan_history.count_documents(
    query
)


print(
    f"Existing matching scan records: {total_before}"
)


# =========================================================
# UPDATE ONLY RECORDS WITHOUT ORGANIZATION ID
# =========================================================

update_query = {
    **query,
    "$or": [
        {
            "organization_id": {
                "$exists": False
            }
        },
        {
            "organization_id": None
        },
        {
            "organization_id": ""
        },
    ],
}


result = db.scan_history.update_many(
    update_query,
    {
        "$set": {
            "organization_id": ORGANIZATION_ID
        }
    }
)


# =========================================================
# RESULT
# =========================================================

print(
    f"Records updated: {result.modified_count}"
)


# =========================================================
# VERIFY
# =========================================================

verified = db.scan_history.count_documents(
    {
        "user_id": USER_ID,
        "account_id": ACCOUNT_ID,
        "organization_id": ORGANIZATION_ID,
        "status": "completed",
    }
)


print(
    f"Completed scans now linked to organization: {verified}"
)


print("Migration completed.")