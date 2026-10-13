from dotenv import load_dotenv

from app.database.connection import db


load_dotenv()


# ------------------------------------------------------------
# Existing SIET organization/user/account
# ------------------------------------------------------------

ORGANIZATION_ID = "6aa28ae9e8236f1222f6709a"
USER_ID = "6a92586562d364eaa3bb9b49"
ACCOUNT_ID = "6a9284137cb6ac34f431b722"


# ------------------------------------------------------------
# Count existing findings
# ------------------------------------------------------------

query = {
    "user_id": USER_ID,
    "account_id": ACCOUNT_ID,
}


total_before = db.findings.count_documents(query)

print(
    f"Existing matching findings: {total_before}"
)


# ------------------------------------------------------------
# Only migrate findings that do not already have
# an organization_id.
# ------------------------------------------------------------

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


result = db.findings.update_many(
    update_query,
    {
        "$set": {
            "organization_id": ORGANIZATION_ID
        }
    },
)


print(
    f"Findings updated: {result.modified_count}"
)


# ------------------------------------------------------------
# Verify
# ------------------------------------------------------------

verified = db.findings.count_documents(
    {
        "user_id": USER_ID,
        "account_id": ACCOUNT_ID,
        "organization_id": ORGANIZATION_ID,
    }
)


print(
    f"Findings now linked to organization: {verified}"
)


print("Findings organization migration completed.")