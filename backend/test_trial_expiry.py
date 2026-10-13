from datetime import datetime, timedelta, timezone

from bson import ObjectId

from app.database.connection import db
from app.services.trial_service import expire_trials


ORGANIZATIONS = db.organizations


def main():

    print("\n=== CloudGuardAI Trial Expiry Test ===")

    # --------------------------------------------------------
    # Create temporary organization
    # --------------------------------------------------------

    organization_id = ObjectId()

    now = datetime.now(
        timezone.utc
    )

    expired_time = now - timedelta(
        days=1
    )

    ORGANIZATIONS.insert_one(
        {
            "_id": organization_id,
            "name": "CloudGuardAI Trial Test",
            "slug": f"trial-test-{organization_id}",
            "owner_id": "test-owner",
            "plan": "free",
            "status": "active",
            "trial_ends_at": expired_time,
            "created_at": now,
            "updated_at": now
        }
    )

    print(
        f"[1] Temporary organization created: {organization_id}"
    )

    # --------------------------------------------------------
    # Verify initial state
    # --------------------------------------------------------

    organization = ORGANIZATIONS.find_one(
        {
            "_id": organization_id
        }
    )

    print(
        "[2] Initial status:",
        organization["status"]
    )

    # --------------------------------------------------------
    # Run trial expiry service
    # --------------------------------------------------------

    result = expire_trials()

    print(
        "[3] Expiry service result:",
        result
    )

    # --------------------------------------------------------
    # Verify organization expired
    # --------------------------------------------------------

    organization = ORGANIZATIONS.find_one(
        {
            "_id": organization_id
        }
    )

    print(
        "[4] Final status:",
        organization["status"]
    )

    if organization["status"] != "trial_expired":

        raise RuntimeError(
            "Trial expiry test failed"
        )

    # --------------------------------------------------------
    # Cleanup
    # --------------------------------------------------------

    ORGANIZATIONS.delete_one(
        {
            "_id": organization_id
        }
    )

    print(
        "[5] Temporary organization removed"
    )

    print(
        "\nSUCCESS: Trial expiry logic works correctly."
    )


if __name__ == "__main__":
    main()