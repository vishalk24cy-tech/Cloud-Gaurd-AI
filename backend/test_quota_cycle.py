from bson import ObjectId

from app.database.connection import db
from app.services.organization_usage_service import (
    reserve_usage,
    release_usage,
    get_current_usage
)


USAGE = db.organization_usage

TEST_ORGANIZATION_ID = str(
    ObjectId()
)


def main():

    print("\n=== CloudGuardAI Quota Cycle Test ===")

    organization_id = TEST_ORGANIZATION_ID

    print(
        f"Temporary Organization: {organization_id}"
    )

    # --------------------------------------------------------
    # Create temporary usage record
    # --------------------------------------------------------

    from app.services.organization_usage_service import (
        ensure_current_usage
    )

    ensure_current_usage(
        organization_id
    )

    print("[1] Usage record created")

    # --------------------------------------------------------
    # Reserve 1 AWS account
    # --------------------------------------------------------

    reservation = reserve_usage(
        organization_id=organization_id,
        usage_field="aws_accounts_used",
        limit=1,
        amount=1
    )

    print(
        "[2] Reservation:",
        reservation
    )

    if not reservation.get("reserved"):
        raise RuntimeError(
            "Reservation test failed"
        )

    # --------------------------------------------------------
    # Verify usage = 1
    # --------------------------------------------------------

    usage = get_current_usage(
        organization_id
    )

    print(
        "[3] Usage after reservation:",
        usage["aws_accounts_used"]
    )

    if usage["aws_accounts_used"] != 1:
        raise RuntimeError(
            "Usage did not increase to 1"
        )

    # --------------------------------------------------------
    # Release reservation
    # --------------------------------------------------------

    released = release_usage(
        organization_id=organization_id,
        usage_field="aws_accounts_used",
        amount=1
    )

    print(
        "[4] Release:",
        released
    )

    # --------------------------------------------------------
    # Verify usage = 0
    # --------------------------------------------------------

    usage = get_current_usage(
        organization_id
    )

    print(
        "[5] Usage after release:",
        usage["aws_accounts_used"]
    )

    if usage["aws_accounts_used"] != 0:
        raise RuntimeError(
            "Usage did not return to 0"
        )

    # --------------------------------------------------------
    # Cleanup temporary record
    # --------------------------------------------------------

    USAGE.delete_one(
        {
            "organization_id": organization_id
        }
    )

    print("[6] Temporary test data removed")

    print(
        "\nSUCCESS: Quota reservation/release cycle works."
    )


if __name__ == "__main__":
    main()