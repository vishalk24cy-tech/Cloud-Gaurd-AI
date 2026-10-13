import os
import json
import hmac
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Request, HTTPException
from pymongo.errors import DuplicateKeyError

from app.database.connection import db


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/webhooks",
    tags=["Webhooks"]
)


# ============================================================
# CONFIGURATION
# ============================================================

RAZORPAY_WEBHOOK_SECRET = os.getenv(
    "RAZORPAY_WEBHOOK_SECRET",
    ""
).strip()


# ============================================================
# COLLECTION
# ============================================================

WEBHOOK_EVENTS = db.billing_webhook_events


# ============================================================
# INDEX INITIALIZATION
# ============================================================

def initialize_webhook_indexes():
    """
    Create the unique Razorpay event ID index.

    Razorpay may send the same webhook more than once.
    The unique event ID prevents duplicate processing.
    """

    return WEBHOOK_EVENTS.create_index(
        [("event_id", 1)],
        unique=True,
        name="razorpay_event_unique_idx"
    )


# ============================================================
# SIGNATURE VERIFICATION
# ============================================================

def verify_razorpay_webhook_signature(
    raw_body: bytes,
    received_signature: str
) -> bool:
    """
    Verify Razorpay webhook authenticity.

    IMPORTANT:
    Signature verification must use the RAW request body.
    """

    if not RAZORPAY_WEBHOOK_SECRET:
        raise RuntimeError(
            "RAZORPAY_WEBHOOK_SECRET is not configured."
        )

    if not received_signature:
        return False

    expected_signature = hmac.new(
        RAZORPAY_WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(
        expected_signature,
        received_signature.strip()
    )


# ============================================================
# EXTRACT WEBHOOK METADATA
# ============================================================

def extract_webhook_metadata(payload: dict) -> dict:
    """
    Extract only the billing metadata required by CloudGuardAI.

    Sensitive payment information is not persisted.
    """

    event_name = str(
        payload.get("event", "")
    ).strip()

    event_payload = payload.get(
        "payload",
        {}
    )

    order_entity = (
        event_payload
        .get("order", {})
        .get("entity", {})
    )

    payment_entity = (
        event_payload
        .get("payment", {})
        .get("entity", {})
    )

    notes = order_entity.get(
        "notes",
        {}
    )

    if not isinstance(notes, dict):
        notes = {}

    return {
        "event": event_name,

        "organization_id": str(
            notes.get(
                "organization_id",
                ""
            )
        ).strip(),

        "plan": str(
            notes.get(
                "plan",
                ""
            )
        ).strip().lower(),

        "billing_cycle": str(
            notes.get(
                "billing_cycle",
                ""
            )
        ).strip().lower(),

        "order_id": str(
            order_entity.get(
                "id",
                ""
            )
        ).strip(),

        "payment_id": str(
            payment_entity.get(
                "id",
                ""
            )
        ).strip(),

        "order_status": str(
            order_entity.get(
                "status",
                ""
            )
        ).strip().lower(),

        "payment_status": str(
            payment_entity.get(
                "status",
                ""
            )
        ).strip().lower(),

        "amount": order_entity.get(
            "amount"
        ),

        "currency": str(
            order_entity.get(
                "currency",
                ""
            )
        ).strip().upper(),
    }


# ============================================================
# PROCESS ORDER PAID
# ============================================================

def process_order_paid(
    metadata: dict
) -> dict:
    """
    Activate the organization's subscription when
    Razorpay confirms order.paid.
    """

    organization_id = metadata.get(
        "organization_id"
    )

    if not organization_id:
        return {
            "processed": False,
            "reason": (
                "Organization ID missing from order notes."
            )
        }

    plan = metadata.get(
        "plan"
    ) or "pro"

    billing_cycle = metadata.get(
        "billing_cycle"
    ) or "monthly"

    order_id = metadata.get(
        "order_id"
    )

    payment_id = metadata.get(
        "payment_id"
    )

    now = datetime.now(
        timezone.utc
    )

    # --------------------------------------------------------
    # UPDATE SUBSCRIPTION
    # --------------------------------------------------------

    subscription_update = {
        "$set": {
            "plan": plan,
            "status": "active",
            "provider": "razorpay",
            "billing_cycle": billing_cycle,
            "updated_at": now,
        }
    }

    if payment_id:
        subscription_update[
            "$set"
        ]["subscription_id"] = payment_id

    if order_id:
        subscription_update[
            "$set"
        ]["razorpay_order_id"] = order_id

    subscription_result = (
        db.organization_subscriptions.update_one(
            {
                "organization_id": organization_id
            },
            subscription_update
        )
    )

    # --------------------------------------------------------
    # UPDATE ORGANIZATION
    # --------------------------------------------------------

    organization_result = {
        "matched_count": 0,
        "modified_count": 0,
    }

    try:
        from bson import ObjectId

        organization_object_id = ObjectId(
            organization_id
        )

        organization_result = (
            db.organizations.update_one(
                {
                    "_id": organization_object_id
                },
                {
                    "$set": {
                        "plan": plan,
                        "status": "active",
                        "updated_at": now,
                    }
                }
            )
        )

    except Exception:
        organization_result = {
            "matched_count": 0,
            "modified_count": 0,
        }

    return {
        "processed": True,

        "organization_id": organization_id,

        "plan": plan,

        "billing_cycle": billing_cycle,

        "subscription_updated": (
            subscription_result.modified_count > 0
            or subscription_result.matched_count > 0
        ),

        "organization_updated": (
            (
                organization_result.get("modified_count", 0)
                if isinstance(organization_result, dict)
                else organization_result.modified_count
            ) > 0
            or (
                organization_result.get("matched_count", 0)
                if isinstance(organization_result, dict)
                else organization_result.matched_count
            ) > 0
        ),
    }


# ============================================================
# RAZORPAY WEBHOOK ENDPOINT
# ============================================================

@router.post("/razorpay")
async def razorpay_webhook(
    request: Request
):
    """
    Receive and securely process Razorpay webhooks.

    Endpoint:

        POST /webhooks/razorpay

    JWT authentication is NOT used here.
    Razorpay signature verification is used instead.
    """

    # --------------------------------------------------------
    # CONFIGURATION CHECK
    # --------------------------------------------------------

    if not RAZORPAY_WEBHOOK_SECRET:
        raise HTTPException(
            status_code=503,
            detail="Razorpay webhook is not configured."
        )

    # --------------------------------------------------------
    # READ RAW BODY
    # --------------------------------------------------------

    raw_body = await request.body()

    if not raw_body:
        raise HTTPException(
            status_code=400,
            detail="Webhook body is empty."
        )

    # --------------------------------------------------------
    # READ SIGNATURE
    # --------------------------------------------------------

    signature = request.headers.get(
        "X-Razorpay-Signature"
    )

    if not signature:
        raise HTTPException(
            status_code=400,
            detail="Missing Razorpay webhook signature."
        )

    # --------------------------------------------------------
    # VERIFY SIGNATURE
    # --------------------------------------------------------

    try:

        valid_signature = (
            verify_razorpay_webhook_signature(
                raw_body=raw_body,
                received_signature=signature
            )
        )

    except RuntimeError as error:

        raise HTTPException(
            status_code=503,
            detail=str(error)
        )

    if not valid_signature:

        raise HTTPException(
            status_code=400,
            detail="Invalid Razorpay webhook signature."
        )

    # --------------------------------------------------------
    # EVENT ID
    # --------------------------------------------------------

    event_id = request.headers.get(
        "x-razorpay-event-id"
    )

    if not event_id:

        raise HTTPException(
            status_code=400,
            detail="Missing Razorpay event ID."
        )

    event_id = event_id.strip()

    if not event_id:

        raise HTTPException(
            status_code=400,
            detail="Invalid Razorpay event ID."
        )

    # --------------------------------------------------------
    # PARSE JSON
    # --------------------------------------------------------

    try:

        payload = json.loads(
            raw_body.decode("utf-8")
        )

    except (
        UnicodeDecodeError,
        json.JSONDecodeError
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid webhook JSON."
        )

    if not isinstance(payload, dict):

        raise HTTPException(
            status_code=400,
            detail="Invalid webhook payload."
        )

    # --------------------------------------------------------
    # INITIALIZE INDEX
    # --------------------------------------------------------

    try:

        initialize_webhook_indexes()

    except Exception as error:

        print(
            "[WARNING] Razorpay webhook index "
            f"initialization failed: {error}"
        )

    # --------------------------------------------------------
    # DUPLICATE EVENT / ATOMIC PROCESSING CLAIM
    # --------------------------------------------------------

    existing_event = (
        WEBHOOK_EVENTS.find_one(
            {
                "event_id": event_id
            },
            {
                "_id": 1,
                "status": 1,
                "processing_at": 1,
            }
        )
    )

    if existing_event:

        existing_status = str(
            existing_event.get(
                "status",
                ""
            )
        ).strip().lower()

        # ----------------------------------------------------
        # ALREADY SUCCESSFULLY PROCESSED
        # ----------------------------------------------------

        if existing_status == "processed":

            return {
                "status": "success",
                "message": "Webhook already processed.",
                "duplicate": True,
                "event_id": event_id,
            }

        # ----------------------------------------------------
        # FAILED / INCOMPLETE EVENT
        # ----------------------------------------------------
        #
        # Razorpay can retry webhook deliveries. Reset failed
        # events so a retry can attempt processing again.
        #

        if existing_status != "processing":

            WEBHOOK_EVENTS.update_one(
                {
                    "event_id": event_id
                },
                {
                    "$set": {
                        "status": "received",
                        "retry_at": datetime.now(
                            timezone.utc
                        ),
                        "error": None,
                        "error_message": None,
                    }
                }
            )

    # --------------------------------------------------------
    # ATOMIC PROCESSING CLAIM
    # --------------------------------------------------------
    #
    # Only one request is allowed to transition this event
    # into processing. Concurrent duplicate deliveries cannot
    # execute the billing action twice.
    #

    processing_now = datetime.now(
        timezone.utc
    )

    claim_result = WEBHOOK_EVENTS.update_one(
        {
            "event_id": event_id,
            "$or": [
                {"status": "received"},
                {"status": "failed"},
                {
                    "status": "processing",
                    "processing_at": {
                        "$lt": processing_now - timedelta(minutes=10)
                    },
                },
            ],
        },
        {
            "$set": {
                "status": "processing",
                "processing_at": processing_now,
                "error": None,
                "error_message": None,
            }
        }
    )

    # A brand-new event has not been inserted yet, so the first
    # claim cannot match it. Existing events can be claimed here.
    # For a new event, we insert it as "received" below and then
    # perform the atomic claim after insertion.
    if claim_result.matched_count == 0 and existing_event:

        latest_event = WEBHOOK_EVENTS.find_one(
            {
                "event_id": event_id
            },
            {
                "_id": 0,
                "status": 1,
            }
        )

        latest_status = str(
            (latest_event or {}).get(
                "status",
                ""
            )
        ).strip().lower()

        if latest_status == "processed":

            return {
                "status": "success",
                "message": "Webhook already processed.",
                "duplicate": True,
                "event_id": event_id,
            }

        return {
            "status": "success",
            "message": "Webhook is already being processed.",
            "duplicate": True,
            "processing": True,
            "event_id": event_id,
        }

    # --------------------------------------------------------
    # EXTRACT METADATA
    # --------------------------------------------------------

    metadata = extract_webhook_metadata(
        payload
    )

    event_name = metadata.get(
        "event",
        ""
    )

    now = datetime.now(
        timezone.utc
    )

    # --------------------------------------------------------
    # STORE EVENT
    # --------------------------------------------------------

    webhook_record = {
        "event_id": event_id,

        "event": event_name,

        "created_at": now,

        "organization_id": metadata.get(
            "organization_id"
        ),

        "order_id": metadata.get(
            "order_id"
        ),

        "payment_id": metadata.get(
            "payment_id"
        ),

        "plan": metadata.get(
            "plan"
        ),

        "billing_cycle": metadata.get(
            "billing_cycle"
        ),

        "amount": metadata.get(
            "amount"
        ),

        "currency": metadata.get(
            "currency"
        ),

        "status": "received",

        "received_at": now,

        "processed_at": None,
    }

    # --------------------------------------------------------
    # INSERT ONLY FOR NEW EVENTS
    # --------------------------------------------------------

    if not existing_event:

        try:

            WEBHOOK_EVENTS.insert_one(
                webhook_record
            )

        except DuplicateKeyError:

            latest_event = WEBHOOK_EVENTS.find_one(
                {
                    "event_id": event_id
                },
                {
                    "_id": 0,
                    "status": 1,
                }
            )

            latest_status = str(
                (latest_event or {}).get(
                    "status",
                    ""
                )
            ).strip().lower()

            if latest_status == "processed":
                return {
                    "status": "success",
                    "message": "Webhook already processed.",
                    "duplicate": True,
                    "event_id": event_id,
                }

            return {
                "status": "success",
                "message": "Webhook is already being processed.",
                "duplicate": True,
                "processing": True,
                "event_id": event_id,
            }

        # The event is now persisted as "received". Claim it
        # atomically so only one delivery can process it.
        claim_result = WEBHOOK_EVENTS.update_one(
            {
                "event_id": event_id,
                "status": "received",
            },
            {
                "$set": {
                    "status": "processing",
                    "processing_at": datetime.now(timezone.utc),
                    "error": None,
                    "error_message": None,
                }
            }
        )

        if claim_result.matched_count == 0:
            latest_event = WEBHOOK_EVENTS.find_one(
                {
                    "event_id": event_id
                },
                {
                    "_id": 0,
                    "status": 1,
                }
            )

            latest_status = str(
                (latest_event or {}).get(
                    "status",
                    ""
                )
            ).strip().lower()

            if latest_status == "processed":
                return {
                    "status": "success",
                    "message": "Webhook already processed.",
                    "duplicate": True,
                    "event_id": event_id,
                }

            return {
                "status": "success",
                "message": "Webhook is already being processed.",
                "duplicate": True,
                "processing": True,
                "event_id": event_id,
            }

    # --------------------------------------------------------
    # PROCESS EVENT
    # --------------------------------------------------------

    processing_result = {
        "processed": False,
        "reason": (
            "Event acknowledged but no "
            "billing action required."
        )
    }

    try:

        # ----------------------------------------------------
        # ORDER PAID
        # ----------------------------------------------------

        if event_name == "order.paid":

            processing_result = (
                process_order_paid(
                    metadata
                )
            )

        # ----------------------------------------------------
        # PAYMENT CAPTURED
        # ----------------------------------------------------

        elif event_name == "payment.captured":

            processing_result = {
                "processed": True,
                "reason": (
                    "Payment captured event acknowledged."
                )
            }

        # ----------------------------------------------------
        # PAYMENT AUTHORIZED
        # ----------------------------------------------------

        elif event_name == "payment.authorized":

            processing_result = {
                "processed": True,
                "reason": (
                    "Payment authorized event acknowledged."
                )
            }

        # ----------------------------------------------------
        # PAYMENT FAILED
        # ----------------------------------------------------

        elif event_name == "payment.failed":

            processing_result = {
                "processed": True,
                "reason": (
                    "Payment failure event acknowledged."
                )
            }

        # ----------------------------------------------------
        # UNKNOWN EVENT
        # ----------------------------------------------------

        else:

            processing_result = {
                "processed": True,
                "reason": (
                    "Unsupported event acknowledged safely."
                )
            }

        # ----------------------------------------------------
        # MARK PROCESSED
        # ----------------------------------------------------

        WEBHOOK_EVENTS.update_one(
            {
                "event_id": event_id
            },
            {
                "$set": {
                    "status": "processed",

                    "processed_at": datetime.now(
                        timezone.utc
                    ),

                    "processing_at": None,

                    "processing_result": (
                        processing_result
                    ),
                }
            }
        )

    except Exception as error:

        print(
            "[ERROR] Razorpay webhook processing failed: "
            f"{type(error).__name__}: {error}"
        )

        WEBHOOK_EVENTS.update_one(
            {
                "event_id": event_id
            },
            {
                "$set": {
                    "status": "failed",

                    "processed_at": datetime.now(
                        timezone.utc
                    ),

                    "processing_at": None,

                    "error": type(
                        error
                    ).__name__,

                    "error_message": str(error),
                }
            }
        )

        raise HTTPException(
            status_code=500,
            detail="Webhook processing failed."
        )

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {
        "status": "success",

        "message": (
            "Razorpay webhook processed."
        ),

        "event_id": event_id,

        "event": event_name,

        "processing": processing_result,
    }