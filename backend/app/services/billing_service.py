import os
import secrets
from datetime import datetime, timezone
from typing import Optional

import razorpay
from dotenv import load_dotenv

from app.services.subscription_plan_service import get_plan

load_dotenv()


# ============================================================
# RAZORPAY CONFIGURATION
# ============================================================

RAZORPAY_KEY_ID = os.getenv(
    "RAZORPAY_KEY_ID",
    ""
).strip()

RAZORPAY_KEY_SECRET = os.getenv(
    "RAZORPAY_KEY_SECRET",
    ""
).strip()

RAZORPAY_CURRENCY = "INR"


# ============================================================
# CLIENT
# ============================================================

def _get_client() -> razorpay.Client:
    """
    Create and return a Razorpay client.

    Credentials are loaded only from environment variables.
    """

    if not RAZORPAY_KEY_ID:
        raise RuntimeError(
            "RAZORPAY_KEY_ID is not configured."
        )

    if not RAZORPAY_KEY_SECRET:
        raise RuntimeError(
            "RAZORPAY_KEY_SECRET is not configured."
        )

    return razorpay.Client(
        auth=(
            RAZORPAY_KEY_ID,
            RAZORPAY_KEY_SECRET,
        )
    )


# ============================================================
# PLAN VALIDATION
# ============================================================

def _get_paid_plan(
    plan_name: str,
    billing_cycle: str,
) -> tuple[dict, int]:
    """
    Validate a paid subscription plan and return:

        (plan, amount_in_paise)
    """

    plan_name = str(
        plan_name or ""
    ).strip().lower()

    billing_cycle = str(
        billing_cycle or ""
    ).strip().lower()

    if billing_cycle not in {
        "monthly",
        "yearly",
    }:
        raise ValueError(
            "Billing cycle must be 'monthly' or 'yearly'."
        )

    plan = get_plan(
        plan_name
    )

    if not plan:
        raise ValueError(
            f"Invalid subscription plan: {plan_name}"
        )

    if not plan.get(
        "active",
        True
    ):
        raise ValueError(
            f"Subscription plan '{plan_name}' is not active."
        )

    if plan_name == "free":
        raise ValueError(
            "The free plan does not require payment."
        )

    if billing_cycle == "monthly":
        amount_rupees = plan.get(
            "price_monthly"
        )
    else:
        amount_rupees = plan.get(
            "price_yearly"
        )

    if amount_rupees is None:
        raise ValueError(
            f"Pricing is not configured for "
            f"{plan_name} {billing_cycle} billing."
        )

    try:
        amount_rupees = float(
            amount_rupees
        )
    except (
        TypeError,
        ValueError
    ):
        raise ValueError(
            "Invalid plan price configuration."
        )

    if amount_rupees <= 0:
        raise ValueError(
            "Paid plan amount must be greater than zero."
        )

    amount_paise = int(
        round(
            amount_rupees * 100
        )
    )

    return (
        plan,
        amount_paise
    )


# ============================================================
# CREATE RAZORPAY ORDER
# ============================================================

def create_razorpay_order(
    organization_id: str,
    plan_name: str,
    billing_cycle: str,
    user_id: Optional[str] = None,
    user_email: Optional[str] = None,
) -> dict:
    """
    Create a Razorpay Test/Live order.
    """

    organization_id = str(
        organization_id or ""
    ).strip()

    if not organization_id:
        raise ValueError(
            "Organization ID is required."
        )

    plan, amount_paise = _get_paid_plan(
        plan_name=plan_name,
        billing_cycle=billing_cycle,
    )

    receipt = (
        f"cga_"
        f"{organization_id[-8:]}_"
        f"{secrets.token_hex(8)}"
    )

    notes = {
        "organization_id": organization_id,
        "plan": plan["name"],
        "billing_cycle": billing_cycle,
        "product": "CloudGuardAI",
    }

    if user_id:
        notes["user_id"] = str(
            user_id
        )

    if user_email:
        notes["user_email"] = str(
            user_email
        )

    order_data = {
        "amount": amount_paise,
        "currency": RAZORPAY_CURRENCY,
        "receipt": receipt,
        "notes": notes,
    }

    client = _get_client()

    try:
        order = client.order.create(
            data=order_data
        )
    except Exception as exc:
        print(
            "RAZORPAY ORDER ERROR TYPE:",
            type(exc).__name__
        )
        print(
            "RAZORPAY ORDER ERROR:",
            str(exc)
        )
        raise

    return {
        "provider": "razorpay",
        "order_id": order.get("id"),
        "amount": amount_paise,
        "currency": RAZORPAY_CURRENCY,
        "amount_rupees": amount_paise / 100,
        "status": order.get("status"),
        "receipt": receipt,
        "organization_id": organization_id,
        "plan": plan["name"],
        "plan_display_name": plan.get(
            "display_name"
        ),
        "billing_cycle": billing_cycle,
        "razorpay_key_id": RAZORPAY_KEY_ID,
        "created_at": datetime.now(
            timezone.utc
        ),
    }


# ============================================================
# GET RAZORPAY ORDER
# ============================================================

def get_razorpay_order(
    razorpay_order_id: str,
) -> dict:
    """
    Retrieve an order directly from Razorpay.
    """

    razorpay_order_id = str(
        razorpay_order_id or ""
    ).strip()

    if not razorpay_order_id:
        raise ValueError(
            "Razorpay order ID is required."
        )

    client = _get_client()

    try:
        order = client.order.fetch(
            razorpay_order_id
        )
    except Exception as exc:
        print(
            "RAZORPAY FETCH ORDER ERROR TYPE:",
            type(exc).__name__
        )
        print(
            "RAZORPAY FETCH ORDER ERROR:",
            str(exc)
        )
        raise

    if not order:
        raise ValueError(
            "Razorpay order was not found."
        )

    return order


# ============================================================
# VERIFY PAYMENT SIGNATURE
# ============================================================

def verify_payment_signature(
    razorpay_order_id: str,
    razorpay_payment_id: str,
    razorpay_signature: str,
) -> bool:
    """
    Verify the Razorpay Checkout payment signature.
    """

    razorpay_order_id = str(
        razorpay_order_id or ""
    ).strip()

    razorpay_payment_id = str(
        razorpay_payment_id or ""
    ).strip()

    razorpay_signature = str(
        razorpay_signature or ""
    ).strip()

    if not razorpay_order_id:
        raise ValueError(
            "Razorpay order ID is required."
        )

    if not razorpay_payment_id:
        raise ValueError(
            "Razorpay payment ID is required."
        )

    if not razorpay_signature:
        raise ValueError(
            "Razorpay signature is required."
        )

    client = _get_client()

    try:
        client.utility.verify_payment_signature(
            {
                "razorpay_order_id": razorpay_order_id,
                "razorpay_payment_id": razorpay_payment_id,
                "razorpay_signature": razorpay_signature,
            }
        )
    except Exception as exc:
        print(
            "RAZORPAY SIGNATURE ERROR TYPE:",
            type(exc).__name__
        )
        print(
            "RAZORPAY SIGNATURE ERROR:",
            str(exc)
        )
        return False

    return True


# ============================================================
# CREATE RAZORPAY RECURRING PLAN
# ============================================================

def create_razorpay_subscription_plan(
    plan_name: str,
    billing_cycle: str,
) -> dict:
    """
    Create a Razorpay recurring billing plan.

    This creates the Razorpay Plan that can later be used
    to create real recurring subscriptions.

    NOTE:
    This does NOT charge the customer.
    It only creates the billing plan in Razorpay.
    """

    plan_name = str(
        plan_name or ""
    ).strip().lower()

    billing_cycle = str(
        billing_cycle or ""
    ).strip().lower()

    if billing_cycle not in {
        "monthly",
        "yearly",
    }:
        raise ValueError(
            "Billing cycle must be 'monthly' or 'yearly'."
        )

    plan, amount_paise = _get_paid_plan(
        plan_name=plan_name,
        billing_cycle=billing_cycle,
    )

    if billing_cycle == "monthly":
        period = "monthly"
        interval = 1
    else:
        period = "yearly"
        interval = 1

    plan_data = {
        "period": period,
        "interval": interval,
        "item": {
            "name": (
                f"CloudGuardAI "
                f"{plan.get('display_name', plan_name).title()} "
                f"{billing_cycle.title()}"
            ),
            "amount": amount_paise,
            "currency": RAZORPAY_CURRENCY,
            "description": (
                f"CloudGuardAI "
                f"{plan.get('display_name', plan_name)} "
                f"{billing_cycle} subscription"
            ),
        },
        "notes": {
            "product": "CloudGuardAI",
            "plan": plan_name,
            "billing_cycle": billing_cycle,
        },
    }

    client = _get_client()

    try:
        razorpay_plan = client.plan.create(
            data=plan_data
        )
    except Exception as exc:
        print(
            "RAZORPAY PLAN ERROR TYPE:",
            type(exc).__name__
        )
        print(
            "RAZORPAY PLAN ERROR:",
            str(exc)
        )
        raise

    return {
        "provider": "razorpay",
        "plan_id": razorpay_plan.get("id"),
        "status": "created",
        "plan": plan_name,
        "plan_display_name": plan.get(
            "display_name"
        ),
        "billing_cycle": billing_cycle,
        "period": period,
        "interval": interval,
        "amount": amount_paise,
        "amount_rupees": amount_paise / 100,
        "currency": RAZORPAY_CURRENCY,
        "created_at": datetime.now(
            timezone.utc
        ),
    }