from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.middleware.auth_middleware import verify_token
from app.database.connection import db

from app.services.subscription_plan_service import (
    get_all_plans,
    get_plan,
)

from app.services.billing_service import (
    create_razorpay_order,
    get_razorpay_order,
    verify_payment_signature,
)

from app.services.organization_subscription_service import (
    activate_razorpay_subscription,
)


# ============================================================
# ROUTER
# ============================================================

router = APIRouter(
    prefix="/subscriptions",
    tags=["Subscriptions"]
)


# ============================================================
# CONSTANTS
# ============================================================

RAZORPAY_CURRENCY = "INR"


# ============================================================
# REQUEST MODELS
# ============================================================

class CheckoutRequest(BaseModel):
    plan: str
    billing_cycle: str


class PaymentVerificationRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str


# ============================================================
# GET SUBSCRIPTION PLANS
# ============================================================

@router.get("/plans")
def list_subscription_plans():

    """
    Return all active CloudGuardAI subscription plans.
    """

    plans = get_all_plans()

    active_plans = [
        plan
        for plan in plans
        if plan.get("active", True)
    ]

    return {
        "total_plans": len(active_plans),
        "plans": active_plans
    }


# ============================================================
# CREATE CHECKOUT ORDER
# ============================================================

@router.post("/{organization_id}/checkout")
def create_checkout_order(
    organization_id: str,
    request: CheckoutRequest,
    current_user=Depends(verify_token)
):

    """
    Create a Razorpay checkout order for an organization.

    Only organization Owner/Admin users can initiate billing.
    """

    organization_id = str(
        organization_id or ""
    ).strip()

    if not organization_id:

        raise HTTPException(
            status_code=400,
            detail="Organization ID is required."
        )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active organization membership
    # --------------------------------------------------------

    membership = db.organization_members.find_one(
        {
            "organization_id": organization_id,
            "user_id": current_user_id,
            "status": "active"
        },
        {
            "_id": 0,
            "role": 1
        }
    )

    if not membership:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization."
        )

    role = str(
        membership.get("role", "")
    ).strip().lower()

    # --------------------------------------------------------
    # Billing permission
    # --------------------------------------------------------

    if role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail="Only organization Owner/Admin can manage billing."
        )

    # --------------------------------------------------------
    # Create Razorpay order
    # --------------------------------------------------------

    try:

        order = create_razorpay_order(
            organization_id=organization_id,
            plan_name=request.plan,
            billing_cycle=request.billing_cycle,
            user_id=current_user_id,
            user_email=current_user.get("email")
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except RuntimeError as error:

        raise HTTPException(
            status_code=502,
            detail=str(error)
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to create checkout order."
        )

    return {
        "status": "success",
        "message": "Checkout order created successfully.",
        "checkout": order
    }


# ============================================================
# VERIFY + ACTIVATE RAZORPAY PAYMENT
# ============================================================

@router.post("/{organization_id}/verify-payment")
def verify_razorpay_payment(
    organization_id: str,
    request: PaymentVerificationRequest,
    current_user=Depends(verify_token)
):

    """
    Verify Razorpay payment and activate the purchased
    organization subscription.
    """

    organization_id = str(
        organization_id or ""
    ).strip()

    if not organization_id:

        raise HTTPException(
            status_code=400,
            detail="Organization ID is required."
        )

    current_user_id = str(
        current_user["_id"]
    )

    # --------------------------------------------------------
    # Verify active organization membership
    # --------------------------------------------------------

    membership = db.organization_members.find_one(
        {
            "organization_id": organization_id,
            "user_id": current_user_id,
            "status": "active"
        },
        {
            "_id": 0,
            "role": 1
        }
    )

    if not membership:

        raise HTTPException(
            status_code=403,
            detail="You do not have access to this organization."
        )

    role = str(
        membership.get("role", "")
    ).strip().lower()

    # --------------------------------------------------------
    # Billing permission
    # --------------------------------------------------------

    if role not in {
        "owner",
        "admin"
    }:

        raise HTTPException(
            status_code=403,
            detail="Only organization Owner/Admin can verify billing."
        )

    # --------------------------------------------------------
    # Validate payment fields
    # --------------------------------------------------------

    order_id = str(
        request.razorpay_order_id or ""
    ).strip()

    payment_id = str(
        request.razorpay_payment_id or ""
    ).strip()

    signature = str(
        request.razorpay_signature or ""
    ).strip()

    if not order_id:

        raise HTTPException(
            status_code=400,
            detail="Razorpay order ID is required."
        )

    if not payment_id:

        raise HTTPException(
            status_code=400,
            detail="Razorpay payment ID is required."
        )

    if not signature:

        raise HTTPException(
            status_code=400,
            detail="Razorpay signature is required."
        )

    # --------------------------------------------------------
    # Step 1: Verify Razorpay signature
    # --------------------------------------------------------

    try:

        verified = verify_payment_signature(
            razorpay_order_id=order_id,
            razorpay_payment_id=payment_id,
            razorpay_signature=signature
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except RuntimeError:

        raise HTTPException(
            status_code=502,
            detail="Unable to connect to Razorpay."
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to verify payment."
        )

    if not verified:

        raise HTTPException(
            status_code=400,
            detail="Payment signature verification failed."
        )

    # --------------------------------------------------------
    # Step 2: Retrieve server-side Razorpay order
    # --------------------------------------------------------

    try:

        razorpay_order = get_razorpay_order(
            order_id
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except RuntimeError:

        raise HTTPException(
            status_code=502,
            detail="Unable to retrieve Razorpay order."
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Unable to validate Razorpay order."
        )

    # --------------------------------------------------------
    # Step 3: Validate order status
    # --------------------------------------------------------

    order_status = str(
        razorpay_order.get(
            "status",
            ""
        )
    ).strip().lower()

    if order_status != "paid":

        raise HTTPException(
            status_code=400,
            detail="Razorpay order has not been paid."
        )

    # --------------------------------------------------------
    # Step 4: Extract order metadata
    # --------------------------------------------------------

    notes = razorpay_order.get(
        "notes",
        {}
    ) or {}

    order_organization_id = str(
        notes.get(
            "organization_id",
            ""
        )
    ).strip()

    order_plan = str(
        notes.get(
            "plan",
            ""
        )
    ).strip().lower()

    order_billing_cycle = str(
        notes.get(
            "billing_cycle",
            ""
        )
    ).strip().lower()

    order_user_id = str(
        notes.get(
            "user_id",
            ""
        )
    ).strip()

    # --------------------------------------------------------
    # Validate organization
    # --------------------------------------------------------

    if order_organization_id != organization_id:

        raise HTTPException(
            status_code=400,
            detail="Razorpay order does not belong to this organization."
        )

    # --------------------------------------------------------
    # Validate order creator
    # --------------------------------------------------------

    if (
        order_user_id
        and
        order_user_id != current_user_id
    ):

        raise HTTPException(
            status_code=403,
            detail="Razorpay order was created by another user."
        )

    # --------------------------------------------------------
    # Validate paid plan
    # --------------------------------------------------------

    if order_plan not in {
        "pro",
        "business"
    }:

        raise HTTPException(
            status_code=400,
            detail="Invalid paid subscription plan."
        )

    # --------------------------------------------------------
    # Validate billing cycle
    # --------------------------------------------------------

    if order_billing_cycle not in {
        "monthly",
        "yearly"
    }:

        raise HTTPException(
            status_code=400,
            detail="Invalid billing cycle."
        )

    # ========================================================
    # STEP 5: PRODUCTION BILLING VALIDATION
    # ========================================================

    plan = get_plan(
        order_plan
    )

    if not plan:

        raise HTTPException(
            status_code=400,
            detail="Subscription plan configuration not found."
        )

    if not plan.get(
        "active",
        True
    ):

        raise HTTPException(
            status_code=400,
            detail="Subscription plan is not active."
        )

    # --------------------------------------------------------
    # Get expected CloudGuardAI price
    # --------------------------------------------------------

    if order_billing_cycle == "monthly":

        configured_price = plan.get(
            "price_monthly"
        )

    else:

        configured_price = plan.get(
            "price_yearly"
        )

    try:

        expected_amount_paise = int(
            round(
                float(
                    configured_price
                ) * 100
            )
        )

    except (
        TypeError,
        ValueError
    ):

        raise HTTPException(
            status_code=500,
            detail="Subscription plan price configuration is invalid."
        )

    if expected_amount_paise <= 0:

        raise HTTPException(
            status_code=500,
            detail="Subscription plan amount must be greater than zero."
        )

    # --------------------------------------------------------
    # Get actual Razorpay order amount
    # --------------------------------------------------------

    try:

        actual_amount_paise = int(
            razorpay_order.get(
                "amount",
                0
            )
        )

    except (
        TypeError,
        ValueError
    ):

        raise HTTPException(
            status_code=400,
            detail="Invalid Razorpay order amount."
        )

    # --------------------------------------------------------
    # Amount must match exactly
    # --------------------------------------------------------

    if actual_amount_paise != expected_amount_paise:

        raise HTTPException(
            status_code=400,
            detail=(
                "Razorpay order amount does not match "
                "the selected subscription plan."
            )
        )

    # --------------------------------------------------------
    # Validate currency
    # --------------------------------------------------------

    actual_currency = str(
        razorpay_order.get(
            "currency",
            ""
        )
    ).strip().upper()

    if actual_currency != RAZORPAY_CURRENCY:

        raise HTTPException(
            status_code=400,
            detail="Razorpay order currency is invalid."
        )

    # ========================================================
    # STEP 6: ACTIVATE SUBSCRIPTION
    # ========================================================

    try:

        activation = activate_razorpay_subscription(
            organization_id=organization_id,
            plan_name=order_plan,
            billing_cycle=order_billing_cycle,
            razorpay_order_id=order_id,
            razorpay_payment_id=payment_id,
        )

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception:

        raise HTTPException(
            status_code=500,
            detail="Payment verified but subscription activation failed."
        )

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {

        "status": "success",

        "verified": True,

        "activated": activation.get(
            "activated",
            False
        ),

        "already_processed": activation.get(
            "already_processed",
            False
        ),

        "message":
            "Payment verified and subscription activated successfully.",

        "organization_id":
            organization_id,

        "plan":
            activation.get(
                "plan"
            ),

        "billing_cycle":
            activation.get(
                "billing_cycle"
            ),

        "provider":
            activation.get(
                "provider"
            ),

        "razorpay_order_id":
            order_id,

        "razorpay_payment_id":
            payment_id,

        "subscription_id":
            activation.get(
                "subscription_id"
            ),

    }