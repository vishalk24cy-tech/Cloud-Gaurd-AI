from fastapi import APIRouter, HTTPException, Depends

from app.middleware.auth_middleware import verify_token

from app.models.aws_account import get_user_accounts

from app.services.aws_connection import assume_aws_role

from app.services.cost_optimizer import (
    get_cost_overview,
    get_cost_recommendations
)

router = APIRouter()


# ============================================================
# GET COST OVERVIEW
# ============================================================

@router.get("/overview")
def cost_overview(
    account_id: str,
    current_user=Depends(verify_token)
):

    try:

        # -----------------------------------------
        # Get accounts belonging to logged-in user
        # -----------------------------------------

        accounts = get_user_accounts(
            current_user["_id"]
        )

        if not accounts:

            raise HTTPException(
                status_code=404,
                detail="No AWS account connected"
            )

        # -----------------------------------------
        # Find requested account
        # -----------------------------------------

        account = None

        for item in accounts:

            if str(item.get("_id")) == str(account_id):

                account = item
                break

        if not account:

            raise HTTPException(
                status_code=404,
                detail="AWS account not found"
            )

        # -----------------------------------------
        # Get IAM Role ARN
        # -----------------------------------------

        role_arn = account.get("role_arn")

        if not role_arn:

            raise HTTPException(
                status_code=400,
                detail="AWS scanner role ARN not configured"
            )

        # -----------------------------------------
        # Get AWS Region
        # -----------------------------------------

        region = account.get(
            "region",
            "ap-south-1"
        )

        # -----------------------------------------
        # Assume AWS Role
        # -----------------------------------------

        session = assume_aws_role(
            role_arn,
            region
        )

        # -----------------------------------------
        # Get Cost Data
        # -----------------------------------------

        result = get_cost_overview(
            session,
            days=30
        )

        if result.get("status") == "error":

            raise HTTPException(
                status_code=500,
                detail=result.get(
                    "message",
                    "Unable to retrieve AWS cost data"
                )
            )

        return {

            "status": "success",

            "account_id":
                account.get(
                    "account_id",
                    account_id
                ),

            "period":
                "Last 30 Days",

            "cost":
                result

        }

    except HTTPException:

        raise

    except Exception as e:

        print(
            "Cost Overview Error:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# GET COST OPTIMIZATION RECOMMENDATIONS
# ============================================================

@router.get("/recommendations")
def cost_recommendations(
    account_id: str,
    current_user=Depends(verify_token)
):

    try:

        # -----------------------------------------
        # Get logged-in user's AWS accounts
        # -----------------------------------------

        accounts = get_user_accounts(
            current_user["_id"]
        )

        if not accounts:

            raise HTTPException(
                status_code=404,
                detail="No AWS account connected"
            )

        # -----------------------------------------
        # Find requested account
        # -----------------------------------------

        account = None

        for item in accounts:

            if str(item.get("_id")) == str(account_id):

                account = item
                break

        if not account:

            raise HTTPException(
                status_code=404,
                detail="AWS account not found"
            )

        # -----------------------------------------
        # Get Role ARN
        # -----------------------------------------

        role_arn = account.get("role_arn")

        if not role_arn:

            raise HTTPException(
                status_code=400,
                detail="AWS scanner role ARN not configured"
            )

        region = account.get(
            "region",
            "ap-south-1"
        )

        # -----------------------------------------
        # Assume AWS Role
        # -----------------------------------------

        session = assume_aws_role(
            role_arn,
            region
        )

        # -----------------------------------------
        # Analyze Resources
        # -----------------------------------------

        result = get_cost_recommendations(
            session
        )

        if result.get("status") == "error":

            raise HTTPException(
                status_code=500,
                detail=result.get(
                    "message",
                    "Unable to generate cost recommendations"
                )
            )

        return {

            "status": "success",

            "account_id":
                account.get(
                    "account_id",
                    account_id
                ),

            "optimization":
                result

        }

    except HTTPException:

        raise

    except Exception as e:

        print(
            "Cost Recommendation Error:",
            str(e)
        )

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )