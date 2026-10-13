from fastapi import APIRouter, HTTPException, Depends

from app.schemas.user_schema import UserRegister
from app.schemas.login_schema import UserLogin

from app.database.connection import db

from app.utils.security import hash_password, verify_password
from app.utils.jwt_handler import create_access_token

from app.middleware.auth_middleware import verify_token

from app.services.organization_service import create_organization
from app.services.organization_invitation_service import (
    get_invitation_by_token,
    accept_invitation
)


router = APIRouter()


# -------------------------------
# Test API
# -------------------------------
@router.get("/test")
def test():
    return {
        "message": "Authentication API Working"
    }


# -------------------------------
# Register User
# -------------------------------
@router.post("/register")
def register(user: UserRegister):

    # -----------------------------------------
    # Normalize input
    # -----------------------------------------
    email = user.email.strip().lower()
    name = user.name.strip()

    if not name:
        raise HTTPException(
            status_code=400,
            detail="Name is required"
        )

    if not user.password:
        raise HTTPException(
            status_code=400,
            detail="Password is required"
        )

    invitation_token = (
        user.invitation_token.strip()
        if user.invitation_token
        else None
    )

    # -----------------------------------------
    # Check whether email already exists
    # -----------------------------------------
    existing_user = db.users.find_one({
        "email": email
    })

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    # =========================================================
    # INVITED USER REGISTRATION
    # =========================================================

    if invitation_token:

        try:

            # -----------------------------------------
            # Validate invitation BEFORE creating user
            # -----------------------------------------
            invitation = get_invitation_by_token(
                invitation_token
            )

            if not invitation:
                raise HTTPException(
                    status_code=400,
                    detail="Invalid or expired invitation"
                )

            invitation_email = (
                str(invitation.get("email", ""))
                .strip()
                .lower()
            )

            if invitation_email != email:
                raise HTTPException(
                    status_code=400,
                    detail="Invitation email does not match registration email"
                )

            organization_id = str(
                invitation.get("organization_id", "")
            ).strip()

            if not organization_id:
                raise HTTPException(
                    status_code=400,
                    detail="Invitation organization is invalid"
                )

            # -----------------------------------------
            # Create invited user
            # -----------------------------------------
            user_data = {
                "name": name,
                "email": email,
                "password": hash_password(
                    user.password
                ),
                "organization": None,
                "role": "viewer"
            }

            result = db.users.insert_one(
                user_data
            )

            user_id = str(
                result.inserted_id
            )

            try:

                # -----------------------------------------
                # Accept invitation
                #
                # The invitation service determines
                # the organization and role.
                # -----------------------------------------
                membership = accept_invitation(
                    token=invitation_token,
                    user_id=user_id
                )

                if str(
                    membership.get("organization_id", "")
                ) != organization_id:

                    raise ValueError(
                        "Invitation organization mismatch"
                    )

            except Exception:

                # -----------------------------------------
                # Roll back user if invitation acceptance
                # fails.
                # -----------------------------------------
                db.users.delete_one({
                    "_id": result.inserted_id
                })

                raise

            # -----------------------------------------
            # Return invited registration result
            # -----------------------------------------
            return {
                "message": "User Registered Successfully",
                "organization": {
                    "id": organization_id,
                    "role": membership.get(
                        "role",
                        "viewer"
                    )
                }
            }

        except HTTPException:
            raise

        except ValueError as error:

            raise HTTPException(
                status_code=400,
                detail=str(error)
            )

        except Exception as error:

            print(
                f"[ERROR] Invitation registration failed: {error}"
            )

            raise HTTPException(
                status_code=500,
                detail="Unable to complete invited registration"
            ) from error

    # =========================================================
    # NORMAL USER REGISTRATION
    # =========================================================

    # -----------------------------------------
    # Determine organization name
    # -----------------------------------------
    organization_name = (
        user.organization.strip()
        if user.organization
        else f"{name}'s Organization"
    )

    if not organization_name:
        organization_name = (
            "CloudGuardAI Organization"
        )

    # -----------------------------------------
    # Create user data
    # -----------------------------------------
    user_data = {
        "name": name,
        "email": email,
        "password": hash_password(
            user.password
        ),
        "organization": None,
        "role": "owner"
    }

    try:

        # -----------------------------------------
        # Insert user
        # -----------------------------------------
        result = db.users.insert_one(
            user_data
        )

        user_id = str(
            result.inserted_id
        )

        # -----------------------------------------
        # Create SaaS organization
        # -----------------------------------------
        organization = create_organization(
            name=organization_name,
            owner_id=user_id,
            plan="free"
        )

        organization_id = organization["_id"]

        # -----------------------------------------
        # Link user to organization
        # -----------------------------------------
        db.users.update_one(
            {
                "_id": result.inserted_id
            },
            {
                "$set": {
                    "organization": organization_id,
                    "role": "owner"
                }
            }
        )

    except ValueError as error:

        # Roll back user if organization creation fails
        if "result" in locals():

            db.users.delete_one({
                "_id": result.inserted_id
            })

        raise HTTPException(
            status_code=400,
            detail=str(error)
        )

    except Exception as error:

        # Roll back user if unexpected failure occurs
        if "result" in locals():

            db.users.delete_one({
                "_id": result.inserted_id
            })

        print(
            f"[ERROR] Normal registration failed: {error}"
        )

        raise HTTPException(
            status_code=500,
            detail="Unable to create account"
        ) from error

    return {
        "message": "User Registered Successfully",
        "organization": {
            "id": organization_id,
            "name": organization["name"],
            "slug": organization["slug"],
            "plan": organization["plan"],
            "role": "owner"
        }
    }


# -------------------------------
# Login User
# -------------------------------
@router.post("/login")
def login(user: UserLogin):

    db_user = db.users.find_one({
        "email": user.email
    })

    if not db_user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if not verify_password(
        user.password,
        db_user["password"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid Password"
        )

    access_token = create_access_token(
        data={
            "_id": str(db_user["_id"]),
            "email": db_user["email"],
            "organization": db_user.get("organization"),
            "role": db_user.get("role", "admin")
        }
    )

    return {
        "message": "Login Successful",
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "_id": str(db_user["_id"]),
            "name": db_user["name"],
            "email": db_user["email"],
            "organization": db_user.get("organization"),
            "role": db_user.get("role", "admin")
        }
    }


# -------------------------------
# Protected Profile API
# -------------------------------
@router.get("/profile")
def profile(current_user=Depends(verify_token)):

    return {
        "message": "Welcome to CloudGuardAI",
        "logged_in_user": current_user
    }