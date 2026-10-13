from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.database.connection import db, client

from app.services.quota_service import (
    reserve_quota
)

from app.services.organization_usage_service import (
    release_usage
)


# ============================================================
# COLLECTIONS
# ============================================================

INVITATIONS = db.organization_invitations
MEMBERS = db.organization_members
USERS = db.users


# ============================================================
# CONFIGURATION
# ============================================================

INVITATION_EXPIRY_HOURS = 72

ALLOWED_ROLES = {
    "admin",
    "analyst",
    "viewer"
}


# ============================================================
# INDEXES
# ============================================================

def initialize_invitation_indexes():

    INVITATIONS.create_index(
        "token_hash",
        unique=True,
        name="invitation_token_hash_unique_idx"
    )

    INVITATIONS.create_index(
        [
            ("organization_id", 1),
            ("email", 1),
            ("status", 1)
        ],
        name="organization_invitation_email_status_idx"
    )

    INVITATIONS.create_index(
        [
            ("organization_id", 1),
            ("created_at", -1)
        ],
        name="organization_invitation_created_idx"
    )

    INVITATIONS.create_index(
        [
            ("status", 1),
            ("expires_at", 1)
        ],
        name="invitation_expiration_idx"
    )


# ============================================================
# TOKEN HASH
# ============================================================

def _hash_token(token: str) -> str:

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


# ============================================================
# CREATE INVITATION
# ============================================================

def create_invitation(
    organization_id: str,
    email: str,
    invited_by: str,
    role: str = "viewer"
):

    organization_id = str(
        organization_id
    ).strip()

    email = email.strip().lower()

    invited_by = str(
        invited_by
    ).strip()

    role = role.strip().lower()

    if not organization_id:
        raise ValueError(
            "Organization ID is required"
        )

    if not email:
        raise ValueError(
            "Invitation email is required"
        )

    if not invited_by:
        raise ValueError(
            "Inviting user is required"
        )

    if role not in ALLOWED_ROLES:
        raise ValueError(
            "Invalid invitation role"
        )

    now = datetime.now(timezone.utc)

    existing = INVITATIONS.find_one({
        "organization_id": organization_id,
        "email": email,
        "status": "pending",
        "expires_at": {
            "$gt": now
        }
    })

    if existing:
        raise ValueError(
            "A pending invitation already exists for this email"
        )

    raw_token = secrets.token_urlsafe(32)

    token_hash = _hash_token(
        raw_token
    )

    expires_at = (
        now +
        timedelta(
            hours=INVITATION_EXPIRY_HOURS
        )
    )

    invitation = {
        "organization_id": organization_id,
        "email": email,
        "invited_by": invited_by,
        "role": role,
        "status": "pending",
        "token_hash": token_hash,
        "expires_at": expires_at,
        "accepted_at": None,
        "revoked_at": None,
        "created_at": now,
        "updated_at": now
    }

    try:

        result = INVITATIONS.insert_one(
            invitation
        )

    except DuplicateKeyError:

        raise ValueError(
            "Unable to create invitation"
        )

    return {
        "id": str(
            result.inserted_id
        ),
        "organization_id": organization_id,
        "email": email,
        "role": role,
        "status": "pending",
        "expires_at": expires_at,
        "token": raw_token
    }


# ============================================================
# GET INVITATION BY TOKEN
# ============================================================

def get_invitation_by_token(
    token: str
):

    if not token:
        return None

    token_hash = _hash_token(
        token
    )

    invitation = INVITATIONS.find_one({
        "token_hash": token_hash,
        "status": "pending",
        "expires_at": {
            "$gt": datetime.now(timezone.utc)
        }
    })

    if not invitation:
        return None

    invitation["_id"] = str(
        invitation["_id"]
    )

    return invitation


# ============================================================
# LIST ORGANIZATION INVITATIONS
# ============================================================

def list_invitations(
    organization_id: str,
    status: str | None = None
):

    organization_id = str(
        organization_id
    ).strip()

    query = {
        "organization_id": organization_id
    }

    if status:
        query["status"] = (
            status.strip().lower()
        )

    invitations = list(
        INVITATIONS.find(query)
        .sort(
            "created_at",
            -1
        )
    )

    result = []

    for invitation in invitations:

        result.append({
            "id": str(
                invitation["_id"]
            ),
            "organization_id": str(
                invitation.get(
                    "organization_id",
                    organization_id
                )
            ),
            "email": invitation.get(
                "email"
            ),
            "invited_by": invitation.get(
                "invited_by"
            ),
            "role": invitation.get(
                "role",
                "viewer"
            ),
            "status": invitation.get(
                "status",
                "pending"
            ),
            "expires_at": invitation.get(
                "expires_at"
            ),
            "accepted_at": invitation.get(
                "accepted_at"
            ),
            "revoked_at": invitation.get(
                "revoked_at"
            ),
            "created_at": invitation.get(
                "created_at"
            ),
            "updated_at": invitation.get(
                "updated_at"
            )
        })

    return result


# ============================================================
# REVOKE INVITATION
# ============================================================

def revoke_invitation(
    invitation_id: str,
    organization_id: str
):

    try:

        object_id = ObjectId(
            invitation_id
        )

    except Exception:

        raise ValueError(
            "Invalid invitation ID"
        )

    now = datetime.now(
        timezone.utc
    )

    result = INVITATIONS.update_one(
        {
            "_id": object_id,
            "organization_id": str(
                organization_id
            ),
            "status": "pending"
        },
        {
            "$set": {
                "status": "revoked",
                "revoked_at": now,
                "updated_at": now
            }
        }
    )

    if result.matched_count == 0:

        raise ValueError(
            "Pending invitation not found"
        )

    return True


# ============================================================
# ACCEPT INVITATION
# ============================================================

def accept_invitation(
    token: str,
    user_id: str
):

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not token or not token.strip():

        raise ValueError(
            "Invitation token is required"
        )

    if not user_id or not str(user_id).strip():

        raise ValueError(
            "User ID is required"
        )

    user_id = str(
        user_id
    ).strip()

    # --------------------------------------------------------
    # Validate user ID
    # --------------------------------------------------------

    try:

        user_object_id = ObjectId(
            user_id
        )

    except Exception:

        raise ValueError(
            "Invalid user ID"
        )

    # --------------------------------------------------------
    # Find invitation
    # --------------------------------------------------------

    token_hash = _hash_token(
        token.strip()
    )

    now = datetime.now(
        timezone.utc
    )

    invitation = INVITATIONS.find_one({
        "token_hash": token_hash,
        "status": "pending",
        "expires_at": {
            "$gt": now
        }
    })

    if not invitation:

        raise ValueError(
            "Invitation is invalid or expired"
        )

    # --------------------------------------------------------
    # Organization + email
    # --------------------------------------------------------

    organization_id = str(
        invitation["organization_id"]
    )

    invited_email = (
        invitation
        .get("email", "")
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Find user
    # --------------------------------------------------------

    user = USERS.find_one({
        "_id": user_object_id
    })

    if not user:

        raise ValueError(
            "User account not found"
        )

    user_email = (
        user
        .get("email", "")
        .strip()
        .lower()
    )

    # --------------------------------------------------------
    # Email verification
    # --------------------------------------------------------

    if user_email != invited_email:

        raise ValueError(
            "Invitation email does not match "
            "the authenticated user"
        )

    # --------------------------------------------------------
    # Existing membership
    # --------------------------------------------------------

    existing_member = MEMBERS.find_one({
        "organization_id": organization_id,
        "user_id": user_id
    })

    # --------------------------------------------------------
    # Already active
    # --------------------------------------------------------

    if (
        existing_member
        and existing_member.get("status") == "active"
    ):

        raise ValueError(
            "User is already a member of this organization"
        )

    # ========================================================
    # TEAM MEMBER QUOTA
    # ========================================================
    #
    # Reserve quota only when the invitation is accepted.
    #
    # Pending invitations are NOT counted as team members.
    #
    # This uses the atomic reservation mechanism so concurrent
    # invitation acceptances cannot exceed the plan limit.
    # ========================================================

    quota_reserved = False

    try:

        quota_result = reserve_quota(
            organization_id=organization_id,
            quota_type="team_members",
            amount=1
        )

        quota_reserved = bool(
            quota_result.get(
                "reserved",
                False
            )
        )

        if not quota_reserved:

            raise ValueError(
                "Team member quota could not be reserved"
            )

        # ====================================================
        # TRANSACTION
        # ====================================================

        with client.start_session() as session:

            with session.start_transaction():

                # ============================================
                # Re-check invitation inside transaction
                # ============================================

                current_invitation = (
                    INVITATIONS.find_one(
                        {
                            "_id": invitation["_id"],
                            "status": "pending",
                            "expires_at": {
                                "$gt": now
                            }
                        },
                        session=session
                    )
                )

                if not current_invitation:

                    raise ValueError(
                        "Invitation is no longer available"
                    )

                # ============================================
                # Re-check membership inside transaction
                # ============================================

                current_member = (
                    MEMBERS.find_one(
                        {
                            "organization_id": organization_id,
                            "user_id": user_id
                        },
                        session=session
                    )
                )

                if (
                    current_member
                    and current_member.get(
                        "status"
                    ) == "active"
                ):

                    raise ValueError(
                        "User is already a member of this organization"
                    )

                # ============================================
                # Previously removed member
                # Reactivate membership
                # ============================================

                if (
                    current_member
                    and current_member.get(
                        "status"
                    ) == "removed"
                ):

                    MEMBERS.update_one(
                        {
                            "_id": current_member["_id"],
                            "organization_id": organization_id,
                            "user_id": user_id
                        },
                        {
                            "$set": {
                                "role": current_invitation[
                                    "role"
                                ],
                                "status": "active",
                                "invited_by": current_invitation[
                                    "invited_by"
                                ],
                                "invited_at": current_invitation[
                                    "created_at"
                                ],
                                "joined_at": now,
                                "updated_at": now
                            }
                        },
                        session=session
                    )

                # ============================================
                # No previous membership
                # Create membership
                # ============================================

                else:

                    membership = {
                        "organization_id": organization_id,
                        "user_id": user_id,
                        "role": current_invitation[
                            "role"
                        ],
                        "status": "active",
                        "invited_by": current_invitation[
                            "invited_by"
                        ],
                        "invited_at": current_invitation[
                            "created_at"
                        ],
                        "joined_at": now,
                        "created_at": now,
                        "updated_at": now
                    }

                    MEMBERS.insert_one(
                        membership,
                        session=session
                    )

                # ============================================
                # Update user organization/role
                # ============================================

                USERS.update_one(
                    {
                        "_id": user_object_id
                    },
                    {
                        "$set": {
                            "organization": organization_id,
                            "role": current_invitation[
                                "role"
                            ]
                        }
                    },
                    session=session
                )

                # ============================================
                # Mark invitation accepted
                # ============================================

                result = INVITATIONS.update_one(
                    {
                        "_id": invitation["_id"],
                        "status": "pending",
                        "expires_at": {
                            "$gt": now
                        }
                    },
                    {
                        "$set": {
                            "status": "accepted",
                            "accepted_at": now,
                            "updated_at": now
                        }
                    },
                    session=session
                )

                if result.modified_count != 1:

                    raise ValueError(
                        "Invitation is no longer available"
                    )

        # ====================================================
        # SUCCESS
        #
        # The reserved quota is now consumed because the
        # member was successfully activated.
        # ====================================================

        quota_reserved = False

    except DuplicateKeyError:

        # ----------------------------------------------------
        # Release reservation if membership creation failed
        # ----------------------------------------------------

        if quota_reserved:

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="team_members_used",
                    amount=1
                )

            except Exception as release_error:

                print(
                    "[ERROR] Failed to release "
                    f"team-member quota: {release_error}"
                )

        raise ValueError(
            "User is already a member of this organization"
        )

    except ValueError:

        # ----------------------------------------------------
        # Release quota for failed acceptance
        # ----------------------------------------------------

        if quota_reserved:

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="team_members_used",
                    amount=1
                )

            except Exception as release_error:

                print(
                    "[ERROR] Failed to release "
                    f"team-member quota: {release_error}"
                )

        raise

    except Exception as error:

        # ----------------------------------------------------
        # Release quota for unexpected failure
        # ----------------------------------------------------

        if quota_reserved:

            try:

                release_usage(
                    organization_id=organization_id,
                    usage_field="team_members_used",
                    amount=1
                )

            except Exception as release_error:

                print(
                    "[ERROR] Failed to release "
                    f"team-member quota: {release_error}"
                )

        print(
            "[ERROR] Invitation acceptance failed: "
            f"{error}"
        )

        raise ValueError(
            "Unable to accept invitation"
        )

    # --------------------------------------------------------
    # Success
    # --------------------------------------------------------

    return {
        "organization_id": organization_id,
        "user_id": user_id,
        "role": invitation["role"],
        "status": "active",
        "accepted_at": now
    }