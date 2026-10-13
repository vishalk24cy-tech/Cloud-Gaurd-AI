from datetime import datetime, timedelta, timezone
import hashlib
import secrets

from bson import ObjectId
from pymongo.errors import DuplicateKeyError

from app.database.connection import db


INVITATIONS = db.organization_invitations

INVITATION_EXPIRY_HOURS = 72

ALLOWED_ROLES = {
    "admin",
    "analyst",
    "viewer",
}


def initialize_invitation_indexes():
    """
    Initialize indexes required for secure SaaS invitation management.
    """

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


def _hash_token(token: str) -> str:
    """
    Hash an invitation token before storing it.
    """

    return hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()


def create_invitation(
    organization_id: str,
    email: str,
    invited_by: str,
    role: str = "viewer",
):
    """
    Create a secure organization invitation.

    Only the token hash is stored in MongoDB.
    The raw token is returned to the caller once.
    """

    organization_id = str(organization_id).strip()
    email = email.strip().lower()
    invited_by = str(invited_by).strip()
    role = role.strip().lower()

    if not organization_id:
        raise ValueError("Organization ID is required")

    if not email:
        raise ValueError("Invitation email is required")

    if not invited_by:
        raise ValueError("Inviting user is required")

    if role not in ALLOWED_ROLES:
        raise ValueError("Invalid invitation role")

    now = datetime.now(timezone.utc)

    # Check for an existing active invitation
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

    # Generate cryptographically secure token
    raw_token = secrets.token_urlsafe(32)

    token_hash = _hash_token(raw_token)

    expires_at = now + timedelta(
        hours=INVITATION_EXPIRY_HOURS
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
        "updated_at": now,
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
        "id": str(result.inserted_id),
        "organization_id": organization_id,
        "email": email,
        "role": role,
        "status": "pending",
        "expires_at": expires_at,
        "token": raw_token,
    }


def get_invitation_by_token(token: str):
    """
    Find a valid pending invitation using its raw token.
    """

    if not token:
        return None

    token_hash = _hash_token(token)

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


def revoke_invitation(
    invitation_id: str,
    organization_id: str,
):
    """
    Revoke a pending invitation belonging
    to the specified organization.
    """

    try:
        object_id = ObjectId(invitation_id)

    except Exception:
        raise ValueError(
            "Invalid invitation ID"
        )

    now = datetime.now(timezone.utc)

    result = INVITATIONS.update_one(
        {
            "_id": object_id,
            "organization_id": str(organization_id),
            "status": "pending",
        },
        {
            "$set": {
                "status": "revoked",
                "revoked_at": now,
                "updated_at": now,
            }
        }
    )

    if result.matched_count == 0:
        raise ValueError(
            "Pending invitation not found"
        )

    return True