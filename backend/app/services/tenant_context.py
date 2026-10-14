# ============================================================
# CloudGuardAI - Shared Tenant Context & RBAC Authorization Helper
# Production / Commercial SaaS
# ============================================================

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Set

from fastapi import Depends, HTTPException, Request, status

from app.database.connection import db
from app.middleware.auth_middleware import verify_token

logger = logging.getLogger("cloudguardai.tenant_context")

# Canonical member roles permitted in the multi-tenant system
ALLOWED_MEMBER_ROLES: Set[str] = {
    "owner",
    "admin",
    "analyst",
    "viewer",
}

VALID_MEMBERSHIP_STATUS: str = "active"

RESTRICTED_MEMBERSHIP_STATUSES: Set[str] = {
    "inactive",
    "revoked",
    "suspended",
    "removed",
}


@dataclass(frozen=True)
class TenantContext:
    """
    Authoritative, immutable tenant context resolved from trusted server-side identity
    and validated organization membership in MongoDB.

    Does not trust unverified JWT role or organization claims.
    """
    user_id: str
    organization_id: str
    role: str
    status: str
    email: str
    membership: Dict[str, Any]

    @property
    def is_owner(self) -> bool:
        return self.role == "owner"

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_analyst(self) -> bool:
        return self.role == "analyst"

    @property
    def is_viewer(self) -> bool:
        return self.role == "viewer"

    def has_role(self, allowed_roles: Iterable[str]) -> bool:
        """Return True if the context role matches any of the specified roles."""
        return self.role in {
            str(r).strip().lower()
            for r in allowed_roles
            if r is not None
        }

    def to_dict(self) -> Dict[str, Any]:
        """
        Safe, explicit dictionary projection for logging and downstream helpers.
        Never exposes arbitrary or internal database fields.
        """
        return {
            "_id": self.user_id,
            "user_id": self.user_id,
            "organization": self.organization_id,
            "organization_id": self.organization_id,
            "role": self.role,
            "status": self.status,
            "email": self.email,
        }


def _safe_string(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


def resolve_tenant_context(
    target_organization_id: Optional[str] = None,
    current_user: Optional[Dict[str, Any]] = None,
    request: Optional[Request] = None,
    database: Optional[Any] = None,
    user: Optional[Dict[str, Any]] = None,
) -> TenantContext:
    """
    Core resolver that validates user identity and current database membership.

    Security guarantees:
    1. Derives user identity from trusted server-side decode (verify_token payload).
    2. Treats any path or query organization ID only as an intended target resource.
    3. Requires active membership in that exact organization from db.organization_members.
    4. Overrides any client-provided or JWT role claim with current database membership role.
    5. Fails closed (403 Forbidden) on missing, inactive, revoked, suspended, removed,
       missing role, or unsupported role. Never converts invalid roles to viewer.
    6. Caches only successfully validated contexts on request.state strictly keyed
       by (user_id, organization_id).
    """
    if current_user is None and user is not None:
        current_user = user

    if not current_user or not isinstance(current_user, dict):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required.",
        )

    user_id = _safe_string(
        current_user.get("_id")
        or current_user.get("user_id")
        or current_user.get("id")
    )
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user identity is unavailable.",
        )

    # --------------------------------------------------------
    # 1. Resolve intended target organization
    # --------------------------------------------------------
    org_id = _safe_string(target_organization_id)

    if not org_id and request is not None:
        # Check path parameters first (e.g. /{organization_id}/..., /{org_id}/...)
        if hasattr(request, "path_params") and isinstance(request.path_params, dict):
            org_id = _safe_string(
                request.path_params.get("organization_id")
                or request.path_params.get("org_id")
                or request.path_params.get("target_organization_id")
            )

        # Check query parameters as fallback
        if not org_id and hasattr(request, "query_params") and isinstance(request.query_params, dict):
            org_id = _safe_string(
                request.query_params.get("organization_id")
                or request.query_params.get("org_id")
                or request.query_params.get("target_organization_id")
            )

        # Check request headers
        if not org_id and hasattr(request, "headers") and hasattr(request.headers, "get"):
            org_id = _safe_string(request.headers.get("x-organization-id"))

    # Fallback to organization claim in JWT token
    if not org_id:
        org_id = _safe_string(
            current_user.get("organization")
            or current_user.get("organization_id")
        )

    if not org_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization context is required.",
        )

    # --------------------------------------------------------
    # 2. Check request-state cache strictly by (user_id, org_id)
    # --------------------------------------------------------
    cache_key = (user_id, org_id)
    if request is not None and hasattr(request, "state"):
        tenant_cache = getattr(request.state, "_tenant_context_cache", None)
        if isinstance(tenant_cache, dict) and cache_key in tenant_cache:
            return tenant_cache[cache_key]

    # --------------------------------------------------------
    # 3. Query authoritative membership in MongoDB
    # --------------------------------------------------------
    db_conn = database if database is not None else db
    try:
        member = db_conn.organization_members.find_one({
            "organization_id": org_id,
            "user_id": user_id,
        })
    except Exception as exc:
        logger.error(
            "Database error validating organization membership for user=%s org=%s: %s",
            user_id,
            org_id,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error validating organization membership.",
        ) from exc

    if not member:
        logger.warning(
            "Access denied: No membership document for user=%s in org=%s",
            user_id,
            org_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership not found. Access denied.",
        )

    # --------------------------------------------------------
    # 4. Enforce membership status (fail closed)
    # --------------------------------------------------------
    raw_status = _safe_string(member.get("status")).lower()
    if raw_status in RESTRICTED_MEMBERSHIP_STATUSES:
        logger.warning(
            "Access denied: User=%s membership in org=%s is restricted (%s)",
            user_id,
            org_id,
            raw_status,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Organization membership is {raw_status}. Access denied.",
        )

    if raw_status != VALID_MEMBERSHIP_STATUS:
        logger.warning(
            "Access denied: User=%s membership in org=%s is not active (%s)",
            user_id,
            org_id,
            raw_status,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Organization membership is not active. Access denied.",
        )

    # --------------------------------------------------------
    # 5. Enforce canonical role from database (fail closed)
    # --------------------------------------------------------
    raw_role = _safe_string(member.get("role")).lower()
    if not raw_role or raw_role not in ALLOWED_MEMBER_ROLES:
        logger.warning(
            "Access denied: User=%s in org=%s has invalid/unsupported role '%s'",
            user_id,
            org_id,
            raw_role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or unsupported organization role. Access denied.",
        )

    email = _safe_string(
        current_user.get("email")
        or member.get("email")
    ).lower()

    context = TenantContext(
        user_id=user_id,
        organization_id=org_id,
        role=raw_role,
        status=VALID_MEMBERSHIP_STATUS,
        email=email,
        membership=dict(member),
    )

    # --------------------------------------------------------
    # 6. Store in request-scoped cache (only validated contexts)
    # --------------------------------------------------------
    if request is not None and hasattr(request, "state"):
        tenant_cache = getattr(request.state, "_tenant_context_cache", None)
        if not isinstance(tenant_cache, dict):
            request.state._tenant_context_cache = {}
            tenant_cache = request.state._tenant_context_cache
        tenant_cache[cache_key] = context

    return context


def get_tenant_context(
    request: Request = None,
    current_user: Dict[str, Any] = Depends(verify_token),
) -> TenantContext:
    """
    FastAPI dependency that returns the validated TenantContext for the active request.

    Extracts the target organization from route path parameters (e.g. /{organization_id}),
    query parameters, headers (x-organization-id), or JWT token claims, and verifies
    active membership in MongoDB.

    Safely inspects request.path_params using the native Request parameter without
    declaring an unbindable parameter name like target_organization_id in the dependency
    signature.
    """
    target_org_id = None
    if request is not None:
        if hasattr(request, "path_params") and isinstance(request.path_params, dict):
            target_org_id = (
                request.path_params.get("organization_id")
                or request.path_params.get("org_id")
                or request.path_params.get("target_organization_id")
            )
        if not target_org_id and hasattr(request, "query_params") and isinstance(request.query_params, dict):
            target_org_id = (
                request.query_params.get("organization_id")
                or request.query_params.get("org_id")
                or request.query_params.get("target_organization_id")
            )
        if not target_org_id and hasattr(request, "headers") and hasattr(request.headers, "get"):
            target_org_id = request.headers.get("x-organization-id")

    return resolve_tenant_context(
        target_organization_id=target_org_id,
        current_user=current_user,
        request=request,
    )


def tenant_context_dependency(param_name: str = "organization_id") -> Callable[..., TenantContext]:
    """
    FastAPI dependency factory to extract and validate TenantContext from an explicit
    route path or query parameter name.
    """
    def _dependency(
        request: Request = None,
        current_user: Dict[str, Any] = Depends(verify_token),
    ) -> TenantContext:
        target_org = None
        if request is not None:
            if hasattr(request, "path_params") and isinstance(request.path_params, dict):
                target_org = request.path_params.get(param_name)
            if not target_org and hasattr(request, "query_params") and isinstance(request.query_params, dict):
                target_org = request.query_params.get(param_name)

        return resolve_tenant_context(
            target_organization_id=target_org,
            current_user=current_user,
            request=request,
        )

    return _dependency


def require_roles(*allowed_roles: str, context_dep: Any = get_tenant_context):
    """
    FastAPI dependency factory enforcing that the authenticated tenant context
    has one of the specified canonical roles. Fails closed with 403 Forbidden.
    """
    normalized_allowed = {
        str(r).strip().lower()
        for r in allowed_roles
        if r is not None and str(r).strip()
    }

    if not normalized_allowed:
        raise ValueError("At least one allowed role must be specified.")

    invalid_roles = normalized_allowed - ALLOWED_MEMBER_ROLES
    if invalid_roles:
        raise ValueError(
            f"Unrecognized roles specified in require_roles: {invalid_roles}. "
            f"Allowed roles are: {ALLOWED_MEMBER_ROLES}"
        )

    def role_dependency(
        context: TenantContext = Depends(context_dep),
    ) -> TenantContext:
        if not context.has_role(normalized_allowed):
            formatted_roles = ", ".join(sorted(normalized_allowed))
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {formatted_roles}.",
            )
        return context

    return role_dependency


# Pre-configured role dependencies for common access control tiers
require_owner_or_admin = require_roles("owner", "admin")
require_analyst_or_above = require_roles("owner", "admin", "analyst")

__all__ = [
    "ALLOWED_MEMBER_ROLES",
    "VALID_MEMBERSHIP_STATUS",
    "RESTRICTED_MEMBERSHIP_STATUSES",
    "TenantContext",
    "resolve_tenant_context",
    "get_tenant_context",
    "tenant_context_dependency",
    "require_roles",
    "require_owner_or_admin",
    "require_analyst_or_above",
]
