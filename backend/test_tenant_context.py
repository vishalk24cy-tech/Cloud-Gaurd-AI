# ============================================================
# CloudGuardAI - Unit Tests for Shared Tenant Context & RBAC Helper
# Phase 3A: Tenant Isolation & RBAC Architecture
# ============================================================

import os
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from bson import ObjectId
from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient

# ------------------------------------------------------------
# Test mode & Offline database guard
# ------------------------------------------------------------
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("DATABASE_NAME", "cloudguardai_test")

# Prevent live MongoDB Atlas network connection on initial import
if "app.database.connection" not in sys.modules:
    mock_pymongo = MagicMock()
    mock_db_instance = MagicMock()
    mock_pymongo.MongoClient.return_value.__getitem__.return_value = mock_db_instance
    mock_pymongo.MongoClient.return_value.admin.command.return_value = {"ok": 1}
    _real_pymongo = sys.modules.get("pymongo")
    sys.modules["pymongo"] = mock_pymongo
    import contextlib
    import io
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            import app.database.connection
    finally:
        if _real_pymongo is not None:
            sys.modules["pymongo"] = _real_pymongo
        elif "pymongo" in sys.modules:
            del sys.modules["pymongo"]

from app.services.tenant_context import (
    ALLOWED_MEMBER_ROLES,
    RESTRICTED_MEMBERSHIP_STATUSES,
    VALID_MEMBERSHIP_STATUS,
    TenantContext,
    get_tenant_context,
    require_analyst_or_above,
    require_owner_or_admin,
    require_roles,
    resolve_tenant_context,
    tenant_context_dependency,
)


class TestTenantContext(unittest.TestCase):
    """Unit tests for TenantContext model, resolver, and RBAC dependencies."""

    def setUp(self):
        self.user_id = str(ObjectId())
        self.org_a_id = "org-cloudguard-alpha"
        self.org_b_id = "org-cloudguard-beta"
        self.email = "analyst@cloudguard.ai"

        self.valid_jwt_user = {
            "_id": self.user_id,
            "email": self.email,
            "organization": self.org_a_id,
            "role": "admin",  # JWT claims admin, but DB must be authoritative
        }

        self.mock_member_record = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "analyst",
            "status": "active",
            "email": self.email,
        }

    # ============================================================
    # 1. Model Properties and Methods
    # ============================================================

    def test_tenant_context_role_properties(self):
        roles_and_props = [
            ("owner", "is_owner"),
            ("admin", "is_admin"),
            ("analyst", "is_analyst"),
            ("viewer", "is_viewer"),
        ]
        for role, prop in roles_and_props:
            ctx = TenantContext(
                user_id=self.user_id,
                organization_id=self.org_a_id,
                role=role,
                status="active",
                email=self.email,
                membership={},
            )
            for _, other_prop in roles_and_props:
                self.assertEqual(
                    getattr(ctx, other_prop),
                    other_prop == prop,
                    f"Property {other_prop} mismatch for role {role}",
                )

    def test_has_role_matching(self):
        ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="analyst",
            status="active",
            email=self.email,
            membership={},
        )
        self.assertTrue(ctx.has_role(["ANALYST", "admin"]))
        self.assertTrue(ctx.has_role(("owner", " analyst ")))
        self.assertFalse(ctx.has_role(["owner", "admin"]))
        self.assertFalse(ctx.has_role([]))
        self.assertFalse(ctx.has_role([None]))

    def test_to_dict_projection(self):
        ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="analyst",
            status="active",
            email=self.email,
            membership={"internal_secret": "do_not_leak", "raw_token": "secret"},
        )
        data = ctx.to_dict()

        self.assertEqual(data["_id"], self.user_id)
        self.assertEqual(data["user_id"], self.user_id)
        self.assertEqual(data["organization"], self.org_a_id)
        self.assertEqual(data["organization_id"], self.org_a_id)
        self.assertEqual(data["role"], "analyst")
        self.assertEqual(data["status"], "active")
        self.assertEqual(data["email"], self.email)
        self.assertNotIn("internal_secret", data)
        self.assertNotIn("raw_token", data)

    # ============================================================
    # 2. Active Role Resolution Tests
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_resolve_active_owner_succeeds(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "owner",
            "status": "active",
        }

        context = resolve_tenant_context(
            current_user=self.valid_jwt_user,
        )

        self.assertIsInstance(context, TenantContext)
        self.assertEqual(context.user_id, self.user_id)
        self.assertEqual(context.organization_id, self.org_a_id)
        self.assertEqual(context.role, "owner")
        self.assertEqual(context.status, "active")
        self.assertTrue(context.is_owner)
        self.assertFalse(context.is_admin)

    @patch("app.services.tenant_context.db")
    def test_resolve_active_admin_succeeds(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "admin",
            "status": "active",
        }

        context = resolve_tenant_context(
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.role, "admin")
        self.assertTrue(context.is_admin)
        self.assertFalse(context.is_owner)

    @patch("app.services.tenant_context.db")
    def test_resolve_active_analyst_succeeds(self, mock_db):
        mock_db.organization_members.find_one.return_value = self.mock_member_record

        context = resolve_tenant_context(
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.role, "analyst")
        self.assertTrue(context.is_analyst)
        self.assertFalse(context.is_viewer)

    @patch("app.services.tenant_context.db")
    def test_resolve_active_viewer_succeeds(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "viewer",
            "status": "active",
        }

        context = resolve_tenant_context(
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.role, "viewer")
        self.assertTrue(context.is_viewer)
        self.assertFalse(context.is_analyst)

    # ============================================================
    # 3. Database Authority & Spoofing Defense
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_jwt_role_spoofing_prevented(self, mock_db):
        """Token claims 'owner', but DB record is 'viewer'. Must resolve as viewer."""
        spoofed_jwt = {
            "_id": self.user_id,
            "organization": self.org_a_id,
            "role": "owner",
        }
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "viewer",
            "status": "active",
        }

        context = resolve_tenant_context(current_user=spoofed_jwt)

        self.assertEqual(context.role, "viewer")
        self.assertFalse(context.is_owner)
        self.assertTrue(context.is_viewer)

    # ============================================================
    # 4. Fail-Closed Role Enforcement
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_missing_role_fails_closed(self, mock_db):
        """DB record without a role must fail closed (403), never default to viewer."""
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": None,
            "status": "active",
        }

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=self.valid_jwt_user)

        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Invalid or unsupported organization role", exc.exception.detail)

    @patch("app.services.tenant_context.db")
    def test_empty_string_role_fails_closed(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "   ",
            "status": "active",
        }

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=self.valid_jwt_user)

        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Invalid or unsupported organization role", exc.exception.detail)

    @patch("app.services.tenant_context.db")
    def test_unsupported_role_fails_closed(self, mock_db):
        """DB record with unrecognized role (e.g. 'superadmin', 'guest') must fail closed."""
        for bad_role in ["superadmin", "guest", "billing_admin", "root"]:
            mock_db.organization_members.find_one.return_value = {
                "organization_id": self.org_a_id,
                "user_id": self.user_id,
                "role": bad_role,
                "status": "active",
            }

            with self.assertRaises(HTTPException) as exc:
                resolve_tenant_context(current_user=self.valid_jwt_user)

            self.assertEqual(exc.exception.status_code, 403)
            self.assertIn("Invalid or unsupported organization role", exc.exception.detail)

    # ============================================================
    # 5. Fail-Closed Membership Status Enforcement
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_missing_membership_rejected_403(self, mock_db):
        mock_db.organization_members.find_one.return_value = None

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=self.valid_jwt_user)

        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Organization membership not found", exc.exception.detail)

    @patch("app.services.tenant_context.db")
    def test_restricted_membership_statuses_rejected_403(self, mock_db):
        for restricted_status in RESTRICTED_MEMBERSHIP_STATUSES:
            mock_db.organization_members.find_one.return_value = {
                "organization_id": self.org_a_id,
                "user_id": self.user_id,
                "role": "owner",
                "status": restricted_status,
            }

            with self.assertRaises(HTTPException) as exc:
                resolve_tenant_context(current_user=self.valid_jwt_user)

            self.assertEqual(exc.exception.status_code, 403)
            self.assertIn(f"membership is {restricted_status}", exc.exception.detail)

    @patch("app.services.tenant_context.db")
    def test_unrecognized_membership_status_rejected_403(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "owner",
            "status": "pending_approval",
        }

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=self.valid_jwt_user)

        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("membership is not active", exc.exception.detail)

    # ============================================================
    # 6. Organization Resolution & Target Validation
    # ============================================================

    def test_missing_current_user_rejected_401(self):
        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=None)
        self.assertEqual(exc.exception.status_code, 401)
        self.assertIn("Authentication required", exc.exception.detail)

    def test_missing_user_id_rejected_401(self):
        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user={"email": "no_id@cloudguard.ai"})
        self.assertEqual(exc.exception.status_code, 401)
        self.assertIn("Authenticated user identity is unavailable", exc.exception.detail)

    def test_missing_organization_context_rejected_403(self):
        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(
                current_user={"_id": self.user_id, "organization": None}
            )
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Organization context is required", exc.exception.detail)

    @patch("app.services.tenant_context.db")
    def test_cross_organization_mismatch_rejected_403(self, mock_db):
        """User is member of Org A, but requests Org B via path parameter. Must be rejected."""
        mock_db.organization_members.find_one.return_value = None  # No membership in Org B

        mock_request = SimpleNamespace(
            path_params={"organization_id": self.org_b_id},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(
                current_user=self.valid_jwt_user,
                request=mock_request,
            )

        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Organization membership not found", exc.exception.detail)
        mock_db.organization_members.find_one.assert_called_once_with({
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
        })

    @patch("app.services.tenant_context.db")
    def test_database_exception_fails_closed_500(self, mock_db):
        mock_db.organization_members.find_one.side_effect = RuntimeError("DB connection timeout")

        with self.assertRaises(HTTPException) as exc:
            resolve_tenant_context(current_user=self.valid_jwt_user)

        self.assertEqual(exc.exception.status_code, 500)
        self.assertIn("Internal error validating organization membership", exc.exception.detail)

    # ============================================================
    # 7. Dependency Signature & Path Parameter Extraction
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_get_tenant_context_extracts_path_params(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
            "role": "owner",
            "status": "active",
        }

        mock_request = SimpleNamespace(
            path_params={"organization_id": self.org_b_id},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        context = get_tenant_context(
            request=mock_request,
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.organization_id, self.org_b_id)
        mock_db.organization_members.find_one.assert_called_once_with({
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
        })

    @patch("app.services.tenant_context.db")
    def test_get_tenant_context_extracts_org_id_alias(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
            "role": "admin",
            "status": "active",
        }

        mock_request = SimpleNamespace(
            path_params={"org_id": self.org_b_id},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        context = get_tenant_context(
            request=mock_request,
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.organization_id, self.org_b_id)

    @patch("app.services.tenant_context.db")
    def test_get_tenant_context_extracts_headers(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
            "role": "analyst",
            "status": "active",
        }

        mock_request = SimpleNamespace(
            path_params={},
            query_params={},
            headers={"x-organization-id": self.org_b_id},
            state=SimpleNamespace(),
        )

        context = get_tenant_context(
            request=mock_request,
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.organization_id, self.org_b_id)

    @patch("app.services.tenant_context.db")
    def test_get_tenant_context_without_request_uses_jwt_org(self, mock_db):
        mock_db.organization_members.find_one.return_value = self.mock_member_record

        context = get_tenant_context(
            request=None,
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.organization_id, self.org_a_id)

    @patch("app.services.tenant_context.db")
    def test_tenant_context_dependency_custom_param(self, mock_db):
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
            "role": "owner",
            "status": "active",
        }

        custom_dep = tenant_context_dependency("tenant_id")
        mock_request = SimpleNamespace(
            path_params={"tenant_id": self.org_b_id},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        context = custom_dep(
            request=mock_request,
            current_user=self.valid_jwt_user,
        )

        self.assertEqual(context.organization_id, self.org_b_id)

    # ============================================================
    # 8. Role Dependency Enforcement Tests
    # ============================================================

    def test_require_owner_or_admin_permits_owner(self):
        owner_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="owner",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_owner_or_admin
        result = dep(context=owner_ctx)
        self.assertEqual(result, owner_ctx)

    def test_require_owner_or_admin_permits_admin(self):
        admin_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="admin",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_owner_or_admin
        result = dep(context=admin_ctx)
        self.assertEqual(result, admin_ctx)

    def test_require_owner_or_admin_rejects_analyst(self):
        analyst_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="analyst",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_owner_or_admin
        with self.assertRaises(HTTPException) as exc:
            dep(context=analyst_ctx)
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Requires one of roles: admin, owner", exc.exception.detail)

    def test_require_owner_or_admin_rejects_viewer(self):
        viewer_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="viewer",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_owner_or_admin
        with self.assertRaises(HTTPException) as exc:
            dep(context=viewer_ctx)
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Requires one of roles: admin, owner", exc.exception.detail)

    def test_require_analyst_or_above_permits_analyst(self):
        analyst_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="analyst",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_analyst_or_above
        result = dep(context=analyst_ctx)
        self.assertEqual(result, analyst_ctx)

    def test_require_analyst_or_above_rejects_viewer(self):
        viewer_ctx = TenantContext(
            user_id=self.user_id,
            organization_id=self.org_a_id,
            role="viewer",
            status="active",
            email=self.email,
            membership={},
        )
        dep = require_analyst_or_above
        with self.assertRaises(HTTPException) as exc:
            dep(context=viewer_ctx)
        self.assertEqual(exc.exception.status_code, 403)
        self.assertIn("Requires one of roles: admin, analyst, owner", exc.exception.detail)

    def test_require_roles_rejects_empty_or_invalid_specification(self):
        with self.assertRaises(ValueError):
            require_roles()

        with self.assertRaises(ValueError):
            require_roles("invalid_role")

    # ============================================================
    # 9. Request-State Caching Tests
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_cache_reuses_context_for_same_user_and_org(self, mock_db):
        mock_db.organization_members.find_one.return_value = self.mock_member_record
        mock_request = SimpleNamespace(
            path_params={},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        ctx1 = resolve_tenant_context(
            current_user=self.valid_jwt_user,
            request=mock_request,
        )
        ctx2 = resolve_tenant_context(
            current_user=self.valid_jwt_user,
            request=mock_request,
        )

        self.assertIs(ctx1, ctx2)
        # Database queried exactly ONCE despite two resolution calls
        mock_db.organization_members.find_one.assert_called_once()

    @patch("app.services.tenant_context.db")
    def test_cache_does_not_cross_pollinate_different_orgs(self, mock_db):
        """Querying Org B on the same request must trigger separate DB validation."""
        mock_db.organization_members.find_one.side_effect = [
            self.mock_member_record,  # Org A record
            {**self.mock_member_record, "organization_id": self.org_b_id, "role": "owner"},  # Org B record
        ]
        mock_request = SimpleNamespace(
            path_params={},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        ctx_a = resolve_tenant_context(
            target_organization_id=self.org_a_id,
            current_user=self.valid_jwt_user,
            request=mock_request,
        )
        ctx_b = resolve_tenant_context(
            target_organization_id=self.org_b_id,
            current_user=self.valid_jwt_user,
            request=mock_request,
        )

        self.assertIsNot(ctx_a, ctx_b)
        self.assertEqual(ctx_a.organization_id, self.org_a_id)
        self.assertEqual(ctx_a.role, "analyst")
        self.assertEqual(ctx_b.organization_id, self.org_b_id)
        self.assertEqual(ctx_b.role, "owner")
        self.assertEqual(mock_db.organization_members.find_one.call_count, 2)

    @patch("app.services.tenant_context.db")
    def test_failed_validation_does_not_pollute_cache(self, mock_db):
        mock_db.organization_members.find_one.return_value = None  # Missing membership
        mock_request = SimpleNamespace(
            path_params={},
            query_params={},
            headers={},
            state=SimpleNamespace(),
        )

        with self.assertRaises(HTTPException):
            resolve_tenant_context(
                current_user=self.valid_jwt_user,
                request=mock_request,
            )

        # Ensure cache dict is either uninitialized or does not contain failed key
        tenant_cache = getattr(mock_request.state, "_tenant_context_cache", {})
        self.assertNotIn((self.user_id, self.org_a_id), tenant_cache)

    # ============================================================
    # 10. Live FastAPI TestClient Route Integration Tests
    # ============================================================

    @patch("app.services.tenant_context.db")
    def test_fastapi_route_with_path_param_binds_and_validates(self, mock_db):
        """
        Verify that a real FastAPI app route with /{organization_id}/settings
        binds the path parameter into request.path_params, executes get_tenant_context,
        and returns the validated context.
        """
        test_app = FastAPI()
        test_router = APIRouter()

        @test_router.get("/{organization_id}/settings")
        def get_settings(
            organization_id: str,
            context: TenantContext = Depends(get_tenant_context),
        ):
            return {
                "organization_id": context.organization_id,
                "role": context.role,
                "user_id": context.user_id,
            }

        test_app.include_router(test_router, prefix="/api/v1/organizations")

        # Mock database membership for Org B
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
            "role": "admin",
            "status": "active",
        }

        # Override verify_token dependency on the test app
        from app.middleware.auth_middleware import verify_token
        test_app.dependency_overrides[verify_token] = lambda: self.valid_jwt_user

        client = TestClient(test_app)
        response = client.get(f"/api/v1/organizations/{self.org_b_id}/settings")

        self.assertEqual(response.status_code, 200)
        json_resp = response.json()
        self.assertEqual(json_resp["organization_id"], self.org_b_id)
        self.assertEqual(json_resp["role"], "admin")
        self.assertEqual(json_resp["user_id"], self.user_id)

        mock_db.organization_members.find_one.assert_called_once_with({
            "organization_id": self.org_b_id,
            "user_id": self.user_id,
        })

    @patch("app.services.tenant_context.db")
    def test_fastapi_route_cross_tenant_rejected_by_path_param(self, mock_db):
        """
        User belonging to Org A attempts to call /{organization_id}/settings for Org B.
        Database returns None for Org B membership. Must receive 403 Forbidden.
        """
        test_app = FastAPI()
        test_router = APIRouter()

        @test_router.get("/{organization_id}/settings")
        def get_settings(
            organization_id: str,
            context: TenantContext = Depends(get_tenant_context),
        ):
            return {"status": "ok"}

        test_app.include_router(test_router, prefix="/api/v1/organizations")

        # No membership in Org B
        mock_db.organization_members.find_one.return_value = None

        from app.middleware.auth_middleware import verify_token
        test_app.dependency_overrides[verify_token] = lambda: self.valid_jwt_user

        client = TestClient(test_app)
        response = client.get(f"/api/v1/organizations/{self.org_b_id}/settings")

        self.assertEqual(response.status_code, 403)
        self.assertIn("Organization membership not found", response.json()["detail"])

    @patch("app.services.tenant_context.db")
    def test_fastapi_route_with_role_enforcement(self, mock_db):
        """
        Route requiring require_owner_or_admin rejects analyst member with 403.
        """
        test_app = FastAPI()
        test_router = APIRouter()

        @test_router.post("/{organization_id}/billing")
        def manage_billing(
            organization_id: str,
            context: TenantContext = Depends(require_owner_or_admin),
        ):
            return {"status": "billing_managed"}

        test_app.include_router(test_router, prefix="/api/v1/organizations")

        # User is only an analyst
        mock_db.organization_members.find_one.return_value = {
            "organization_id": self.org_a_id,
            "user_id": self.user_id,
            "role": "analyst",
            "status": "active",
        }

        from app.middleware.auth_middleware import verify_token
        test_app.dependency_overrides[verify_token] = lambda: self.valid_jwt_user

        client = TestClient(test_app)
        response = client.post(f"/api/v1/organizations/{self.org_a_id}/billing")

        self.assertEqual(response.status_code, 403)
        self.assertIn("Requires one of roles: admin, owner", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
