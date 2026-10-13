# ============================================================
# CloudGuardAI - Remediation Settings Data Model
# Phase 10: Persistent Per-Organization & Per-Account Remediation Governance
# ============================================================

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, Optional

from app.database.connection import db
from app.models.aws_account import get_account

logger = logging.getLogger("cloudguardai.remediation_settings")

remediation_settings_collection = db["remediation_settings"]

ALLOWED_SERVICE_KEYS = {"ec2", "s3", "vpc", "rds", "iam", "cloudtrail"}

DEFAULT_SERVICES: Dict[str, bool] = {
    "ec2": False,
    "s3": False,
    "vpc": False,
    "rds": False,
    "iam": False,
    "cloudtrail": False,
}


def _safe_string(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


def _normalize_services(raw_services: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    """
    Ensures every allowed service key exists and defaults to False if missing or invalid.
    """
    normalized = DEFAULT_SERVICES.copy()
    if not isinstance(raw_services, dict):
        return normalized

    for key in ALLOWED_SERVICE_KEYS:
        if key in raw_services:
            val = raw_services[key]
            if isinstance(val, bool):
                normalized[key] = val
            elif isinstance(val, (int, str)):
                str_val = str(val).strip().lower()
                normalized[key] = str_val in ("true", "1", "yes")
            else:
                normalized[key] = False
    return normalized


def get_remediation_settings(
    organization_id: Any,
    account_id: Any,
) -> Dict[str, Any]:
    """
    Retrieves the remediation settings for a connected AWS account under an organization.
    
    Fails closed: if organization/account association is invalid or missing,
    returns a default settings structure where all service remediations are False.
    """
    clean_org_id = _safe_string(organization_id)
    clean_acc_id = _safe_string(account_id)

    if not clean_org_id or not clean_acc_id:
        return {
            "organization_id": clean_org_id,
            "account_id": clean_acc_id,
            "services": DEFAULT_SERVICES.copy(),
            "exists": False,
        }

    # Tenant cross-validation: verify account belongs to organization
    try:
        aws_account = get_account(clean_acc_id, organization_id=clean_org_id)
        if not aws_account or aws_account.get("status") != "connected":
            logger.warning(
                "Remediation settings lookup rejected: Account '%s' not found for organization '%s'",
                clean_acc_id,
                clean_org_id,
            )
            return {
                "organization_id": clean_org_id,
                "account_id": clean_acc_id,
                "services": DEFAULT_SERVICES.copy(),
                "exists": False,
            }
    except Exception as exc:
        logger.error("Error validating AWS account ownership for settings lookup: %s", exc)
        return {
            "organization_id": clean_org_id,
            "account_id": clean_acc_id,
            "services": DEFAULT_SERVICES.copy(),
            "exists": False,
        }

    try:
        doc = remediation_settings_collection.find_one({
            "organization_id": clean_org_id,
            "account_id": clean_acc_id,
        })

        if not doc:
            return {
                "organization_id": clean_org_id,
                "account_id": clean_acc_id,
                "aws_account_id": str(aws_account.get("aws_account_id") or ""),
                "services": DEFAULT_SERVICES.copy(),
                "exists": False,
            }

        return {
            "_id": str(doc.get("_id")),
            "organization_id": clean_org_id,
            "account_id": clean_acc_id,
            "aws_account_id": str(doc.get("aws_account_id") or aws_account.get("aws_account_id") or ""),
            "services": _normalize_services(doc.get("services")),
            "updated_at": doc.get("updated_at"),
            "updated_by": str(doc.get("updated_by") or ""),
            "exists": True,
        }
    except Exception as exc:
        logger.error("Database error fetching remediation settings: %s", exc)
        return {
            "organization_id": clean_org_id,
            "account_id": clean_acc_id,
            "services": DEFAULT_SERVICES.copy(),
            "exists": False,
        }


def update_remediation_settings(
    organization_id: Any,
    account_id: Any,
    service_toggles: Dict[str, Any],
    user_id: Any,
) -> Optional[Dict[str, Any]]:
    """
    Updates or creates remediation settings for an AWS account.
    
    Fails closed:
    - Verifies organization & account mapping before modifying.
    - Merges new toggles into existing services to prevent unintentional resets.
    - Rejects invalid service keys.
    """
    clean_org_id = _safe_string(organization_id)
    clean_acc_id = _safe_string(account_id)
    clean_user_id = _safe_string(user_id)

    if not clean_org_id or not clean_acc_id or not clean_user_id:
        logger.warning("Remediation settings update rejected: Missing required context parameters.")
        return None

    # Validate tenant relationship
    try:
        aws_account = get_account(clean_acc_id, organization_id=clean_org_id)
        if not aws_account or aws_account.get("status") != "connected":
            logger.warning(
                "Remediation settings update rejected: Account '%s' not associated with org '%s'",
                clean_acc_id,
                clean_org_id,
            )
            return None
    except Exception as exc:
        logger.error("Error validating AWS account ownership during settings update: %s", exc)
        return None

    # Fetch current settings to perform safe merge
    existing = get_remediation_settings(clean_org_id, clean_acc_id)
    current_services = existing.get("services", DEFAULT_SERVICES.copy())

    # Merge incoming toggles safely
    if isinstance(service_toggles, dict):
        for k, v in service_toggles.items():
            clean_k = _safe_string(k).lower()
            if clean_k in ALLOWED_SERVICE_KEYS:
                if isinstance(v, bool):
                    current_services[clean_k] = v
                elif isinstance(v, (int, str)):
                    str_val = str(v).strip().lower()
                    current_services[clean_k] = str_val in ("true", "1", "yes")

    now = datetime.now(timezone.utc)
    aws_account_num = str(aws_account.get("aws_account_id") or "")

    update_payload = {
        "organization_id": clean_org_id,
        "account_id": clean_acc_id,
        "aws_account_id": aws_account_num,
        "services": current_services,
        "updated_at": now,
        "updated_by": clean_user_id,
    }

    try:
        remediation_settings_collection.update_one(
            {
                "organization_id": clean_org_id,
                "account_id": clean_acc_id,
            },
            {
                "$set": update_payload,
                "$setOnInsert": {
                    "created_at": now,
                },
            },
            upsert=True,
        )

        return get_remediation_settings(clean_org_id, clean_acc_id)
    except Exception as exc:
        logger.error("Database error updating remediation settings: %s", exc)
        return None


def is_remediation_enabled(
    organization_id: Any,
    account_id: Any,
    service_key: Any,
) -> bool:
    """
    Evaluates whether remediation is enabled for a specific service.
    
    FAIL-CLOSED GUARANTEE: Returns False on any database error, missing settings,
    unrecognized service key, or organization/account mismatch.
    """
    try:
        clean_service = _safe_string(service_key).lower()
        if clean_service not in ALLOWED_SERVICE_KEYS:
            logger.warning("Unrecognized service key '%s' evaluated for remediation.", service_key)
            return False

        settings = get_remediation_settings(organization_id, account_id)
        if not settings or not isinstance(settings.get("services"), dict):
            return False

        return bool(settings.get("services", {}).get(clean_service, False))
    except Exception as exc:
        logger.error("Error evaluating remediation enablement for service '%s': %s", service_key, exc)
        return False
