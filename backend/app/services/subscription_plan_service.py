from copy import deepcopy


# ============================================================
# CloudGuardAI SaaS Plan Catalog
# ============================================================

PLAN_CATALOG = {
    "free": {
        "name": "free",
        "display_name": "Free",
        "description": "For individuals evaluating CloudGuardAI.",

        "price_monthly": 0.0,
        "price_yearly": 0.0,

        # Usage limits
        "max_aws_accounts": 1,
        "max_team_members": 2,
        "max_scans_per_month": 10,
        "max_reports_per_month": 5,
        "max_storage_mb": 500,

        # Features
        "ai_analysis": False,
        "advanced_monitoring": False,
        "security_graph": False,
        "compliance_reports": False,
        "audit_logs": False,
        "priority_support": False,

        "active": True,

        "features": [
            "AWS security scanning",
            "Basic findings",
            "Basic dashboard",
            "Basic reports"
        ]
    },

    "pro": {
        "name": "pro",
        "display_name": "Pro",
        "description": "For growing teams that need advanced cloud security capabilities.",

        "price_monthly": 29.0,
        "price_yearly": 290.0,

        # Usage limits
        "max_aws_accounts": 5,
        "max_team_members": 10,
        "max_scans_per_month": 100,
        "max_reports_per_month": 50,
        "max_storage_mb": 5000,

        # Features
        "ai_analysis": True,
        "advanced_monitoring": True,
        "security_graph": True,
        "compliance_reports": True,
        "audit_logs": True,
        "priority_support": False,

        "active": True,

        "features": [
            "AWS security scanning",
            "Advanced findings",
            "AI security analysis",
            "Advanced monitoring",
            "Security graph",
            "Compliance reports",
            "Audit logs",
            "Advanced reports"
        ]
    },

    "business": {
        "name": "business",
        "display_name": "Business",
        "description": "For organizations requiring higher limits and advanced security operations.",

        "price_monthly": 99.0,
        "price_yearly": 990.0,

        # -1 means unlimited
        "max_aws_accounts": -1,
        "max_team_members": -1,
        "max_scans_per_month": -1,
        "max_reports_per_month": -1,
        "max_storage_mb": -1,

        # Features
        "ai_analysis": True,
        "advanced_monitoring": True,
        "security_graph": True,
        "compliance_reports": True,
        "audit_logs": True,
        "priority_support": True,

        "active": True,

        "features": [
            "Unlimited AWS accounts",
            "Unlimited team members",
            "Unlimited scans",
            "AI security analysis",
            "Advanced monitoring",
            "Security graph",
            "Compliance reports",
            "Audit logs",
            "Priority support",
            "Advanced reports"
        ]
    }
}


# ============================================================
# Get Single Plan
# ============================================================

def get_plan(plan_name: str):

    if not plan_name:
        return None

    plan_name = str(plan_name).strip().lower()

    plan = PLAN_CATALOG.get(plan_name)

    if not plan:
        return None

    # Return a copy so callers cannot accidentally
    # modify the central plan catalog.
    return deepcopy(plan)


# ============================================================
# Get All Active Plans
# ============================================================

def get_all_plans():

    return [
        deepcopy(plan)
        for plan in PLAN_CATALOG.values()
        if plan.get("active") is True
    ]


# ============================================================
# Check Whether Plan Exists
# ============================================================

def plan_exists(plan_name: str) -> bool:

    if not plan_name:
        return False

    return (
        str(plan_name).strip().lower()
        in PLAN_CATALOG
    )


# ============================================================
# Get Plan Limit
# ============================================================

def get_plan_limit(
    plan_name: str,
    limit_name: str
):

    plan = get_plan(plan_name)

    if not plan:
        return None

    return plan.get(limit_name)


# ============================================================
# Check Feature Availability
# ============================================================

def has_plan_feature(
    plan_name: str,
    feature_name: str
) -> bool:

    plan = get_plan(plan_name)

    if not plan:
        return False

    return bool(
        plan.get(feature_name, False)
    )