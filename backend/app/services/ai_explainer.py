# ============================================================
# CloudGuardAI - Production AI Finding Explainer
# Commercial / Production SaaS
# ============================================================

from collections import OrderedDict


_SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _text(finding):
    return " ".join(
        str(finding.get(key, "") or "")
        for key in (
            "issue",
            "description",
            "recommendation",
            "remediation",
        )
    ).strip().lower()


def _resource(finding):
    for key in (
        "resource",
        "security_group_id",
        "security_group",
        "bucket",
        "user",
        "function_name",
        "db_identifier",
        "key_id",
    ):
        value = finding.get(key)
        if value not in (None, ""):
            return str(value).strip()
    return "AWS Resource"


def _severity(finding):
    value = str(finding.get("severity", "LOW") or "LOW").strip().upper()
    return value if value in _SEVERITY_RANK else "LOW"


def _add(store, key, finding, issue, why, impact, fix, risk_reduction):
    if key not in store:
        store[key] = {
            "issue": issue,
            "why": why,
            "impact": impact,
            "fix": fix,
            "risk_reduction": risk_reduction,
            "finding_count": 0,
            "affected_resources": [],
            "severities": [],
        }

    item = store[key]
    item["finding_count"] += 1

    resource = _resource(finding)
    if resource not in item["affected_resources"]:
        item["affected_resources"].append(resource)

    severity = _severity(finding)
    if severity not in item["severities"]:
        item["severities"].append(severity)

    current = _SEVERITY_RANK.get(item["impact"].upper(), 0)
    incoming = _SEVERITY_RANK.get(severity, 0)

    if incoming > current:
        item["impact"] = "Critical" if severity == "CRITICAL" else severity.title()


def explain(findings):
    """
    Produce concise customer-facing explanations from canonical findings.

    Identical logical issues are aggregated so three affected security
    groups do not produce three copies of the same explanation.
    """

    if not isinstance(findings, list):
        return []

    explanations = OrderedDict()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        text = _text(finding)
        severity = _severity(finding)

        # --------------------------------------------------------
        # IAM MFA
        # --------------------------------------------------------
        if (
            "mfa is not enabled" in text
            or "mfa not enabled" in text
            or ("multi-factor authentication" in text and "not enabled" in text)
            or ("multifactor authentication" in text and "not enabled" in text)
        ):
            _add(
                explanations,
                "IAM_MFA",
                finding,
                "Multi-Factor Authentication is missing for IAM users.",
                "Without MFA, stolen IAM credentials are easier to use for unauthorized account access.",
                "High",
                "Enable MFA for all human IAM users with console access and privileged permissions.",
                "High",
            )
            continue

        # --------------------------------------------------------
        # IAM AdministratorAccess
        # --------------------------------------------------------
        if (
            "administratoraccess" in text
            or "administrator access" in text
            or "full administrator" in text
        ):
            _add(
                explanations,
                "IAM_ADMINISTRATOR_ACCESS",
                finding,
                "IAM user has excessive administrative privileges.",
                "Full administrator permissions increase the blast radius of credential compromise or misuse.",
                "Critical",
                "Replace AdministratorAccess with narrowly scoped least-privilege permissions.",
                "Very High",
            )
            continue

        # --------------------------------------------------------
        # Active access key
        # --------------------------------------------------------
        if "access key is active" in text or "active access key" in text:
            _add(
                explanations,
                "IAM_ACTIVE_ACCESS_KEY",
                finding,
                "IAM access key is active.",
                "Long-lived or unnecessary access keys increase the risk of credential leakage and unauthorized access.",
                "Low",
                "Review the key's business need and rotate or remove it when it is no longer required.",
                "Moderate",
            )
            continue

        # --------------------------------------------------------
        # S3 public access
        # --------------------------------------------------------
        if "block public access" in text and (
            "not fully" in text
            or "not enabled" in text
            or "disabled" in text
        ):
            _add(
                explanations,
                "S3_BLOCK_PUBLIC_ACCESS",
                finding,
                "S3 Block Public Access is not fully enabled.",
                "Incomplete public-access protection can allow an incorrect bucket policy or ACL to expose data.",
                "High",
                "Enable all four S3 Block Public Access settings and verify bucket/account-level controls.",
                "High",
            )
            continue

        # --------------------------------------------------------
        # SSH
        # --------------------------------------------------------
        if "ssh" in text or "port 22" in text:
            _add(
                explanations,
                "NETWORK_SSH",
                finding,
                "SSH (port 22) is exposed to the Internet.",
                "Public SSH exposure increases brute-force attempts and the attack surface of compute resources.",
                "High",
                "Restrict SSH to trusted IP ranges or use AWS Systems Manager Session Manager.",
                "High",
            )
            continue

        # --------------------------------------------------------
        # RDP
        # --------------------------------------------------------
        if "rdp" in text or "port 3389" in text:
            _add(
                explanations,
                "NETWORK_RDP",
                finding,
                "RDP (port 3389) is exposed to the Internet.",
                "Public RDP exposure increases the risk of password attacks and remote exploitation.",
                "High",
                "Restrict RDP to trusted networks or use a secure remote-management solution.",
                "High",
            )
            continue

        # --------------------------------------------------------
        # HTTP / HTTPS
        # --------------------------------------------------------
        if "port 80" in text or "http is open" in text:
            _add(
                explanations,
                "NETWORK_HTTP",
                finding,
                "HTTP (port 80) is exposed to the Internet.",
                "Public HTTP access increases the reachable attack surface and may expose services that should be private.",
                "Medium",
                "Restrict port 80 unless public access is explicitly required, and prefer HTTPS for public applications.",
                "Medium",
            )
            continue

        if "port 443" in text or "https is open" in text:
            _add(
                explanations,
                "NETWORK_HTTPS",
                finding,
                "HTTPS (port 443) is exposed to the Internet.",
                "Public HTTPS is often intentional for web applications, but should still be limited to required resources and hardened services.",
                "Medium",
                "Keep HTTPS public only where required and enforce strong TLS and application-layer controls.",
                "Medium",
            )
            continue

        # --------------------------------------------------------
        # CloudTrail
        # --------------------------------------------------------
        if "cloudtrail" in text and (
            "not configured" in text
            or "not enabled" in text
            or "disabled" in text
            or "not logging" in text
        ):
            _add(
                explanations,
                "CLOUDTRAIL_LOGGING",
                finding,
                "CloudTrail audit logging is not configured correctly.",
                "Without CloudTrail, security teams lose visibility into management API activity and important incident-response evidence.",
                "High",
                "Enable multi-region CloudTrail with protected log storage and integrity validation.",
                "High",
            )
            continue

        # --------------------------------------------------------
        # Generic fallback
        # --------------------------------------------------------
        issue = str(finding.get("issue") or "Security finding").strip()
        recommendation = str(
            finding.get("remediation")
            or finding.get("recommendation")
            or "Review and remediate the finding according to your security requirements."
        ).strip()

        impact = "Critical" if severity == "CRITICAL" else severity.title()

        _add(
            explanations,
            "GENERIC:" + issue.lower(),
            finding,
            issue,
            "This security condition may increase the risk of unauthorized access, data exposure, or operational impact.",
            impact,
            recommendation,
            "Review",
        )

    result = list(explanations.values())

    for item in result:
        item["severities"].sort(
            key=lambda value: _SEVERITY_RANK.get(value, 0),
            reverse=True,
        )

    result.sort(
        key=lambda item: (
            -_SEVERITY_RANK.get(item.get("severities", ["LOW"])[0], 0),
            item.get("issue", ""),
        )
    )

    return result
