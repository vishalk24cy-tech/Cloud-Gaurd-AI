# ============================================================
# CloudGuardAI - Production Remediation Policy Generator
# Commercial / Production SaaS
# ============================================================

from collections import OrderedDict


_SEVERITY_PRIORITY = {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 3,
    "LOW": 4,
    "INFO": 5,
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
    severity = str(finding.get("severity", "LOW") or "LOW").strip().upper()
    return severity if severity in _SEVERITY_PRIORITY else "LOW"


def _make_policy(store, key, finding, service, policy, priority):
    if key not in store:
        store[key] = {
            "service": service,
            "policy": policy,
            "priority": priority,
            "finding_count": 0,
            "affected_resources": [],
        }

    item = store[key]
    item["finding_count"] += 1

    resource = _resource(finding)
    if resource not in item["affected_resources"]:
        item["affected_resources"].append(resource)

    current_rank = _SEVERITY_PRIORITY.get(item["priority"], 99)
    incoming_rank = _SEVERITY_PRIORITY.get(_severity(finding), 99)

    if incoming_rank < current_rank:
        item["priority"] = _severity(finding)


def generate_policies(ai_findings):
    """
    Generate customer-facing remediation policies from canonical findings.

    Production behavior:
      - one policy per logical remediation category
      - identical remediation guidance is aggregated
      - affected AWS resources are retained
      - policy priority follows the highest severity
      - malformed/non-dict findings are ignored safely
    """

    if not isinstance(ai_findings, list):
        return []

    policies = OrderedDict()

    for finding in ai_findings:
        if not isinstance(finding, dict):
            continue

        text = _text(finding)
        severity = _severity(finding)

        # --------------------------------------------------------
        # IAM - MFA
        # --------------------------------------------------------
        if (
            "mfa is not enabled" in text
            or "mfa not enabled" in text
            or "multi-factor authentication" in text and "not enabled" in text
            or "multifactor authentication" in text and "not enabled" in text
        ):
            _make_policy(
                policies,
                "IAM_MFA",
                finding,
                "IAM",
                "Enable MFA for all human IAM users with console access.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # IAM - AdministratorAccess / excessive privilege
        # --------------------------------------------------------
        if (
            "administratoraccess" in text
            or "administrator access" in text
            or "full administrator" in text
            or "excessive privilege" in text
        ):
            _make_policy(
                policies,
                "IAM_LEAST_PRIVILEGE",
                finding,
                "IAM",
                "Replace full administrative access with least-privilege permissions required by the user.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # IAM - active access key
        # --------------------------------------------------------
        if "access key is active" in text or "active access key" in text:
            _make_policy(
                policies,
                "IAM_ACCESS_KEY",
                finding,
                "IAM",
                "Review active IAM access keys and rotate or remove keys that are not required.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # S3 - public access
        # --------------------------------------------------------
        if (
            "block public access" in text
            and (
                "not fully" in text
                or "not enabled" in text
                or "disabled" in text
                or "public access" in text
            )
        ):
            _make_policy(
                policies,
                "S3_BLOCK_PUBLIC_ACCESS",
                finding,
                "S3",
                "Enable all S3 Block Public Access settings for the affected bucket.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # Network - SSH
        # --------------------------------------------------------
        if "ssh" in text or "port 22" in text:
            _make_policy(
                policies,
                "NETWORK_SSH",
                finding,
                "EC2",
                "Restrict SSH (22) to trusted IP ranges or use AWS Systems Manager.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # Network - RDP
        # --------------------------------------------------------
        if "rdp" in text or "port 3389" in text:
            _make_policy(
                policies,
                "NETWORK_RDP",
                finding,
                "EC2",
                "Restrict RDP (3389) to trusted IP ranges or use a secure management solution.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # Network - HTTP / HTTPS
        # --------------------------------------------------------
        if "port 80" in text or "http is open" in text:
            _make_policy(
                policies,
                "NETWORK_HTTP",
                finding,
                "EC2",
                "Restrict HTTP (80) to trusted IP ranges unless public access is explicitly required.",
                severity,
            )
            continue

        if "port 443" in text or "https is open" in text:
            _make_policy(
                policies,
                "NETWORK_HTTPS",
                finding,
                "EC2",
                "Restrict HTTPS (443) to trusted IP ranges unless public access is explicitly required.",
                severity,
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
            _make_policy(
                policies,
                "CLOUDTRAIL_LOGGING",
                finding,
                "CLOUDTRAIL",
                "Enable a multi-region AWS CloudTrail trail with appropriate log protection and integrity validation.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # RDS public exposure / encryption / backups
        # --------------------------------------------------------
        if "rds" in text and "public" in text:
            _make_policy(
                policies,
                "RDS_PUBLIC_ACCESS",
                finding,
                "RDS",
                "Disable public accessibility for the affected RDS database and restrict database access to trusted networks.",
                severity,
            )
            continue

        if "storage encryption" in text and ("disabled" in text or "not enabled" in text):
            _make_policy(
                policies,
                "RDS_ENCRYPTION",
                finding,
                "RDS",
                "Enable encryption at rest for the affected RDS database using an appropriate KMS key.",
                severity,
            )
            continue

        if "automated backups" in text and ("disabled" in text or "not enabled" in text):
            _make_policy(
                policies,
                "RDS_BACKUPS",
                finding,
                "RDS",
                "Enable automated backups and configure an appropriate retention period for the affected RDS database.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # Lambda wildcard access
        # --------------------------------------------------------
        if "wildcard principal" in text or "principal" in text and "*" in text and "lambda" in text:
            _make_policy(
                policies,
                "LAMBDA_WILDCARD_PRINCIPAL",
                finding,
                "LAMBDA",
                "Remove unrestricted wildcard principals from the Lambda resource policy and allow only trusted principals.",
                severity,
            )
            continue

        # --------------------------------------------------------
        # Generic remediation fallback
        # --------------------------------------------------------
        recommendation = str(
            finding.get("remediation")
            or finding.get("recommendation")
            or "Review and remediate the identified security finding."
        ).strip()

        service = str(finding.get("service") or finding.get("resource_type") or "AWS").strip().upper()
        issue_key = "GENERIC:" + str(finding.get("issue") or recommendation).strip().lower()

        _make_policy(
            policies,
            issue_key,
            finding,
            service,
            recommendation,
            severity,
        )

    result = list(policies.values())

    result.sort(
        key=lambda item: (
            _SEVERITY_PRIORITY.get(item.get("priority", "LOW"), 99),
            item.get("service", ""),
            item.get("policy", ""),
        )
    )

    return result
