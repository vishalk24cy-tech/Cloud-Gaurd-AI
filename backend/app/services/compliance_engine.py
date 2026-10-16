# ============================================================
# CloudGuardAI - Compliance Engine
# Production / Commercial SaaS
#
# Frameworks:
#   - CIS AWS Foundations Benchmark
#   - NIST CSF
#   - PCI DSS
#
# Design:
#   AWS Findings
#       ↓
#   Control Mapping
#       ↓
#   PASS / FAIL / REVIEW
#       ↓
#   Framework Scores
#       ↓
#   Evidence + Remediation
# ============================================================

from datetime import datetime, timezone


# ============================================================
# FRAMEWORK CONSTANTS
# ============================================================

FRAMEWORK_CIS = "CIS_AWS_Benchmark"
FRAMEWORK_NIST = "NIST_CSF"
FRAMEWORK_PCI = "PCI_DSS"

SUPPORTED_FRAMEWORKS = {
    FRAMEWORK_CIS,
    FRAMEWORK_NIST,
    FRAMEWORK_PCI,
}


# ============================================================
# CONTROL STATUS
# ============================================================

STATUS_PASSED = "PASSED"
STATUS_FAILED = "FAILED"
STATUS_REVIEW = "REVIEW"
STATUS_NOT_ASSESSED = "NOT_ASSESSED"

VALID_CONTROL_STATUSES = {
    STATUS_PASSED,
    STATUS_FAILED,
    STATUS_REVIEW,
    STATUS_NOT_ASSESSED,
}


# ============================================================
# DETECTION STATUS
# ============================================================

PROTECTED_STATUSES = {
    "PROTECTED",
    "PASS",
    "PASSED",
}

REVIEW_STATUSES = {
    "REVIEW",
    "WARNING",
    "UNKNOWN",
}


# ============================================================
# FRAMEWORK CONTROL MAPPING
#
# These are CloudGuardAI's internal mappings.
#
# IMPORTANT:
# The mappings are intentionally kept in one place so they
# can be versioned and updated independently when benchmark
# versions change.
# ============================================================

CONTROL_MAPPING = {

    # --------------------------------------------------------
    # S3
    # --------------------------------------------------------

    "S3_PUBLIC_ACCESS": {
        "cis": "CIS 2.1.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.2",
    },

    "S3_PUBLIC_POLICY": {
        "cis": "CIS 2.1.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.2",
    },

    "S3_ENCRYPTION": {
        "cis": "CIS 2.1.2",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.5",
    },

    # --------------------------------------------------------
    # EC2 / VPC
    # --------------------------------------------------------

    "SECURITY_GROUP": {
        "cis": "CIS 5.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    "SSH_EXPOSED": {
        "cis": "CIS 5.2",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    "RDP_EXPOSED": {
        "cis": "CIS 5.2",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    "UNRESTRICTED_INBOUND": {
        "cis": "CIS 5.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    # --------------------------------------------------------
    # IAM
    # --------------------------------------------------------

    "IAM_MFA": {
        "cis": "CIS 1.10",
        "nist": "PR.AC",
        "pci": "PCI DSS 8.4",
    },

    "IAM_ADMINISTRATOR_ACCESS": {
        "cis": "CIS 1.16",
        "nist": "PR.AC",
        "pci": "PCI DSS 7.2",
    },

    "IAM_POLICY": {
        "cis": "CIS 1.16",
        "nist": "PR.AC",
        "pci": "PCI DSS 7.2",
    },

    # --------------------------------------------------------
    # CloudTrail
    # --------------------------------------------------------

    "CLOUDTRAIL": {
        "cis": "CIS 3.1",
        "nist": "DE.CM",
        "pci": "PCI DSS 10.2",
    },

    "CLOUDTRAIL_LOGGING": {
        "cis": "CIS 3.1",
        "nist": "DE.CM",
        "pci": "PCI DSS 10.2",
    },

    # --------------------------------------------------------
    # RDS
    # --------------------------------------------------------

    "RDS_PUBLIC": {
        "cis": "CIS 2.3.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    "RDS_ENCRYPTION": {
        "cis": "CIS 2.3.1",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.5",
    },

    "RDS_BACKUP": {
        "cis": "CIS 2.3.1",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.4",
    },

    # --------------------------------------------------------
    # Lambda
    # --------------------------------------------------------

    "LAMBDA_PUBLIC": {
        "cis": "CIS 2.1",
        "nist": "PR.AC",
        "pci": "PCI DSS 1.3",
    },

    "LAMBDA_ENCRYPTION": {
        "cis": "CIS 2.1",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.5",
    },

    # --------------------------------------------------------
    # KMS
    # --------------------------------------------------------

    "KMS_ROTATION": {
        "cis": "CIS 3.8",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.6",
    },

    "KMS_ENCRYPTION": {
        "cis": "CIS 3.8",
        "nist": "PR.DS",
        "pci": "PCI DSS 3.6",
    },
}


# ============================================================
# FRAMEWORK METADATA / VERSIONING
# ============================================================
# These versions identify CloudGuardAI's mapping/catalog release.
# They are NOT claims that CloudGuardAI is certified by the framework owner.
FRAMEWORK_METADATA = {
    FRAMEWORK_CIS: {
        "name": "CIS AWS Benchmark",
        "version": "CloudGuardAI-MAP-1.0",
        "catalog_version": "1.0",
        "mapping_source": "CloudGuardAI internal control mapping",
    },
    FRAMEWORK_NIST: {
        "name": "NIST CSF",
        "version": "CloudGuardAI-MAP-1.0",
        "catalog_version": "1.0",
        "mapping_source": "CloudGuardAI internal control mapping",
    },
    FRAMEWORK_PCI: {
        "name": "PCI DSS",
        "version": "CloudGuardAI-MAP-1.0",
        "catalog_version": "1.0",
        "mapping_source": "CloudGuardAI internal control mapping",
    },
}

CONTROL_CATALOG = {
    key: {
        "control_key": key,
        "framework_controls": {
            FRAMEWORK_CIS: value.get("cis"),
            FRAMEWORK_NIST: value.get("nist"),
            FRAMEWORK_PCI: value.get("pci"),
        },
    }
    for key, value in CONTROL_MAPPING.items()
}


def _framework_metadata(framework):
    metadata = FRAMEWORK_METADATA.get(framework, {})
    return {
        "framework": framework,
        "name": metadata.get("name", framework),
        "version": metadata.get("version", "CloudGuardAI-MAP-1.0"),
        "catalog_version": metadata.get("catalog_version", "1.0"),
        "mapping_source": metadata.get(
            "mapping_source",
            "CloudGuardAI internal control mapping",
        ),
    }


def _evidence_confidence(finding):
    evidence = finding.get("evidence", {}) if isinstance(finding, dict) else {}
    if isinstance(evidence, dict) and evidence:
        return "HIGH"
    if evidence not in (None, "", [], {}):
        return "MEDIUM"
    if isinstance(finding, dict) and (
        finding.get("resource") or finding.get("arn") or finding.get("finding_id")
    ):
        return "MEDIUM"
    return "LOW"


# ============================================================
# TEXT HELPERS
# ============================================================

def _clean(value):
    """
    Safely normalize a value to string.
    """

    if value is None:
        return ""

    return str(value).strip()


def _upper(value):
    return _clean(value).upper()


def _lower(value):
    return _clean(value).lower()


# ============================================================
# FINDING CONTROL KEY
# ============================================================

def _get_control_key(finding):
    """
    Determine the internal CloudGuardAI control mapping key.

    Priority:

        1. Explicit control_key
        2. Explicit control_id
        3. Service + issue inference
    """

    if not isinstance(finding, dict):
        return "UNKNOWN_CONTROL"

    explicit_key = finding.get("control_key")

    if explicit_key:
        return _upper(explicit_key)

    control_id = finding.get("control_id")

    if control_id:
        control_id = _upper(control_id)

        if control_id in CONTROL_MAPPING:
            return control_id

    service = _upper(
        finding.get("service")
    )

    issue = _lower(
        finding.get("issue")
    )

    description = _lower(
        finding.get("description")
    )

    combined = f"{issue} {description}"

    # --------------------------------------------------------
    # S3
    # --------------------------------------------------------

    if "S3" in service:

        if "policy" in combined and "public" in combined:
            return "S3_PUBLIC_POLICY"

        if "public" in combined:
            return "S3_PUBLIC_ACCESS"

        if "encrypt" in combined:
            return "S3_ENCRYPTION"

    # --------------------------------------------------------
    # IAM
    # --------------------------------------------------------

    if "IAM" in service:

        if (
            "mfa" in combined
            or "multi-factor" in combined
        ):
            return "IAM_MFA"

        if (
            "administrator" in combined
            or "admin access" in combined
            or "high privilege" in combined
        ):
            return "IAM_ADMINISTRATOR_ACCESS"

        if (
            "policy" in combined
            or "permission" in combined
            or "privilege" in combined
        ):
            return "IAM_POLICY"

    # --------------------------------------------------------
    # EC2 / VPC
    # --------------------------------------------------------

    if (
        "EC2" in service
        or "VPC" in service
    ):

        if "ssh" in combined:
            return "SSH_EXPOSED"

        if "rdp" in combined:
            return "RDP_EXPOSED"

        if (
            "0.0.0.0/0" in combined
            or "::/0" in combined
            or "unrestricted" in combined
            or "inbound" in combined
        ):
            return "UNRESTRICTED_INBOUND"

        if "security group" in combined:
            return "SECURITY_GROUP"

    # --------------------------------------------------------
    # CloudTrail
    # --------------------------------------------------------

    if "CLOUDTRAIL" in service:

        return "CLOUDTRAIL_LOGGING"

    if "cloudtrail" in combined:

        return "CLOUDTRAIL_LOGGING"

    # --------------------------------------------------------
    # RDS
    # --------------------------------------------------------

    if "RDS" in service:

        if (
            "public" in combined
            or "accessible" in combined
        ):
            return "RDS_PUBLIC"

        if "encrypt" in combined:
            return "RDS_ENCRYPTION"

        if (
            "backup" in combined
            or "retention" in combined
        ):
            return "RDS_BACKUP"

    # --------------------------------------------------------
    # Lambda
    # --------------------------------------------------------

    if "LAMBDA" in service:

        if "public" in combined:
            return "LAMBDA_PUBLIC"

        if "encrypt" in combined:
            return "LAMBDA_ENCRYPTION"

    # --------------------------------------------------------
    # KMS
    # --------------------------------------------------------

    if "KMS" in service:

        if (
            "rotation" in combined
            or "rotate" in combined
        ):
            return "KMS_ROTATION"

        if "encrypt" in combined:
            return "KMS_ENCRYPTION"

    return "UNKNOWN_CONTROL"


# ============================================================
# CONTROL ID RESOLUTION
# ============================================================

def _resolve_control_ids(
    finding,
    control_key,
):
    """
    Resolve framework-specific control identifiers.
    """

    mapping = CONTROL_MAPPING.get(
        control_key,
        {}
    )

    # Allow scanner-provided compliance metadata
    compliance = finding.get(
        "compliance",
        []
    )

    if not isinstance(compliance, list):
        compliance = []

    cis = mapping.get("cis")
    nist = mapping.get("nist")
    pci = mapping.get("pci")

    for item in compliance:

        if isinstance(item, dict):

            framework = _upper(
                item.get("framework")
            )

            control = _clean(
                item.get("control_id")
                or item.get("control")
            )

            if not control:
                continue

            if framework == "CIS":
                cis = control

            elif framework == "NIST":
                nist = control

            elif framework in {
                "PCI",
                "PCI DSS",
            }:
                pci = control

    return {
        FRAMEWORK_CIS: cis,
        FRAMEWORK_NIST: nist,
        FRAMEWORK_PCI: pci,
    }


# ============================================================
# DETERMINE CONTROL STATUS
# ============================================================

def _evaluate_finding(finding):
    """
    Convert one security finding into a compliance result.

    Important:
        Compliance is NOT based purely on severity.

    Protected detection:
        PASSED

    Explicit uncertainty:
        REVIEW

    Active security issue:
        FAILED
    """

    detection_status = _upper(
        finding.get(
            "detection_status",
            finding.get(
                "status",
                ""
            )
        )
    )

    workflow_status = _upper(
        finding.get(
            "workflow_status",
            finding.get(
                "status",
                ""
            )
        )
    )

    if (
        detection_status in PROTECTED_STATUSES
        or workflow_status == "NOT_APPLICABLE"
    ):
        return STATUS_PASSED

    if detection_status in REVIEW_STATUSES:
        return STATUS_REVIEW

    if workflow_status == "RESOLVED":
        return STATUS_PASSED

    if workflow_status == "IGNORED":
        return STATUS_REVIEW

    return STATUS_FAILED


# ============================================================
# SCORE CALCULATION
# ============================================================

def _calculate_score(
    passed,
    failed,
    review,
):
    """
    Calculate a conservative compliance score.

    Passed:
        100%

    Review:
        50%

    Failed:
        0%
    """

    total = (
        passed
        + failed
        + review
    )

    if total == 0:
        # No evaluated controls means there is insufficient evidence
        # to make a compliance claim. Never report false 100% compliance.
        return 0

    weighted_points = (
        passed * 100
        + review * 50
        + failed * 0
    )

    return int(
        round(
            weighted_points / total
        )
    )


# ============================================================
# FRAMEWORK RESULT
# ============================================================

def _empty_framework_result():
    return {
        "score": 0,
        "status": STATUS_NOT_ASSESSED,
        "metadata": {},
        "coverage": {
            "assessed_controls": 0,
            "catalog_controls": 0,
            "coverage_percent": 0,
        },
        "evidence": {
            "high": 0,
            "medium": 0,
            "low": 0,
            "confidence": "LOW",
        },
        "controls": {
            "total": 0,
            "passed": 0,
            "failed": 0,
            "review": 0,
        },
        "control_results": [],
    }


# ============================================================
# FRAMEWORK STATUS
# ============================================================

def _framework_status(
    score,
    failed,
    review,
):
    total = failed + review

    # A framework with no passed/failed/review controls has not been
    # assessed. This prevents an empty evidence set from becoming
    # a misleading COMPLIANT result.
    if score == 0 and total == 0:
        return STATUS_NOT_ASSESSED

    if failed > 0:
        if score < 70:
            return "NON_COMPLIANT"

        return "AT_RISK"

    if review > 0:
        return "REVIEW_REQUIRED"

    return "COMPLIANT"


# ============================================================
# BUILD CONTROL RESULT
# ============================================================

def _build_control_result(
    finding,
    framework,
    control_id,
    status,
    control_key,
):
    """
    Build a customer-facing compliance control record.
    """

    severity = _upper(
        finding.get(
            "severity",
            "LOW"
        )
    )

    finding_id = _clean(
        finding.get(
            "finding_id"
        )
    )

    service = _clean(
        finding.get(
            "service",
            "AWS"
        )
    )

    resource = _clean(
        finding.get(
            "resource",
            "AWS Resource"
        )
    )

    issue = _clean(
        finding.get(
            "issue",
            "Security control evaluation"
        )
    )

    evidence = finding.get(
        "evidence",
        {}
    )

    if not isinstance(evidence, dict):
        evidence = {
            "details": evidence
        }

    recommendation = _clean(
        finding.get(
            "recommendation",
            finding.get(
                "remediation",
                "Review security configuration"
            )
        )
    )

    return {
        "control_id": control_id,
        "control_key": control_key,
        "framework": framework,
        "framework_version": _framework_metadata(framework)["version"],
        "catalog_version": _framework_metadata(framework)["catalog_version"],
        "status": status,
        "finding_id": finding_id,
        "scan_id": _clean(finding.get("scan_id")),
        "account_id": _clean(finding.get("account_id")),
        "aws_account_id": _clean(finding.get("aws_account_id")),
        "severity": severity,
        "service": service,
        "resource": resource,
        "arn": _clean(finding.get("arn")),
        "issue": issue,
        "evidence": evidence,
        "evidence_confidence": _evidence_confidence(finding),
        "recommendation": recommendation,
        "evaluated_at": datetime.now(timezone.utc),
    }


# ============================================================
# BUILD FRAMEWORK
# ============================================================

def _build_framework(
    framework,
    findings,
):
    """
    Evaluate all findings against one framework.
    """

    result = _empty_framework_result()

    control_results = {}

    for finding in findings:

        if not isinstance(finding, dict):
            continue

        control_key = _get_control_key(
            finding
        )

        control_ids = _resolve_control_ids(
            finding,
            control_key
        )

        control_id = control_ids.get(
            framework
        )

        # No mapping means the control cannot safely
        # be claimed as compliant.
        if not control_id:
            continue

        status = _evaluate_finding(
            finding
        )

        control_result = _build_control_result(
            finding,
            framework,
            control_id,
            status,
            control_key,
        )

        # ----------------------------------------------------
        # Multiple findings may affect the same control.
        #
        # Worst state wins:
        #
        # FAILED > REVIEW > PASSED
        # ----------------------------------------------------

        existing = control_results.get(
            control_id
        )

        if existing:

            priority = {
                STATUS_PASSED: 1,
                STATUS_REVIEW: 2,
                STATUS_FAILED: 3,
            }

            if priority.get(
                status,
                0
            ) > priority.get(
                existing["status"],
                0
            ):
                control_results[
                    control_id
                ] = control_result

        else:

            control_results[
                control_id
            ] = control_result

    controls = list(
        control_results.values()
    )

    passed = sum(
        1
        for item in controls
        if item["status"] == STATUS_PASSED
    )

    failed = sum(
        1
        for item in controls
        if item["status"] == STATUS_FAILED
    )

    review = sum(
        1
        for item in controls
        if item["status"] == STATUS_REVIEW
    )

    score = _calculate_score(
        passed,
        failed,
        review
    )

    result["score"] = score

    result["status"] = _framework_status(
        score,
        failed,
        review
    )

    result["controls"] = {
        "total": len(controls),
        "passed": passed,
        "failed": failed,
        "review": review,
    }

    result["control_results"] = controls

    catalog_controls = sum(
        1
        for item in CONTROL_CATALOG.values()
        if item.get("framework_controls", {}).get(framework)
    )
    assessed = len(controls)
    coverage_percent = int(round((assessed / catalog_controls) * 100)) if catalog_controls else 0

    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in controls:
        confidence = item.get("evidence_confidence", "LOW")
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

    if confidence_counts["HIGH"] == assessed and assessed > 0:
        confidence = "HIGH"
    elif confidence_counts["HIGH"] or confidence_counts["MEDIUM"]:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    result["metadata"] = _framework_metadata(framework)
    result["coverage"] = {
        "assessed_controls": assessed,
        "catalog_controls": catalog_controls,
        "coverage_percent": coverage_percent,
    }
    result["evidence"] = {
        **confidence_counts,
        "confidence": confidence,
    }

    return result


# ============================================================
# MAIN COMPLIANCE CALCULATOR
# ============================================================

def calculate_compliance(
    findings,
    frameworks=None,
):
    """
    Calculate commercial CloudGuardAI compliance posture.

    Parameters
    ----------
    findings:
        List of CloudGuardAI security findings.

    frameworks:
        Optional list/set of requested frameworks.

        Example:

            [
                "CIS_AWS_Benchmark",
                "NIST_CSF",
                "PCI_DSS"
            ]

        If omitted, all supported frameworks are evaluated.

    Returns
    -------
    dict
        Complete compliance posture.
    """

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if not isinstance(
        findings,
        list
    ):
        findings = []

    # --------------------------------------------------------
    # Framework selection
    # --------------------------------------------------------

    if frameworks is None:

        selected_frameworks = [
            FRAMEWORK_CIS,
            FRAMEWORK_NIST,
            FRAMEWORK_PCI,
        ]

    else:

        if isinstance(
            frameworks,
            str
        ):
            frameworks = [
                frameworks
            ]

        selected_frameworks = []

        for framework in frameworks:

            normalized = _clean(
                framework
            )

            if normalized in SUPPORTED_FRAMEWORKS:

                if normalized not in selected_frameworks:
                    selected_frameworks.append(
                        normalized
                    )

    # --------------------------------------------------------
    # Evaluate frameworks
    # --------------------------------------------------------

    framework_results = {}

    for framework in selected_frameworks:

        framework_results[
            framework
        ] = _build_framework(
            framework,
            findings
        )

    # --------------------------------------------------------
    # Aggregate scores
    # --------------------------------------------------------

    scores = [
        result["score"]
        for result in framework_results.values()
    ]

    if scores:

        overall_score = int(
            round(
                sum(scores)
                / len(scores)
            )
        )

    else:

        overall_score = 100

    # --------------------------------------------------------
    # Aggregate control counts
    # --------------------------------------------------------

    total_controls = 0
    passed_controls = 0
    failed_controls = 0
    review_controls = 0

    for result in framework_results.values():

        controls = result.get(
            "controls",
            {}
        )

        total_controls += controls.get(
            "total",
            0
        )

        passed_controls += controls.get(
            "passed",
            0
        )

        failed_controls += controls.get(
            "failed",
            0
        )

        review_controls += controls.get(
            "review",
            0
        )

    # --------------------------------------------------------
    # Overall status
    # --------------------------------------------------------

    if total_controls == 0:
        overall_status = STATUS_NOT_ASSESSED
    elif failed_controls > 0:

        if overall_score < 70:
            overall_status = "NON_COMPLIANT"

        else:
            overall_status = "AT_RISK"

    elif review_controls > 0:

        overall_status = "REVIEW_REQUIRED"

    else:

        overall_status = "COMPLIANT"

    # --------------------------------------------------------
    # Failed controls
    #
    # Backward-compatible field for existing frontend.
    # --------------------------------------------------------

    failed_control_list = []

    for framework, result in framework_results.items():

        for control in result.get(
            "control_results",
            []
        ):

            if control.get(
                "status"
            ) != STATUS_FAILED:
                continue

            failed_control_list.append({
                "framework": framework,
                "control": control.get(
                    "control_id"
                ),
                "control_key": control.get(
                    "control_key"
                ),
                "finding_id": control.get(
                    "finding_id"
                ),
                "service": control.get(
                    "service"
                ),
                "resource": control.get(
                    "resource"
                ),
                "severity": control.get(
                    "severity"
                ),
                "status": "Failed",
                "issue": control.get(
                    "issue"
                ),
                "evidence": control.get(
                    "evidence",
                    {}
                ),
                "recommendation": control.get(
                    "recommendation"
                ),
            })

    # --------------------------------------------------------
    # Review controls
    # --------------------------------------------------------

    review_control_list = []

    for framework, result in framework_results.items():

        for control in result.get(
            "control_results",
            []
        ):

            if control.get(
                "status"
            ) != STATUS_REVIEW:
                continue

            review_control_list.append({
                "framework": framework,
                "control": control.get(
                    "control_id"
                ),
                "control_key": control.get(
                    "control_key"
                ),
                "finding_id": control.get(
                    "finding_id"
                ),
                "service": control.get(
                    "service"
                ),
                "resource": control.get(
                    "resource"
                ),
                "severity": control.get(
                    "severity"
                ),
                "status": "Review",
                "issue": control.get(
                    "issue"
                ),
                "evidence": control.get(
                    "evidence",
                    {}
                ),
                "recommendation": control.get(
                    "recommendation"
                ),
            })

    # --------------------------------------------------------
    # Passed controls
    # --------------------------------------------------------

    passed_control_list = []

    for framework, result in framework_results.items():

        for control in result.get(
            "control_results",
            []
        ):

            if control.get(
                "status"
            ) != STATUS_PASSED:
                continue

            passed_control_list.append({
                "framework": framework,
                "control": control.get(
                    "control_id"
                ),
                "control_key": control.get(
                    "control_key"
                ),
                "finding_id": control.get(
                    "finding_id"
                ),
                "service": control.get(
                    "service"
                ),
                "resource": control.get(
                    "resource"
                ),
                "severity": control.get(
                    "severity"
                ),
                "status": "Passed",
                "issue": control.get(
                    "issue"
                ),
                "evidence": control.get(
                    "evidence",
                    {}
                ),
                "recommendation": control.get(
                    "recommendation"
                ),
            })

    # --------------------------------------------------------
    # Assessment coverage / evidence confidence
    # --------------------------------------------------------

    assessed_catalog = sum(
        result.get("coverage", {}).get("catalog_controls", 0)
        for result in framework_results.values()
    )
    assessed_controls = sum(
        result.get("coverage", {}).get("assessed_controls", 0)
        for result in framework_results.values()
    )
    coverage_percent = int(round((assessed_controls / assessed_catalog) * 100)) if assessed_catalog else 0

    high_evidence = sum(result.get("evidence", {}).get("high", 0) for result in framework_results.values())
    medium_evidence = sum(result.get("evidence", {}).get("medium", 0) for result in framework_results.values())
    low_evidence = sum(result.get("evidence", {}).get("low", 0) for result in framework_results.values())

    if total_controls == 0:
        overall_score = 0
        overall_status = STATUS_NOT_ASSESSED
        evidence_confidence = "LOW"
    elif high_evidence == total_controls:
        evidence_confidence = "HIGH"
    elif high_evidence or medium_evidence:
        evidence_confidence = "MEDIUM"
    else:
        evidence_confidence = "LOW"

    # --------------------------------------------------------
    # Final response
    # --------------------------------------------------------

    return {
        "compliance_score": overall_score,

        "status": overall_status,

        "assessment": {
            "state": overall_status,
            "has_evaluated_controls": total_controls > 0,
            "evidence_sufficient": total_controls > 0,
        },

        "frameworks": framework_results,

        "summary": {
            "frameworks_evaluated": len(
                framework_results
            ),
            "total_controls": total_controls,
            "passed": passed_controls,
            "failed": failed_controls,
            "review": review_controls,
        },

        "controls": {
            "total": total_controls,
            "passed": passed_controls,
            "failed": failed_controls,
            "review": review_controls,
        },

        "passed_controls": passed_control_list,

        "failed_controls": failed_control_list,

        "review_controls": review_control_list,

        "assessment_coverage": {
            "assessed_controls": assessed_controls,
            "catalog_controls": assessed_catalog,
            "coverage_percent": coverage_percent,
        },

        "evidence_confidence": {
            "overall": evidence_confidence,
            "high": high_evidence,
            "medium": medium_evidence,
            "low": low_evidence,
        },

        "framework_metadata": {
            framework: _framework_metadata(framework)
            for framework in framework_results
        },

        "engine_metadata": {
            "engine_version": "2.1",
            "mapping_version": "CloudGuardAI-MAP-1.0",
            "assessment_model": "evidence_backed_control_assessment",
            "empty_evidence_status": STATUS_NOT_ASSESSED,
        },

        "generated_at": datetime.now(timezone.utc),
    }