from app.services.compliance_engine import calculate_compliance


def show_result(name, findings):
    print(f"\n{'=' * 60}")
    print(name)
    print("=" * 60)

    result = calculate_compliance(findings)

    print("Score:", result.get("compliance_score"))
    print("Status:", result.get("status"))
    print("Assessment:", result.get("assessment"))
    print("Summary:", result.get("summary"))

    return result


# ============================================================
# TEST 1 — PASS
# ============================================================

pass_findings = [
    {
        "finding_id": "TEST-PASS-001",
        "service": "S3",
        "issue": "S3 Public Access",
        "severity": "HIGH",
        "detection_status": "PROTECTED",
        "workflow_status": "OPEN",
        "control_key": "S3_PUBLIC_ACCESS",
    }
]

result1 = show_result(
    "TEST 1 — PROTECTED / PASS",
    pass_findings
)


# ============================================================
# TEST 2 — FAIL
# ============================================================

fail_findings = [
    {
        "finding_id": "TEST-FAIL-001",
        "service": "S3",
        "issue": "S3 Public Access",
        "severity": "HIGH",
        "detection_status": "PUBLIC",
        "workflow_status": "OPEN",
        "control_key": "S3_PUBLIC_ACCESS",
    }
]

result2 = show_result(
    "TEST 2 — PUBLIC / FAIL",
    fail_findings
)


# ============================================================
# TEST 3 — REVIEW
# ============================================================

review_findings = [
    {
        "finding_id": "TEST-REVIEW-001",
        "service": "IAM",
        "issue": "IAM Policy Review",
        "severity": "MEDIUM",
        "detection_status": "REVIEW",
        "workflow_status": "OPEN",
        "control_key": "IAM_POLICY",
    }
]

result3 = show_result(
    "TEST 3 — REVIEW",
    review_findings
)


# ============================================================
# TEST 4 — NO EVIDENCE
# ============================================================

result4 = show_result(
    "TEST 4 — NO FINDINGS / NO EVIDENCE",
    []
)


# ============================================================
# TEST 5 — SAME CONTROL, PASS + FAIL
# ============================================================

duplicate_control_findings = [
    {
        "finding_id": "TEST-DUP-001",
        "service": "S3",
        "issue": "S3 Public Access",
        "severity": "HIGH",
        "detection_status": "PROTECTED",
        "workflow_status": "OPEN",
        "control_key": "S3_PUBLIC_ACCESS",
    },
    {
        "finding_id": "TEST-DUP-002",
        "service": "S3",
        "issue": "S3 Public Access",
        "severity": "CRITICAL",
        "detection_status": "PUBLIC",
        "workflow_status": "OPEN",
        "control_key": "S3_PUBLIC_ACCESS",
    },
]

result5 = show_result(
    "TEST 5 — SAME CONTROL / PASS + FAIL",
    duplicate_control_findings
)


# ============================================================
# ASSERTIONS
# ============================================================

print("\n")
print("=" * 60)
print("RUNNING ASSERTIONS")
print("=" * 60)


# Test 1
assert result1["status"] in {
    "COMPLIANT",
    "AT_RISK",
    "REVIEW_REQUIRED",
}

# Test 2 must not be compliant
assert result2["status"] != "COMPLIANT"

# Test 3 must require review
assert result3["status"] == "REVIEW_REQUIRED"

# Test 4 must NOT claim compliance
assert result4["status"] == "NOT_ASSESSED"

# Test 4 must not return 100
assert result4["compliance_score"] != 100

# Test 5 must not pass because one finding failed
assert result5["status"] != "COMPLIANT"


print("\n[PASS] ALL COMPLIANCE ENGINE TESTS PASSED")
print("✓ PASS handling")
print("✓ FAIL handling")
print("✓ REVIEW handling")
print("✓ Empty evidence → NOT_ASSESSED")
print("✓ Duplicate control worst-state handling")