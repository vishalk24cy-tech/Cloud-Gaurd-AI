# ============================================================
# CloudGuardAI - Notification Severity Escalation Test
# Production Verification Test
# ============================================================

from app.services.notification_service import create_alert
from app.models.notification import (
    get_finding_notifications,
    notification_collection,
)


# ============================================================
# TEST DATA
# ============================================================

TEST_USER_ID = "ESCALATION_TEST_USER"
TEST_FINDING_ID = "ESCALATION_TEST_FINDING"


# ============================================================
# CLEAN PREVIOUS TEST DATA
# ============================================================

print("\n============================================================")
print(" CloudGuardAI - Notification Escalation Test")
print("============================================================")

print("\n[1] Cleaning previous test notifications...")

notification_collection.delete_many(
    {
        "user_id": TEST_USER_ID,
        "finding_id": TEST_FINDING_ID,
    }
)

print("[OK] Previous test data removed.")


# ============================================================
# TEST 1 - CREATE HIGH NOTIFICATION
# ============================================================

print("\n[2] Creating HIGH notification...")

high_id = create_alert(
    title="Test Security Risk",
    message="Test finding is HIGH severity.",
    severity="HIGH",
    user_id=TEST_USER_ID,
    finding_id=TEST_FINDING_ID,
    account_id="TEST_ACCOUNT",
    aws_account_id="000000000000",
    account_name="Escalation Test Account",
    service="EC2",
    resource="test-instance",
    detection_status="EXPOSED",
)

print(f"[RESULT] HIGH notification ID: {high_id}")


# ============================================================
# TEST 2 - SAME HIGH AGAIN
# ============================================================

print("\n[3] Creating the SAME HIGH notification again...")

duplicate_high_id = create_alert(
    title="Test Security Risk",
    message="Test finding is HIGH severity.",
    severity="HIGH",
    user_id=TEST_USER_ID,
    finding_id=TEST_FINDING_ID,
    account_id="TEST_ACCOUNT",
    aws_account_id="000000000000",
    account_name="Escalation Test Account",
    service="EC2",
    resource="test-instance",
    detection_status="EXPOSED",
)

print(
    f"[RESULT] Duplicate HIGH returned ID: "
    f"{duplicate_high_id}"
)


# ============================================================
# TEST 3 - ESCALATE TO CRITICAL
# ============================================================

print("\n[4] Escalating finding from HIGH → CRITICAL...")

critical_id = create_alert(
    title="Test Security Risk Escalated",
    message="Test finding has escalated to CRITICAL severity.",
    severity="CRITICAL",
    user_id=TEST_USER_ID,
    finding_id=TEST_FINDING_ID,
    account_id="TEST_ACCOUNT",
    aws_account_id="000000000000",
    account_name="Escalation Test Account",
    service="EC2",
    resource="test-instance",
    detection_status="EXPOSED",
)

print(
    f"[RESULT] CRITICAL escalation ID: "
    f"{critical_id}"
)


# ============================================================
# FETCH HISTORY
# ============================================================

print("\n[5] Reading notification history...")

history = get_finding_notifications(
    user_id=TEST_USER_ID,
    finding_id=TEST_FINDING_ID,
    limit=20,
)


# ============================================================
# DISPLAY RESULTS
# ============================================================

print("\n============================================================")
print(" NOTIFICATION HISTORY")
print("============================================================")

for index, notification in enumerate(
    history,
    start=1,
):
    print(f"\nNotification #{index}")

    print(
        "  ID: "
        f"{notification.get('_id')}"
    )

    print(
        "  Severity: "
        f"{notification.get('severity')}"
    )

    print(
        "  Type: "
        f"{notification.get('notification_type')}"
    )

    print(
        "  Previous Severity: "
        f"{notification.get('previous_severity')}"
    )


# ============================================================
# VALIDATION
# ============================================================

print("\n============================================================")
print(" VALIDATION")
print("============================================================")

total = len(history)

high_notifications = [
    item
    for item in history
    if item.get("severity") == "HIGH"
]

critical_notifications = [
    item
    for item in history
    if item.get("severity") == "CRITICAL"
]

escalations = [
    item
    for item in history
    if item.get("notification_type")
    == "SECURITY_FINDING_ESCALATION"
]


print(f"\nTotal notifications: {total}")
print(f"HIGH notifications: {len(high_notifications)}")
print(f"CRITICAL notifications: {len(critical_notifications)}")
print(f"Escalation notifications: {len(escalations)}")


# ============================================================
# EXPECTED RESULTS
# ============================================================

if total != 2:
    print(
        "\n[FAIL] Expected exactly 2 notifications."
    )
    raise SystemExit(1)


if len(high_notifications) != 1:
    print(
        "\n[FAIL] Expected exactly 1 HIGH notification."
    )
    raise SystemExit(1)


if len(critical_notifications) != 1:
    print(
        "\n[FAIL] Expected exactly 1 CRITICAL notification."
    )
    raise SystemExit(1)


if len(escalations) != 1:
    print(
        "\n[FAIL] Expected exactly 1 escalation notification."
    )
    raise SystemExit(1)


escalation = escalations[0]

if escalation.get("previous_severity") != "HIGH":
    print(
        "\n[FAIL] Escalation previous_severity "
        "should be HIGH."
    )
    raise SystemExit(1)


# ============================================================
# SUCCESS
# ============================================================

print("\n============================================================")
print(" [PASS] SEVERITY ESCALATION TEST PASSED")
print("============================================================")

print(
    "\nVerified:"
    "\n  ✓ HIGH notification created"
    "\n  ✓ Duplicate HIGH suppressed"
    "\n  ✓ HIGH → CRITICAL escalation created"
    "\n  ✓ previous_severity = HIGH"
    "\n  ✓ Exactly 2 notifications exist"
)

print("\nCloudGuardAI notification escalation is working.\n")