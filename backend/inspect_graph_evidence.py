from app.database.connection import db

findings = list(
    db.findings.find(
        {},
        {
            "_id": 0,
            "finding_id": 1,
            "service": 1,
            "resource": 1,
            "resource_type": 1,
            "arn": 1,
            "severity": 1,
            "issue": 1,
            "detection_status": 1,
            "security_graph": 1,
            "evidence": 1,
        },
    ).limit(100)
)

print("=" * 80)
print("CloudGuardAI - Graph Evidence Inspector")
print("=" * 80)

print(f"\nTotal findings inspected: {len(findings)}\n")

for index, finding in enumerate(findings, 1):
    print("\n" + "-" * 80)
    print(f"FINDING #{index}")
    print("-" * 80)

    print("finding_id     :", finding.get("finding_id"))
    print("service        :", finding.get("service"))
    print("resource       :", finding.get("resource"))
    print("resource_type  :", finding.get("resource_type"))
    print("arn            :", finding.get("arn"))
    print("severity       :", finding.get("severity"))
    print("issue          :", finding.get("issue"))
    print("detection      :", finding.get("detection_status"))

    print("\nsecurity_graph:")
    print(finding.get("security_graph") or {})

    print("\nevidence:")
    print(finding.get("evidence") or {})