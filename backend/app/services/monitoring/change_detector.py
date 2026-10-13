def detect_changes(old_scan, new_scan):

    changes = []


    if not old_scan:
        return [
            "First scan created"
        ]



    old_risk = old_scan.get(
        "risk_score",
        0
    )


    new_risk = new_scan.get(
        "risk_score",
        0
    )


    if new_risk > old_risk:

        changes.append(
            f"Risk increased {old_risk} → {new_risk}"
        )


    old_findings = len(
        old_scan.get(
            "findings",
            []
        )
    )


    new_findings = len(
        new_scan.get(
            "findings",
            []
        )
    )


    if new_findings > old_findings:

        changes.append(
            "New security findings detected"
        )



    return changes