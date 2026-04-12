def summarize_findings(findings):
    total_findings = len(findings)
    high = sum(1 for f in findings if f.severity == "High")
    medium = sum(1 for f in findings if f.severity == "Medium")
    low = sum(1 for f in findings if f.severity == "Low")

    average_risk = 0
    if findings:
        average_risk = round(
            sum(f.risk_score() for f in findings) / len(findings),
            2
        )

    return {
        "total_findings": total_findings,
        "high": high,
        "medium": medium,
        "low": low,
        "average_risk_score": average_risk
    }
