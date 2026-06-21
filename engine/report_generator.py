import json
import csv
from pathlib import Path
from datetime import datetime


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def save_structured_json_report(findings, summary, correlated_risks, filename="outputs/security_report.json"):
    report = {
        "metadata": {
            "project": "AWS Misconfiguration Detection and Risk Scoring Framework",
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scanner_version": "1.0",
            "cloud_provider": "AWS"
        },
        "summary": summary,
        "correlated_risks": correlated_risks,
        "findings": [finding.to_dict() for finding in findings]
    }

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)


def save_findings_to_json(findings, filename="outputs/all_findings.json"):
    if not findings:
        print("No findings to save to JSON. Existing JSON report was preserved.")
        return

    data = [finding.to_dict() for finding in findings]

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def save_findings_to_csv(findings, filename="outputs/all_findings.csv"):
    if not findings:
        print("No findings to save to CSV. Existing CSV report was preserved.")
        return

    fieldnames = list(findings[0].to_dict().keys())

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding.to_dict())
