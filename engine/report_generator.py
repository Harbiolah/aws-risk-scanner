import json
import csv
from pathlib import Path


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def save_findings_to_json(findings, filename="outputs/findings.json"):
    """
    Save findings to JSON.
    If findings is empty, do not overwrite an existing report with [].
    """
    if not findings:
        print("No findings to save to JSON. Existing JSON report was preserved.")
        return

    data = [finding.to_dict() for finding in findings]

    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def save_findings_to_csv(findings, filename="outputs/findings.csv"):
    """
    Save findings to CSV.
    If findings is empty, do not overwrite an existing report.
    """
    if not findings:
        print("No findings to save to CSV. Existing CSV report was preserved.")
        return

    fieldnames = list(findings[0].to_dict().keys())

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for finding in findings:
            writer.writerow(finding.to_dict())
