import json
import csv
from pathlib import Path


OUTPUT_DIR = Path("outputs")
OUTPUT_DIR.mkdir(exist_ok=True)


def save_findings_to_json(findings, filename="outputs/findings.json"):
    data = [finding.to_dict() for finding in findings]
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def save_findings_to_csv(findings, filename="outputs/findings.csv"):
    if not findings:
        return

    fieldnames = list(findings[0].to_dict().keys())

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding.to_dict())
