import boto3
from rules.iam_rules import generate_iam_findings


class IAMScanner:
    def __init__(self):
        self.iam = boto3.client("iam")

    def get_users(self):
        response = self.iam.list_users()
        return response.get("Users", [])

    def scan_users(self):
        users = self.get_users()
        return generate_iam_findings(users, self.iam)


if __name__ == "__main__":
    scanner = IAMScanner()
    findings = scanner.scan_users()

    print("IAM Security Findings:")
    for finding in findings:
        print("\n-----------------------------")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Resource      : {finding.resource_id}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Risk Score    : {finding.risk_score()}")
        print(f"Description   : {finding.description}")
