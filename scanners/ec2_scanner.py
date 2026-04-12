import boto3
from rules.ec2_rules import generate_ec2_findings


class EC2Scanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def get_security_groups(self):
        response = self.ec2.describe_security_groups()
        return response.get("SecurityGroups", [])

    def scan_security_groups(self):
        security_groups = self.get_security_groups()
        return generate_ec2_findings(security_groups)


if __name__ == "__main__":
    scanner = EC2Scanner()
    findings = scanner.scan_security_groups()

    print("EC2 Security Findings:")
    for finding in findings:
        print("\n-----------------------------")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Resource      : {finding.resource_id}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Risk Score    : {finding.risk_score()}")
        print(f"Description   : {finding.description}")
