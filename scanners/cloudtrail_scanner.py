import boto3
from botocore.exceptions import ClientError
from rules.cloudtrail_rules import generate_cloudtrail_findings


class CloudTrailScanner:
    def __init__(self):
        self.session = boto3.Session()
        self.cloudtrail = self.session.client("cloudtrail", region_name="us-east-1")

    def get_account_trails(self):
        response = self.cloudtrail.describe_trails(includeShadowTrails=True)
        trails = response.get("trailList", [])

        enriched_trails = []

        for trail in trails:
            trail_name = trail["Name"]

            try:
                status = self.cloudtrail.get_trail_status(Name=trail_name)
                trail["IsLogging"] = status.get("IsLogging", False)
            except ClientError:
                trail["IsLogging"] = False

            enriched_trails.append(trail)

        return enriched_trails

    def scan_trails(self):
        trails = self.get_account_trails()
        return generate_cloudtrail_findings(trails)


if __name__ == "__main__":
    scanner = CloudTrailScanner()
    findings = scanner.scan_trails()

    print("CloudTrail Security Findings:")

    for finding in findings:
        print("\n-----------------------------")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Resource      : {finding.resource_id}")
        print(f"Region        : {finding.region}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Risk Score    : {finding.risk_score()}")
        print(f"Description   : {finding.description}")
