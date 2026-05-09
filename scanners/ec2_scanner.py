import boto3
from botocore.exceptions import ClientError
from rules.ec2_rules import generate_ec2_findings


class EC2Scanner:
    def __init__(self):
        self.session = boto3.Session()
        self.ec2_global = self.session.client("ec2", region_name="us-east-1")

    def get_enabled_regions(self):
        response = self.ec2_global.describe_regions(AllRegions=True)

        regions = []

        for region in response.get("Regions", []):
            region_name = region["RegionName"]
            opt_status = region.get("OptInStatus", "opt-in-not-required")

            if opt_status in ["opt-in-not-required", "opted-in"]:
                regions.append(region_name)

        return regions

    def get_security_groups(self, region_name):
        ec2 = self.session.client("ec2", region_name=region_name)
        response = ec2.describe_security_groups()
        return response.get("SecurityGroups", [])

    def get_instances(self, region_name):
        ec2 = self.session.client("ec2", region_name=region_name)

        response = ec2.describe_instances()

        instances = []

        for reservation in response["Reservations"]:
            instances.extend(reservation["Instances"])

        return instances

    def scan_security_groups(self):
        all_findings = []

        regions = self.get_enabled_regions()

        for region in regions:
            try:
                security_groups = self.get_security_groups(region)
                instances = self.get_instances(region)

                findings = generate_ec2_findings(
                    security_groups,
                    instances,
                    region
                )

                all_findings.extend(findings)

            except ClientError as e:
                print(f"Skipping region {region}: {e.response['Error']['Message']}")

            except Exception as e:
                print(f"Unexpected error in region {region}: {e}")

        return all_findings


if __name__ == "__main__":
    scanner = EC2Scanner()

    findings = scanner.scan_security_groups()

    print("EC2 Findings Across All Regions:")

    for finding in findings:
        print("\n-----------------------------")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Resource      : {finding.resource_id}")
        print(f"Region        : {finding.region}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Risk Score    : {finding.risk_score()}")
        print(f"Description   : {finding.description}")
