import boto3

from rules.vpc_rules import (
    create_default_vpc_finding
)


class VPCScanner:

    def __init__(self):
        self.session = boto3.Session()

    def get_regions(self):

        ec2 = self.session.client(
            "ec2",
            region_name="us-east-1"
        )

        response = ec2.describe_regions()

        return [
            region["RegionName"]
            for region in response["Regions"]
        ]

    def scan_vpcs(self):

        findings = []

        for region in self.get_regions():

            try:

                ec2 = self.session.client(
                    "ec2",
                    region_name=region
                )

                vpcs = ec2.describe_vpcs()["Vpcs"]

                for vpc in vpcs:

                    if vpc.get("IsDefault", False):

                        findings.append(
                            create_default_vpc_finding(
                                vpc["VpcId"],
                                region
                            )
                        )

            except Exception:
                continue

        return findings


if __name__ == "__main__":

    scanner = VPCScanner()

    findings = scanner.scan_vpcs()

    print("VPC Security Findings:\n")

    if findings:

        for finding in findings:

            print("-----------------------------")
            print(f"Rule ID       : {finding.rule_id}")
            print(f"Resource      : {finding.resource_id}")
            print(f"Region        : {finding.region}")
            print(f"Title         : {finding.title}")
            print(f"Severity      : {finding.severity}")
            print(f"Risk Score    : {finding.risk_score()}")
            print(f"Description   : {finding.description}")
            print()

    else:
        print("No VPC findings detected.")
