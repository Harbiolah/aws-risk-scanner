import boto3
from botocore.exceptions import ClientError
from rules.rds_rules import generate_rds_findings


class RDSScanner:
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

    def get_db_instances(self, region_name):
        rds = self.session.client("rds", region_name=region_name)
        response = rds.describe_db_instances()
        return response.get("DBInstances", [])

    def scan_databases(self):
        all_findings = []
        regions = self.get_enabled_regions()

        for region in regions:
            try:
                db_instances = self.get_db_instances(region)
                findings = generate_rds_findings(db_instances, region)
                all_findings.extend(findings)

            except ClientError as e:
                error_code = e.response["Error"]["Code"]

                # Some regions may not support RDS or may be unavailable
                if error_code in ["OptInRequired", "AuthFailure", "UnauthorizedOperation"]:
                    print(f"Skipping RDS scan in {region}: {e.response['Error']['Message']}")
                else:
                    print(f"RDS error in {region}: {e.response['Error']['Message']}")

            except Exception as e:
                print(f"Unexpected error in RDS scan for {region}: {e}")

        return all_findings


if __name__ == "__main__":
    scanner = RDSScanner()
    findings = scanner.scan_databases()

    print("RDS Security Findings Across All Regions:")

    if findings:
        for finding in findings:
            print("\n-----------------------------")
            print(f"Rule ID       : {finding.rule_id}")
            print(f"Resource      : {finding.resource_id}")
            print(f"Region        : {finding.region}")
            print(f"Title         : {finding.title}")
            print(f"Severity      : {finding.severity}")
            print(f"Risk Score    : {finding.risk_score()}")
            print(f"Description   : {finding.description}")
    else:
        print("No RDS findings detected.")
