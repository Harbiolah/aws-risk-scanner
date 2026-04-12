import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from rules.s3_rules import generate_s3_findings
from engine.report_generator import save_findings_to_json, save_findings_to_csv


class S3Scanner:
    def __init__(self, profile_name=None):
        if profile_name:
            self.session = boto3.Session(profile_name=profile_name)
        else:
            self.session = boto3.Session()

        self.s3 = self.session.client("s3")

    def list_buckets(self):
        try:
            response = self.s3.list_buckets()
            return response.get("Buckets", [])
        except NoCredentialsError:
            print("AWS credentials not found.")
            return []
        except ClientError as e:
            print(f"AWS client error while listing buckets: {e}")
            return []
        except Exception as e:
            print(f"Unexpected error while listing buckets: {e}")
            return []

    def check_bucket_encryption(self, bucket_name):
        try:
            self.s3.get_bucket_encryption(Bucket=bucket_name)
            return "Enabled"
        except ClientError:
            return "Not Enabled"

    def check_bucket_versioning(self, bucket_name):
        try:
            response = self.s3.get_bucket_versioning(Bucket=bucket_name)
            return response.get("Status", "Disabled")
        except ClientError:
            return "Unknown"

    def check_bucket_public_access(self, bucket_name):
        try:
            response = self.s3.get_public_access_block(Bucket=bucket_name)
            config = response.get("PublicAccessBlockConfiguration", {})

            all_blocked = (
                config.get("BlockPublicAcls", False)
                and config.get("IgnorePublicAcls", False)
                and config.get("BlockPublicPolicy", False)
                and config.get("RestrictPublicBuckets", False)
            )

            if all_blocked:
                return "Blocked"
            return "Possibly Public"

        except ClientError:
            return "Unknown or Not Configured"

    def scan_buckets(self):
        buckets = self.list_buckets()
        results = []

        for bucket in buckets:
            bucket_name = bucket["Name"]
            results.append({
                "bucket_name": bucket_name,
                "encryption": self.check_bucket_encryption(bucket_name),
                "versioning": self.check_bucket_versioning(bucket_name),
                "public_access": self.check_bucket_public_access(bucket_name),
            })

        return results


from rules.s3_rules import generate_s3_findings


if __name__ == "__main__":
    scanner = S3Scanner()
    results = scanner.scan_buckets()
    findings = generate_s3_findings(results)

    print("S3 Bucket Security Findings:")
    for finding in findings:
        print("\n-----------------------------")
        print(f"Rule ID       : {finding.rule_id}")
        print(f"Resource      : {finding.resource_id}")
        print(f"Title         : {finding.title}")
        print(f"Severity      : {finding.severity}")
        print(f"Risk Score    : {finding.risk_score()}")
        print(f"Description   : {finding.description}")

    save_findings_to_json(findings)
    save_findings_to_csv(findings)

    print("\nReports saved successfully to outputs/findings.json and outputs/findings.csv")
