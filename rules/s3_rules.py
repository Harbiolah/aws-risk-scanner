from models.finding import Finding


def generate_s3_findings(scan_results):
    findings = []

    for result in scan_results:
        bucket_name = result["bucket_name"]

        if result["versioning"] == "Disabled":
            findings.append(Finding(
                resource_id=bucket_name,
                resource_type="S3Bucket",
                rule_id="S3-001",
                title="Bucket versioning is disabled",
                description=f"S3 bucket '{bucket_name}' has versioning disabled.",
                severity="Medium",
                impact=3,
                likelihood=3,
                exposure=2,
                asset_sensitivity=3
            ))

        if result["public_access"] == "Possibly Public":
            findings.append(Finding(
                resource_id=bucket_name,
                resource_type="S3Bucket",
                rule_id="S3-002",
                title="Bucket may be publicly accessible",
                description=f"S3 bucket '{bucket_name}' may allow public access.",
                severity="High",
                impact=5,
                likelihood=4,
                exposure=5,
                asset_sensitivity=4
            ))

        if result["encryption"] == "Not Enabled":
            findings.append(Finding(
                resource_id=bucket_name,
                resource_type="S3Bucket",
                rule_id="S3-003",
                title="Bucket encryption is not enabled",
                description=f"S3 bucket '{bucket_name}' does not have server-side encryption enabled.",
                severity="High",
                impact=4,
                likelihood=3,
                exposure=3,
                asset_sensitivity=4
            ))

    return findings
