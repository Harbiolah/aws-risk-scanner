from scanners.s3_scanner import S3Scanner
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner
from scanners.cloudtrail_scanner import CloudTrailScanner
from scanners.rds_scanner import RDSScanner
from scanners.vpc_scanner import VPCScanner

from rules.s3_rules import generate_s3_findings

from engine.report_generator import (
    save_findings_to_json,
    save_findings_to_csv,
    save_structured_json_report
)

from engine.risk_engine import summarize_findings
from engine.correlator import correlate_findings


def main():
    all_findings = []

    # S3 Scan
    s3_scanner = S3Scanner()
    s3_results = s3_scanner.scan_buckets()
    s3_findings = generate_s3_findings(s3_results)
    all_findings.extend(s3_findings)

    # EC2 Scan
    ec2_scanner = EC2Scanner()
    ec2_findings = ec2_scanner.scan_security_groups()
    all_findings.extend(ec2_findings)

    # IAM Scan
    iam_scanner = IAMScanner()
    iam_findings = iam_scanner.scan_users()
    all_findings.extend(iam_findings)

    # CloudTrail Scan
    cloudtrail_scanner = CloudTrailScanner()
    cloudtrail_findings = cloudtrail_scanner.scan_trails()
    all_findings.extend(cloudtrail_findings)

    # RDS Scan
    rds_scanner = RDSScanner()
    rds_findings = rds_scanner.scan_databases()
    all_findings.extend(rds_findings)

    # VPC Scan
    vpc_scanner = VPCScanner()
    vpc_findings = vpc_scanner.scan_vpcs()
    all_findings.extend(vpc_findings)

    # Summary
    summary = summarize_findings(all_findings)

    # Correlation
    correlated_risks = correlate_findings(all_findings)

    print("AWS Misconfiguration Scan Results")
    print("=" * 40)

    # S3 Findings
    print("\nS3 Findings:")
    if s3_findings:
        for finding in s3_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id})"
            )
    else:
        print("- No S3 findings detected")

    # EC2 Findings
    print("\nEC2 Findings:")
    if ec2_findings:
        for finding in ec2_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id}) "
                f"[{finding.region}]"
            )
    else:
        print("- No EC2 findings detected")

    # IAM Findings
    print("\nIAM Findings:")
    if iam_findings:
        for finding in iam_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id})"
            )
    else:
        print("- No IAM findings detected")

    # CloudTrail Findings
    print("\nCloudTrail Findings:")
    if cloudtrail_findings:
        for finding in cloudtrail_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id}) "
                f"[{finding.region}]"
            )
    else:
        print("- No CloudTrail findings detected")

    # RDS Findings
    print("\nRDS Findings:")
    if rds_findings:
        for finding in rds_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id}) "
                f"[{finding.region}]"
            )
    else:
        print("- No RDS findings detected")

    # VPC Findings
    print("\nVPC Findings:")
    if vpc_findings:
        for finding in vpc_findings:
            print(
                f"- {finding.rule_id}: "
                f"{finding.title} "
                f"({finding.resource_id}) "
                f"[{finding.region}]"
            )
    else:
        print("- No VPC findings detected")

    # Correlated Risks
    print("\nCorrelated Risks:")
    if correlated_risks:
        for risk in correlated_risks:
            print(
                f"- {risk['correlation_id']}: "
                f"{risk['title']} "
                f"({risk['severity']})"
            )
    else:
        print("- No correlated risks detected")

    # Save Reports
    if all_findings:

        save_findings_to_json(
            all_findings,
            "outputs/all_findings.json"
        )

        save_findings_to_csv(
            all_findings,
            "outputs/all_findings.csv"
        )

        save_structured_json_report(
            all_findings,
            summary,
            correlated_risks,
            "outputs/security_report.json"
        )

        print("\nCombined reports saved successfully.")

    else:
        print("\nNo findings generated.")

    # Summary
    print("\nSummary:")
    print(f"Total Findings      : {summary['total_findings']}")
    print(f"High Severity       : {summary['high']}")
    print(f"Medium Severity     : {summary['medium']}")
    print(f"Low Severity        : {summary['low']}")
    print(f"Average Risk Score  : {summary['average_risk_score']}")

    print("\nScan completed.")


if __name__ == "__main__":
    main()
