from scanners.s3_scanner import S3Scanner
from scanners.ec2_scanner import EC2Scanner
from scanners.iam_scanner import IAMScanner

from rules.s3_rules import generate_s3_findings

from engine.report_generator import save_findings_to_json, save_findings_to_csv
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
            print(f"- {finding.rule_id}: {finding.title} ({finding.resource_id})")
    else:
        print("- No S3 findings detected")

    # EC2 Findings
    print("\nEC2 Findings:")
    if ec2_findings:
        for finding in ec2_findings:
            print(f"- {finding.rule_id}: {finding.title} ({finding.resource_id}) [{finding.region}]")
    else:
        print("- No EC2 findings detected")

    # IAM Findings
    print("\nIAM Findings:")
    if iam_findings:
        for finding in iam_findings:
            print(f"- {finding.rule_id}: {finding.title} ({finding.resource_id})")
    else:
        print("- No IAM findings detected")

    # Correlated Risks
    print("\nCorrelated Risks:")
    if correlated_risks:
        for risk in correlated_risks:
            print(f"- {risk['correlation_id']}: {risk['title']} ({risk['severity']})")
    else:
        print("- No correlated risks detected")

    # Save Reports
    if all_findings:
        save_findings_to_json(all_findings, "outputs/all_findings.json")
        save_findings_to_csv(all_findings, "outputs/all_findings.csv")
        print("\nCombined reports saved successfully.")
    else:
        print("\nNo findings generated.")

    # Summary Output
    print("\nSummary:")
    print(f"Total Findings      : {summary['total_findings']}")
    print(f"High Severity       : {summary['high']}")
    print(f"Medium Severity     : {summary['medium']}")
    print(f"Low Severity        : {summary['low']}")
    print(f"Average Risk Score  : {summary['average_risk_score']}")

    print("\nScan completed.")


if __name__ == "__main__":
    main()
