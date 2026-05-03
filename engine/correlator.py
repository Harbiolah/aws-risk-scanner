def correlate_findings(findings):
    """
    Detect compound risks by combining related findings.
    """
    correlated_risks = []

    has_public_s3 = any(f.rule_id == "S3-002" for f in findings)
    has_no_mfa = any(f.rule_id == "IAM-002" for f in findings)
    has_ssh_open = any(f.rule_id == "EC2-001" for f in findings)
    has_admin_access = any(f.rule_id == "IAM-001" for f in findings)

    if has_public_s3 and has_no_mfa:
        correlated_risks.append({
            "correlation_id": "CORR-001",
            "title": "Public S3 Bucket with Weak IAM Protection",
            "severity": "Critical",
            "description": "A publicly accessible S3 bucket combined with an IAM user without MFA increases the risk of unauthorized data access.",
            "related_findings": ["S3-002", "IAM-002"]
        })

    if has_ssh_open and has_no_mfa:
        correlated_risks.append({
            "correlation_id": "CORR-002",
            "title": "Exposed Server with Weak Authentication",
            "severity": "High",
            "description": "SSH open to the internet combined with an IAM user without MFA increases the likelihood of unauthorized access.",
            "related_findings": ["EC2-001", "IAM-002"]
        })

    if has_admin_access and has_no_mfa:
        correlated_risks.append({
            "correlation_id": "CORR-003",
            "title": "Privileged User Without MFA",
            "severity": "Critical",
            "description": "An administrative IAM user without MFA creates a high-impact account compromise risk.",
            "related_findings": ["IAM-001", "IAM-002"]
        })

    return correlated_risks
