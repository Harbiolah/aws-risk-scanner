from models.finding import Finding


def generate_cloudtrail_findings(trails):
    findings = []

    if not trails:
        findings.append(Finding(
            resource_id="cloudtrail-global",
            resource_type="CloudTrail",
            rule_id="CT-001",
            title="CloudTrail is not enabled globally",
            description="No CloudTrail trail was found in the AWS account. This reduces audit visibility and incident investigation capability.",
            severity="High",
            impact=5,
            likelihood=4,
            exposure=4,
            asset_sensitivity=4,
            region="global"
        ))
        return findings

    has_multi_region_trail = any(
        trail.get("IsMultiRegionTrail", False) for trail in trails
    )

    if not has_multi_region_trail:
        findings.append(Finding(
            resource_id="cloudtrail-global",
            resource_type="CloudTrail",
            rule_id="CT-002",
            title="No multi-region CloudTrail configured",
            description="CloudTrail exists, but no multi-region trail was found. Activity in some regions may not be fully monitored.",
            severity="Medium",
            impact=4,
            likelihood=3,
            exposure=3,
            asset_sensitivity=4,
            region="global"
        ))

    for trail in trails:
        trail_name = trail.get("Name", "UnknownTrail")

        if not trail.get("LogFileValidationEnabled", False):
            findings.append(Finding(
                resource_id=trail_name,
                resource_type="CloudTrail",
                rule_id="CT-003",
                title="CloudTrail log file validation is disabled",
                description=f"CloudTrail trail '{trail_name}' does not have log file validation enabled.",
                severity="Medium",
                impact=4,
                likelihood=3,
                exposure=3,
                asset_sensitivity=4,
                region=trail.get("HomeRegion", "global")
            ))

    return findings
