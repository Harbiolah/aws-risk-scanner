def evaluate_context(finding):
    """
    Adjusts risk factors based on resource context.
    This makes scoring more realistic than static rule-only scoring.
    """

    impact = finding.impact
    likelihood = finding.likelihood
    exposure = finding.exposure
    asset_sensitivity = finding.asset_sensitivity

    resource_id = finding.resource_id.lower()
    rule_id = finding.rule_id

    # S3 public/static website context
    if rule_id == "S3-002":
        exposure += 1

        if "website" in resource_id or "static" in resource_id:
            asset_sensitivity += 1

    # EC2 SSH open to world context
    if rule_id == "EC2-001":
        exposure += 1
        likelihood += 1

    # IAM no MFA context
    if rule_id == "IAM-002":
        likelihood += 1

    # Keep values within 1–5 range
    impact = min(impact, 5)
    likelihood = min(likelihood, 5)
    exposure = min(exposure, 5)
    asset_sensitivity = min(asset_sensitivity, 5)

    return impact, likelihood, exposure, asset_sensitivity
