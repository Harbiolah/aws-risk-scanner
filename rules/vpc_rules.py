from models.finding import Finding


def create_default_vpc_finding(vpc_id, region):
    return Finding(
        resource_id=vpc_id,
        resource_type="VPC",
        rule_id="VPC-001",
        title="Default VPC exists",
        description=f"Default VPC '{vpc_id}' exists in region '{region}'.",
        severity="Low",
        impact=2,
        likelihood=2,
        exposure=2,
        asset_sensitivity=2,
        region=region
    )


def create_public_subnet_finding(subnet_id, region):
    return Finding(
        resource_id=subnet_id,
        resource_type="Subnet",
        rule_id="VPC-002",
        title="Public subnet detected",
        description=f"Subnet '{subnet_id}' automatically assigns public IP addresses.",
        severity="Medium",
        impact=3,
        likelihood=3,
        exposure=3,
        asset_sensitivity=3,
        region=region
    )
