from models.finding import Finding


def generate_ec2_findings(security_groups):
    findings = []

    for sg in security_groups:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")
            to_port = rule.get("ToPort")

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")

                if cidr == "0.0.0.0/0":
                    if from_port == 22:
                        findings.append(Finding(
                            resource_id=sg_id,
                            resource_type="SecurityGroup",
                            rule_id="EC2-001",
                            title="SSH port open to the world",
                            description=f"Security Group '{sg_name}' allows SSH (port 22) from anywhere.",
                            severity="High",
                            impact=5,
                            likelihood=4,
                            exposure=5,
                            asset_sensitivity=4
                        ))

                    if from_port == 3389:
                        findings.append(Finding(
                            resource_id=sg_id,
                            resource_type="SecurityGroup",
                            rule_id="EC2-002",
                            title="RDP port open to the world",
                            description=f"Security Group '{sg_name}' allows RDP (port 3389) from anywhere.",
                            severity="High",
                            impact=5,
                            likelihood=4,
                            exposure=5,
                            asset_sensitivity=4
                        ))

    return findings
