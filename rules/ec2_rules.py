from models.finding import Finding


def generate_ec2_findings(security_groups, instances, region_name):
    findings = []

    # -----------------------------------
    # SECURITY GROUP CHECKS
    # -----------------------------------
    for sg in security_groups:
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort")

            for ip_range in rule.get("IpRanges", []):
                cidr = ip_range.get("CidrIp")

                if cidr == "0.0.0.0/0":

                    # SSH OPEN
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
                            asset_sensitivity=4,
                            region=region_name
                        ))

                    # RDP OPEN
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
                            asset_sensitivity=4,
                            region=region_name
                        ))

    # -----------------------------------
    # INSTANCE-LEVEL CHECKS
    # -----------------------------------
    for instance in instances:

        instance_id = instance["InstanceId"]

        # PUBLIC IP CHECK
        if instance.get("PublicIpAddress"):
            findings.append(Finding(
                resource_id=instance_id,
                resource_type="EC2Instance",
                rule_id="EC2-003",
                title="Instance has public IP address",
                description=f"EC2 instance '{instance_id}' is publicly accessible.",
                severity="Medium",
                impact=4,
                likelihood=3,
                exposure=4,
                asset_sensitivity=3,
                region=region_name
            ))

        # MONITORING CHECK
        monitoring = instance.get("Monitoring", {}).get("State")

        if monitoring != "enabled":
            findings.append(Finding(
                resource_id=instance_id,
                resource_type="EC2Instance",
                rule_id="EC2-004",
                title="Detailed monitoring disabled",
                description=f"EC2 instance '{instance_id}' does not have detailed monitoring enabled.",
                severity="Low",
                impact=2,
                likelihood=2,
                exposure=2,
                asset_sensitivity=2,
                region=region_name
            ))

        # IAM ROLE CHECK
        if "IamInstanceProfile" not in instance:
            findings.append(Finding(
                resource_id=instance_id,
                resource_type="EC2Instance",
                rule_id="EC2-005",
                title="No IAM role attached",
                description=f"EC2 instance '{instance_id}' does not have an IAM role attached.",
                severity="Medium",
                impact=3,
                likelihood=3,
                exposure=2,
                asset_sensitivity=3,
                region=region_name
            ))

    return findings
