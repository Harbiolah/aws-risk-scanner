import boto3


class EC2Scanner:
    def __init__(self):
        self.ec2 = boto3.client("ec2")

    def get_security_groups(self):
        response = self.ec2.describe_security_groups()
        return response.get("SecurityGroups", [])

    def scan_security_groups(self):
        findings = []

        security_groups = self.get_security_groups()

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
                            findings.append({
                                "rule_id": "EC2-001",
                                "resource": sg_id,
                                "title": "SSH port open to the world",
                                "severity": "High",
                                "description": f"Security Group '{sg_name}' allows SSH (port 22) from anywhere."
                            })

                        if from_port == 3389:
                            findings.append({
                                "rule_id": "EC2-002",
                                "resource": sg_id,
                                "title": "RDP port open to the world",
                                "severity": "High",
                                "description": f"Security Group '{sg_name}' allows RDP (port 3389) from anywhere."
                            })

        return findings


if __name__ == "__main__":
    scanner = EC2Scanner()
    findings = scanner.scan_security_groups()

    print("EC2 Security Findings:")
    for f in findings:
        print("\n-----------------------------")
        print(f"Rule ID     : {f['rule_id']}")
        print(f"Resource    : {f['resource']}")
        print(f"Title       : {f['title']}")
        print(f"Severity    : {f['severity']}")
        print(f"Description : {f['description']}")
