from models.finding import Finding


def generate_iam_findings(users, iam_client):
    findings = []

    for user in users:
        username = user["UserName"]

        # Rule 1: Check for AdministratorAccess policy
        attached_policies = iam_client.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
        for policy in attached_policies:
            if policy["PolicyName"] == "AdministratorAccess":
                findings.append(Finding(
                    resource_id=username,
                    resource_type="IAMUser",
                    rule_id="IAM-001",
                    title="User has AdministratorAccess policy",
                    description=f"IAM user '{username}' has the AdministratorAccess policy attached.",
                    severity="High",
                    impact=5,
                    likelihood=4,
                    exposure=4,
                    asset_sensitivity=5
                ))

        # Rule 2: Check if console password exists but MFA is not enabled
        try:
            iam_client.get_login_profile(UserName=username)
            mfa_devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])
            if not mfa_devices:
                findings.append(Finding(
                    resource_id=username,
                    resource_type="IAMUser",
                    rule_id="IAM-002",
                    title="Console user does not have MFA enabled",
                    description=f"IAM user '{username}' has console access but no MFA device enabled.",
                    severity="Medium",
                    impact=4,
                    likelihood=3,
                    exposure=3,
                    asset_sensitivity=4
                ))
        except iam_client.exceptions.NoSuchEntityException:
            # No console access
            pass

    return findings
