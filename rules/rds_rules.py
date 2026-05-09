from models.finding import Finding


def generate_rds_findings(db_instances, region_name):
    findings = []

    for db in db_instances:
        db_id = db.get("DBInstanceIdentifier", "unknown-rds")

        if db.get("PubliclyAccessible", False):
            findings.append(Finding(
                resource_id=db_id,
                resource_type="RDSInstance",
                rule_id="RDS-001",
                title="RDS instance is publicly accessible",
                description=f"RDS instance '{db_id}' is publicly accessible from the internet.",
                severity="High",
                impact=5,
                likelihood=4,
                exposure=5,
                asset_sensitivity=5,
                region=region_name
            ))

        if not db.get("StorageEncrypted", False):
            findings.append(Finding(
                resource_id=db_id,
                resource_type="RDSInstance",
                rule_id="RDS-002",
                title="RDS storage encryption is disabled",
                description=f"RDS instance '{db_id}' does not have storage encryption enabled.",
                severity="High",
                impact=5,
                likelihood=3,
                exposure=3,
                asset_sensitivity=5,
                region=region_name
            ))

        backup_retention = db.get("BackupRetentionPeriod", 0)
        if backup_retention == 0:
            findings.append(Finding(
                resource_id=db_id,
                resource_type="RDSInstance",
                rule_id="RDS-003",
                title="RDS automated backups are disabled",
                description=f"RDS instance '{db_id}' has automated backups disabled.",
                severity="Medium",
                impact=4,
                likelihood=3,
                exposure=2,
                asset_sensitivity=5,
                region=region_name
            ))

    return findings
