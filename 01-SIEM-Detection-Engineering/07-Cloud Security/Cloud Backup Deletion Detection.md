# Cloud Backup Deletion Detection

## 1. Overview
Detects successful deletion of Azure backup resources or recovery points that may indicate malicious activity, sabotage, or attempts to prevent recovery after a ransomware attack.

## 2. Data Sources
- Microsoft Azure Activity Logs
- Microsoft Sentinel
- Azure Backup operational logs, where configured

## 3. Detection Logic
Monitor successful administrative operations involving the deletion of Recovery Services vaults, backup items, backup policies, and recovery points. Prioritize unexpected deletion of critical backups.

## 4. KQL Detection Query

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where ActivityStatusValue =~ "Success"
| where OperationNameValue has_any (
    "MICROSOFT.RECOVERYSERVICES/VAULTS/DELETE",
    "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPFABRICS/PROTECTIONCONTAINERS/PROTECTEDITEMS/DELETE",
    "MICROSOFT.RECOVERYSERVICES/VAULTS/BACKUPPOLICIES/DELETE",
    "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/DELETE",
    "MICROSOFT.DATAPROTECTION/BACKUPVAULTS/BACKUPINSTANCES/DELETE"
)
| project
    TimeGenerated,
    Caller,
    OperationNameValue,
    ResourceGroup,
    ResourceId,
    SubscriptionId,
    CallerIpAddress,
    ActivityStatusValue
| order by TimeGenerated desc
```

## 5. MITRE ATT&CK
- Tactic: Impact
- Technique: T1490 – Inhibit System Recovery

## 6. Investigation Steps
1. Identify the user or service principal responsible for the deletion.
2. Determine which vault, backup item, or policy was affected.
3. Verify whether the deletion was approved.
4. Check for other backup deletions or suspicious administrative operations.
5. Review related identity sign-ins and resource activity.

## 7. False Positives
- Approved backup-retention activities
- Planned resource decommissioning
- Authorized backup policy changes
- Infrastructure migrations

## 8. Response Actions
- Contact the backup or cloud operations team immediately.
- Investigate the initiating identity and related activity.
- Stop further unauthorized deletion where possible.
- Assess whether recovery points or alternate backups remain available.
- Restore or recreate backup protection and escalate suspected malicious activity.

## 9. Severity
High when critical recovery points or backup protection are deleted unexpectedly; Critical when widespread deletion threatens recovery from an active incident.

## 10. Recommended Improvements
- Monitor backup deletion and protection-disabling operations separately.
- Alert on bulk deletion across subscriptions.
- Protect critical backups with appropriate immutability and authorization controls.
- Correlate backup deletion with ransomware indicators and privileged account activity.
