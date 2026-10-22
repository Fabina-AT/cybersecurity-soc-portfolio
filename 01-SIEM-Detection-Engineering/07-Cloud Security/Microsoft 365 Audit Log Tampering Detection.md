# Microsoft 365 Audit Log Tampering Detection

## 1. Overview
Detects attempts to disable or modify Microsoft 365 audit logging, potentially allowing an attacker to hide suspicious administrative or user activity.

## 2. Data Sources
- Microsoft Purview Unified Audit Log
- Microsoft Sentinel
- Office 365 Management Activity API

## 3. Detection Logic
Monitor administrative audit events associated with disabling or changing audit logging settings.

## 4. KQL Detection Query

```kusto
OfficeActivity
| where TimeGenerated > ago(24h)
| where OfficeWorkload =~ "Exchange"
    or OfficeWorkload =~ "SecurityComplianceCenter"
| where Operation has_any (
    "Set-AdminAuditLogConfig",
    "Set-OrganizationConfig",
    "Disable-AdminAuditLog"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    OfficeWorkload,
    ClientIP,
    ResultStatus,
    Parameters
| order by TimeGenerated desc
```

## 5. MITRE ATT&CK
- Tactic: Defense Evasion
- Technique: T1562.008 – Disable or Modify Cloud Logs

## 6. Investigation Steps
1. Identify the administrator who performed the operation.
2. Review the source IP address and associated sign-in activity.
3. Examine the operation parameters and result status.
4. Check whether audit logging settings actually changed.
5. Investigate other suspicious administrative actions around the same time.

## 7. False Positives
- Approved Microsoft 365 configuration changes
- Planned administrative maintenance
- Authorized audit configuration updates

## 8. Response Actions
- Verify the change with the Microsoft 365 security team.
- Restore required audit logging settings if necessary.
- Investigate potentially compromised administrator accounts.
- Preserve available audit evidence.
- Escalate confirmed unauthorized changes.

## 9. Severity
High if audit logging was disabled without authorization; Medium for suspicious but unconfirmed configuration changes.

## 10. Recommended Improvements
- Monitor changes to audit configuration separately from ordinary administrative changes.
- Alert on successful unauthorized modifications.
- Correlate activity with Entra ID sign-in logs.
- Verify audit log ingestion and retention after any configuration change.
