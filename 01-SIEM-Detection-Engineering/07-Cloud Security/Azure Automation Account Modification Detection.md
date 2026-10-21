# Azure Automation Account Modification Detection

## 1. Overview
Detects changes to Azure Automation accounts that may indicate an attacker is modifying automation settings, changing runbooks, or establishing persistence.

## 2. Data Sources
- Microsoft Azure Activity Logs
- Microsoft Sentinel
- Azure Automation

## 3. Detection Logic
Monitor successful Azure control-plane operations that modify Automation accounts, runbooks, schedules, or linked resources.

## 4. KQL Detection Query

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where CategoryValue =~ "Administrative"
| where ActivityStatusValue =~ "Success"
| where OperationNameValue has_any (
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/DELETE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/WRITE",
    "MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/SCHEDULES/WRITE"
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
- Tactic: Persistence
- Technique: T1053 – Scheduled Task/Job (potentially relevant when schedules are abused)
- Technique: T1098 – Account Manipulation (potentially relevant depending on the activity)

## 6. Investigation Steps
1. Identify the user or service principal making the change.
2. Check the affected Automation account and runbook.
3. Review the source IP and related sign-in events.
4. Compare the change with approved deployment or maintenance activity.
5. Investigate unexpected runbook edits, schedule changes, or new automation jobs.

## 7. False Positives
- Approved infrastructure deployments
- Routine runbook updates
- Authorized schedule changes
- Automated configuration management

## 8. Response Actions
- Confirm the change with the resource owner.
- Review runbook content and execution history.
- Revoke or restrict compromised credentials if necessary.
- Disable suspicious schedules or jobs after assessing operational impact.
- Preserve logs and escalate confirmed malicious activity.

## 9. Severity
Medium by default; High when an unauthorized runbook or schedule change can execute privileged actions.

## 10. Recommended Improvements
- Baseline expected administrators and service principals.
- Monitor runbook content changes separately from account changes.
- Correlate modifications with subsequent job executions.
- Alert on changes made by unfamiliar identities or from unusual locations.
