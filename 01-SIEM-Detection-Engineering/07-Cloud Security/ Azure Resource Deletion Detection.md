# Azure Resource Deletion Detection

## 1. Overview
Detects the deletion of Azure resources that may indicate malicious activity, unauthorized changes, or sabotage.

## 2. Data Source
- Microsoft Azure Activity Logs
- Microsoft Sentinel
- Azure Resource Manager

## 3. Detection Logic
Monitor Azure Activity Logs for resource deletion operations, particularly when performed by unexpected users, service principals, or outside approved change windows.

## 4. KQL Detection Query

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| where OperationNameValue has "delete"
| where ActivityStatusValue =~ "Success"
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
- Technique: T1485 – Data Destruction (potential impact, depending on context)

## 6. Investigation Steps
1. Identify the user or service principal that deleted the resource.
2. Review the resource ID and resource group.
3. Check the source IP address and sign-in activity.
4. Verify whether an approved change request exists.
5. Look for related resource deletions or suspicious account activity.

## 7. False Positives
- Approved infrastructure deployments
- Automated cleanup jobs
- Scheduled resource lifecycle management
- Authorized administrative changes

## 8. Response Actions
- Validate the deletion with the resource owner.
- Investigate related Azure Activity Logs and identity events.
- Disable or restrict a compromised identity if compromise is confirmed.
- Restore the deleted resource from backups or redeploy it where possible.
- Document findings and escalate according to incident severity.

## 9. Severity
Medium by default; High or Critical when critical resources are deleted unexpectedly or multiple resources are affected.

## 10. Recommended Improvements
- Alert on deletion of critical resources.
- Maintain an approved change-window allowlist.
- Correlate deletions with identity and administrative activity.
- Monitor for bulk deletions across subscriptions.
