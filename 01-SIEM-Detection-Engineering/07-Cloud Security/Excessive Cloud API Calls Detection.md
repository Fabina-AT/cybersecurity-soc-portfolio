# Excessive Cloud API Calls Detection

## 1. Overview
Detects unusually high volumes of Azure management API operations by a user or service principal. This activity may indicate cloud resource enumeration, automated abuse, compromised credentials, or unauthorized changes.

## 2. Data Sources
- Microsoft Azure Activity Logs
- Microsoft Sentinel
- Microsoft Entra ID sign-in logs (for additional investigation)

## 3. Detection Logic
Identify identities performing an unusually high number of Azure management operations within a short time window.

## 4. KQL Detection Query

```kusto
AzureActivity
| where TimeGenerated > ago(24h)
| summarize
    ApiCallCount = count(),
    UniqueOperations = dcount(OperationNameValue),
    ResourcesAccessed = dcount(ResourceId),
    SourceIPs = make_set(CallerIpAddress, 10),
    Operations = make_set(OperationNameValue, 10)
    by Caller, bin(TimeGenerated, 15m)
| where ApiCallCount > 100
| order by ApiCallCount desc
```

## 5. MITRE ATT&CK
- Tactic: Discovery
- Technique: T1580 – Cloud Infrastructure Discovery

## 6. Investigation Steps
1. Identify the user or service principal generating the API calls.
2. Review the number and types of operations performed.
3. Examine the resources and subscriptions accessed.
4. Check source IP addresses and related sign-in activity.
5. Determine whether the activity matches an approved script or deployment.

## 7. False Positives
- Infrastructure-as-code deployments
- Automated monitoring and inventory tools
- Resource discovery scripts
- Large-scale administrative operations

## 8. Response Actions
- Validate the activity with the resource owner.
- Review the identity's permissions and recent sign-ins.
- Restrict or revoke credentials if compromise is confirmed.
- Investigate unauthorized resource changes following the API burst.
- Document the findings and escalate when appropriate.

## 9. Severity
Medium by default; High when the API burst is associated with suspicious identities, unauthorized changes, or sensitive resource access.

## 10. Recommended Improvements
- Establish a baseline for each identity.
- Tune thresholds by workload and subscription.
- Create separate detections for destructive operations.
- Correlate API bursts with identity risk and cloud audit events.
