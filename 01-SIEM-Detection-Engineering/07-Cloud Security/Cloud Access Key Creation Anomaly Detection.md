# Cloud Access Key Creation Anomaly Detection

## 1. Overview
Detects the creation of new access keys or credentials for Azure applications and service principals. Unexpected credential creation may indicate persistence by an attacker who has compromised a cloud identity.

## 2. Data Sources
- Microsoft Entra ID audit logs
- Microsoft Sentinel
- Azure Activity Logs

## 3. Detection Logic
Monitor audit events for application credential additions and flag unexpected credential creation, particularly by unfamiliar users or service principals.

## 4. KQL Detection Query

```kusto
AuditLogs
| where TimeGenerated > ago(24h)
| where Category =~ "ApplicationManagement"
| where OperationName has_any (
    "Add service principal credentials",
    "Update application - Certificates and secrets management",
    "Add app role assignment to service principal"
)
| extend InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName)
| extend InitiatedByApp = tostring(InitiatedBy.app.displayName)
| extend TargetResources = tostring(TargetResources)
| project
    TimeGenerated,
    OperationName,
    Result,
    InitiatedByUser,
    InitiatedByApp,
    TargetResources,
    CorrelationId
| order by TimeGenerated desc
```

## 5. MITRE ATT&CK
- Tactic: Persistence
- Technique: T1098.001 – Additional Cloud Credentials

## 6. Investigation Steps
1. Identify the user or application that initiated the change.
2. Identify the target application or service principal.
3. Determine whether a new password credential or certificate was added.
4. Check whether the change was approved by the application owner.
5. Review subsequent sign-ins and API activity involving the affected identity.

## 7. False Positives
- Approved application secret rotation
- Certificate renewal
- Application deployments
- Authorized identity administration

## 8. Response Actions
- Validate the credential change with the application owner.
- Revoke unauthorized credentials and review active sessions where appropriate.
- Investigate the initiating account for compromise.
- Review permissions and activity of the affected application.
- Preserve audit evidence and escalate confirmed malicious activity.

## 9. Severity
High when an unauthorized credential is added to a privileged application; Medium for unexpected changes awaiting validation.

## 10. Recommended Improvements
- Maintain an approved list of credential administrators.
- Alert on credentials added to privileged service principals.
- Monitor credential changes outside approved maintenance windows.
- Correlate credential additions with subsequent sign-ins and privilege changes.
