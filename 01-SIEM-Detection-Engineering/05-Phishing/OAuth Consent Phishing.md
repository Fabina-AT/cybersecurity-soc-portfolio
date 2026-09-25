# OAuth Consent Phishing Detection

## 1. Detection Summary

**Use Case:** OAuth Consent Phishing  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Entra ID / Audit Logs  
**Severity:** High  
**MITRE ATT&CK:** T1528 – Steal Application Access Token

### Description

Detects suspicious OAuth application consent activity that may indicate phishing or abuse of application permissions.

Attackers may trick users into granting a malicious application access to organizational resources.

---

## 2. Detection Logic

```text
OAuth Consent
     ↓
New / Unusual Application
     ↓
Suspicious Permissions
     ↓
User / Application Validation
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
AuditLogs
| where TimeGenerated >= ago(24h)
| where OperationName has_any (
    "Consent to application",
    "Add delegated permission grant"
)
| project
    TimeGenerated,
    OperationName,
    InitiatedBy,
    TargetResources,
    Result
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews recent Entra ID audit activity.
2. Identifies application consent events.
3. Captures the user and target application.
4. Flags activity for investigation.

Additional enrichment should be used to determine whether the application and requested permissions are legitimate.

---

## 5. Investigation

Review:

- User who granted consent
- Application name
- Application ID
- Publisher
- Requested permissions
- Consent type
- Application registration details
- User's previous application activity
- Sign-in activity
- Application usage after consent

Pay particular attention to unexpected applications requesting access to mail, files, or directory information.

---

## 6. False Positives

Possible legitimate activity:

- Approved SaaS applications
- Microsoft applications
- Business applications
- IT-approved integrations
- Application deployments

Maintain an approved application baseline.

---

## 7. Response

If malicious consent is confirmed:

1. Identify the affected user.
2. Validate the application and publisher.
3. Review granted permissions.
4. Revoke unauthorized consent.
5. Disable or remove the malicious application if appropriate.
6. Investigate application activity after consent.
7. Review the user's authentication activity.
8. Search for the same application across the environment.

**Detection Goal:** Identify suspicious OAuth consent activity that may provide attackers unauthorized access to organizational resources.
