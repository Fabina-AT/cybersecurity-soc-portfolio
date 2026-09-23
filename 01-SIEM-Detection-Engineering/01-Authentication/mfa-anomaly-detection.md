# MFA Anomaly Detection

## 1. Detection Summary

**Use Case:** MFA Anomaly Detection

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** High

**MITRE ATT&CK:** T1621 – Multi-Factor Authentication Request Generation

### Description

Detects repeated or unusual MFA activity that may indicate MFA abuse, compromised credentials, or an attempt to gain unauthorized access.

---

## 2. Detection Logic

```text
MFA Activity
     ↓
Multiple / Unusual Requests
     ↓
User + IP + Device Analysis
     ↓
Generate Alert
     ↓
SOC Investigation
```

**Example threshold:** 5 or more MFA-related authentication events for the same user within 10 minutes.

---

## 3. KQL Detection

```kql
SigninLogs
| where TimeGenerated >= ago(10m)
| where AuthenticationRequirement == "multiFactorAuthentication"
| summarize
    MFAAttempts = count(),
    SourceIPs = make_set(IPAddress, 10),
    Applications = make_set(AppDisplayName, 10),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by UserPrincipalName
| where MFAAttempts >= 5
| project
    UserPrincipalName,
    MFAAttempts,
    SourceIPs,
    Applications,
    FirstAttempt,
    LastAttempt
| order by MFAAttempts desc
```

---

## 4. Investigation

Review:

* User account
* MFA request count
* Source IP
* Location
* Device
* Application
* Authentication method
* Whether the user expected the MFA requests
* Related failed or successful logins

---

## 5. False Positives & Tuning

Potential causes include:

* User repeatedly authenticating
* Application authentication issues
* Device or MFA configuration problems
* Legitimate repeated authentication

Tune using normal authentication patterns, trusted applications, and approved users.

---

## 6. Response

If suspicious activity is confirmed:

1. Validate the MFA activity with the user.
2. Investigate the source IP and device.
3. Review recent authentication activity.
4. Revoke sessions where appropriate.
5. Reset credentials if compromise is suspected.
6. Escalate according to the incident-response process.

---

## 7. Validation

Test controlled MFA authentication activity and verify that the alert captures:

* User
* MFA activity
* Source IP
* Application
* Authentication timeline

**Detection Status:** Ready for testing and tuning.
