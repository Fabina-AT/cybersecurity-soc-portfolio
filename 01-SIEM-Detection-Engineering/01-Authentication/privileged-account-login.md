# Privileged Account Login Detection

## 1. Detection Summary


**Use Case:** Privileged Account Login

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** High

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication by privileged or administrative accounts. Monitoring privileged authentication helps identify unauthorized access to high-value accounts.

---

## 2. Detection Logic

```text id="8bqv0d"
Privileged Account
       ↓
Successful Authentication
       ↓
Review Source / Location / Device
       ↓
Generate Alert
       ↓
SOC Investigation
```

The detection should focus on privileged accounts such as:

* Global Administrators
* Security Administrators
* Privileged Role Administrators
* Other high-impact administrative accounts

---

## 3. KQL Detection

```kql id="yq9l24"
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType == 0
| where UserPrincipalName in (
    "admin1@example.com",
    "admin2@example.com"
)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    DeviceDetail,
    AuthenticationRequirement
| order by TimeGenerated desc
```

> In production, maintain the privileged-account list dynamically rather than hard-coding individual accounts.

---

## 4. Investigation

Review:

* Privileged account
* Source IP and reputation
* Login location
* Device
* Authentication method
* MFA result
* Application accessed
* Normal administrative activity
* Changes performed after login

---

## 5. False Positives & Tuning

Expected activity may include:

* Approved administrative work
* Maintenance activities
* Change-management tasks
* Emergency administration
* Automated administrative processes

Tune using approved administrator accounts, trusted locations, maintenance windows, and expected administrative activity.

---

## 6. Response

If the login is unauthorized:

1. Validate the administrative activity.
2. Investigate the source IP and device.
3. Review actions performed after authentication.
4. Revoke sessions where appropriate.
5. Reset credentials if compromise is confirmed.
6. Escalate according to the incident-response process.

---

## 7. Validation

Test using an approved privileged test account and verify that the detection captures:

* Account
* Source IP
* Login time
* Location
* Device
* Application
* Authentication information

**Detection Status:** Ready for testing and tuning.
