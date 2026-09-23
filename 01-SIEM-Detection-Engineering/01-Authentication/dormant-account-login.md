# Dormant Account Login Detection

## 1. Detection Summary

**Use Case:** Dormant Account Reactivation

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** High

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication from an account that has not had a successful login for 30 or more days.

Unexpected reactivation of a dormant account may indicate compromised credentials or unauthorized account usage.

---

## 2. Detection Logic

```text
Current Successful Login
        ↓
Find Previous Successful Login
        ↓
Previous Login > 30 Days Ago
        ↓
Analyze IP / Device / Location
        ↓
Generate Alert
        ↓
SOC Investigation
```

---

## 3. KQL Detection

```kql
let HistoricalLogins =
    SigninLogs
    | where TimeGenerated >= ago(180d)
    | where ResultType == 0
    | summarize
        LastSuccessfulLogin = max(TimeGenerated)
        by UserPrincipalName;

SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| join kind=inner HistoricalLogins
    on UserPrincipalName
| where LastSuccessfulLogin < ago(30d)
| where TimeGenerated > LastSuccessfulLogin
| project
    TimeGenerated,
    UserPrincipalName,
    LastSuccessfulLogin,
    InactiveDays = datetime_diff("day", TimeGenerated, LastSuccessfulLogin),
    IPAddress,
    Location,
    AppDisplayName,
    DeviceDetail,
    AuthenticationRequirement
| order by TimeGenerated desc
```

### Important

The `180d` is the **lookback period** used to find historical authentication.

The `30d` is the **dormancy threshold**.

For example:

```text
Last successful login
        ↓
45 days ago
        ↓
User logs in today
        ↓
45 days inactive
        ↓
ALERT
```

---

## 4. Investigation

Review:

* User and privilege level
* Last successful login
* Source IP and reputation
* Device
* Location
* MFA result
* Application accessed
* Recent account changes
* Activity after authentication

Give additional attention to **privileged and sensitive accounts**.

---

## 5. False Positives & Tuning

Common legitimate scenarios:

* Employees returning from leave
* Seasonal users
* Infrequently used administrative accounts
* Emergency accounts
* Approved business activity

Tune using:

* Inactivity threshold
* Account type
* Privileged-account status
* Approved exceptions
* Business ownership

---

## 6. Response

If unauthorized activity is suspected:

1. Validate the login with the user.
2. Investigate the source IP, device, and location.
3. Review activity after authentication.
4. Check for privilege or configuration changes.
5. Revoke sessions where appropriate.
6. Disable the account if compromise is confirmed and appropriate.
7. Reset credentials and escalate according to the incident-response process.

---

## 7. Validation

Test using an approved dormant test account and verify:

* Previous login is identified.
* Inactivity period is calculated correctly.
* New login generates the alert.
* IP, device, and location are available.
* Investigation context is sufficient.

**Detection Status:** Ready for testing and tuning.
