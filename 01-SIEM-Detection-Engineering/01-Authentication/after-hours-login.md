# After-Hours Authentication Detection

## 1. Detection Summary

**Use Case:** After-Hours Authentication

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** Medium

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication outside the organization's normal working hours.

---

## 2. Detection Logic

```text
Successful Login
      ↓
Before 08:00 or After 18:00
      ↓
Generate Alert
      ↓
SOC Investigation
```

---

## 3. KQL Detection

```kql
SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| extend LoginHour = datetime_part("Hour", TimeGenerated)
| where LoginHour < 8 or LoginHour >= 18
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

### How it works

```text
08:30 → Normal → No alert
14:00 → Normal → No alert
19:30 → After hours → Alert
02:15 → After hours → Alert
```

---

## 4. Investigation

Review:

* User
* Login time
* Source IP
* Location
* Device
* MFA
* Application accessed
* Recent authentication activity

---

## 5. False Positives & Tuning

Possible legitimate activity:

* Shift workers
* On-call employees
* Remote users
* Different time zones
* Maintenance activity

Tune the working-hour threshold according to the organization's requirements.

---

## 6. Response

If suspicious:

1. Validate the login with the user.
2. Investigate the source IP and device.
3. Review activity after authentication.
4. Revoke sessions if required.
5. Reset credentials if compromise is confirmed.
6. Escalate according to the incident-response process.

---

## 7. Validation

Test successful logins before and after the configured working hours.

Confirm the alert captures:

* User
* Login time
* Source IP
* Location
* Device

**Detection Status:** Ready for testing and tuning.
