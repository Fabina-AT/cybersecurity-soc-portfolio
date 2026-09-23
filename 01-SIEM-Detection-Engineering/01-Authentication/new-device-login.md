# New Device Login Detection

## 1. Detection Summary

**Use Case:** First-Seen Device Authentication

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** Medium

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication from a device that has not previously been associated with the user during the defined historical baseline.

A first-seen device can indicate legitimate device replacement, remote access, or potentially compromised credentials.

---

## 2. Detection Logic

```text
Successful Login
       ↓
Extract Device ID
       ↓
Compare with User's Historical Devices
       ↓
Device Not Previously Seen
       ↓
Generate Alert
       ↓
SOC Investigation
```

**Baseline:** Previous 30 days
**Detection Window:** Last 24 hours

---

## 3. KQL Detection

```kql
let KnownDevices =
    SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where ResultType == 0
    | extend DeviceId = tostring(DeviceDetail.deviceId)
    | where isnotempty(DeviceId)
    | summarize by UserPrincipalName, DeviceId;

SigninLogs
| where TimeGenerated >= ago(24h)
| where ResultType == 0
| extend DeviceId = tostring(DeviceDetail.deviceId)
| where isnotempty(DeviceId)
| join kind=leftanti KnownDevices
    on UserPrincipalName, DeviceId
| project
    TimeGenerated,
    UserPrincipalName,
    DeviceId,
    IPAddress,
    Location,
    AppDisplayName,
    DeviceDetail,
    AuthenticationRequirement
| order by TimeGenerated desc
```

---

## 4. Investigation

Review:

* User and privilege level
* Device ID and device details
* Source IP and reputation
* Geographic location
* MFA result
* Application accessed
* Previous devices used by the user
* Activity following authentication

Correlate with **sign-in risk and endpoint alerts** where available.

---

## 5. False Positives & Tuning

Common legitimate scenarios:

* New corporate device
* Device replacement
* New virtual desktop
* Browser or device reconfiguration
* Legitimate remote access

Tune using:

* Registered/managed device status
* User baseline
* Corporate IP ranges
* Approved VDI infrastructure
* Privileged-account context

---

## 6. Response

If unauthorized access is suspected:

1. Validate the device with the user.
2. Investigate the source IP and location.
3. Check device management/EDR information.
4. Review activity following authentication.
5. Revoke sessions where appropriate.
6. Reset credentials if compromise is confirmed.
7. Escalate according to the incident-response process.

---

## 7. Validation

Test using a controlled login from a previously unseen test device.

Confirm that the alert identifies:

* User
* Device ID
* Source IP
* Location
* Application
* Authentication details

**Detection Status:** Ready for testing and tuning.
