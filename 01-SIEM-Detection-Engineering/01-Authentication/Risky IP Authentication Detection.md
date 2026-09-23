# Risky IP Authentication Detection

## 1. Detection Summary

**Use Case:** Risky IP Authentication

**Platform:** Microsoft Sentinel

**Data Source:** Microsoft Entra ID (`SigninLogs`)

**Severity:** High

**MITRE ATT&CK:** T1078 – Valid Accounts

### Description

Detects successful authentication from an IP associated with elevated sign-in risk, while correlating the authentication with user, device, location, and MFA context.

This helps identify potentially compromised accounts using suspicious infrastructure.

---

## 2. Detection Logic

```text
Successful Authentication
        ↓
Elevated Sign-In Risk
        ↓
Review IP + User + Device
        ↓
MFA / Location / Application Context
        ↓
Generate Alert
        ↓
SOC Investigation
```

---

## 3. KQL Detection

```kql
SigninLogs
| where TimeGenerated >= ago(1h)
| where ResultType == 0
| where RiskLevelDuringSignIn in ("medium", "high")
    or RiskLevelAggregated in ("medium", "high")
| extend
    DeviceId = tostring(DeviceDetail.deviceId),
    OS = tostring(DeviceDetail.operatingSystem),
    Browser = tostring(DeviceDetail.browser),
    Country = tostring(LocationDetails.countryOrRegion)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Country,
    AppDisplayName,
    DeviceId,
    OS,
    Browser,
    AuthenticationRequirement,
    RiskLevelDuringSignIn,
    RiskLevelAggregated
| order by TimeGenerated desc
```

---

## 4. Investigation

Review:

* User and privilege level
* Source IP reputation
* Sign-in risk
* Geographic location
* Device ID
* Operating system and browser
* MFA requirement/result
* Application accessed
* Previous authentication activity
* Activity after successful authentication

Correlate with **MFA, endpoint, and identity-risk alerts** where available.

---

## 5. False Positives & Tuning

Potential legitimate activity includes:

* Corporate VPN
* Proxy infrastructure
* Cloud security services
* Mobile networks
* Remote access solutions

Tune using:

* Trusted IP ranges
* Known VPN infrastructure
* Managed devices
* User behavior baselines
* Risk-level thresholds

---

## 6. Response

If unauthorized access is suspected:

1. Investigate the source IP and risk details.
2. Validate the authentication with the user.
3. Review device and application activity.
4. Check for additional suspicious authentication.
5. Revoke sessions where appropriate.
6. Reset credentials if compromise is confirmed.
7. Escalate according to the incident-response process.

---

## 7. Validation

Test using controlled authentication from approved test infrastructure and verify that the detection captures:

* User
* Source IP
* Risk level
* Device
* Location
* Application
* Authentication context

**Detection Status:** Ready for testing and tuning.

