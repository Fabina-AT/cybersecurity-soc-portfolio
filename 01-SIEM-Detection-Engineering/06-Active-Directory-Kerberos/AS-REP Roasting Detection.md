# AS-REP Roasting Detection

## 1. Detection Summary

**Use Case:** AS-REP Roasting  
**Platform:** Microsoft Sentinel  
**Data Source:** Windows Security Events  
**Severity:** High  
**MITRE ATT&CK:** T1558.004 – Steal or Forge Kerberos Tickets: AS-REP Roasting

### Description

Detects unusual Kerberos authentication requests for accounts that do not require Kerberos preauthentication.

Attackers can request AS-REP responses for these accounts and attempt to crack the response offline to obtain account credentials.

---

## 2. Detection Logic

```text
Kerberos Authentication Request
            ↓
Preauthentication Not Required
            ↓
Unusual Account / Source
            ↓
Review Encryption Type
            ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4768
| where PreAuthType == 0
| summarize
    Requests = count(),
    SourceIPs = make_set(IpAddress, 10)
    by Account
| where Requests >= 3
| project
    Account,
    Requests,
    SourceIPs
| order by Requests desc
```

---

## 4. How It Works

The detection:

1. Monitors **Event ID 4768**, which records Kerberos authentication-ticket requests.
2. Looks for requests where Kerberos preauthentication was not used.
3. Groups activity by account.
4. Identifies repeated requests that require investigation.

The absence of preauthentication is the key indicator for AS-REP Roasting.

---

## 5. Investigation

Review:

- User account
- Source IP
- Source hostname
- Number of requests
- Request timestamps
- Encryption type
- Account privileges
- Whether the account requires preauthentication
- Recent authentication activity
- Related endpoint activity

Pay particular attention to accounts that normally do not generate this type of authentication activity.

---

## 6. False Positives

Possible legitimate activity:

- Legacy applications
- Service accounts
- Applications configured without Kerberos preauthentication
- Approved authentication workflows

Maintain an inventory of accounts where preauthentication is intentionally disabled.

---

## 7. Response

If AS-REP Roasting is suspected:

1. Identify the affected account.
2. Identify the source endpoint.
3. Confirm whether preauthentication is intentionally disabled.
4. Investigate the requesting process.
5. Review related Kerberos activity.
6. Protect or reset the affected account credentials if required.
7. Investigate for additional credential-access or lateral-movement activity.

**Detection Goal:** Identify suspicious Kerberos authentication requests that may indicate AS-REP Roasting and potential credential compromise.
