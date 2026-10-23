# Phishing to Account Compromise Investigation

## Case Details

- **Type:** Lab simulation
- **Severity:** High
- **MITRE ATT&CK:** T1566.002, T1078, T1114.003

## Incident Summary

A user clicked a credential-harvesting link in a phishing email and entered their Microsoft 365 password on a fake sign-in page. An unfamiliar IP subsequently signed in to the account and created a mailbox rule to hide replies. The account was contained within one hour of the alert. No data exfiltration was confirmed.

## Investigation

- Reviewed the Sentinel alert and Microsoft 365 sign-in logs.
- Checked the phishing URL and IP using VirusTotal.
- Analyzed the URL in Any.Run to identify the fake login page.
- Compared the sign-in location with the user's normal activity.
- Checked mailbox rules and forwarding settings.
- Searched other mailboxes for the same sender and URL.

### Detection Queries

**1. Successful sign-in after a URL click**

```kql
let clicks =
    UrlClickEvents
    | where ActionType == "ClickAllowed"
    | project
        ClickTime = Timestamp,
        AccountUpn,
        Url;
SigninLogs
| where ResultType == "0"
| join kind=inner clicks
    on $left.UserPrincipalName == $right.AccountUpn
| where TimeGenerated between
    (ClickTime .. ClickTime + 2h)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    Url
| order by TimeGenerated desc
```

**2. Suspicious mailbox rule creation**

```kql
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule")
| where UserId =~ "user@contoso.example"
| project
    TimeGenerated,
    UserId,
    ClientIP,
    Operation,
    Parameters
| order by TimeGenerated desc
```

*Schema note: Validate table columns and event availability in your Sentinel workspace. The correlation query finds successful sign-ins after a recorded click; it does not prove the click caused the compromise.*

## Timeline

- **09:02** — Phishing email delivered.
- **09:07** — User clicked the link.
- **09:08** — Fake credential-harvesting page identified during sandbox analysis.
- **09:15** — Successful sign-in from an unfamiliar IP.
- **09:19** — Suspicious inbox rule created.
- **09:40** — Sentinel alert raised.

## Findings

The email contained a credential-harvesting link. A successful sign-in from an unfamiliar IP occurred shortly after the click, followed by creation of a mailbox rule designed to hide replies.

Four other recipients received the same email, and one additional user clicked the link. No successful sign-in was identified for that user during the investigation.

**Root cause:** Credential theft through phishing was the suspected cause. The simulated account did not have MFA enforced.

## Response

- Disabled the compromised account temporarily and revoked active sessions.
- Reset the user's password and reviewed authentication methods.
- Blocked the phishing sender and domain.
- Removed the malicious inbox rule and checked for forwarding settings.
- Searched for and removed the phishing email from affected mailboxes.
- Enforced MFA and restored the account after validation.
- Monitored the account for 72 hours.

## Outcome

- **Status:** Contained
- **Impact:** Account compromise identified; no data exfiltration confirmed.
- **Evidence:** Sign-in logs, email records, mailbox audit events, and sandbox analysis.

## Lessons Learned

- Correlate email clicks with subsequent sign-ins and mailbox changes.
- Enforce MFA for all users.
- Include mailbox-rule and forwarding checks in compromised-account investigations.
- Review all recipients of a phishing campaign and monitor users who clicked the link.

## Indicators of Compromise (IOCs)

- **Domain:** `m365-login-verify[.]example` — simulated phishing domain.
- **IP:** `203.0.113.45` — documentation-only example IP.
- **Sender:** `no-reply@secure-docs[.]example` — simulated sender.
- **Subject:** `Action required: document shared with you` — simulated phishing email.

## Portfolio Note

This is a simulated case study. The timestamps, affected accounts, investigation findings, and response actions are illustrative. Replace them with verified lab evidence before presenting the case as a completed investigation.
