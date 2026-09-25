# Suspicious Email Forwarding Detection

## 1. Detection Summary

**Use Case:** Suspicious Email Forwarding  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft 365 / Exchange Audit Logs  
**Severity:** High  
**MITRE ATT&CK:** T1114.003 – Email Forwarding Rule

### Description

Detects the creation or modification of email forwarding rules that may allow an attacker to automatically send mailbox contents to an external address.

Attackers may create forwarding rules after compromising an account to maintain access to sensitive email information.

---

## 2. Detection Logic

```text
Mailbox Rule Created
        ↓
External Forwarding
        ↓
Unexpected Destination
        ↓
User / Rule Validation
        ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
OfficeActivity
| where TimeGenerated >= ago(24h)
| where OfficeWorkload =~ "Exchange"
| where Operation has_any (
    "New-InboxRule",
    "Set-InboxRule"
)
| where Parameters has_any (
    "ForwardTo",
    "ForwardAsAttachmentTo",
    "RedirectTo"
)
| project
    TimeGenerated,
    UserId,
    Operation,
    Parameters,
    ClientIP
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews Exchange activity.
2. Identifies inbox rule creation or modification.
3. Looks for forwarding or redirect actions.
4. Flags the activity for investigation.

External forwarding should receive additional scrutiny because it can expose mailbox contents outside the organization.

---

## 5. Investigation

Review:

- User account
- Rule name
- Forwarding destination
- Rule creation time
- Source IP
- User's recent sign-ins
- Recent MFA activity
- Other mailbox changes
- Suspicious emails
- Authentication anomalies

Correlate the rule creation with recent account compromise indicators.

---

## 6. False Positives

Possible legitimate activity:

- Approved business forwarding
- Shared mailbox workflows
- Automated mail processing
- Temporary business requirements
- Approved external integrations

Maintain an approved forwarding baseline.

---

## 7. Response

If unauthorized forwarding is confirmed:

1. Disable or remove the forwarding rule.
2. Review the affected mailbox.
3. Investigate recent authentication activity.
4. Check for additional inbox rules.
5. Review suspicious email activity.
6. Reset or protect the account if compromise is confirmed.
7. Search for similar forwarding rules across the environment.

**Detection Goal:** Identify unauthorized email forwarding that may indicate mailbox compromise or attempted email data exposure.
