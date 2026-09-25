# Mass Phishing Campaign Detection

## 1. Detection Summary

**Use Case:** Mass Phishing Campaign  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566 – Phishing

### Description

Detects a phishing campaign where similar or identical emails are delivered to multiple users within a short period.

This helps identify coordinated phishing activity and determine the scope of affected users.

---

## 2. Detection Logic

```text
Email Activity
     ↓
Same Sender / Subject
     ↓
Multiple Recipients
     ↓
Campaign Threshold
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="j3m8qa"
EmailEvents
| where TimeGenerated >= ago(1h)
| summarize
    Recipients = dcount(RecipientEmailAddress),
    EmailCount = count(),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by SenderFromAddress, Subject
| where Recipients >= 10
| project
    FirstSeen,
    LastSeen,
    SenderFromAddress,
    Subject,
    Recipients,
    EmailCount
| order by Recipients desc
```

---

## 4. How It Works

The detection:

1. Reviews email activity from the last hour.
2. Groups emails by sender and subject.
3. Counts unique recipients.
4. Flags campaigns sent to **10 or more users**.

A high recipient count does not automatically confirm phishing. Email threat classification and message analysis should be used for validation.

---

## 5. Investigation

Review:

- Sender address
- Sender domain
- Subject
- Recipients
- URLs
- Attachments
- Threat classification
- Delivery action
- Sender authentication
- Similar messages
- User interaction

Search for the same sender, domain, URL, or attachment across the environment.

---

## 6. False Positives

Possible legitimate campaigns:

- Internal announcements
- Marketing emails
- Security awareness simulations
- Company-wide notifications
- Automated application emails

Exclude approved bulk senders and security-testing campaigns.

---

## 7. Response

If the campaign is confirmed malicious:

1. Identify all recipients.
2. Search for matching messages across mailboxes.
3. Remove or quarantine malicious emails.
4. Block confirmed malicious indicators.
5. Identify users who interacted with the email.
6. Investigate related URLs, attachments, and authentication activity.
7. Escalate affected accounts for further investigation.

**Detection Goal:** Identify coordinated phishing campaigns and quickly determine their scope across the organization.
