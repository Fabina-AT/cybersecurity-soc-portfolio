# Malicious URL in Email Detection

## 1. Detection Summary

**Use Case:** Malicious URL in Email  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566.002 – Spearphishing Link

### Description

Detects emails containing URLs identified as malicious or suspicious by email security controls.

Malicious links may lead users to phishing pages, malware downloads, or credential-harvesting infrastructure.

---

## 2. Detection Logic

```text
Email Received
      ↓
URL Detected
      ↓
URL Threat Classification
      ↓
Sender / Recipient Review
      ↓
Generate Alert
```

---

## 3. KQL Detection

```kql id="d4m7qx"
EmailUrlInfo
| where TimeGenerated >= ago(24h)
| where ThreatTypes has_any ("Phish", "Malware")
| project
    TimeGenerated,
    NetworkMessageId,
    Url,
    UrlDomain,
    ThreatTypes
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection:

1. Reviews URLs observed in email messages.
2. Filters URLs associated with phishing or malware classifications.
3. Captures the URL and domain.
4. Provides the message identifier for further email investigation.

The URL itself should be validated using available threat intelligence and email-security verdicts.

---

## 5. Investigation

Review:

- URL
- Domain
- Sender
- Recipient
- Email subject
- URL reputation
- Threat classification
- Redirect chain
- User interaction
- Related authentication activity
- Other recipients who received the same URL

Search for the URL or domain across the environment.

---

## 6. False Positives

Possible causes:

- Legitimate websites incorrectly classified
- Shared hosting
- Security scanners
- URL reputation changes
- Legitimate links hosted on newly created domains

Validate the URL before blocking it.

---

## 7. Response

If the URL is confirmed malicious:

1. Identify all recipients.
2. Search for the URL across mailboxes.
3. Remove or quarantine affected messages.
4. Block the confirmed URL/domain.
5. Check whether users clicked the URL.
6. Investigate subsequent authentication activity.
7. Investigate affected endpoints if malware delivery is suspected.

**Detection Goal:** Identify malicious URLs delivered through email and correlate them with affected users and subsequent activity.
