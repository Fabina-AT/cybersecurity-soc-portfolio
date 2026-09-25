# QR Code Phishing Detection

## 1. Detection Summary

**Use Case:** QR Code Phishing (Quishing)  
**Platform:** Microsoft Sentinel  
**Data Source:** Microsoft Defender for Office 365 / Email Security Logs  
**Severity:** High  
**MITRE ATT&CK:** T1566 – Phishing

### Description

Detects emails containing QR codes that direct users to external URLs. Attackers may use QR codes to bypass traditional URL inspection and redirect users to phishing or credential-harvesting pages.

---

## 2. Detection Logic

```text
Email Received
     ↓
QR Code Detected
     ↓
URL Extracted
     ↓
URL Reputation Check
     ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
EmailEvents
| where TimeGenerated >= ago(24h)
| where ThreatTypes has_any ("Phish", "Malware")
| project
    TimeGenerated,
    SenderFromAddress,
    RecipientEmailAddress,
    Subject,
    ThreatTypes,
    DeliveryAction
| order by TimeGenerated desc
```

> QR-code identification itself should come from Microsoft Defender's email/URL analysis or an enrichment pipeline. `EmailEvents` alone does not provide a universal `QRDetected` field.

---

## 4. How It Works

The detection identifies suspicious emails classified by email security controls and then investigates whether the message contains a QR code leading to an external URL.

The SOC should correlate:

- QR-code presence
- Extracted URL
- URL reputation
- Sender reputation
- Recipient
- User interaction
- Subsequent authentication activity

---

## 5. Investigation

Review:

- Sender address
- Recipient
- Subject
- QR-code image
- Extracted URL
- Destination domain
- URL reputation
- Authentication activity
- Endpoint activity
- Similar emails received by other users

---

## 6. False Positives

Possible legitimate QR codes include:

- Event invitations
- Marketing emails
- Authentication/setup emails
- Business applications
- Internal communications

Validate the destination URL before classifying the message as malicious.

---

## 7. Response

If malicious activity is confirmed:

1. Identify all recipients.
2. Extract and investigate the QR destination.
3. Search for the same email across the environment.
4. Remove or quarantine the message.
5. Block confirmed malicious URLs/domains.
6. Check whether users visited the URL.
7. Investigate subsequent sign-in activity.

**Detection Goal:** Identify QR-based phishing attempts and correlate the QR destination with user and authentication activity.
