# DCSync Detection

## 1. Detection Summary

**Use Case:** DCSync  
**Platform:** Microsoft Sentinel  
**Data Source:** Windows Security Events  
**Severity:** Critical  
**MITRE ATT&CK:** T1003.006 – OS Credential Dumping: DCSync

### Description

Detects suspicious directory replication activity that may indicate an attacker attempting to obtain credential information from Active Directory.

DCSync abuses Active Directory replication permissions to request directory data without directly accessing the domain controller's credential database.

---

## 2. Detection Logic

```text
Directory Replication Request
          ↓
Unexpected User / Host
          ↓
Sensitive Replication Rights
          ↓
Review Account Privileges
          ↓
Generate Alert
```

---

## 3. KQL Detection

```kql
SecurityEvent
| where TimeGenerated >= ago(24h)
| where EventID == 4662
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
)
| project
    TimeGenerated,
    Computer,
    Account,
    SubjectUserName,
    ObjectName,
    Properties
| order by TimeGenerated desc
```

---

## 4. How It Works

The detection monitors **Event ID 4662**, which records operations performed on Active Directory objects.

DCSync-related activity can involve directory replication permissions such as:

- Replicating Directory Changes
- Replicating Directory Changes All

The detection identifies events associated with these permissions and provides them for investigation.

---

## 5. Investigation

Review:

- Account performing the operation
- Source computer
- Domain controller
- Object accessed
- Replication-related permissions
- Account privileges
- Time of activity
- Other authentication activity
- Subsequent credential or lateral-movement activity

The most important question is:

> **Was this account and computer expected to perform directory replication?**

---

## 6. False Positives

Possible legitimate activity:

- Domain controllers
- Active Directory synchronization
- Identity-management systems
- Backup systems
- Approved administrative tools

Maintain a list of authorized systems that legitimately perform directory replication.

---

## 7. Response

If unauthorized DCSync activity is confirmed:

1. Identify the account performing the replication.
2. Identify the source host.
3. Disable or protect the compromised account if required.
4. Investigate privileged-account activity.
5. Review other domain-controller activity.
6. Investigate possible credential compromise.
7. Reset affected privileged credentials according to incident procedures.
8. Hunt for subsequent lateral movement and persistence.

**Detection Goal:** Identify unauthorized Active Directory replication activity that may indicate credential theft through DCSync.
