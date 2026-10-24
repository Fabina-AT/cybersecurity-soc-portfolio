# Cloud Account Takeover Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | Critical |
| **MITRE ATT&CK Tactics** | Initial Access, Persistence, Privilege Escalation, Discovery, Impact |
| **Attack Stage** | Initial Access to Impact |

### MITRE ATT&CK Techniques

- **T1078.004** - Valid Accounts: Cloud Accounts (Initial Access)
- **T1098.001** - Account Manipulation: Additional Cloud Credentials (Persistence)
- **T1136.003** - Create Account: Cloud Account (Persistence)
- **T1580** - Cloud Infrastructure Discovery (Discovery)
- **T1496** - Resource Hijacking (Impact)

## Incident Summary

The SOC received a Microsoft Sentinel alert for an AWS IAM user signing in from an unfamiliar country and then creating new access keys and a new IAM user. Minutes later, a large number of compute instances were launched in regions the company never uses. The identity was confirmed as compromised, the access was revoked and the unauthorised resources were removed before significant cost or data exposure occurred.

## Investigation

- Reviewed the alert and identified the identity, source IP and actions taken.
- Checked the sign-in history of the identity and whether MFA was used.
- Listed every API call made by the identity since the first unfamiliar sign-in.
- Checked for new users, access keys, roles and policy changes.
- Checked which resources were created, in which regions and by which identity.
- Checked storage buckets and data access for signs of data theft.
- Checked how the credentials were exposed.

## Detection Queries

### 1. AWS Console Sign-in from a New Location (CloudTrail)

```kql id="a7k3mx"
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventName == "ConsoleLogin"
| where UserIdentityUserName == "dev-user01"
| extend Result = tostring(parse_json(ResponseElements).ConsoleLogin)
| project TimeGenerated, UserIdentityUserName, SourceIpAddress, Result, AWSRegion
```

### 2. Persistence Actions by the Identity

```kql id="b8n4qy"
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where UserIdentityUserName == "dev-user01"
| where EventName in ("CreateAccessKey", "CreateUser", "AttachUserPolicy", "PutUserPolicy", "CreateLoginProfile", "UpdateAssumeRolePolicy")
| project TimeGenerated, EventName, SourceIpAddress, RequestParameters
```

### 3. Instances Launched in Unusual Regions

```kql id="c9p5wr"
AWSCloudTrail
| where TimeGenerated > ago(24h)
| where EventName == "RunInstances"
| summarize Launches = count() by UserIdentityUserName, AWSRegion, SourceIpAddress
| where AWSRegion !in ("me-central-1", "eu-west-1")
| order by Launches desc
```

### 4. Azure Equivalent: Sign-in and Role Changes for a Cloud Identity

```kql id="d2m6vz"
AuditLogs
| where TimeGenerated > ago(24h)
| where OperationName has_any ("Add member to role", "Add service principal credentials", "Add user")
| project TimeGenerated, OperationName, InitiatedBy, TargetResources
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 03:12 | Console sign-in to dev-user01 from an unfamiliar country, no MFA | CloudTrail |
| 03:15 | New access key created for dev-user01 | CloudTrail |
| 03:18 | New IAM user backup-svc created and given admin permissions | CloudTrail |
| 03:22 | Enumeration calls across services (list instances, buckets, roles) | CloudTrail |
| 03:30 | 40 compute instances launched in two unused regions | CloudTrail |
| 03:41 | Sentinel alert raised | Sentinel |
| 03:55 | Identity disabled, keys revoked and instances terminated | AWS console |

## Findings

The identity had no MFA and its access key had been exposed in a public code repository earlier that week. The attacker signed in from an unfamiliar country, created a second access key and a new admin user to keep access, listed resources across services, and launched 40 compute instances in unused regions, which points to resource hijacking for cryptocurrency mining. No storage bucket downloads were seen. Root cause: exposed credentials on an identity with excessive permissions and no MFA.

## Response

- Disabled the identity, deactivated and deleted all its access keys, and removed its console password.
- Deleted the attacker-created IAM user and its access keys.
- Terminated the unauthorised instances and checked for other resources such as snapshots, images and scheduled functions.
- Removed the exposed key from the code repository and rotated every other key stored there.
- Reviewed CloudTrail for the identity and the new user for 30 days to find any other actions.
- Restored the legitimate user with a new password, MFA and a limited permission set.
- Contacted the cloud provider about the usage charges.
- Monitored the account for 14 days.

## Outcome

- **Status:** Contained, no data theft found, unauthorised resources removed
- **Evidence:** CloudTrail logs, IAM change records, billing data and repository history

## Lessons Learned

Exposed access keys and missing MFA were the cause of the takeover. Recommend MFA on all identities, no long-term access keys where roles can be used, least-privilege permissions, a region restriction policy, secret scanning on repositories, and billing and instance-launch alerts. Keep the persistence-actions query as a scheduled detection.

## IOCs

- **Identity:** `dev-user01` - compromised IAM user
- **Identity:** `backup-svc` - attacker-created IAM user
- **IP:** `203.0.113.210` - attacker source address
- **Event:** `CreateAccessKey` followed by `CreateUser` - persistence pattern
- **Event:** `RunInstances` in unused regions - resource hijacking

## Portfolio Note

This is a simulated case study. Replace the figures, times and findings with verified results from your lab before presenting it as a completed investigation.
