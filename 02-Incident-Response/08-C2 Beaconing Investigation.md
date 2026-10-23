# C2 Beaconing Investigation

## Case Details

| Field | Details |
|---|---|
| **Type** | Lab simulation |
| **Severity** | High |
| **MITRE ATT&CK** | T1071.001, T1071.004, T1573, T1568 |

## Incident Summary

The SOC received a Microsoft Sentinel alert for a workstation making regular outbound connections to a rarely seen external domain, with a near-constant interval and small response sizes. The pattern matched command-and-control beaconing. The host was isolated, the implant was removed and no data theft or spread to other hosts was found.

## Investigation

- Reviewed the alert and identified the host, the process making the connections and the destination.
- Measured the time between connections to check for a fixed interval.
- Checked the domain age, reputation and DNS records in VirusTotal and AlienVault OTX.
- Checked DNS logs for abnormal query patterns such as long or random subdomains.
- Checked how the process was started and whether it had persistence.
- Searched other hosts for connections to the same domain or IP.

## Detection Queries

### 1. Regular Outbound Connections from One Process

```kql id="j4k8vn"
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where ActionType == "ConnectionSuccess"
| where RemoteIPType == "Public"
| summarize Connections = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| where Connections > 100
| order by Connections desc
```

### 2. Interval Check Between Connections

```kql id="u6p2xr"
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName == "WKS-0457" and RemoteIP == "203.0.113.175"
| sort by Timestamp asc
| extend Gap = datetime_diff("second", Timestamp, prev(Timestamp))
| summarize AvgGap = avg(Gap), StdDevGap = stdev(Gap), Count = count()
```

### 3. DNS Queries with Long or Random Subdomains

```kql id="c8m5zt"
DnsEvents
| where TimeGenerated > ago(24h)
| extend Subdomain = tostring(split(Name, ".")[0])
| where strlen(Subdomain) > 30
| summarize Queries = count() by ClientIP, Name
| order by Queries desc
```

### 4. Other Hosts Contacting the Same Destination

```kql id="r3n7qw"
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteIP == "203.0.113.175" or RemoteUrl has "update-checker-svc.example"
| summarize Hosts = dcount(DeviceName), HostList = make_set(DeviceName)
```

## Timeline

| Time | Event | Evidence Source |
|---|---|---|
| 09:00 | Unknown process started from the user's AppData folder | DeviceProcessEvents |
| 09:01 | First connection to update-checker-svc[.]example | DeviceNetworkEvents |
| 09:01–14:00 | Connections every 60 seconds with a small jitter | DeviceNetworkEvents |
| 14:05 | Sentinel alert raised for beaconing pattern | Sentinel |
| 14:20 | Host isolated | Defender |

## Findings

The process connected to the same domain about every 60 seconds with a small random jitter, sending small requests and receiving small responses. The domain was registered 5 days earlier and flagged as malicious by several vendors. The process ran from the user's AppData folder with an unsigned file and a startup entry in the registry. No large uploads were seen and no other host contacted the domain. Root cause: malware installed through a phishing download earlier that morning.

## Response

- Isolated the host using the EDR.
- Killed the process and removed the file and the startup registry entry.
- Blocked the domain and IP at the firewall and DNS filter.
- Reset the user's password and revoked sessions.
- Searched 7 days of logs for the same destination across all hosts, with no other hits.
- Reimaged the workstation and returned it to the user.
- Monitored DNS and network logs for the domain for 14 days.

## Outcome

- **Status:** Contained, no data loss or spread found
- **Evidence:** Network connection logs, DNS logs, process data and threat intelligence results

## Lessons Learned

Regular connections with a fixed interval to a new domain are a strong C2 signal, even when each connection is small. Recommend alerting on newly registered domains, blocking uncategorised domains at the proxy, logging DNS centrally, and keeping the first query as a scheduled detection with an allowlist for known update and monitoring services.

## IOCs

- **Domain:** `update-checker-svc[.]example` - C2 domain
- **IP:** `203.0.113.175` - C2 server
- **Interval:** about 60 seconds with jitter - beacon pattern
- **File:** `svchost_update
