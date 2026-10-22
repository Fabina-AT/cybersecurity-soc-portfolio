02 - Incident Response

Incident response write-ups built as lab simulations using realistic scenarios, sample log data and standard SOC tooling (Microsoft Sentinel, Defender, SentinelOne, VirusTotal, Any.Run). No real client data is used. IPs and domains are reserved or example values.

Framework

Each case follows the NIST SP 800-61 lifecycle: Preparation → Detection & Analysis → Containment → Eradication → Recovery → Lessons Learned

Case Index
Case	Folder	Scenario	MITRE ATT&CK	Status
1	01-Phishing-Compromise	Phishing to account compromise	T1566, T1078	Done
2	03-Compromised-Account	Brute force / password spraying to successful login	T1110, T1078	Done
3	04-Malware-Infection	Malware execution on an endpoint	T1204, T1059.001	Done
4	02-Ransomware	Ransomware triage	T1486, T1490	Planned
5	05-Suspicious-PowerShell	Suspicious PowerShell / LOLBin execution	T1059.001, T1218	Planned
6	06-Credential-Dumping	Credential dumping (LSASS access)	T1003.001	Planned
7	07-Lateral-Movement	Lateral movement (RDP / SMB / WinRM)	T1021	Planned
8	08-C2-Beaconing	C2 beaconing / DNS tunneling	T1071, T1572	Planned
9	09-Data-Exfiltration	Data exfiltration / insider threat	T1567, T1048	Planned
10	10-Cloud-Account-Takeover	Azure / AWS account takeover	T1078.004	Planned
Templates

See 00-IR-Templates/ for the incident report template and severity matrix used across all cases.
