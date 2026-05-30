# sentinel-ssh-brute-force-lab
Detected live SSH brute force attacks on an Azure VM using Microsoft Sentinel, 
KQL analytics rules, and MITRE ATT&CK mapping.

## What I Built
- Deployed an Azure VM exposed to the public internet via SSH
- Forwarded syslog data to Microsoft Sentinel via Azure Monitor Agent
- Wrote KQL queries to detect brute force patterns in auth logs
- Built a scheduled analytics rule triggering on 10+ failed logins per IP per hour
- Investigated a live incident with 13 attacker IPs and 158 attempts from one source
- Confirmed only one successful login — my own

## Tools & Technologies
- Microsoft Sentinel
- Azure Log Analytics Workspace
- KQL (Kusto Query Language)
- Azure Monitor Agent (Syslog via AMA)
- MITRE ATT&CK T1110 — Brute Force

## Key Detection Query
```kql
let LookbackWindow = 1h;
let FailureThreshold = 10;
Syslog
| where TimeGenerated > ago(LookbackWindow)
| where Facility in ("auth", "authpriv")
| where SyslogMessage has "Failed password"
| extend SourceIP = extract(@"from (\S+) port", 1, SyslogMessage)
| where isnotempty(SourceIP)
| summarize FailureCount = count() by SourceIP
| where FailureCount >= FailureThreshold
| order by FailureCount desc
```

## Results
- 13 external IPs detected attempting SSH login
- Top attacker: 158 attempts from a single IP
- MITRE T1110.001 — Password Guessing confirmed
- Zero unauthorized successful logins

## Status
Lab complete. Part of my transition from emergency medicine into cybersecurity.
