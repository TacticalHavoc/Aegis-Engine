# Incident Analysis API Specification

**Path**: `POST /api/v1/incidents/analyze`  
**Status**: Implemented  
**Verification**: Pending  

---

## 1. Purpose

Receives a security incident bundle from the upstream Kafka + ML detection pipeline containing flagged log events (processes, network connections, file access, authentication events) and executes multi-agent analysis to return an exhaustive `IncidentReport`.

---

## 2. Request Schema

```json
{
  "incident_id": "INC-2026-001",
  "title": "Suspicious Encoded PowerShell with Outbound Beaconing",
  "severity": "critical",
  "rule_name": "PowerShell.ObfuscatedPayload.Beacon",
  "timestamp": "2026-10-06T22:30:00Z",
  "description": "PowerShell executed with Base64 encoded payload and outbound socket established.",
  "flagged_logs": [
    {
      "timestamp": "2026-10-06T22:30:05Z",
      "event_type": "process",
      "host": "FINANCE-WS01",
      "user": "corp\\aditya",
      "data": {
        "process_name": "powershell.exe",
        "process_id": 5820,
        "parent_process_id": 1040,
        "parent_process_name": "explorer.exe",
        "command_line": "powershell.exe -NoP -NonI -Enc SQBFA..."
      }
    },
    {
      "timestamp": "2026-10-06T22:30:25Z",
      "event_type": "network",
      "host": "FINANCE-WS01",
      "user": "corp\\aditya",
      "data": {
        "process_id": 5820,
        "process_name": "powershell.exe",
        "source_ip": "10.0.4.15",
        "destination_ip": "198.51.100.23",
        "destination_port": 443,
        "protocol": "TCP",
        "domain": "malicious.site"
      }
    }
  ]
}
```

---

## 3. Response Schema (`200 OK`)

```json
{
  "incident_id": "INC-2026-001",
  "verdict": "MALICIOUS",
  "confidence": 0.95,
  "severity": "CRITICAL",
  "executive_summary": "Active threat activity identified in incident INC-2026-001. Obfuscated PowerShell execution detected (PID 5820). Correlated outbound C2 network socket from suspicious PID 5820 to 198.51.100.23:443 (malicious.site).",
  "root_cause": "Execution of suspicious command sequence on host(s) FINANCE-WS01.",
  "attack_timeline": [
    {
      "timestamp": "2026-10-06T22:30:05Z",
      "event_type": "process",
      "summary": "Obfuscated PowerShell executed (PID 5820): powershell.exe -NoP -NonI -Enc SQBFA...",
      "details": {
        "process_name": "powershell.exe",
        "process_id": 5820
      }
    },
    {
      "timestamp": "2026-10-06T22:30:25Z",
      "event_type": "network",
      "summary": "Outbound C2 connection from PID 5820 to 198.51.100.23:443 (malicious.site)",
      "details": {
        "destination_ip": "198.51.100.23",
        "domain": "malicious.site"
      }
    }
  ],
  "mitre_attack": [
    {
      "tactic": "Execution",
      "technique_id": "T1059.001",
      "name": "PowerShell"
    },
    {
      "tactic": "Defense Evasion",
      "technique_id": "T1027",
      "name": "Obfuscated Files or Information"
    },
    {
      "tactic": "Command and Control",
      "technique_id": "T1071.001",
      "name": "Web Protocols"
    }
  ],
  "affected_entities": {
    "hosts": ["FINANCE-WS01"],
    "users": ["corp\\aditya"],
    "suspicious_pids": [5820],
    "ioc_ips": ["198.51.100.23"],
    "ioc_domains": ["malicious.site"]
  },
  "recommended_actions": [
    "Isolate compromised host(s) FINANCE-WS01 from network.",
    "Terminate malicious process PID 5820 on host FINANCE-WS01.",
    "Block remote destination IP 198.51.100.23 on boundary firewalls.",
    "Block domain malicious.site across DNS sinks and web proxies."
  ],
  "analyzed_at": "2026-10-06T22:35:00Z"
}
```
