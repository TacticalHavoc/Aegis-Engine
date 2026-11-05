import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.incident import (
    AffectedEntities,
    FlaggedLog,
    Incident,
    IncidentReport,
    MitreItem,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


SYSTEM_PROMPT = """You are an elite Tier-3 SOC Incident Analysis Multi-Agent Engine.
Your task is to analyze a security incident bundle comprising an initial alert and a series of flagged logs (process, network, file, auth, dns) flagged by an upstream Kafka/ML detection pipeline.

You must perform three collaborative agent roles:
1. Lead Investigator: Reconstruct the exact attack timeline, trace execution flow (parent-child processes, commands, and network connections), and determine root cause.
2. Threat Analyst: Map observed adversary behaviors to MITRE ATT&CK tactics & techniques, estimate confidence, and assess severity and blast radius.
3. Response & Remediation Advisor: Determine immediate, actionable containment and remediation steps.

Return ONLY a valid JSON object matching the exact following structure:
{
  "incident_id": "<incident_id>",
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INCONCLUSIVE",
  "confidence": <float between 0.0 and 1.0>,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "executive_summary": "<concise high-level summary of what occurred>",
  "root_cause": "<the initial infection vector or triggering action>",
  "attack_timeline": [
    {
      "timestamp": "<ISO-8601 string>",
      "event_type": "<process|network|file|auth|dns|alert>",
      "summary": "<readable event summary>",
      "details": {}
    }
  ],
  "mitre_attack": [
    {
      "tactic": "<e.g. Execution, Defense Evasion, Command and Control>",
      "technique_id": "<e.g. T1059.001>",
      "name": "<e.g. PowerShell>"
    }
  ],
  "affected_entities": {
    "hosts": ["<host1>"],
    "users": ["<user1>"],
    "suspicious_pids": [<pid1>],
    "ioc_ips": ["<ip1>"],
    "ioc_domains": ["<domain1>"]
  },
  "recommended_actions": [
    "<action 1>",
    "<action 2>"
  ]
}
"""


class IncidentAnalyzer:
    """
    Multi-Agent Incident Analysis Engine that ingests flagged logs from Kafka/ML
    and synthesizes a comprehensive incident analysis report.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.getenv("AGENT_MODEL")

    def _analyze_deterministic(self, incident: Incident) -> IncidentReport:
        """
        Deterministic correlation engine used in offline/test mode or when no LLM API key is provided.
        Reconstructs the attack timeline, correlates process and network activity, and maps MITRE tactics.
        """
        # 1. Sort flagged logs chronologically
        sorted_logs = sorted(incident.flagged_logs, key=lambda log: log.timestamp)
        
        timeline: List[TimelineEvent] = []
        hosts: set[str] = set()
        users: set[str] = set()
        suspicious_pids: set[int] = set()
        ioc_ips: set[str] = set()
        ioc_domains: set[str] = set()
        mitre_items: List[MitreItem] = []
        recommended_actions: List[str] = []

        is_malicious = False
        is_suspicious = False
        summary_points: List[str] = []

        if not sorted_logs:
            return IncidentReport(
                incident_id=incident.incident_id,
                verdict="INCONCLUSIVE",
                confidence=0.5,
                severity="LOW",
                executive_summary=f"Incident {incident.incident_id} contains no flagged logs for analysis.",
                root_cause="No telemetry provided in incident bundle.",
                attack_timeline=[],
                mitre_attack=[],
                affected_entities=AffectedEntities(),
                recommended_actions=["Verify Kafka ingestion pipeline and log collector connectivity."],
                analyzed_at=datetime.now(timezone.utc),
            )

        for log in sorted_logs:
            hosts.add(log.host)
            if log.user:
                users.add(log.user)

            data = log.data
            event_summary = f"[{log.event_type.upper()}] on {log.host}"

            # Analyze Process Events
            if log.event_type == "process":
                proc_name = str(data.get("process_name", "")).lower()
                cmd = str(data.get("command_line", ""))
                pid = data.get("pid") or data.get("process_id")
                parent_proc = str(data.get("parent_process", data.get("parent_process_name", ""))).lower()

                if pid and isinstance(pid, int):
                    # Check for encoded PowerShell commands
                    if "powershell" in proc_name and ("-enc" in cmd.lower() or "-encodedcommand" in cmd.lower()):
                        is_malicious = True
                        suspicious_pids.add(pid)
                        mitre_items.append(MitreItem(tactic="Execution", technique_id="T1059.001", name="PowerShell"))
                        mitre_items.append(MitreItem(tactic="Defense Evasion", technique_id="T1027", name="Obfuscated Files or Information"))
                        summary_points.append(f"Obfuscated PowerShell execution detected (PID {pid}).")
                        event_summary = f"Obfuscated PowerShell executed (PID {pid}): {cmd}"
                        recommended_actions.append(f"Terminate malicious process PID {pid} on host {log.host}.")

                    # Check for reconnaissance child processes
                    elif parent_proc and "powershell" in parent_proc and proc_name in ["whoami.exe", "whoami", "net.exe", "net", "cmd.exe", "cmd"]:
                        is_malicious = True
                        suspicious_pids.add(pid)
                        mitre_items.append(MitreItem(tactic="Discovery", technique_id="T1033", name="System Owner/User Discovery"))
                        summary_points.append(f"Reconnaissance binary {proc_name} spawned by PowerShell (PID {pid}).")
                        event_summary = f"Reconnaissance command spawned: {cmd}"
                    else:
                        event_summary = f"Process {proc_name} executed (PID {pid}): {cmd}"
                else:
                    event_summary = f"Process {proc_name} executed: {cmd}"

            # Analyze Network Events
            elif log.event_type == "network":
                dest_ip = str(data.get("destination_ip", ""))
                dest_port = data.get("destination_port", "")
                domain = str(data.get("domain", ""))
                net_pid = data.get("pid") or data.get("process_id")

                if dest_ip:
                    ioc_ips.add(dest_ip)
                if domain:
                    ioc_domains.add(domain)

                if net_pid in suspicious_pids:
                    is_malicious = True
                    mitre_items.append(MitreItem(tactic="Command and Control", technique_id="T1071.001", name="Web Protocols"))
                    summary_points.append(f"Correlated outbound C2 network socket from suspicious PID {net_pid} to {dest_ip}:{dest_port} ({domain or 'No Domain'}).")
                    event_summary = f"Outbound C2 connection from PID {net_pid} to {dest_ip}:{dest_port} ({domain})"
                    if dest_ip:
                        recommended_actions.append(f"Block remote destination IP {dest_ip} on boundary firewalls.")
                    if domain:
                        recommended_actions.append(f"Block domain {domain} across DNS sinks and web proxies.")
                else:
                    event_summary = f"Network connection to {dest_ip}:{dest_port} ({domain})"

            # Analyze Auth Events
            elif log.event_type == "auth":
                status = data.get("status", "unknown")
                event_summary = f"Authentication event for {log.user}: status={status}"
                if status in ["failed", "unauthorized"]:
                    is_suspicious = True
                    mitre_items.append(MitreItem(tactic="Credential Access", technique_id="T1110", name="Brute Force"))

            # Build timeline event
            timeline.append(
                TimelineEvent(
                    timestamp=log.timestamp,
                    event_type=log.event_type,
                    summary=event_summary,
                    details=data,
                )
            )

        # Deduplicate MITRE items
        seen_mitre = set()
        deduped_mitre = []
        for m in mitre_items:
            if m.technique_id not in seen_mitre:
                seen_mitre.add(m.technique_id)
                deduped_mitre.append(m)

        # Final verdict and severity determination
        if is_malicious:
            verdict = "MALICIOUS"
            confidence = 0.95
            severity = "CRITICAL" if ioc_ips else "HIGH"
            exec_summary = f"Active threat activity identified in incident {incident.incident_id}. " + " ".join(summary_points)
            root_cause = f"Execution of suspicious command sequence on host(s) {', '.join(hosts)}."
            if hosts:
                recommended_actions.insert(0, f"Isolate compromised host(s) {', '.join(hosts)} from network.")
        elif is_suspicious:
            verdict = "SUSPICIOUS"
            confidence = 0.80
            severity = "MEDIUM"
            exec_summary = f"Suspicious behavior detected in incident {incident.incident_id} requiring human review."
            root_cause = "Anomalous authentication or activity sequence."
        else:
            verdict = "BENIGN"
            confidence = 0.90
            severity = "LOW"
            exec_summary = f"Analyzed {len(sorted_logs)} log event(s) in incident {incident.incident_id}. No indicators of compromise detected."
            root_cause = "False positive detection or routine administrative operation."
            recommended_actions.append("No immediate remediation required; mark incident as benign.")

        return IncidentReport(
            incident_id=incident.incident_id,
            verdict=verdict,
            confidence=confidence,
            severity=severity,
            executive_summary=exec_summary,
            root_cause=root_cause,
            attack_timeline=timeline,
            mitre_attack=deduped_mitre,
            affected_entities=AffectedEntities(
                hosts=sorted(list(hosts)),
                users=sorted(list(users)),
                suspicious_pids=sorted(list(suspicious_pids)),
                ioc_ips=sorted(list(ioc_ips)),
                ioc_domains=sorted(list(ioc_domains)),
            ),
            recommended_actions=list(dict.fromkeys(recommended_actions)),
            analyzed_at=datetime.now(timezone.utc),
        )

    async def analyze_incident(self, incident: Incident) -> IncidentReport:
        """
        Analyze an incident bundle asynchronously using live LLM if configured,
        or deterministic multi-agent heuristics.
        """
        logger.info(f"[IncidentAnalyzer] Starting multi-agent analysis for incident {incident.incident_id} with {len(incident.flagged_logs)} flagged log(s)")

        # Check for live LLM configuration (Gemini or OpenAI)
        gemini_key = os.getenv("GEMINI_API_KEY")
        openai_key = os.getenv("OPENAI_API_KEY")

        if gemini_key:
            try:
                from google import genai
                client = genai.Client(api_key=gemini_key)
                prompt_content = f"{SYSTEM_PROMPT}\n\nIncident Input Payload:\n{incident.model_dump_json(indent=2)}"
                response = client.models.generate_content(
                    model=self.model_name or "gemini-2.0-flash",
                    contents=prompt_content,
                    config={"response_mime_type": "application/json"},
                )
                if response.text:
                    parsed_json = json.loads(response.text)
                    return IncidentReport(**parsed_json)
            except Exception as e:
                logger.warning(f"Live Gemini model analysis encountered error ({e}); falling back to deterministic correlation engine.")

        elif openai_key:
            try:
                from openai import AsyncOpenAI
                client = AsyncOpenAI(api_key=openai_key)
                prompt_content = f"Incident Input Payload:\n{incident.model_dump_json(indent=2)}"
                response = await client.chat.completions.create(
                    model=self.model_name or "gpt-4o",
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt_content},
                    ],
                    response_format={"type": "json_object"},
                )
                content = response.choices[0].message.content
                if content:
                    parsed_json = json.loads(content)
                    return IncidentReport(**parsed_json)
            except Exception as e:
                logger.warning(f"Live OpenAI model analysis encountered error ({e}); falling back to deterministic correlation engine.")

        # Fallback / offline deterministic analysis
        return self._analyze_deterministic(incident)
