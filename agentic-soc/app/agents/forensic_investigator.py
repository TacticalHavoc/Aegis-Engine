import json
import logging
import os
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.models.incident import FlaggedLog, Incident, TimelineEvent

logger = logging.getLogger(__name__)

FORENSIC_INVESTIGATOR_PROMPT = """You are an elite Digital Forensics and Incident Response (DFIR) Lead Investigator.
Your task is to analyze a raw security incident and its associated collection of flagged log events.

Your Responsibilities:
1. Reconstruct the chronological sequence of events (parent processes -> child processes -> commands -> network sockets).
2. Deobfuscate and decode any obfuscated payloads (e.g. Base64 encoded PowerShell commands).
3. Identify all compromised hosts, user accounts, suspicious process IDs (PIDs), and Indicators of Compromise (IOCs: IPs, domains, hashes).
4. Determine the exact root cause / initial execution vector.

Return ONLY a valid JSON object matching this schema:
{
  "root_cause": "<detailed root cause>",
  "attack_timeline": [
    {
      "timestamp": "<ISO-8601 string>",
      "event_type": "<process|network|file|auth|dns>",
      "summary": "<clear summary of what occurred>",
      "details": {}
    }
  ],
  "compromised_hosts": ["<host1>"],
  "compromised_users": ["<user1>"],
  "suspicious_pids": [<pid1>],
  "ioc_ips": ["<ip1>"],
  "ioc_domains": ["<domain1>"],
  "forensic_narrative": "<technical narrative detailing the attacker's execution flow>"
}
"""


class ForensicReport(BaseModel):
    root_cause: str
    attack_timeline: List[TimelineEvent] = Field(default_factory=list)
    compromised_hosts: List[str] = Field(default_factory=list)
    compromised_users: List[str] = Field(default_factory=list)
    suspicious_pids: List[int] = Field(default_factory=list)
    ioc_ips: List[str] = Field(default_factory=list)
    ioc_domains: List[str] = Field(default_factory=list)
    forensic_narrative: str


class ForensicInvestigatorAgent:
    """Agent 1: Specialized LLM Forensic Analyst reconstructing execution and timelines."""

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.getenv("AGENT_MODEL", "gemini-3.5-flash-lite")

    def analyze(self, incident: Incident) -> ForensicReport:
        gemini_key = os.getenv("GEMINI_API_KEY")

        if gemini_key:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            prompt = (
                f"{FORENSIC_INVESTIGATOR_PROMPT}\n\n"
                f"Incident ID: {incident.incident_id}\n"
                f"Title: {incident.title}\n"
                f"Severity: {incident.severity}\n"
                f"Description: {incident.description}\n"
                f"Flagged Logs:\n{incident.model_dump_json(indent=2)}"
            )

            candidate_models = [self.model_name, "gemini-3.5-flash-lite", "gemini-3.7-flash", "gemini-3.1-flash-lite"]
            for model in dict.fromkeys(candidate_models):
                try:
                    if hasattr(client, "interactions"):
                        interaction = client.interactions.create(
                            model=model,
                            input=prompt,
                        )
                        text = interaction.output_text
                        if text:
                            clean_text = text.strip()
                            if clean_text.startswith("```json"):
                                clean_text = clean_text[7:]
                            if clean_text.startswith("```"):
                                clean_text = clean_text[3:]
                            if clean_text.endswith("```"):
                                clean_text = clean_text[:-3]
                            return ForensicReport(**json.loads(clean_text.strip()))
                except Exception as e:
                    logger.debug(f"Interactions API with {model} failed ({e}); trying generate_content...")

                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config={"response_mime_type": "application/json"},
                    )
                    if response.text:
                        return ForensicReport(**json.loads(response.text))
                except Exception as e:
                    logger.warning(f"ForensicInvestigatorAgent model {model} failed ({e}); trying next candidate...")

        # Heuristic fallback for offline/test environments
        sorted_logs = sorted(incident.flagged_logs, key=lambda l: l.timestamp)
        timeline = []
        pids = []
        ips = []
        domains = []
        hosts = list({l.host for l in sorted_logs})
        users = list({l.user for l in sorted_logs if l.user})

        for l in sorted_logs:
            summary = f"[{l.event_type.upper()}] on {l.host}"
            if l.event_type == "process":
                pid = l.data.get("pid") or l.data.get("process_id")
                if pid:
                    pids.append(pid)
                summary = f"Process {l.data.get('process_name')} (PID {pid}) executed: {l.data.get('command_line')}"
            elif l.event_type == "network":
                ip = l.data.get("destination_ip")
                dom = l.data.get("domain")
                if ip:
                    ips.append(ip)
                if dom:
                    domains.append(dom)
                summary = f"Outbound socket to {ip}:{l.data.get('destination_port')} ({dom})"
            timeline.append(TimelineEvent(timestamp=l.timestamp, event_type=l.event_type, summary=summary, details=l.data))

        return ForensicReport(
            root_cause="Execution of suspicious process with external network beaconing.",
            attack_timeline=timeline,
            compromised_hosts=hosts,
            compromised_users=users,
            suspicious_pids=list(set(pids)),
            ioc_ips=list(set(ips)),
            ioc_domains=list(set(domains)),
            forensic_narrative=f"Observed {len(sorted_logs)} sequential events on host(s) {', '.join(hosts)}.",
        )
