import json
import logging
import os
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel, Field

from app.agents.forensic_investigator import ForensicReport
from app.agents.threat_analyst import ThreatAssessment
from app.models.incident import AffectedEntities, Incident, IncidentReport

logger = logging.getLogger(__name__)

RESPONSE_ADVISOR_PROMPT = """You are a Principal SOC Incident Commander and Incident Response (IR) Lead.
You are provided with:
1. An Incident bundle from the Kafka/ML pipeline.
2. A Forensic Investigation Report from the Lead Investigator Agent.
3. A Threat & MITRE Assessment from the Threat Analyst Agent.

Your Responsibilities:
1. Synthesize all findings into a high-level, executive summary suitable for SOC management and CISOs.
2. Formulate the final authoritative verdict: MALICIOUS, SUSPICIOUS, BENIGN, or INCONCLUSIVE.
3. Develop a prioritized, tactical remediation checklist (Containment -> Eradication -> Recovery -> Prevention).
   Include specific process IDs to kill, firewall blocking rules, domain sinkholes, and host isolation orders.

Return ONLY a valid JSON object matching this schema:
{
  "verdict": "MALICIOUS" | "SUSPICIOUS" | "BENIGN" | "INCONCLUSIVE",
  "executive_summary": "<concise, authoritative narrative summary for executives and analysts>",
  "recommended_actions": [
    "<action 1: immediate containment>",
    "<action 2: eradication>",
    "<action 3: recovery>"
  ]
}
"""


class ResponseSynthesis(BaseModel):
    verdict: str
    executive_summary: str
    recommended_actions: List[str] = Field(default_factory=list)


class ResponseAdvisorAgent:
    """Agent 3: Specialized LLM Incident Commander & Remediation Advisor."""

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.getenv("AGENT_MODEL", "gemini-3.5-flash-lite")

    def synthesize(
        self,
        incident: Incident,
        forensic_report: ForensicReport,
        threat_assessment: ThreatAssessment,
    ) -> IncidentReport:
        gemini_key = os.getenv("GEMINI_API_KEY")
        synthesis = None

        if gemini_key:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            prompt = (
                f"{RESPONSE_ADVISOR_PROMPT}\n\n"
                f"Incident:\n{incident.model_dump_json(indent=2)}\n\n"
                f"Forensic Report:\n{forensic_report.model_dump_json(indent=2)}\n\n"
                f"Threat Assessment:\n{threat_assessment.model_dump_json(indent=2)}"
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
                            synthesis = ResponseSynthesis(**json.loads(clean_text.strip()))
                            break
                except Exception as e:
                    logger.debug(f"Interactions API with {model} failed ({e}); trying generate_content...")

                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config={"response_mime_type": "application/json"},
                    )
                    if response.text:
                        synthesis = ResponseSynthesis(**json.loads(response.text))
                        break
                except Exception as e:
                    logger.warning(f"ResponseAdvisorAgent model {model} failed ({e}); trying next candidate...")

        if not synthesis:
            actions = []
            if forensic_report.compromised_hosts:
                actions.append(f"Isolate host(s) {', '.join(forensic_report.compromised_hosts)} immediately.")
            for pid in forensic_report.suspicious_pids:
                actions.append(f"Terminate malicious process PID {pid}.")
            for ip in forensic_report.ioc_ips:
                actions.append(f"Block outbound destination IP {ip} at network perimeter.")
            for dom in forensic_report.ioc_domains:
                actions.append(f"Sinkhole malicious domain {dom} on internal DNS servers.")

            synthesis = ResponseSynthesis(
                verdict="MALICIOUS" if forensic_report.suspicious_pids or forensic_report.ioc_ips else "SUSPICIOUS",
                executive_summary=f"Incident {incident.incident_id} confirmed {threat_assessment.calculated_severity} severity threat. {forensic_report.forensic_narrative}",
                recommended_actions=actions,
            )

        return IncidentReport(
            incident_id=incident.incident_id,
            verdict=synthesis.verdict,  # type: ignore
            confidence=threat_assessment.confidence_score,
            severity=threat_assessment.calculated_severity,  # type: ignore
            executive_summary=synthesis.executive_summary,
            root_cause=forensic_report.root_cause,
            attack_timeline=forensic_report.attack_timeline,
            mitre_attack=threat_assessment.mitre_attack,
            affected_entities=AffectedEntities(
                hosts=forensic_report.compromised_hosts,
                users=forensic_report.compromised_users,
                suspicious_pids=forensic_report.suspicious_pids,
                ioc_ips=forensic_report.ioc_ips,
                ioc_domains=forensic_report.ioc_domains,
            ),
            recommended_actions=synthesis.recommended_actions,
            analyzed_at=datetime.now(timezone.utc),
        )
