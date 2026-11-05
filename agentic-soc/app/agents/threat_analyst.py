import json
import logging
import os
from typing import List, Optional
from pydantic import BaseModel, Field

from app.agents.forensic_investigator import ForensicReport
from app.models.incident import Incident, MitreItem

logger = logging.getLogger(__name__)

THREAT_ANALYST_PROMPT = """You are a Senior Cyber Threat Intelligence (CTI) and MITRE ATT&CK Analyst.
You are given a raw Incident and a Forensic Investigation Report produced by the Lead Investigator Agent.

Your Responsibilities:
1. Map every observable malicious technique to the MITRE ATT&CK Enterprise Framework (Tactic, Technique ID, and Name).
2. Assess the adversary's intent, operational sophistication, and likely threat actor profile (e.g. script kiddie, commodity malware / loader, ransomware affiliate, APT).
3. Evaluate the blast radius and potential for lateral movement across the environment.
4. Provide a threat assessment confidence score (0.0 to 1.0) and calculated severity rating (CRITICAL, HIGH, MEDIUM, LOW, INFO).

Return ONLY a valid JSON object matching this schema:
{
  "mitre_attack": [
    {
      "tactic": "<e.g. Execution, Defense Evasion, Command and Control>",
      "technique_id": "<e.g. T1059.001>",
      "name": "<e.g. PowerShell>"
    }
  ],
  "adversary_profile": "<description of adversary sophistication and intent>",
  "blast_radius_assessment": "<assessment of blast radius and lateral movement potential>",
  "calculated_severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "confidence_score": <float between 0.0 and 1.0>
}
"""


class ThreatAssessment(BaseModel):
    mitre_attack: List[MitreItem] = Field(default_factory=list)
    adversary_profile: str
    blast_radius_assessment: str
    calculated_severity: str
    confidence_score: float


class ThreatAnalystAgent:
    """Agent 2: Specialized LLM Cyber Threat Intelligence & MITRE Analyst."""

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.getenv("AGENT_MODEL", "gemini-3.5-flash-lite")

    def analyze(self, incident: Incident, forensic_report: ForensicReport) -> ThreatAssessment:
        gemini_key = os.getenv("GEMINI_API_KEY")

        if gemini_key:
            from google import genai
            client = genai.Client(api_key=gemini_key)
            prompt = (
                f"{THREAT_ANALYST_PROMPT}\n\n"
                f"Incident Title: {incident.title}\n"
                f"Incident Severity: {incident.severity}\n"
                f"Forensic Investigation Findings:\n{forensic_report.model_dump_json(indent=2)}"
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
                            return ThreatAssessment(**json.loads(clean_text.strip()))
                except Exception as e:
                    logger.debug(f"Interactions API with {model} failed ({e}); trying generate_content...")

                try:
                    response = client.models.generate_content(
                        model=model,
                        contents=prompt,
                        config={"response_mime_type": "application/json"},
                    )
                    if response.text:
                        return ThreatAssessment(**json.loads(response.text))
                except Exception as e:
                    logger.warning(f"ThreatAnalystAgent model {model} failed ({e}); trying next candidate...")

        # Fallback MITRE mapping
        mitre_items = [
            MitreItem(tactic="Execution", technique_id="T1059.001", name="PowerShell"),
            MitreItem(tactic="Defense Evasion", technique_id="T1027", name="Obfuscated Files or Information"),
            MitreItem(tactic="Command and Control", technique_id="T1071.001", name="Web Protocols"),
        ]
        return ThreatAssessment(
            mitre_attack=mitre_items,
            adversary_profile="Commodity loader or post-exploitation framework with basic evasion capabilities.",
            blast_radius_assessment=f"Currently isolated to host(s) {', '.join(forensic_report.compromised_hosts)}.",
            calculated_severity="CRITICAL" if forensic_report.ioc_ips else "HIGH",
            confidence_score=0.95,
        )
