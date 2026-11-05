import os
import logging
from typing import Optional

from app.agents.forensic_investigator import ForensicInvestigatorAgent, ForensicReport
from app.agents.response_advisor import ResponseAdvisorAgent
from app.agents.threat_analyst import ThreatAnalystAgent, ThreatAssessment
from app.models.incident import Incident, IncidentReport

logger = logging.getLogger(__name__)


class MultiAgentPipeline:
    """
    Coordinates the collaborative 3-Agent LLM Investigation Pipeline:
    1. ForensicInvestigatorAgent -> Reconstructs execution flow & timeline.
    2. ThreatAnalystAgent        -> Maps MITRE ATT&CK & evaluates adversary intent.
    3. ResponseAdvisorAgent      -> Generates final executive verdict & tactical action plan.
    """

    def __init__(self, model_name: Optional[str] = None):
        selected_model = model_name or os.getenv("AGENT_MODEL", "gemini-3.7-flash")
        self.forensic_agent = ForensicInvestigatorAgent(model_name=selected_model)
        self.threat_agent = ThreatAnalystAgent(model_name=selected_model)
        self.response_agent = ResponseAdvisorAgent(model_name=selected_model)

    def analyze(self, incident: Incident) -> IncidentReport:
        logger.info(f"[MultiAgentPipeline] Step 1: Running Forensic Investigator Agent for {incident.incident_id}...")
        forensic_report: ForensicReport = self.forensic_agent.analyze(incident)

        logger.info(f"[MultiAgentPipeline] Step 2: Running Threat Intelligence & MITRE Analyst Agent...")
        threat_assessment: ThreatAssessment = self.threat_agent.analyze(incident, forensic_report)

        logger.info(f"[MultiAgentPipeline] Step 3: Running Incident Commander & Response Advisor Agent...")
        final_report: IncidentReport = self.response_agent.synthesize(
            incident=incident,
            forensic_report=forensic_report,
            threat_assessment=threat_assessment,
        )

        logger.info(f"[MultiAgentPipeline] Completed multi-agent analysis for {incident.incident_id}: verdict={final_report.verdict}")
        return final_report
