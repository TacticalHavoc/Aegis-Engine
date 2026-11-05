import logging
from typing import Optional
from app.agents.multi_agent_pipeline import MultiAgentPipeline
from app.models.incident import Incident, IncidentReport

logger = logging.getLogger(__name__)


class IncidentService:
    """Service layer coordinating incident ingestion and multi-agent analysis."""

    def __init__(self, pipeline: Optional[MultiAgentPipeline] = None):
        self.pipeline = pipeline or MultiAgentPipeline()

    async def analyze_incident(self, incident: Incident) -> IncidentReport:
        """
        Processes an incoming incident bundle through the 3-agent LLM analysis pipeline.
        """
        logger.info(f"Received incident {incident.incident_id} ({incident.title}) for analysis")
        report = self.pipeline.analyze(incident)
        logger.info(f"Incident {incident.incident_id} analysis completed: verdict={report.verdict}, severity={report.severity}")
        return report
