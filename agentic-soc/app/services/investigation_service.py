import logging
from datetime import datetime, timezone
from typing import Optional
from app.agents.investigator import InvestigationAgent
from app.models.alert import Alert, AlertAcknowledgement
from app.models.investigation import InvestigationResult

logger = logging.getLogger(__name__)


class InvestigationService:
    """Service layer responsible for ingesting alerts and coordinating investigations."""

    def __init__(self, agent: Optional[InvestigationAgent] = None):
        self.agent = agent or InvestigationAgent()

    async def ingest_alert(self, alert: Alert) -> AlertAcknowledgement:
        """
        Receives and validates a security alert, queuing / triggering investigation.
        """
        logger.info(f"Ingested alert {alert.alert_id} for host {alert.host} with severity {alert.severity}")
        
        # Trigger investigation workflow
        investigation_result = await self.investigate_alert(alert)
        logger.info(f"Investigation completed for {alert.alert_id}: verdict={investigation_result.verdict}")

        return AlertAcknowledgement(
            status="accepted",
            alert_id=alert.alert_id,
            message=f"Alert received and investigated: verdict={investigation_result.verdict}",
            received_at=datetime.now(timezone.utc),
        )

    async def investigate_alert(self, alert: Alert) -> InvestigationResult:
        """
        Invokes the Investigation Agent to investigate the alert.
        """
        return await self.agent.investigate(alert)
