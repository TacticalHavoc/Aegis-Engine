import logging
from fastapi import APIRouter, Depends, status
from app.models.incident import Incident, IncidentReport
from app.services.incident_service import IncidentService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


def get_incident_service() -> IncidentService:
    """Dependency provider for IncidentService."""
    return IncidentService()


@router.post(
    "/analyze",
    response_model=IncidentReport,
    status_code=status.HTTP_200_OK,
    summary="Analyze a security incident with flagged logs",
    description="Receives an incident bundle containing flagged logs from Kafka/ML and returns a comprehensive multi-agent incident analysis report.",
)
async def analyze_incident(
    incident: Incident,
    service: IncidentService = Depends(get_incident_service),
) -> IncidentReport:
    """
    Endpoint for multi-agent incident analysis.
    """
    logger.info(f"POST /api/v1/incidents/analyze called for incident {incident.incident_id}")
    return await service.analyze_incident(incident)
