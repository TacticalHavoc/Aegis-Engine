from fastapi import APIRouter, Depends, status
from app.models.alert import Alert, AlertAcknowledgement
from app.services.investigation_service import InvestigationService

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


def get_investigation_service() -> InvestigationService:
    return InvestigationService()


@router.post(
    "",
    response_model=AlertAcknowledgement,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a security alert",
    description="Receives a structured security alert from upstream detection engines or producers for triage and investigation.",
)
async def ingest_alert(
    alert: Alert,
    service: InvestigationService = Depends(get_investigation_service),
) -> AlertAcknowledgement:
    return await service.ingest_alert(alert)
