from datetime import datetime, timezone
from pydantic import BaseModel, Field


def get_utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Alert(BaseModel):
    alert_id: str
    timestamp: datetime
    host: str
    severity: str
    rule_name: str
    mitre_technique: str | None = None
    description: str


class AlertAcknowledgement(BaseModel):
    status: str = "accepted"
    alert_id: str
    message: str = "Alert received and queued for investigation"
    received_at: datetime = Field(default_factory=get_utc_now)
