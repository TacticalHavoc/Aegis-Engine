from datetime import datetime, timezone
from typing import Any, List, Optional
from pydantic import BaseModel, Field


class ProcessEvent(BaseModel):
    """Represents a process execution telemetry record."""
    event_id: str
    timestamp: datetime
    host: str
    process_id: int
    parent_process_id: int
    process_name: str
    command_line: str
    user: str
    parent_process_name: Optional[str] = None


class NetworkEvent(BaseModel):
    """Represents a network connection telemetry record."""
    event_id: str
    timestamp: datetime
    host: str
    process_id: int
    process_name: str
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str = "TCP"
    domain: Optional[str] = None


class Evidence(BaseModel):
    """Represents a discrete piece of evidence correlated during an investigation."""
    artifact_type: str  # e.g., "process_execution", "network_connection", "encoded_command"
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)


class InvestigationResult(BaseModel):
    """Structured output produced by the Investigation Agent."""
    alert_id: str
    host: str
    verdict: str  # "suspicious" | "benign" | "inconclusive"
    summary: str
    evidence: List[Evidence] = Field(default_factory=list)
    investigated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
