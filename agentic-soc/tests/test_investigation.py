from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.alert import Alert
from app.agents.investigator import InvestigationAgent
from app.tools.process_tools import get_process_logs
from app.tools.network_tools import get_network_logs

client = TestClient(app)


def test_get_process_logs_tool_matches():
    """Verify read-only tool correctly retrieves process events within time window."""
    alert_time = datetime.fromisoformat("2026-09-26T10:30:00+00:00")
    events = get_process_logs(host="DESKTOP-01", timestamp=alert_time, window_minutes=15)
    
    assert len(events) >= 2
    process_names = [e.process_name for e in events]
    assert "powershell.exe" in process_names
    assert "cmd.exe" in process_names


def test_get_process_logs_tool_no_match():
    """Verify tool returns empty list when host or timestamp does not match."""
    alert_time = datetime.fromisoformat("2026-09-26T10:30:00+00:00")
    events = get_process_logs(host="NON-EXISTENT-HOST", timestamp=alert_time, window_minutes=15)
    assert events == []


def test_get_network_logs_tool_matches():
    """Verify read-only network tool retrieves network events by host and timestamp."""
    alert_time = datetime.fromisoformat("2026-09-26T10:30:00+00:00")
    net_events = get_network_logs(host="DESKTOP-01", timestamp=alert_time, window_minutes=15)
    
    assert len(net_events) >= 2
    destinations = [e.destination_ip for e in net_events]
    assert "198.51.100.23" in destinations


def test_get_network_logs_tool_pid_filter():
    """Verify network tool correctly filters by process_id."""
    alert_time = datetime.fromisoformat("2026-09-26T10:30:00+00:00")
    net_events = get_network_logs(host="DESKTOP-01", timestamp=alert_time, window_minutes=15, process_id=5820)
    
    assert len(net_events) == 2
    assert all(e.process_id == 5820 for e in net_events)


@pytest.mark.anyio
async def test_investigator_correlates_process_and_network_evidence():
    """Verify InvestigationAgent correlates suspicious process with outbound network C2 traffic."""
    agent = InvestigationAgent()
    alert = Alert(
        alert_id="ALERT-001",
        timestamp=datetime.fromisoformat("2026-09-26T10:30:00+00:00"),
        host="DESKTOP-01",
        severity="high",
        rule_name="Suspicious PowerShell Execution",
        mitre_technique="T1059.001",
        description="PowerShell executed with an encoded command",
    )

    result = await agent.investigate(alert)

    assert result.alert_id == "ALERT-001"
    assert result.host == "DESKTOP-01"
    assert result.verdict == "suspicious"
    
    evidence_types = [e.artifact_type for e in result.evidence]
    assert "encoded_powershell_execution" in evidence_types
    assert "network_c2_connection" in evidence_types
    
    # Confirm network evidence contains domain and remote IP
    net_ev = next(e for e in result.evidence if e.artifact_type == "network_c2_connection")
    assert net_ev.data["destination_ip"] == "198.51.100.23"
    assert "malicious.site" in (net_ev.data["domain"] or "")


@pytest.mark.anyio
async def test_investigator_handles_missing_logs():
    """Verify InvestigationAgent returns inconclusive verdict when no telemetry is found."""
    agent = InvestigationAgent()
    alert = Alert(
        alert_id="ALERT-002",
        timestamp=datetime.fromisoformat("2026-09-26T10:30:00+00:00"),
        host="UNKNOWN-HOST-99",
        severity="low",
        rule_name="Unknown Alert",
        description="Alert for non-existent host",
    )

    result = await agent.investigate(alert)

    assert result.alert_id == "ALERT-002"
    assert result.verdict == "inconclusive"
    assert len(result.evidence) == 0


def test_api_alert_ingest_with_investigation():
    """Verify end-to-end API ingestion returns 202 and acknowledges investigation."""
    payload = {
        "alert_id": "ALERT-001",
        "timestamp": "2026-09-26T10:30:00Z",
        "host": "DESKTOP-01",
        "severity": "high",
        "rule_name": "Suspicious PowerShell Execution",
        "mitre_technique": "T1059.001",
        "description": "PowerShell executed with an encoded command",
    }

    response = client.post("/api/v1/alerts", json=payload)
    assert response.status_code == 202
    data = response.json()
    assert data["alert_id"] == "ALERT-001"
    assert data["status"] == "accepted"
    assert "verdict=suspicious" in data["message"]
