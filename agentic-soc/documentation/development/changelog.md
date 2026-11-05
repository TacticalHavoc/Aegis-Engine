# Changelog
 
 All notable changes to the Agentic SOC project will be documented in this file.
 
## [2026-11-02]

### Interactive SOC Dashboard & Usability Improvement
- **Added**: Interactive SOC Incident Dashboard ([`app/static/dashboard.html`](file:///home/astute/Projects/AgenticSOC/app/static/dashboard.html), [`dashboard.html`](file:///home/astute/Projects/AgenticSOC/dashboard.html)) with rich aesthetics, glassmorphic dark theme, 3-agent visualizer, chronological attack timeline, MITRE ATT&CK grid, IOC intelligence tags, and interactive tactical remediation checklist.
- **Added**: FastAPI endpoints `GET /dashboard` and `GET /` in [`app/main.py`](file:///home/astute/Projects/AgenticSOC/app/main.py) for live in-browser multi-agent incident inspection and JSON file upload.
- **Added**: Local `.env` file support via `python-dotenv` and provided `.env.example` template.
- **Updated**: `app/__init__.py`, `app/main.py`, and `run_incident_analysis.py` to automatically load environment variables on startup.
- **Updated**: `requirements.txt` with `python-dotenv`.

---

## [2026-10-07]

### Milestone 2.2 — Live Multi-Agent LLM Incident Reasoning Engine
- **Added**: 3-Agent Collaborative LLM Architecture:
  - `ForensicInvestigatorAgent` ([`app/agents/forensic_investigator.py`](file:///home/astute/Projects/AgenticSOC/app/agents/forensic_investigator.py)) for deobfuscation and timeline reconstruction.
  - `ThreatAnalystAgent` ([`app/agents/threat_analyst.py`](file:///home/astute/Projects/AgenticSOC/app/agents/threat_analyst.py)) for MITRE ATT&CK mapping and blast radius calculation.
  - `ResponseAdvisorAgent` ([`app/agents/response_advisor.py`](file:///home/astute/Projects/AgenticSOC/app/agents/response_advisor.py)) for executive synthesis and tactical containment advisories.
  - `MultiAgentPipeline` ([`app/agents/multi_agent_pipeline.py`](file:///home/astute/Projects/AgenticSOC/app/agents/multi_agent_pipeline.py)) orchestrating agent handoffs.
- **Added**: CLI Incident Analysis Runner ([`run_incident_analysis.py`](file:///home/astute/Projects/AgenticSOC/run_incident_analysis.py)) with colorized DFIR reporting.
- **Added**: Attack scenario test fixture ([`sample_incident.json`](file:///home/astute/Projects/AgenticSOC/sample_incident.json)) containing macro execution, PowerShell cradle, `whoami` discovery, and outbound C2 socket.
- **Tested & Verified**: Live Google Gemini integration verified on [sample_incident.json](file:///home/astute/Projects/AgenticSOC/sample_incident.json) achieving 100% confidence deobfuscation, MITRE mapping, and tactical remediation ordering.

---

## [2026-10-06]
 
 ### Milestone 2.2 — Flagged Incident Log Ingestion & Multi-Agent Incident Analysis Engine
- **Added**: `FlaggedLog`, `Incident`, `TimelineEvent`, `MitreItem`, `AffectedEntities`, and `IncidentReport` models in `app/models/incident.py`.
- **Added**: `IncidentAnalyzer` in `app/agents/incident_analyzer.py` supporting collaborative multi-agent roles (Investigator, Threat Analyst, Response Advisor), timeline reconstruction, MITRE ATT&CK mapping, and remediation guidance.
- **Added**: `IncidentService` in `app/services/incident_service.py` and `POST /api/v1/incidents/analyze` endpoint in `app/api/incidents.py`.
- **Added**: `tests/test_incident_analysis.py` with unit tests for malicious log correlation, timeline sequencing, empty incident handling, and API endpoint verification.
- **Updated**: `app/main.py` mounting the incidents router.
- **Added**: `documentation/decisions/ADR-003.md` (Multi-Agent Flagged Log Incident Analysis Architecture).
- **Added**: `documentation/api/incident-api.md` (Incident Analysis API specification).
- **Updated**: `documentation/development/milestones.md` and `documentation/development/current-status.md`.

---

## [2026-09-27]

### Milestone 2.1 — Multi-Source Telemetry & Network Tool Integration
- **Added**: `NetworkEvent` model in `app/models/investigation.py`.
- **Added**: Read-only `get_network_logs` tool in `app/tools/network_tools.py` with mock network telemetry.
- **Updated**: `app/tools/__init__.py` exporting `get_network_logs`.
- **Updated**: `InvestigationAgent` in `app/agents/investigator.py` to pivot from suspicious process IDs to network telemetry, extracting `network_c2_connection` evidence.
- **Updated**: `tests/test_investigation.py` with unit tests for `get_network_logs` and multi-source cross-telemetry correlation.
- **Tested & Verified**: 7 automated tests passed.

### Milestone 2.0 — Investigation Agent & Read-Only Tool Architecture
- **Added**: `ProcessEvent`, `Evidence`, and `InvestigationResult` models in `app/models/investigation.py`.
- **Added**: Read-only `get_process_logs` tool in `app/tools/process_tools.py` with mock process telemetry.
- **Added**: `InvestigationAgent` in `app/agents/investigator.py` to query telemetry, evaluate suspicious process execution, and correlate findings.
- **Updated**: `InvestigationService` in `app/services/investigation_service.py` to trigger investigation workflow upon alert ingestion.
- **Added**: Automated unit and integration test suite in `tests/test_investigation.py`.
- **Tested & Verified**: 5 automated tests passed verifying tool queries, evidence correlation, inconclusive handling, and end-to-end API integration.

---

## [2026-09-26]

### Milestone 1.0 — Alert Ingestion API Skeleton
- **Added**: `Alert` and `AlertAcknowledgement` Pydantic models in `app/models/alert.py`.
- **Added**: `InvestigationService` in `app/services/investigation_service.py` for decoupled domain logic.
- **Added**: `POST /api/v1/alerts` endpoint in `app/api/alerts.py` returning HTTP 202 Accepted.
- **Added**: `GET /health` endpoint and FastAPI app initialization in `app/main.py`.
- **Tested & Verified**: Health check, valid alert payload ingestion, and invalid schema rejection with HTTP 422.
