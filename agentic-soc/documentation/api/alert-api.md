# Alert Ingestion API Specification

Status: Implemented  
Verification: Verified

## 1. Overview

The Alert Ingestion API serves as the formal boundary between upstream alert producers (e.g., detection engines, Kafka consumers, SIEMs, or testing clients like Postman/curl) and the Agentic SOC.

It decouples log detection pipelines from the downstream investigation workflow.

---

## 2. Endpoints

### 2.1 Health Check

- **Method**: `GET`
- **Path**: `/health`
- **Purpose**: Liveness and readiness probe for the service.
- **Authentication**: None

#### Response

- **Status Code**: `200 OK`
- **Content-Type**: `application/json`

```json
{
  "status": "healthy"
}
```

---

### 2.2 Alert Ingestion

- **Method**: `POST`
- **Path**: `/api/v1/alerts`
- **Purpose**: Ingests a structured security alert and queues it for triage and investigation.
- **Authentication**: None (Milestone 1.0; authentication planned for future infrastructure milestone).

#### Request Schema

| Field | Type | Required | Description |
| :--- | :--- | :--- | :--- |
| `alert_id` | string | Yes | Unique identifier for the alert. |
| `timestamp` | string (ISO-8601) | Yes | Timestamp of when the alert condition was detected. |
| `host` | string | Yes | Target hostname or endpoint identifier. |
| `severity` | string | Yes | Alert severity (`low`, `medium`, `high`, `critical`). |
| `rule_name` | string | Yes | Name of the triggering detection rule. |
| `mitre_technique` | string \| null | No | Associated MITRE ATT&CK technique ID (e.g., `T1059.001`). Default: `null`. |
| `description` | string | Yes | Detailed description of the suspicious behavior observed. |

#### Request Example

```json
{
  "alert_id": "ALERT-001",
  "timestamp": "2026-09-26T10:30:00Z",
  "host": "DESKTOP-01",
  "severity": "high",
  "rule_name": "Suspicious PowerShell Execution",
  "mitre_technique": "T1059.001",
  "description": "PowerShell executed with an encoded command"
}
```

#### Response: Success

- **Status Code**: `202 Accepted`
- **Content-Type**: `application/json`

```json
{
  "status": "accepted",
  "alert_id": "ALERT-001",
  "message": "Alert received and queued for investigation",
  "received_at": "2026-09-26T11:43:03.420063Z"
}
```

#### Response: Validation Error

- **Status Code**: `422 Unprocessable Content`
- **Content-Type**: `application/json`

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "timestamp"],
      "msg": "Field required",
      "input": { "alert_id": "ALERT-002" }
    }
  ]
}
```

---

## 3. Dependencies & Service Boundary

The endpoint delegates alert ingestion to `app.services.investigation_service.InvestigationService.ingest_alert()`. The endpoint does not directly invoke agents or databases.
