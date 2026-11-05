import os
import json
import logging
import threading
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from kafka import KafkaConsumer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis-backend")

KAFKA_SERVER = os.getenv("KAFKA_SERVER", "kafka:29092")
AGENTIC_SOC_URL = os.getenv(
    "AGENTIC_SOC_URL", "http://agentic-soc:8000"
).rstrip("/")

raw_logs = deque(maxlen=1000)
normalized_logs = deque(maxlen=1000)
alerts = deque(maxlen=1000)

data_lock = threading.RLock()
consumer_threads = []
stop_event = threading.Event()


def consume_topic(topic: str, destination: deque):
    while not stop_event.is_set():
        consumer = None
        try:
            consumer = KafkaConsumer(
                topic,
                bootstrap_servers=KAFKA_SERVER,
                group_id=f"aegis-backend-{topic.replace('.', '-')}",
                auto_offset_reset="earliest",
                enable_auto_commit=True,
                value_deserializer=lambda value: json.loads(
                    value.decode("utf-8")
                ),
                consumer_timeout_ms=1000,
            )

            logger.info("Consuming Kafka topic: %s", topic)

            while not stop_event.is_set():
                for message in consumer:
                    if stop_event.is_set():
                        break

                    value = message.value
                    if not isinstance(value, dict):
                        continue

                    with data_lock:
                        destination.appendleft(value)

        except Exception:
            logger.exception("Kafka consumer error for %s", topic)
            stop_event.wait(5)

        finally:
            if consumer is not None:
                try:
                    consumer.close()
                except Exception:
                    pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    stop_event.clear()

    topics = [
        ("siem.raw", raw_logs),
        ("siem.normalized", normalized_logs),
        ("siem.alerts", alerts),
    ]

    for topic, destination in topics:
        thread = threading.Thread(
            target=consume_topic,
            args=(topic, destination),
            daemon=True,
        )
        thread.start()
        consumer_threads.append(thread)

    yield

    stop_event.set()
    for thread in consumer_threads:
        thread.join(timeout=2)


app = FastAPI(
    title="Aegis SIEM Backend",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "kafka_server": KAFKA_SERVER,
        "agentic_soc": AGENTIC_SOC_URL,
    }


@app.get("/api/stats")
def get_stats():
    with data_lock:
        return {
            "raw_events": len(raw_logs),
            "normalized_events": len(normalized_logs),
            "alerts": len(alerts),
            "critical_alerts": sum(
                str(a.get("severity", "")).lower() == "critical"
                for a in alerts
            ),
        }


@app.get("/api/raw-logs")
def get_raw_logs(limit: int = 100):
    with data_lock:
        return list(raw_logs)[:max(1, min(limit, 500))]


@app.get("/api/normalized-logs")
def get_normalized_logs(limit: int = 100):
    with data_lock:
        return list(normalized_logs)[:max(1, min(limit, 500))]


@app.get("/api/alerts")
def get_alerts(limit: int = 100):
    with data_lock:
        return list(alerts)[:max(1, min(limit, 500))]


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value

    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            pass

    return datetime.now(timezone.utc)


def classify_event(event: dict) -> str:
    text = " ".join([
        str(event.get("category", "")),
        str(event.get("event_type", "")),
        str(event.get("message", "")),
    ]).lower()

    for keyword, event_type in [
        ("auth", "auth"),
        ("login", "auth"),
        ("ssh", "auth"),
        ("process", "process"),
        ("file", "file"),
        ("network", "network"),
        ("dns", "dns"),
    ]:
        if keyword in text:
            return event_type

    return "other"


def severity_for_agent(value: Any) -> str:
    severity = str(value or "").lower()
    if severity in {"low", "medium", "high", "critical"}:
        return severity
    return "medium"


@app.post("/api/alerts/{alert_id}/analyze")
async def analyze_alert(alert_id: str):
    # Only this endpoint triggers AI analysis.
    with data_lock:
        alert = next(
            (item for item in alerts
             if str(item.get("alert_id")) == alert_id),
            None,
        )

    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")

    rule = alert.get("rule") or {}
    event = alert.get("event") or {}
    mapped = alert.get("mapped_event") or {}

    host = (
        alert.get("host")
        or event.get("host")
        or mapped.get("Computer")
        or "unknown"
    )

    timestamp = parse_timestamp(
        alert.get("timestamp") or event.get("timestamp")
    )

    title = rule.get("title") or "Security alert"
    rule_name = rule.get("id") or title
    description = (
        rule.get("description")
        or event.get("message")
        or "Security detection generated by Aegis Rule Engine."
    )

    incident = {
        "incident_id": str(alert_id),
        "title": title,
        "severity": severity_for_agent(alert.get("severity")),
        "rule_name": str(rule_name),
        "timestamp": timestamp.isoformat(),
        "description": str(description),
        "flagged_logs": [{
            "timestamp": timestamp.isoformat(),
            "event_type": classify_event(event),
            "host": str(host),
            "user": (
                event.get("username")
                or event.get("user", {}).get("name")
                if isinstance(event.get("user"), dict)
                else event.get("username")
            ),
            "data": {
                "alert": alert,
                "original_event": event,
                "mapped_event": mapped,
            },
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"{AGENTIC_SOC_URL}/api/v1/incidents/analyze",
                json=incident,
            )
            response.raise_for_status()
            return response.json()

    except httpx.HTTPStatusError as exc:
        logger.error(
            "AgenticSOC returned HTTP %s: %s",
            exc.response.status_code,
            exc.response.text[:1000],
        )
        raise HTTPException(
            status_code=502,
            detail="AgenticSOC rejected the incident",
        )

    except httpx.RequestError:
        logger.exception("Could not reach AgenticSOC")
        raise HTTPException(
            status_code=502,
            detail="Could not connect to AgenticSOC",
        )


@app.post("/api/logs/analyze")
async def analyze_log(payload: dict):
    """Manually send one raw or normalized event to AgenticSOC."""
    log_type = payload.get("log_type", "raw")
    event = payload.get("event")

    if log_type not in {"raw", "normalized"}:
        raise HTTPException(status_code=400, detail="Invalid log type")

    if not isinstance(event, dict):
        raise HTTPException(status_code=400, detail="Event must be a JSON object")

    original = event.get("raw") if log_type == "normalized" else event
    if not isinstance(original, dict):
        original = event

    timestamp = parse_timestamp(
        event.get("@timestamp") or event.get("timestamp")
        or original.get("@timestamp") or original.get("timestamp")
    )

    host_value = (
        event.get("host")
        or event.get("Computer")
        or original.get("host")
        or original.get("hostname")
        or "unknown"
    )
    if isinstance(host_value, dict):
        host_value = host_value.get("name", "unknown")

    user_value = event.get("username") or event.get("User")
    if not user_value:
        user_obj = original.get("user")
        user_value = user_obj.get("name") if isinstance(user_obj, dict) else original.get("username")

    incident = {
        "incident_id": f"manual-log-{int(datetime.now(timezone.utc).timestamp() * 1000)}",
        "title": f"Manual {log_type} log investigation",
        "severity": "medium",
        "rule_name": "Analyst-Requested-Log-Analysis",
        "timestamp": timestamp.isoformat(),
        "description": str(event.get("message") or original.get("message") or "Manually submitted log for investigation"),
        "flagged_logs": [{
            "timestamp": timestamp.isoformat(),
            "event_type": classify_event(original),
            "host": str(host_value),
            "user": str(user_value) if user_value else None,
            "data": {
                "log_type": log_type,
                "selected_event": event,
                "original_event": original
            }
        }]
    }

    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"{AGENTIC_SOC_URL}/api/v1/incidents/analyze",
                json=incident
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        logger.error("AgenticSOC returned HTTP %s: %s", exc.response.status_code, exc.response.text[:1000])
        raise HTTPException(status_code=502, detail="AgenticSOC rejected the log")
    except httpx.RequestError:
        logger.exception("Could not connect to AgenticSOC")
        raise HTTPException(status_code=502, detail="AgenticSOC is unavailable")
