from datetime import datetime, timedelta, timezone
from typing import List, Optional
from app.models.investigation import NetworkEvent

# Structured mock network telemetry dataset
MOCK_NETWORK_LOGS: List[NetworkEvent] = [
    NetworkEvent(
        event_id="EVT-NET-301",
        timestamp=datetime.fromisoformat("2026-09-26T10:29:50+00:00"),
        host="DESKTOP-01",
        process_id=5820,
        process_name="powershell.exe",
        source_ip="192.168.1.105",
        source_port=49210,
        destination_ip="198.51.100.23",
        destination_port=80,
        protocol="TCP",
        domain="malicious.site",
    ),
    NetworkEvent(
        event_id="EVT-NET-302",
        timestamp=datetime.fromisoformat("2026-09-26T10:30:15+00:00"),
        host="DESKTOP-01",
        process_id=5820,
        process_name="powershell.exe",
        source_ip="192.168.1.105",
        source_port=49212,
        destination_ip="198.51.100.23",
        destination_port=443,
        protocol="TCP",
        domain="c2.malicious.site",
    ),
    NetworkEvent(
        event_id="EVT-NET-401",
        timestamp=datetime.fromisoformat("2026-09-26T11:00:05+00:00"),
        host="SRV-DB-02",
        process_id=1840,
        process_name="postgres.exe",
        source_ip="10.0.0.50",
        source_port=5432,
        destination_ip="10.0.0.12",
        destination_port=51204,
        protocol="TCP",
        domain=None,
    ),
]


def get_network_logs(
    host: str,
    timestamp: datetime,
    window_minutes: int = 15,
    process_id: Optional[int] = None,
    destination_ip: Optional[str] = None,
) -> List[NetworkEvent]:
    """
    Retrieve network connection telemetry for a target host within a time window.
    
    Permissions: Read-only
    Side Effects: None
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    window = timedelta(minutes=window_minutes)
    start_time = timestamp - window
    end_time = timestamp + window

    matched_events = []
    for evt in MOCK_NETWORK_LOGS:
        if evt.host.lower() != host.lower():
            continue

        evt_ts = evt.timestamp
        if evt_ts.tzinfo is None:
            evt_ts = evt_ts.replace(tzinfo=timezone.utc)

        if start_time <= evt_ts <= end_time:
            if process_id is not None and evt.process_id != process_id:
                continue
            if destination_ip is not None and evt.destination_ip != destination_ip:
                continue
            matched_events.append(evt)

    return matched_events
