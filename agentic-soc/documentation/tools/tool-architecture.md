# Tool Architecture Specification

**Status**: Implemented  
**Verification**: Verified  
**Package**: `app/tools/`  

---

## 1. Architectural Philosophy

All agent tools within the Agentic SOC strictly follow the **Read-Only Non-Destructive Invariant**:

- Tools provide bounded, parameterized queries against telemetry.
- Tools enforce strict input types and return typed Pydantic models.
- Tools have **zero side-effects** on host endpoints, systems, or storage backends.

---

## 2. Implemented Tools

### `get_process_logs`

**Location**: [`app/tools/process_tools.py`](file:///home/astute/Projects/AgenticSOC/app/tools/process_tools.py)

**Purpose**:  
Retrieve process execution telemetry (process creations, command lines, parent-child hierarchies) for a target host within a configurable time window around an incident.

**Input Parameters**:
- `host` (`str`): Target hostname (case-insensitive).
- `timestamp` (`datetime`): Reference timestamp (e.g. alert occurrence time).
- `window_minutes` (`int`, default: `15`): Search window buffer before and after the timestamp.
- `process_name` (`Optional[str]`, default: `None`): Optional binary name filter (e.g., `powershell.exe`).

**Output**:
- `list[ProcessEvent]`: Telemetry events including `event_id`, `timestamp`, `host`, `process_id`, `parent_process_id`, `process_name`, `command_line`, `user`, `parent_process_name`.

**Permissions**:
- Read-only.

**Side Effects**:
- None.

---

### `get_network_logs`

**Location**: [`app/tools/network_tools.py`](file:///home/astute/Projects/AgenticSOC/app/tools/network_tools.py)

**Purpose**:  
Retrieve outbound and inbound network connection telemetry (sockets, remote IPs, ports, protocols, associated processes, and resolved domains) for a target host within a time window.

**Input Parameters**:
- `host` (`str`): Target hostname (case-insensitive).
- `timestamp` (`datetime`): Reference timestamp (e.g. alert occurrence time).
- `window_minutes` (`int`, default: `15`): Search window buffer before and after the timestamp.
- `process_id` (`Optional[int]`, default: `None`): Filter connections initiated by a specific process ID.
- `destination_ip` (`Optional[str]`, default: `None`): Filter connections to a specific remote IP address.

**Output**:
- `list[NetworkEvent]`: Telemetry events including `event_id`, `timestamp`, `host`, `process_id`, `process_name`, `source_ip`, `source_port`, `destination_ip`, `destination_port`, `protocol`, `domain`.

**Permissions**:
- Read-only.

**Side Effects**:
- None.

---

## 3. Planned Tools

- `get_user_activity(user, timestamp, window_minutes)`: Authentication, logon sessions, and privilege elevation events.
- `get_mitre_technique_info(technique_id)`: MITRE ATT&CK contextual mapping and threat intelligence references.
- `search_historical_alerts(host, time_range_days)`: Retrieve prior alert occurrences for recurring threat detection.
