def get_nested(data, path):
    """Retrieve a nested field using dot notation."""
    value = data

    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)

    return value


def first_available(*values):
    """Return the first value that is actually available."""
    for value in values:
        if value is not None and value != "":
            return value

    return None


def map_event(event):
    """
    Map normalized Filebeat events to common Sigma field names.

    Original event data is preserved.
    Missing fields are not fabricated.
    """

    mapped = dict(event)

    raw = event.get("raw", {})
    if not isinstance(raw, dict):
        raw = {}

    field_mappings = {
        "Image": [
            "process.executable",
        ],
        "CommandLine": [
            "process.command_line",
        ],
        "ParentImage": [
            "process.parent.executable",
        ],
        "User": [
            "user.name",
        ],
        "DestinationIp": [
            "destination.ip",
        ],
        "DestinationPort": [
            "destination.port",
        ],
        "SourceIp": [
            "source.ip",
        ],
        "SourcePort": [
            "source.port",
        ],
        "ProcessId": [
            "process.pid",
        ],
        "ParentProcessId": [
            "process.parent.pid",
        ],
        "CurrentDirectory": [
            "process.working_directory",
        ],
    }

    for sigma_field, source_paths in field_mappings.items():

        # Don't overwrite an existing Sigma-compatible field.
        if mapped.get(sigma_field) is not None:
            continue

        candidates = []

        for path in source_paths:
            candidates.append(get_nested(raw, path))

        value = first_available(*candidates)

        # Use normalized fields as fallbacks where appropriate.
        if value is None:
            fallbacks = {
                "User": ["username"],
                "DestinationIp": ["destination_ip"],
                "DestinationPort": ["destination_port"],
                "SourceIp": ["source_ip"],
                "SourcePort": ["source_port"],
                "ProcessId": ["process_pid"],
            }

            for fallback in fallbacks.get(sigma_field, []):
                value = event.get(fallback)

                if value is not None:
                    break

        if value is not None:
            mapped[sigma_field] = value

    # Additional common fields
    mapped.setdefault(
        "Computer",
        first_available(
            get_nested(raw, "host.name"),
            event.get("host")
        )
    )

    mapped.setdefault(
        "Message",
        first_available(
            event.get("message"),
            get_nested(raw, "message")
        )
    )

    return mapped
