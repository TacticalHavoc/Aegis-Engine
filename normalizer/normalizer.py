import json
from kafka import KafkaConsumer, KafkaProducer

KAFKA_SERVER = "kafka:29092"
INPUT_TOPIC = "siem.raw"
OUTPUT_TOPIC = "siem.normalized"


def get(data, path):
    value = data
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def first(*values):
    return next((v for v in values if v is not None and v != ""), None)


def normalize(event):
    raw = event

    # ECS/source fields
    host = first(get(raw, "host.name"), raw.get("hostname"), raw.get("host"))
    process_image = first(get(raw, "process.executable"))
    process_name = get(raw, "process.name")
    command = first(get(raw, "process.command_line"), raw.get("command_line"))
    parent_image = get(raw, "process.parent.executable")
    parent_command = get(raw, "process.parent.command_line")

    source_ip = first(get(raw, "source.ip"), raw.get("source_ip"))
    source_port = first(get(raw, "source.port"), raw.get("source_port"))
    dest_ip = first(get(raw, "destination.ip"), raw.get("destination_ip"))
    dest_port = first(get(raw, "destination.port"), raw.get("destination_port"))

    direction = first(get(raw, "network.direction"), get(raw, "event.network_direction"))
    initiated = None
    if isinstance(direction, str):
        if direction.lower() in ("outbound", "egress"):
            initiated = "true"
        elif direction.lower() in ("inbound", "ingress"):
            initiated = "false"

    # Sigma-compatible event
    normalized = {
        "timestamp": first(raw.get("@timestamp"), raw.get("timestamp")),
        "host": host,
        "source": first(raw.get("log_source"), get(raw, "event.dataset")),
        "environment": first(raw.get("environment"), get(raw, "fields.environment")),
        "message": raw.get("message"),

        # Process fields
        "Image": process_image,
        "CommandLine": command,
        "ParentImage": parent_image,
        "ParentCommandLine": parent_command,
        "ProcessId": get(raw, "process.pid"),
        "ParentProcessId": get(raw, "process.parent.pid"),
        "CurrentDirectory": get(raw, "process.working_directory"),

        # Network fields
        "SourceIp": source_ip,
        "SourcePort": source_port,
        "DestinationIp": dest_ip,
        "DestinationPort": dest_port,
        "Initiated": initiated,

        # User and host fields
        "User": first(get(raw, "user.name"), raw.get("username")),
        "Computer": host,

        # File and event context
        "TargetFilename": first(get(raw, "file.path"), get(raw, "file.name")),
        "EventAction": get(raw, "event.action"),
        "EventCategory": get(raw, "event.category"),
        "EventOutcome": get(raw, "event.outcome"),

        # Keep useful fields for dashboard compatibility
        "level": get(raw, "log.level"),
        "process_name": process_name,
        "process_pid": get(raw, "process.pid"),
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": dest_ip,
        "destination_port": dest_port,
        "username": first(get(raw, "user.name"), raw.get("username")),

        # Preserve original event
        "raw": raw,
    }

    # Remove unavailable values rather than inventing them.
    return {key: value for key, value in normalized.items() if value is not None}


consumer = KafkaConsumer(
    INPUT_TOPIC,
    bootstrap_servers=KAFKA_SERVER,
    group_id="normalizer-group",
    auto_offset_reset="earliest",
    enable_auto_commit=True,
)

producer = KafkaProducer(
    bootstrap_servers=KAFKA_SERVER,
    value_serializer=lambda x: json.dumps(x).encode("utf-8"),
)

print("Normalizer started...")
print(f"Consuming: {INPUT_TOPIC}")
print(f"Producing: {OUTPUT_TOPIC}")

for record in consumer:
    try:
        event = record.value
        if isinstance(event, bytes):
            event = json.loads(event.decode("utf-8"))

        if not isinstance(event, dict):
            print("[SKIP] Event is not a JSON object")
            continue

        normalized = normalize(event)
        producer.send(OUTPUT_TOPIC, normalized).get(timeout=10)

        print(
            f"[NORMALIZED] {normalized.get('host', 'unknown')} | "
            f"Image={normalized.get('Image', 'N/A')} | "
            f"DestinationPort={normalized.get('DestinationPort', 'N/A')}"
        )

    except Exception as error:
        print(f"[ERROR] {error}")
