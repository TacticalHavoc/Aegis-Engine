import json

from kafka import KafkaConsumer, KafkaProducer

KAFKA_SERVER = "kafka:29092"
INPUT_TOPIC = "siem.raw"
OUTPUT_TOPIC = "siem.normalized"


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


def normalize(event):
    """
    Convert incoming log events into a common SIEM schema.

    This function does NOT classify, detect, score or interpret
    security events. It only extracts fields that are already
    available in the incoming event.
    """

    host = event.get("host", {})
    if not isinstance(host, dict):
        host = {}

    log = event.get("log", {})
    if not isinstance(log, dict):
        log = {}

    process = event.get("process", {})
    if not isinstance(process, dict):
        process = {}

    source = event.get("source", {})
    if not isinstance(source, dict):
        source = {}

    destination = event.get("destination", {})
    if not isinstance(destination, dict):
        destination = {}

    user = event.get("user", {})
    if not isinstance(user, dict):
        user = {}

    normalized = {
        # Common event information
        "timestamp": event.get("@timestamp"),
        "host": host.get("name"),
        "source": event.get("log_source"),
        "environment": event.get("environment"),
        # Original log information
        "message": event.get("message"),
        "level": log.get("level"),
        # Process information
        "process_name": process.get("name"),
        "process_pid": process.get("pid"),
        # Network information
        "source_ip": source.get("ip"),
        "source_port": source.get("port"),
        "destination_ip": destination.get("ip"),
        "destination_port": destination.get("port"),
        # User information
        "username": user.get("name"),
        # Preserve the complete original event
        "raw": event,
    }

    return normalized


print("Normalizer started...")
print(f"Consuming: {INPUT_TOPIC}")
print(f"Producing: {OUTPUT_TOPIC}")


for record in consumer:
    try:
        # Decode Kafka message
        raw_value = record.value.decode("utf-8")

        try:
            event = json.loads(raw_value)

        except json.JSONDecodeError:
            print(f"[SKIP] Non-JSON message in {record.topic}: {raw_value[:150]}")
            continue

        # Normalize without classification or detection
        normalized = normalize(event)

        # Send normalized event to Kafka
        producer.send(OUTPUT_TOPIC, normalized)

        print(
            f"[NORMALIZED] "
            f"{normalized['host']} | "
            f"{normalized['source']} | "
            f"{normalized['level']} | "
            f"{normalized['message'][:200] if normalized['message'] else ''}"
        )

    except Exception as e:
        print(f"[ERROR] {e}")
