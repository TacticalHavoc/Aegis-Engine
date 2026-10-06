import json
import re

from kafka import KafkaConsumer, KafkaProducer


KAFKA_SERVER = "kafka:9092"
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
    message = event.get("message", "")

    normalized = {
        "timestamp": event.get("@timestamp"),
        "host": event.get("host", {}).get("name"),
        "source": event.get("log_source"),
        "environment": event.get("environment"),
        "event_type": "unknown",
        "severity": "info",
        "message": message,
        "raw": event,
    }

    # Authentication-related events
    if re.search(
        r"(sshd|sudo|login|authentication|auth|failed password|accepted password)",
        message,
        re.IGNORECASE,
    ):
        normalized["event_type"] = "authentication"

    # Basic severity classification
    if re.search(
        r"(failed|failure|error|denied|invalid|fatal)",
        message,
        re.IGNORECASE,
    ):
        normalized["severity"] = "high"

    elif re.search(
        r"(warning|warn)",
        message,
        re.IGNORECASE,
    ):
        normalized["severity"] = "medium"

    return normalized


print("Normalizer started...")
print(f"Consuming: {INPUT_TOPIC}")
print(f"Producing: {OUTPUT_TOPIC}")

for record in consumer:

    try:
        # Decode Kafka message ourselves so malformed/non-JSON
        # messages don't crash the entire normalizer.
        raw_value = record.value.decode("utf-8")

        try:
            event = json.loads(raw_value)
        except json.JSONDecodeError:
            print(
                f"[SKIP] Non-JSON message in {record.topic}: "
                f"{raw_value[:150]}"
            )
            continue

        normalized = normalize(event)

        producer.send(OUTPUT_TOPIC, normalized)

        print(
            f"[NORMALIZED] "
            f"{normalized['host']} | "
            f"{normalized['event_type']} | "
            f"{normalized['severity']} | "
            f"{normalized['message'][:100]}"
        )

    except Exception as e:
        print(f"[ERROR] {e}")
