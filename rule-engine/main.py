import json
import os
import signal
import uuid
from datetime import datetime, timezone
from pathlib import Path

from kafka import KafkaConsumer, KafkaProducer

from engine.loader import load_rules
from engine.matcher import evaluate_rule
from engine.mapper import map_event

KAFKA_SERVER = os.getenv("KAFKA_SERVER", "kafka:29092")
INPUT_TOPIC = "siem.normalized"
OUTPUT_TOPIC = "siem.alerts"

BASE_DIR = Path(__file__).resolve().parent
RULE_DIRECTORY = BASE_DIR / "sigma-rules" / "rules" / "linux"

running = True


def shutdown(signum, frame):
    global running
    print("\n[!] Shutdown requested...")
    running = False


signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)


def create_alert(rule, original_event, mapped_event):
    return {
        "alert_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": mapped_event.get("host") or mapped_event.get("Computer"),
        "severity": rule.get("level", "unknown"),
        "rule": {
            "id": rule.get("id"),
            "title": rule.get("title"),
            "description": rule.get("description"),
            "level": rule.get("level"),
            "status": rule.get("status"),
        },
        "event": original_event,
        "mapped_event": mapped_event,
    }


def main():
    print("[+] Loading Sigma rules...")

    rules = load_rules(str(RULE_DIRECTORY))
    print(f"[+] Loaded {len(rules)} Sigma rules")

    if not rules:
        print("[!] No rules loaded. Check the rule directory.")

    consumer = KafkaConsumer(
        INPUT_TOPIC,
        bootstrap_servers=KAFKA_SERVER,
        group_id="rule-engine-group",
        auto_offset_reset="earliest",
        enable_auto_commit=False,
        max_poll_records=1,
    )

    producer = KafkaProducer(
        bootstrap_servers=KAFKA_SERVER,
        value_serializer=lambda value: json.dumps(value).encode("utf-8"),
    )

    print("[+] Rule Engine started")
    print(f"[+] Consuming: {INPUT_TOPIC}")
    print(f"[+] Publishing alerts to: {OUTPUT_TOPIC}")
    print("[+] Manual offset commits enabled")

    try:
        while running:
            records = consumer.poll(timeout_ms=1000)

            for _, messages in records.items():
                for record in messages:
                    if not running:
                        break

                    try:
                        try:
                            original_event = json.loads(record.value.decode("utf-8"))
                        except (json.JSONDecodeError, UnicodeDecodeError) as error:
                            print(f"[SKIP] Invalid event: {error}")
                            consumer.commit()
                            continue

                        if not isinstance(original_event, dict):
                            print("[SKIP] Event is not a JSON object")
                            consumer.commit()
                            continue

                        mapped_event = map_event(original_event)

                        # Evaluate every loaded rule.
                        for rule in rules:
                            if evaluate_rule(mapped_event, rule):
                                alert = create_alert(
                                    rule,
                                    original_event,
                                    mapped_event,
                                )

                                # Wait for Kafka to acknowledge the alert.
                                producer.send(
                                    OUTPUT_TOPIC,
                                    alert,
                                ).get(timeout=10)

                                print(
                                    f"[ALERT] "
                                    f"{alert['rule']['title']} | "
                                    f"severity={alert['severity']} | "
                                    f"host={alert['host']}"
                                )

                        # Ensure alerts are published before committing.
                        producer.flush()

                        # Acknowledge this event only after successful processing.
                        consumer.commit()

                        print(
                            f"[PROCESSED] "
                            f"{record.topic} partition={record.partition} "
                            f"offset={record.offset}"
                        )

                    except Exception as error:
                        print(
                            f"[FATAL] Processing failed. Offset NOT committed: {error}"
                        )
                        raise

    finally:
        print("[+] Closing Kafka connections...")
        consumer.close()
        producer.flush()
        producer.close()
        print("[+] Rule Engine stopped")


if __name__ == "__main__":
    main()
