import json

from engine.loader import load_rules
from engine.matcher import evaluate_rule

EVENT_FILE = "events/event.json"
RULE_DIRECTORY = "sigma-rules/rules/linux"


# -------------------------
# Load event
# -------------------------

with open(EVENT_FILE, "r", encoding="utf-8") as file:
    event = json.load(file)


# -------------------------
# Load Sigma rules
# -------------------------

rules = load_rules(RULE_DIRECTORY)

print(f"[+] Loaded event")
print(f"[+] Loaded {len(rules)} Sigma rules")
print()


# -------------------------
# Evaluate rules
# -------------------------

matches = []

for rule in rules:
    try:
        if evaluate_rule(event, rule):
            matches.append(
                {
                    "id": rule.get("id"),
                    "title": rule.get("title"),
                    "level": rule.get("level"),
                    "description": rule.get("description"),
                }
            )

    except Exception as e:
        print(f"[!] Error evaluating {rule.get('title', 'Unknown Rule')}: {e}")


# -------------------------
# Results
# -------------------------

print(f"[+] Detection complete")
print(f"[+] Rules matched: {len(matches)}")

print()

for match in matches:
    print(f"[ALERT] {match['title']} | severity={match['level']} | id={match['id']}")
