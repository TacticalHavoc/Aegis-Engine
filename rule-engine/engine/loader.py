import os
import yaml


def load_rules(rule_directory):

    rules = []

    for root, _, files in os.walk(rule_directory):
        for filename in files:
            if not filename.endswith((".yml", ".yaml")):
                continue

            path = os.path.join(root, filename)

            try:
                with open(path, "r", encoding="utf-8") as file:
                    rule = yaml.safe_load(file)

                if rule and isinstance(rule, dict):
                    rules.append(rule)

            except Exception as e:
                print(f"[!] Failed to load {path}: {e}")

    return rules
