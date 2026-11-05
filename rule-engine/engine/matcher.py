def match_value(actual, expected):

    if isinstance(expected, list):
        return actual in expected

    return actual == expected


def evaluate_selection(event, selection):

    for field, expected in selection.items():
        if "|" in field:
            field_name, modifier = field.split("|", 1)
        else:
            field_name = field
            modifier = None

        actual = event.get(field_name)

        if actual is None:
            return False

        if modifier is None:
            if not match_value(actual, expected):
                return False

        elif modifier == "contains":
            if isinstance(expected, list):
                if not any(value in actual for value in expected):
                    return False

            else:
                if expected not in actual:
                    return False

        elif modifier == "startswith":
            if isinstance(expected, list):
                if not any(actual.startswith(value) for value in expected):
                    return False

            else:
                if not actual.startswith(expected):
                    return False

        elif modifier == "endswith":
            if isinstance(expected, list):
                if not any(actual.endswith(value) for value in expected):
                    return False

            else:
                if not actual.endswith(expected):
                    return False

        else:
            return False

    return True


def evaluate_rule(event, rule):

    detection = rule.get("detection")

    if not detection:
        return False

    condition = detection.get("condition")

    if not condition:
        return False

    for selection_name, selection in detection.items():
        if selection_name == "condition":
            continue

        if not isinstance(selection, dict):
            continue

        if evaluate_selection(event, selection):
            return True

    return False
