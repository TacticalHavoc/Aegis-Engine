import fnmatch
import re


def get_field(event, field):
    """Read direct or nested fields."""
    if field in event:
        return event[field]

    value = event

    for part in field.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]

    return value


def scalar_values(value):
    """Extract searchable scalar values from an event."""
    if isinstance(value, dict):
        for item in value.values():
            yield from scalar_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from scalar_values(item)
    elif value is not None:
        yield str(value)


def wildcard_match(actual, expected):
    """Sigma-style case-insensitive wildcard comparison."""
    if isinstance(actual, list):
        return any(wildcard_match(item, expected) for item in actual)

    if actual is None:
        return False

    return fnmatch.fnmatchcase(
        str(actual).casefold(),
        str(expected).casefold()
    )


def match_value(actual, expected):
    if isinstance(expected, list):
        return any(match_value(actual, item) for item in expected)

    if isinstance(actual, list):
        return any(match_value(item, expected) for item in actual)

    return wildcard_match(actual, expected)


def evaluate_selection(event, selection):
    # Keyword-based Sigma selection
    if isinstance(selection, list):
        values = list(scalar_values(event))
        return any(
            wildcard_match(value, keyword)
            for value in values
            for keyword in selection
        )

    if not isinstance(selection, dict):
        return False

    # All fields in a selection must match
    for field, expected in selection.items():

        if "|" in field:
            field_name, modifier = field.split("|", 1)
        else:
            field_name, modifier = field, None

        actual = get_field(event, field_name)

        if actual is None:
            return False

        if modifier is None:
            matched = match_value(actual, expected)

        elif modifier in ("contains", "startswith", "endswith"):
            expected_values = expected if isinstance(expected, list) else [expected]
            actual_values = list(scalar_values(actual))

            def check(value, pattern):
                value = value.casefold()
                pattern = str(pattern).casefold()

                if modifier == "contains":
                    return pattern in value
                if modifier == "startswith":
                    return value.startswith(pattern)
                return value.endswith(pattern)

            matched = any(
                check(value, pattern)
                for value in actual_values
                for pattern in expected_values
            )

        elif modifier == "all":
            expected_values = expected if isinstance(expected, list) else [expected]
            matched = all(match_value(actual, item) for item in expected_values)

        else:
            return False

        if not matched:
            return False

    return True


def evaluate_selection_name(event, name, detection):
    selection = detection.get(name)

    if selection is None:
        return False

    return evaluate_selection(event, selection)


def tokenize(condition):
    pattern = r"\s*(\(|\)|\band\b|\bor\b|\bnot\b|\d+|\ball\b|\bof\b|[A-Za-z0-9_*?.-]+)"
    return re.findall(pattern, condition, flags=re.IGNORECASE)


class ConditionParser:
    def __init__(self, condition, event, detection):
        self.tokens = tokenize(condition)
        self.position = 0
        self.event = event
        self.detection = detection

    def peek(self):
        if self.position >= len(self.tokens):
            return None
        return self.tokens[self.position].lower()

    def consume(self):
        token = self.peek()
        self.position += 1
        return token

    def parse(self):
        result = self.parse_or()

        if self.position != len(self.tokens):
            raise ValueError("Unexpected token in Sigma condition")

        return result

    def parse_or(self):
        result = self.parse_and()

        while self.peek() == "or":
            self.consume()
            right = self.parse_and()
            result = result or right

        return result

    def parse_and(self):
        result = self.parse_not()

        while self.peek() == "and":
            self.consume()
            right = self.parse_not()
            result = result and right

        return result

    def parse_not(self):
        if self.peek() == "not":
            self.consume()
            return not self.parse_not()

        return self.parse_primary()

    def parse_primary(self):
        token = self.peek()

        if token is None:
            raise ValueError("Unexpected end of Sigma condition")

        if token == "(":
            self.consume()
            result = self.parse_or()

            if self.peek() != ")":
                raise ValueError("Missing closing parenthesis")

            self.consume()
            return result

        # Support: 1 of selection* / all of selection*
        if token == "all" or token.isdigit():
            count_token = self.consume()

            if self.peek() != "of":
                raise ValueError("Expected 'of' in Sigma condition")

            self.consume()
            pattern = self.consume()

            if pattern is None:
                raise ValueError("Missing selection pattern")

            names = [
                name for name in self.detection
                if name != "condition" and fnmatch.fnmatchcase(name, pattern)
            ]

            matches = [
                evaluate_selection_name(self.event, name, self.detection)
                for name in names
            ]

            if count_token == "all":
                return bool(matches) and all(matches)

            required = int(count_token)
            return sum(matches) >= required

        # Support: selection, filter, selection1, etc.
        name = self.consume()

        if name not in self.detection:
            raise ValueError(f"Unknown selection: {name}")

        return evaluate_selection_name(self.event, name, self.detection)


def evaluate_rule(event, rule):
    detection = rule.get("detection")

    if not isinstance(detection, dict):
        return False

    condition = detection.get("condition")

    if not isinstance(condition, str):
        return False

    try:
        parser = ConditionParser(condition, event, detection)
        return parser.parse()

    except (ValueError, TypeError) as error:
        print(f"[!] Condition error in '{rule.get('title', 'Unknown')}': {error}")
        return False
