"""Read one explicit result line without altering or discarding the raw log."""
import json


def read_single_result(path, schema, operation=None):
    matches = []
    for line in path.read_text().splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("schema") == schema:
            matches.append(value)
    if len(matches) != 1:
        raise ValueError(f"{path}: expected exactly one {schema} result; found {len(matches)}")
    value = matches[0]
    if operation is not None and value.get("operation") != operation:
        raise ValueError(f"{path}: result operation differs from {operation}")
    return value
