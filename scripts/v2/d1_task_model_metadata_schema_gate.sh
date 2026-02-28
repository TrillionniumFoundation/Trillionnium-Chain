#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCHEMA_FILE="${SCHEMA_FILE:-$ROOT/docs/schemas/task_model_metadata.schema.json}"
METADATA_FILE="${METADATA_FILE:-$ROOT/docs/schemas/examples/task_model_metadata.sample.json}"

python3 - "$SCHEMA_FILE" "$METADATA_FILE" <<'PY'
import json
import re
import sys
from datetime import datetime
from pathlib import Path

schema_path = Path(sys.argv[1])
metadata_path = Path(sys.argv[2])

schema = json.loads(schema_path.read_text())
metadata = json.loads(metadata_path.read_text())


def fail(msg: str):
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)


def validate_datetime(value: str) -> bool:
    if not isinstance(value, str):
        return False
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        datetime.fromisoformat(value)
        return True
    except ValueError:
        return False


def validate(node, schema_node, prefix=""):
    if schema_node.get("type") == "object":
        if not isinstance(node, dict):
            fail(f"{prefix or '<root>'} expected object")

        required = schema_node.get("required", [])
        for field in required:
            if field not in node:
                fail(f"{prefix + '.' if prefix else ''}missing required field: {field}")

        if schema_node.get("additionalProperties") is False:
            allowed = set(schema_node.get("properties", {}).keys())
            for key in node:
                if key not in allowed:
                    fail(f"{prefix + '.' if prefix else ''}unexpected field: {key}")

        for key, child_schema in schema_node.get("properties", {}).items():
            if key in node:
                child_prefix = f"{prefix}.{key}" if prefix else key
                validate(node[key], child_schema, child_prefix)
        return

    expected_type = schema_node.get("type")
    if expected_type == "string" and not isinstance(node, str):
        fail(f"{prefix} expected string")

    if isinstance(node, str):
        min_length = schema_node.get("minLength")
        if min_length is not None and len(node) < min_length:
            fail(f"{prefix} shorter than minLength={min_length}")

        max_length = schema_node.get("maxLength")
        if max_length is not None and len(node) > max_length:
            fail(f"{prefix} longer than maxLength={max_length}")

        pattern = schema_node.get("pattern")
        if pattern is not None and re.fullmatch(pattern, node) is None:
            fail(f"{prefix} does not match pattern {pattern}")

        if schema_node.get("format") == "date-time" and not validate_datetime(node):
            fail(f"{prefix} is not a valid date-time")

    enum_values = schema_node.get("enum")
    if enum_values is not None and node not in enum_values:
        fail(f"{prefix} value {node!r} not in enum {enum_values}")


validate(metadata, schema)
print("[PASS] D1 task/model metadata schema gate")
PY
