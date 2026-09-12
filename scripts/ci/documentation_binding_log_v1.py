#!/usr/bin/env python3
"""M17 bounded, reversible documentation evidence; not independent acceptance.

The emitter preserves every original UTF-8 byte in a validated JSON object.
Recovery verifies framing and integrity only. Callers must separately verify the
source/merge identity, trusted job provenance, and the required log retention.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any

MAX_BINDING_BYTES = 65536
MAX_LOG_BYTES = 16 * 1024 * 1024
CHUNK_CHARACTERS = 3840
PREFIX = "TRNM_DOC_BINDING_V1"
MODES = ("source", "merge")


def strict_json(data: bytes | str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"duplicate JSON member: {key}")
            result[key] = value
        return result

    def nonfinite(value: str) -> None:
        raise ValueError(f"non-finite JSON value: {value}")

    if isinstance(data, bytes):
        data = data.decode("utf-8")
    return json.loads(data, object_pairs_hook=pairs, parse_constant=nonfinite)


def validate_identity(expected_digest: str, mode: str) -> None:
    if mode not in MODES or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise ValueError("explicit valid digest and binding mode required")


def validate_binding(data: bytes, expected_digest: str) -> None:
    if not data or len(data) > MAX_BINDING_BYTES:
        raise ValueError("binding must be non-empty and at most 64 KiB")
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("binding byte count/digest mismatch")
    if not isinstance(strict_json(data), dict):
        raise ValueError("binding JSON object required")


def emit_binding(path: Path, expected_digest: str, mode: str) -> None:
    """Emit validated bounded bytes only; do not modify files or use the network."""
    validate_identity(expected_digest, mode)
    with path.open("rb") as stream:
        data = stream.read(MAX_BINDING_BYTES + 1)
    validate_binding(data, expected_digest)
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [encoded[i:i + CHUNK_CHARACTERS]
              for i in range(0, len(encoded), CHUNK_CHARACTERS)]
    for index, chunk in enumerate(chunks, 1):
        print(f"{PREFIX} {mode} {expected_digest} {len(data)} "
              f"{index}/{len(chunks)} {chunk}")


def recover_binding(log: str, expected_digest: str, mode: str) -> bytes:
    """Reject missing, repeated, reordered, mixed and corrupted binding frames."""
    validate_identity(expected_digest, mode)
    if len(log.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("log exceeds bounded input size")
    chunks: list[str] = []
    expected_size = None
    expected_total = None
    for raw_line in log.splitlines():
        line = re.sub(r"^\ufeff?\d{4}-\d{2}-\d{2}T[0-9:.]+Z ", "", raw_line)
        line = line.lstrip("\ufeff")
        if not line.startswith(f"{PREFIX} {mode} "):
            continue
        match = re.fullmatch(
            rf"{PREFIX} (source|merge) ([0-9a-f]{{64}}) "
            r"([0-9]{1,6}) ([0-9]{1,2})/([0-9]{1,2}) ([A-Za-z0-9+/=]+)", line)
        if match is None:
            raise ValueError("malformed binding record")
        _, digest, size_text, index_text, total_text, payload = match.groups()
        size, index, total = int(size_text), int(index_text), int(total_text)
        if digest != expected_digest or not 1 <= size <= MAX_BINDING_BYTES:
            raise ValueError("binding metadata/digest drift")
        encoded_size = 4 * ((size + 2) // 3)
        canonical_total = (encoded_size + CHUNK_CHARACTERS - 1) // CHUNK_CHARACTERS
        if not 1 <= index <= total == canonical_total <= 23:
            raise ValueError("binding chunk count drift")
        if expected_size is None:
            expected_size, expected_total = size, total
        if size != expected_size or total != expected_total or index != len(chunks) + 1:
            raise ValueError("duplicate, reordered or mixed binding records")
        if not 1 <= len(payload) <= CHUNK_CHARACTERS:
            raise ValueError("non-canonical chunk size")
        if index < total and len(payload) != CHUNK_CHARACTERS:
            raise ValueError("non-canonical chunk size")
        chunks.append(payload)
    if not chunks or len(chunks) != expected_total:
        raise ValueError("missing binding payload/chunk")
    encoded = "".join(chunks)
    data = base64.b64decode(encoded, validate=True)
    if base64.b64encode(data).decode("ascii") != encoded:
        raise ValueError("non-canonical base64 binding")
    if len(data) != expected_size:
        raise ValueError("binding byte count/digest mismatch")
    validate_binding(data, expected_digest)
    return data


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    emit = sub.add_parser("emit")
    emit.add_argument("--binding", type=Path, required=True)
    recover = sub.add_parser("recover")
    recover.add_argument("--log", type=Path, required=True)
    recover.add_argument("--output", type=Path, required=True)
    for command in (emit, recover):
        command.add_argument("--expected-sha256", required=True)
        command.add_argument("--mode", choices=MODES, required=True)
    args = parser.parse_args()
    try:
        if args.command == "emit":
            emit_binding(args.binding, args.expected_sha256, args.mode)
        else:
            with args.log.open("rb") as stream:
                raw = stream.read(MAX_LOG_BYTES + 1)
            if len(raw) > MAX_LOG_BYTES:
                raise ValueError("log exceeds bounded input size")
            data = recover_binding(raw.decode("utf-8-sig"), args.expected_sha256, args.mode)
            with args.output.open("xb") as stream:
                stream.write(data)
    except (OSError, ValueError, RecursionError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
