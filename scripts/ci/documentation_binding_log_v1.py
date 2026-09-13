#!/usr/bin/env python3
"""M17: retain/recover complete documentation bindings, never grant acceptance.

Only the authenticated originating job plus independent source/merge verification
can establish provenance. A checksum and a recovered JSON object cannot do so.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 65536
CHUNK_SIZE = 3840
MAX_LOG_BYTES = 64 * 1024 * 1024
PREFIX = "TRNM_DOC_BINDING_V1"
TIMESTAMP = re.compile(r"^\ufeff?\d{4}-\d{2}-\d{2}T[0-9:.]+Z ")
RECORD = re.compile(
    rf"{PREFIX} (source|merge) ([0-9a-f]{{64}}) "
    r"([0-9]{1,6}) ([0-9]{1,2})/([0-9]{1,2}) ([A-Za-z0-9+/=]+)"
)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _validate(data: bytes) -> None:
    if not data or len(data) > MAX_BYTES:
        raise ValueError("binding must be non-empty and at most 64 KiB")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_object,
                       parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("binding JSON object required")


def _identity(digest: str, mode: str) -> None:
    if mode not in ("source", "merge") or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise ValueError("explicit SHA-256 and source/merge mode required")


def encode_binding(data: bytes, expected_digest: str, mode: str) -> str:
    """Encode exact bytes, rejecting a file changed after its digest was taken."""
    _identity(expected_digest, mode)
    _validate(data)
    if hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("binding changed after digest calculation")
    encoded = base64.b64encode(data).decode("ascii")
    chunks = [encoded[i:i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    return "".join(
        f"{PREFIX} {mode} {expected_digest} {len(data)} {i}/{len(chunks)} {chunk}\n"
        for i, chunk in enumerate(chunks, 1)
    )


def recover_binding(log: str, expected_digest: str, mode: str) -> bytes:
    """Reject missing, duplicate, mixed, reordered, oversized or corrupt chunks."""
    _identity(expected_digest, mode)
    if len(log.encode("utf-8")) > MAX_LOG_BYTES:
        raise ValueError("job log exceeds size bound")
    chunks = []
    expected_size = expected_total = None
    for raw in log.splitlines():
        line = TIMESTAMP.sub("", raw).lstrip("\ufeff")
        if not line.startswith(f"{PREFIX} {mode} "):
            continue
        match = RECORD.fullmatch(line)
        if match is None:
            raise ValueError("malformed binding record")
        _, digest, size_text, index_text, total_text, payload = match.groups()
        size, index, total = int(size_text), int(index_text), int(total_text)
        if digest != expected_digest or not 1 <= size <= MAX_BYTES:
            raise ValueError("binding metadata/digest drift")
        encoded_size = 4 * ((size + 2) // 3)
        if total != (encoded_size + CHUNK_SIZE - 1) // CHUNK_SIZE or not 1 <= index <= total:
            raise ValueError("invalid chunk count")
        if expected_size is None:
            expected_size, expected_total = size, total
        if (size, total) != (expected_size, expected_total) or index != len(chunks) + 1:
            raise ValueError("duplicate, reordered or mixed records")
        required_size = CHUNK_SIZE if index < total else encoded_size - CHUNK_SIZE * (total - 1)
        if len(payload) != required_size:
            raise ValueError("non-canonical chunk size")
        chunks.append(payload)
    if not chunks or len(chunks) != expected_total:
        raise ValueError("missing binding payload/chunk")
    encoded = "".join(chunks)
    data = base64.b64decode(encoded, validate=True)
    if base64.b64encode(data).decode("ascii") != encoded:
        raise ValueError("non-canonical base64")
    if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_digest:
        raise ValueError("binding byte count/digest mismatch")
    _validate(data)
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
        command.add_argument("--mode", choices=("source", "merge"), required=True)
    args = parser.parse_args()
    try:
        if args.command == "emit":
            with args.binding.open("rb") as stream:
                data = stream.read(MAX_BYTES + 1)
            sys.stdout.write(encode_binding(data, args.expected_sha256, args.mode))
        else:
            with args.log.open("rb") as stream:
                raw = stream.read(MAX_LOG_BYTES + 1)
            if len(raw) > MAX_LOG_BYTES:
                raise ValueError("job log exceeds size bound")
            data = recover_binding(raw.decode("utf-8-sig"), args.expected_sha256, args.mode)
            with args.output.open("xb") as stream:
                stream.write(data)
            print("Recovered exact bytes; provenance and independent acceptance remain unverified.")
    except (OSError, ValueError, RecursionError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
