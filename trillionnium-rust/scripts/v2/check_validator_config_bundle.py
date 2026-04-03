#!/usr/bin/env python3
"""Fail-closed validator config bundle checker.

Verifies that a set of TRNM node config files is internally consistent for
bootstrap/handoff use:
- every file parses as TOML
- node_id/rpc_addr/p2p_addr exist and are non-empty after trimming
- node_id rejects boundary whitespace, list separators, path separators, and dot-segment aliases
- rpc_addr/p2p_addr are bare host:port listener addresses with ports in 1..65535
- rpc_addr != p2p_addr within each file
- node_id values are unique across the bundle
- rpc_addr values are unique across the bundle
- p2p_addr values are unique across the bundle
- no listen address is reused across rpc/p2p roles anywhere in the bundle
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    print("python 3.11+ with tomllib is required", file=sys.stderr)
    sys.exit(2)


REQUIRED_FIELDS = ("node_id", "rpc_addr", "p2p_addr")


def fail(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def trimmed_string(raw: object, field: str, path: Path) -> str:
    if not isinstance(raw, str):
        fail(f"invalid node config {path}: {field} must be a string")
    value = raw.strip()
    if not value:
        fail(f"invalid node config {path}: {field} must not be empty")
    return value


def validate_node_id(raw_node_id: object, path: Path) -> str:
    if not isinstance(raw_node_id, str):
        fail(f"invalid node config {path}: node_id must be a string")

    node_id = raw_node_id.strip()
    if not node_id:
        fail(f"invalid node config {path}: node_id must not be empty")
    if raw_node_id != node_id:
        fail(
            f"invalid node config {path}: node_id must not contain leading or trailing whitespace"
        )
    if any(ch in node_id for ch in (",", ";", "|")):
        fail(f"invalid node config {path}: node_id must not contain list separators (, ; |)")
    if any(ch in node_id for ch in ("/", "\\", ":")):
        fail(f"invalid node config {path}: node_id must not contain path separators (/ \\ :)")
    if node_id in {".", ".."}:
        fail(f"invalid node config {path}: node_id must not be '.' or '..'")
    if any(ch.isspace() for ch in node_id):
        fail(f"invalid node config {path}: node_id must not contain whitespace")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in node_id):
        fail(f"invalid node config {path}: node_id must not contain control characters")
    return node_id


def validate_listener_addr(addr: str, field: str, path: Path) -> None:
    if any(ch.isspace() for ch in addr):
        fail(f"invalid node config {path}: {field} must not contain whitespace")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in addr):
        fail(f"invalid node config {path}: {field} must not contain control characters")

    parsed = urlsplit(f"tcp://{addr}")

    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        fail(f"invalid node config {path}: {field} port must be in 1..65535")

    if (
        parsed.scheme != "tcp"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        fail(
            f"invalid node config {path}: {field} must be a bare host:port listener address"
        )
    if not host:
        fail(f"invalid node config {path}: {field} must include a host")
    if port is None:
        fail(f"invalid node config {path}: {field} must include a numeric port")
    if not (1 <= port <= 65535):
        fail(f"invalid node config {path}: {field} port must be in 1..65535")



def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: check_validator_config_bundle.py <config1.toml> [<config2.toml> ...]",
            file=sys.stderr,
        )
        return 2

    seen_node_ids: dict[str, Path] = {}
    seen_addresses: dict[str, tuple[str, Path]] = {}

    for raw_path in argv[1:]:
        path = Path(raw_path)
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            fail(f"missing node config: {path}")
        except IsADirectoryError:
            fail(f"invalid node config {path}: expected a file, got a directory")
        except OSError as exc:
            fail(f"read node config failed: {path}: {exc}")
        except tomllib.TOMLDecodeError as exc:
            fail(f"parse toml failed: {path}: {exc}")

        if not isinstance(data, dict):
            fail(f"invalid node config {path}: expected a top-level TOML table")

        missing = [field for field in REQUIRED_FIELDS if field not in data]
        if missing:
            fail(f"invalid node config {path}: missing required field(s): {', '.join(missing)}")

        node_id = validate_node_id(data.get("node_id"), path)
        rpc_addr = trimmed_string(data.get("rpc_addr"), "rpc_addr", path)
        p2p_addr = trimmed_string(data.get("p2p_addr"), "p2p_addr", path)
        validate_listener_addr(rpc_addr, "rpc_addr", path)
        validate_listener_addr(p2p_addr, "p2p_addr", path)

        if rpc_addr == p2p_addr:
            fail(f"invalid node config {path}: rpc_addr and p2p_addr must differ")

        previous_node = seen_node_ids.get(node_id)
        if previous_node is not None:
            fail(
                f"invalid validator config bundle: node_id {node_id!r} is reused by {previous_node} and {path}"
            )
        seen_node_ids[node_id] = path

        for field, addr in (("rpc_addr", rpc_addr), ("p2p_addr", p2p_addr)):
            previous = seen_addresses.get(addr)
            if previous is not None:
                previous_field, previous_path = previous
                fail(
                    "invalid validator config bundle: "
                    f"{field} {addr!r} in {path} reuses {previous_field} from {previous_path}"
                )
            seen_addresses[addr] = (field, path)

    print(
        "validator config bundle OK: "
        + ", ".join(str(Path(raw_path)) for raw_path in argv[1:])
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
