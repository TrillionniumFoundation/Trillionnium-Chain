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

import argparse
import hashlib
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


REQUIRED_FIELDS = ("node_id", "rpc_addr", "p2p_addr")
SHA256_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
UTC_TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def looks_like_placeholder(value: str) -> bool:
    trimmed = value.strip()
    return trimmed.startswith("<") and trimmed.endswith(">") and len(trimmed) >= 3


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Fail-closed validator config bundle checker for TRNM bootstrap/handoff use."
        )
    )
    parser.add_argument(
        "configs",
        nargs="+",
        help="validator config TOML files to validate",
    )
    parser.add_argument(
        "--emit-ceremony-packet",
        action="store_true",
        help=(
            "print a copyable validator ceremony packet skeleton after validation succeeds"
        ),
    )
    parser.add_argument(
        "--ceremony-id",
        default="mn04-bootstrap-YYYYMMDD-HHMMZ",
        help=(
            "ceremony_id value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires replacing the template default"
        ),
    )
    parser.add_argument(
        "--ceremony-scope",
        default="operator-handoff",
        choices=("local-rehearsal", "operator-handoff", "public-mainnet-input"),
        help="ceremony_scope value to print when --emit-ceremony-packet is used",
    )
    parser.add_argument(
        "--packet-generated-at",
        default="<utc-timestamp>",
        help=(
            "packet_generated_at value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires a UTC ISO-8601 timestamp like 2026-03-31T06:21:00Z"
        ),
    )
    parser.add_argument(
        "--packet-distribution-path",
        default="<absolute-path-to-ceremony-packet>",
        help=(
            "packet_distribution_path value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires one exact absolute path to the generated ceremony packet file"
        ),
    )
    parser.add_argument(
        "--validator-set-version",
        default="v1",
        help=(
            "validator_set_version value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires replacing the default v1 label"
        ),
    )
    parser.add_argument(
        "--startup-order-note",
        default="<startup-order>",
        help=(
            "startup_order_note value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires replacing placeholder/default wording"
        ),
    )
    parser.add_argument(
        "--rollback-owner",
        default="<rollback-owner>",
        help=(
            "rollback_owner value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires an explicit non-placeholder owner"
        ),
    )
    parser.add_argument(
        "--genesis-artifact-path",
        default="<absolute-path-to-genesis-artifact>",
        help=(
            "genesis_artifact_path value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires one exact absolute path to the genesis artifact or bundle member"
        ),
    )
    parser.add_argument(
        "--genesis-artifact-sha256",
        default="<64-character-genesis-sha256>",
        help=(
            "genesis_artifact_sha256 value to print when --emit-ceremony-packet is used; "
            "public-mainnet-input requires a full 64-character hex SHA-256 digest"
        ),
    )
    return parser.parse_args(argv[1:])


def fail(message: str) -> "None":
    print(message, file=sys.stderr)
    raise SystemExit(1)


def trimmed_string(raw: object, field: str, path: Path) -> str:
    if not isinstance(raw, str):
        fail(f"invalid node config {path}: {field} must be a string")
    value = raw.strip()
    if raw != value:
        fail(
            f"invalid node config {path}: {field} must not contain leading or trailing whitespace"
        )
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


def parse_flat_toml_config(text: str, path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            fail(
                f"parse toml failed: {path}:{line_number}: expected key = value assignment"
            )
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            fail(f"parse toml failed: {path}:{line_number}: empty key")
        if key in data:
            fail(f"parse toml failed: {path}:{line_number}: duplicate key {key!r}")
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            data[key] = value[1:-1]
            continue
        fail(
            f"parse toml failed: {path}:{line_number}: only flat quoted string values are supported by the Python <3.11 fallback parser"
        )
    return data


def load_config(path: Path) -> dict[str, object]:
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        fail(f"missing node config: {path}")
    except IsADirectoryError:
        fail(f"invalid node config {path}: expected a file, got a directory")
    except OSError as exc:
        fail(f"read node config failed: {path}: {exc}")

    if tomllib is not None:
        try:
            data = tomllib.loads(raw_text)
        except Exception as exc:
            fail(f"parse toml failed: {path}: {exc}")
    else:
        data = parse_flat_toml_config(raw_text, path)

    if not isinstance(data, dict):
        fail(f"invalid node config {path}: expected a top-level TOML table")
    return data


def validate_packet_line_value(value: str, field: str) -> None:
    if not isinstance(value, str):
        fail(f"invalid ceremony packet arguments: {field} must be a string")
    if value != value.strip():
        fail(f"invalid ceremony packet arguments: {field} must not contain leading or trailing whitespace")
    if not value:
        fail(f"invalid ceremony packet arguments: {field} must not be empty")
    if "\n" in value or "\r" in value:
        fail(f"invalid ceremony packet arguments: {field} must be a single line")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        fail(f"invalid ceremony packet arguments: {field} must not contain control characters")



def validate_packet_atom_value(value: str, field: str) -> None:
    validate_packet_line_value(value, field)
    if any(ch in value for ch in (";", "=")):
        fail(f"invalid ceremony packet arguments: {field} must not contain ';' or '=' separators")



def validate_packet_path(value: str, field: str) -> None:
    validate_packet_line_value(value, field)
    if not Path(value).is_absolute():
        fail(
            f"invalid ceremony packet arguments: public-mainnet-input requires {field} to be an absolute path"
        )



def validate_packet_file_path(value: str, field: str) -> None:
    validate_packet_path(value, field)
    normalized = value.rstrip("/")
    if not normalized or normalized == "/":
        fail(
            f"invalid ceremony packet arguments: public-mainnet-input requires {field} to name one exact packet file"
        )
    if Path(value).name in {"", ".", ".."} or value.endswith("/"):
        fail(
            f"invalid ceremony packet arguments: public-mainnet-input requires {field} to name one exact packet file"
        )



def validate_packet_artifact_path(value: str, field: str) -> None:
    validate_packet_path(value, field)
    normalized = value.rstrip("/")
    if not normalized or normalized == "/":
        fail(
            f"invalid ceremony packet arguments: public-mainnet-input requires {field} to name one exact artifact path"
        )
    if Path(value).name in {"", ".", ".."} or value.endswith("/"):
        fail(
            f"invalid ceremony packet arguments: public-mainnet-input requires {field} to name one exact artifact path"
        )



def validate_ceremony_packet_metadata(args: argparse.Namespace) -> None:
    packet_line_values = {
        "ceremony_id": args.ceremony_id,
        "ceremony_scope": args.ceremony_scope,
        "packet_generated_at": args.packet_generated_at,
        "packet_distribution_path": args.packet_distribution_path,
        "validator_set_version": args.validator_set_version,
        "startup_order_note": args.startup_order_note,
        "rollback_owner": args.rollback_owner,
        "genesis_artifact_path": args.genesis_artifact_path,
        "genesis_artifact_sha256": args.genesis_artifact_sha256,
    }
    for field, value in packet_line_values.items():
        validate_packet_line_value(value, field)

    packet_atom_values = {
        "ceremony_id": args.ceremony_id,
        "ceremony_scope": args.ceremony_scope,
        "packet_generated_at": args.packet_generated_at,
        "validator_set_version": args.validator_set_version,
        "rollback_owner": args.rollback_owner,
        "genesis_artifact_sha256": args.genesis_artifact_sha256,
    }
    for field, value in packet_atom_values.items():
        validate_packet_atom_value(value, field)

    if args.ceremony_scope != "public-mainnet-input":
        return

    required_exact_values = {
        "packet_generated_at": args.packet_generated_at,
        "packet_distribution_path": args.packet_distribution_path,
        "validator_set_version": args.validator_set_version,
        "startup_order_note": args.startup_order_note,
        "rollback_owner": args.rollback_owner,
        "genesis_artifact_path": args.genesis_artifact_path,
        "genesis_artifact_sha256": args.genesis_artifact_sha256,
    }
    placeholder_fields = [
        field for field, value in required_exact_values.items() if looks_like_placeholder(value)
    ]
    if args.validator_set_version == "v1":
        placeholder_fields.append("validator_set_version")
    if placeholder_fields:
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires explicit values for "
            + ", ".join(dict.fromkeys(placeholder_fields))
        )

    if looks_like_placeholder(args.ceremony_id):
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires ceremony_id to be an explicit non-placeholder value"
        )

    if args.ceremony_id == "mn04-bootstrap-YYYYMMDD-HHMMZ":
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires an explicit ceremony_id instead of the template default"
        )

    if not UTC_TIMESTAMP_RE.fullmatch(args.packet_generated_at):
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires packet_generated_at in UTC ISO-8601 form like 2026-03-31T06:21:00Z"
        )

    if not SHA256_HEX_RE.fullmatch(args.genesis_artifact_sha256):
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires genesis_artifact_sha256 to be a 64-character hex sha256 digest"
        )

    validate_packet_artifact_path(args.genesis_artifact_path, "genesis_artifact_path")
    validate_packet_file_path(args.packet_distribution_path, "packet_distribution_path")
    if Path(args.genesis_artifact_path) == Path(args.packet_distribution_path):
        fail(
            "invalid ceremony packet arguments: public-mainnet-input requires packet_distribution_path and genesis_artifact_path to name different files"
        )


def build_validator_entry_hash(entry: dict[str, str], config_path: str) -> str:
    descriptor = "\n".join(
        (
            f"validator_name={entry['node_id']}",
            f"node_id={entry['node_id']}",
            f"config_path={config_path}",
            f"p2p_addr={entry['p2p_addr']}",
            f"rpc_addr={entry['rpc_addr']}",
        )
    )
    return hashlib.sha256(descriptor.encode("utf-8")).hexdigest()


def emit_ceremony_packet(args: argparse.Namespace, entries: list[dict[str, str]]) -> None:
    print("ceremony_id=" + args.ceremony_id)
    print("ceremony_scope=" + args.ceremony_scope)
    print("packet_generated_at=" + args.packet_generated_at)
    print("packet_distribution_path=" + args.packet_distribution_path)
    print("validator_set_version=" + args.validator_set_version)
    print("startup_order_note=" + args.startup_order_note)
    print("rollback_owner=" + args.rollback_owner)
    print("abort_condition=genesis hash mismatch")
    print("abort_condition=duplicate node_id")
    print("abort_condition=assigned worktree/ref mismatch")
    print()
    print("genesis_artifact_path=" + args.genesis_artifact_path)
    print("genesis_artifact_sha256=" + args.genesis_artifact_sha256)
    print()
    print(
        "authority_note=all operators must acknowledge the exact packet above before any validator starts"
    )
    print()
    prefer_absolute_config_paths = args.ceremony_scope == "public-mainnet-input"
    for entry in entries:
        config_path = entry["config_path"]
        if prefer_absolute_config_paths:
            config_path = str(Path(config_path).resolve())
            validate_packet_path(config_path, "validator_entry.config_path")
        validator_name = entry["node_id"]
        validate_packet_atom_value(validator_name, "validator_entry.validator_name")
        validate_packet_atom_value(validator_name, "validator_entry.node_id")
        validate_packet_atom_value(config_path, "validator_entry.config_path")
        validate_packet_atom_value(entry["p2p_addr"], "validator_entry.p2p_addr")
        validate_packet_atom_value(entry["rpc_addr"], "validator_entry.rpc_addr")
        validator_entry_hash = build_validator_entry_hash(entry, config_path)
        validator_owner_placeholder = f"<owner-for-{validator_name}>"
        operator_contact_placeholder = f"<chat/email/oncall-for-{validator_name}>"
        print(
            "validator_entry="
            f"validator_name={validator_name};"
            f"validator_owner={validator_owner_placeholder};"
            f"node_id={validator_name};"
            f"config_path={config_path};"
            f"p2p_addr={entry['p2p_addr']};"
            f"rpc_addr={entry['rpc_addr']}"
        )
        print("validator_entry_hash=" + validator_entry_hash)
        print(f"operator_contact={validator_name}={operator_contact_placeholder}")
        print(
            "operator_ack="
            f"{validator_owner_placeholder} checked genesis_artifact_sha256={args.genesis_artifact_sha256};"
            f"config_path={config_path};"
            f"validator_name={validator_name};"
            f"validator_entry_hash={validator_entry_hash}"
        )
        print(f"operator_ack_signature_path=<optional-ack-path-for-{validator_name}>")
        print(f"operator_ack_digest=<optional-sha256-of-{validator_name}-ack>")
        print()


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    seen_config_paths: dict[Path, Path] = {}
    seen_node_ids: dict[str, Path] = {}
    seen_addresses: dict[str, tuple[str, Path]] = {}
    entries: list[dict[str, str]] = []

    for raw_path in args.configs:
        path = Path(raw_path)
        canonical_path = path.resolve(strict=False)
        previous_path = seen_config_paths.get(canonical_path)
        if previous_path is not None:
            fail(
                "invalid validator config bundle: "
                f"config file {path} resolves to the same path as {previous_path}"
            )
        seen_config_paths[canonical_path] = path

        data = load_config(path)

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

        entries.append(
            {
                "config_path": str(path),
                "node_id": node_id,
                "rpc_addr": rpc_addr,
                "p2p_addr": p2p_addr,
            }
        )

    print(
        "validator config bundle OK: " + ", ".join(str(Path(raw_path)) for raw_path in args.configs)
    )
    if args.emit_ceremony_packet:
        validate_ceremony_packet_metadata(args)
        print()
        emit_ceremony_packet(args, entries)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
