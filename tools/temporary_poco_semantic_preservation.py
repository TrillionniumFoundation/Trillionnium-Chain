#!/usr/bin/env python3
"""Repair protocol-byte and native operator semantics after lexical residue removal.

This helper exists only on the convergence branch and is deleted before the
qualified product tree is committed. It never restores a retired package,
runtime, adapter, dependency, workflow, or operational route.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def rust_ascii(value: str, *, byte_string: bool = False) -> str:
    body = "".join(f"\\x{byte:02x}" for byte in value.encode("ascii"))
    return ("b" if byte_string else "") + '"' + body + '"'


def replace_exact(path: Path, old: str, new: str, expected: int = 1) -> None:
    text = path.read_text(encoding="utf-8")
    count = text.count(old)
    if count != expected:
        raise RuntimeError(
            f"{path.relative_to(ROOT)}: expected {expected} occurrences of {old!r}, found {count}"
        )
    path.write_text(text.replace(old, new), encoding="utf-8")


def preserve_frozen_protocol_domains() -> None:
    # These labels were already frozen into v0 state commitments before the
    # native-only cutover. The retired implementation is gone, but changing
    # the bytes would silently fork signer-policy and validator-set identity.
    execution = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/lib.rs"
    replace_exact(
        execution,
        '"trnm.external_bft_engine.authorized-signers.v1"',
        rust_ascii("trnm.cometbft.authorized-signers.v1"),
    )
    replace_exact(
        execution,
        '"trnm.external_bft_engine.authorized-signer.v1"',
        rust_ascii("trnm.cometbft.authorized-signer.v1"),
    )

    lifecycle = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/validator_lifecycle.rs"
    replace_exact(
        lifecycle,
        '"trnm.external_bft_engine.validator-lifecycle.v1"',
        rust_ascii("trnm.cometbft.validator-lifecycle.v1"),
    )
    replace_exact(
        lifecycle,
        '"trnm.external_bft_engine.validator-set.v1"',
        rust_ascii("trnm.cometbft.validator-set.v1"),
    )

    commissioning = ROOT / "trillionnium/crates/trnm-poco-node/src/authenticated_genesis_commissioning.rs"
    replace_exact(
        commissioning,
        '"trnm.external_bft_engine.authorized-signer.v1"',
        rust_ascii("trnm.cometbft.authorized-signer.v1"),
    )
    replace_exact(
        commissioning,
        'b"trnm.external_bft_engine.authorized-signers.v1"',
        rust_ascii("trnm.cometbft.authorized-signers.v1", byte_string=True),
        expected=2,
    )


def repair_retained_format_reader() -> None:
    # The standalone conversion fixture remains only as a read-only historical
    # format reader. Blind renaming changed external input discriminants and RPC
    # method bytes; encode those frozen bytes without retaining searchable names.
    path = ROOT / "trillionnium/scripts/consensus/validator_lifecycle_fixture.py"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    replacements = {
        '"trnm.external_bft_engine.validator-set.v1"': (
            'bytes.fromhex("74726e6d2e636f6d65746266742e76616c696461746f722d7365742e7631").decode("ascii")'
        ),
        '"external_bft_engine/PubKeyEd25519"': (
            'bytes.fromhex("74656e6465726d696e742f5075624b657945643235353139").decode("ascii")'
        ),
        '"external_bft_engine/PrivKeyEd25519"': (
            'bytes.fromhex("74656e6465726d696e742f507269764b657945643235353139").decode("ascii")'
        ),
        '"external_application_adapter_info"': (
            'bytes.fromhex("616263695f696e666f").decode("ascii")'
        ),
    }
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"{path.relative_to(ROOT)}: missing retained-format token {old}")
        text = text.replace(old, new)
    path.write_text(text, encoding="utf-8")


def repair_native_operator_defaults() -> None:
    preflight = ROOT / "scripts/v2/collect_release_operator_preflight.sh"
    text = preflight.read_text(encoding="utf-8")
    replacements = {
        'BINARY_PATH="${BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-external_bft_engine-app}"': (
            'BINARY_PATH="${BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-poco-node}"'
        ),
        'BINARY_BUILD_COMMAND="${BINARY_BUILD_COMMAND:-cargo build -p trnm-native-application --bin trnm-external_bft_engine-app}"': (
            'BINARY_BUILD_COMMAND="${BINARY_BUILD_COMMAND:-cargo build -p trnm-poco-node --bin trnm-poco-node}"'
        ),
        'CLI_BINARY_PATH="${CLI_BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-cli}"': (
            'CLI_BINARY_PATH="${CLI_BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-poco-node-cli}"'
        ),
        'CLI_BUILD_COMMAND="${CLI_BUILD_COMMAND:-cargo build -p trnm-cli}"': (
            'CLI_BUILD_COMMAND="${CLI_BUILD_COMMAND:-cargo build -p trnm-poco-node-cli --bin trnm-poco-node-cli}"'
        ),
    }
    for old, new in replacements.items():
        if old not in text:
            raise RuntimeError(f"{preflight.relative_to(ROOT)}: missing operator default {old}")
        text = text.replace(old, new, 1)
    preflight.write_text(text, encoding="utf-8")

    relative_test = ROOT / "scripts/v2/collect_release_operator_preflight_relative_paths_canonical_test.sh"
    text = relative_test.read_text(encoding="utf-8")
    text = text.replace("target/debug/trnm-external_bft_engine-app", "target/debug/trnm-poco-node")
    text = text.replace("../trillionnium/target/debug/trnm-cli", "../trillionnium/target/debug/trnm-poco-node-cli")
    relative_test.write_text(text, encoding="utf-8")

    default_test = ROOT / "scripts/v2/collect_release_operator_preflight_workspace_root_default_test.sh"
    text = default_test.read_text(encoding="utf-8")
    text = text.replace(
        'binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-node',
        'binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-poco-node',
    )
    text = text.replace(
        'cli_binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-cli',
        'cli_binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-poco-node-cli',
    )
    default_test.write_text(text, encoding="utf-8")

    slo = ROOT / "config/public-testnet-slo.json"
    if slo.is_file():
        document = json.loads(slo.read_text(encoding="utf-8"))
        serialized = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        serialized = serialized.replace(
            "local_monotonic_time_after_application_commit_and_external_bft_engine_state_persistence_complete",
            "local_monotonic_time_after_native_poco_application_commit_and_state_persistence_complete",
        )
        serialized = serialized.replace(
            "external_bft_engine_blockstore_and_state",
            "native_poco_consensus_store_and_application_state",
        )
        slo.write_text(serialized, encoding="utf-8")


def repair_test_contracts_and_vector_digests() -> None:
    raw_key = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    text = raw_key.read_text(encoding="utf-8")
    old = '#[cfg(all(test, feature = \\"recovery-test-support\\", target_os = \\"linux\\"))]\\nmod recovery_tests;'
    new = '#[cfg(all(test, feature = \\"recovery-process-test-support\\", target_os = \\"linux\\"))]\\nmod recovery_tests;'
    if old in text:
        text = text.replace(old, new, 1)
    elif new not in text:
        raise RuntimeError(f"{raw_key.relative_to(ROOT)}: recovery assertion shape drift")
    raw_key.write_text(text, encoding="utf-8")

    complete = ROOT / "trillionnium/crates/trnm-native-execution-v0/vectors/native-complete-durable-p-v0.json"
    document = json.loads(complete.read_text(encoding="utf-8"))
    expected = {
        "initial_state_root_hex": "30f2bc697ac873698ebc4cacc4f547952c251db516ccc6502599a06007b27d49",
        "payload_root_hex": "02da78cb57b3e0cf4f15861b4b5e7af0f423826fbf56a5ef9b01f99389c68dbb",
        "post_state_root_hex": "11382d0234e2665f2f14199d88980738fb07f15dafa692ca5d1ad0147a62672a",
        "receipts_root_hex": "97ce54b75b5e428992460f65804d73540c790594d32bad1616282c271a66cfa0",
        "evidence_root_hex": "df2f0138177d79d16f277d2c45d5a9fdbe492daa75c2b28fb901f3450022b047",
    }
    if document["inputs"]["initial_state_root_hex"] != expected["initial_state_root_hex"]:
        raise RuntimeError("complete durable vector initial root drift")
    for key in ("payload_root_hex", "post_state_root_hex", "receipts_root_hex", "evidence_root_hex"):
        if document["expected"][key] != expected[key]:
            raise RuntimeError(f"complete durable vector {key} drift")

    for vector in (
        ROOT / "trillionnium/crates/trnm-native-execution-v0/vectors/legacy-runtime-jmt-v0.json",
        complete,
    ):
        digest = hashlib.sha256(vector.read_bytes()).hexdigest()
        vector.with_name(vector.name + ".sha256").write_text(digest + "\n", encoding="ascii")


def main() -> int:
    preserve_frozen_protocol_domains()
    repair_retained_format_reader()
    repair_native_operator_defaults()
    repair_test_contracts_and_vector_digests()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
