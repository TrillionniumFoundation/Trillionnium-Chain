#!/usr/bin/env python3
"""Repair and prepare an exact native PoCO product tree after convergence.

The ops copy is never part of the product branch. During a run it is copied to
`tools/temporary_poco_r17_driver.py`; that copy is removed before any product
candidate commit is created.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHELL = ROOT / "tools/temporary_poco_convergence_r13.sh"
TRANSFORMER = ROOT / "tools/temporary_poco_native_convergence_r13.py"
BACKSLASH = chr(92)


def patch_transformer() -> None:
    text = TRANSFORMER.read_text(encoding="utf-8")
    write_line = '    tests_path.write_text(text, encoding="utf-8")\n'
    repair = (
        '    stripped = text.rstrip()\n'
        '    orphan = "#[test]"\n'
        '    if stripped.endswith(orphan):\n'
        '        text = stripped[: -len(orphan)].rstrip() + "\\n"\n'
    )
    if repair not in text:
        if text.count(write_line) != 1:
            raise RuntimeError("R17 obsolete-test cleanup insertion point drift")
        TRANSFORMER.write_text(text.replace(write_line, repair + write_line, 1), encoding="utf-8")


def patch_shell() -> None:
    script = SHELL.read_text(encoding="utf-8")
    transform_call = "python3 tools/temporary_poco_native_convergence_r13.py\n"
    postfix_call = "python3 tools/temporary_poco_r17_driver.py postfix\n"
    if postfix_call not in script:
        if script.count(transform_call) != 1:
            raise RuntimeError("R17 native-transform call drift")
        script = script.replace(transform_call, transform_call + postfix_call, 1)
    anchor = "  .github/workflows/nonexistent " + BACKSLASH + "\n"
    entries = (
        "tools/temporary_poco_r13_postfix.py",
        "tools/temporary_poco_r14_postfix.py",
        "tools/temporary_poco_r15_postfix.py",
        "tools/temporary_poco_r16_driver.py",
        "tools/temporary_poco_r17_driver.py",
        ".github/workflows/poco-only-convergence-r14-once-20260910.yml",
        ".github/workflows/poco-only-convergence-r15-once-20260910.yml",
        ".github/workflows/poco-only-convergence-r16-once-20260910.yml",
    )
    for entry in entries:
        rendered = f"  {entry} " + BACKSLASH + "\n"
        if rendered in script:
            continue
        if anchor not in script:
            raise RuntimeError("R17 product-cleanup anchor drift")
        script = script.replace(anchor, rendered + anchor, 1)
    SHELL.write_text(script, encoding="utf-8")


def remove_trailing_orphan_test_attribute() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/tests.rs"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    stripped = text.rstrip()
    orphan = "#[test]"
    if stripped.endswith(orphan):
        path.write_text(stripped[: -len(orphan)].rstrip() + "\n", encoding="utf-8")


def harden_raw_key_gate() -> None:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    start_marker = '        if relative == "src/recovery_tests.rs" {'
    end_marker = '        if relative.starts_with("src/bin/") {'
    start = text.find(start_marker)
    end = text.find(end_marker, start + 1)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("R17 raw-key recovery assertion block drift")
    replacement = '''        if relative == "src/recovery_tests.rs" {
            let compact_lib: String = lib.chars().filter(|ch| !ch.is_whitespace()).collect();
            assert!(
                compact_lib.contains(
                    "#[cfg(all(test,feature=\\\"recovery-process-test-support\\\",target_os=\\\"linux\\\"))]modrecovery_tests;"
                ),
                "recovery raw-key module lost its test/fixture gate"
            );
            continue;
        }

'''
    path.write_text(text[:start] + replacement + text[end:], encoding="utf-8")


def normalize_snapshot_codec_version() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    if not path.is_file():
        return
    text = path.read_text(encoding="utf-8")
    identifier = "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0"
    definition = f"const {identifier}: u16 = 1;"
    if text.count(definition) > 1:
        raise RuntimeError("duplicate authenticated-tree snapshot codec definitions")
    text = text.replace(definition, "", 1).replace(identifier, "1u16")
    if identifier in text:
        raise RuntimeError("authenticated-tree snapshot codec identifier remains")
    path.write_text(text, encoding="utf-8")


def replace_regex_line(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        if replacement in text:
            return text
        raise RuntimeError(f"missing operator default line: {label}")
    return updated


def repair_operator_defaults() -> None:
    preflight = ROOT / "scripts/v2/collect_release_operator_preflight.sh"
    if preflight.is_file():
        text = preflight.read_text(encoding="utf-8")
        text = replace_regex_line(
            text,
            r'^BINARY_PATH="\$\{BINARY_PATH:-\$WORKSPACE_ROOT/target/debug/[^"}]+\}"$',
            'BINARY_PATH="${BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-poco-node}"',
            "BINARY_PATH",
        )
        text = replace_regex_line(
            text,
            r'^BINARY_BUILD_COMMAND="\$\{BINARY_BUILD_COMMAND:-[^"}]+\}"$',
            'BINARY_BUILD_COMMAND="${BINARY_BUILD_COMMAND:-cargo build -p trnm-poco-node --bin trnm-poco-node}"',
            "BINARY_BUILD_COMMAND",
        )
        text = replace_regex_line(
            text,
            r'^CLI_BINARY_PATH="\$\{CLI_BINARY_PATH:-\$WORKSPACE_ROOT/target/debug/[^"}]+\}"$',
            'CLI_BINARY_PATH="${CLI_BINARY_PATH:-$WORKSPACE_ROOT/target/debug/trnm-poco-node-cli}"',
            "CLI_BINARY_PATH",
        )
        text = replace_regex_line(
            text,
            r'^CLI_BUILD_COMMAND="\$\{CLI_BUILD_COMMAND:-[^"}]+\}"$',
            'CLI_BUILD_COMMAND="${CLI_BUILD_COMMAND:-cargo build -p trnm-poco-node-cli --bin trnm-poco-node-cli}"',
            "CLI_BUILD_COMMAND",
        )
        preflight.write_text(text, encoding="utf-8")

    relative_test = ROOT / "scripts/v2/collect_release_operator_preflight_relative_paths_canonical_test.sh"
    if relative_test.is_file():
        text = relative_test.read_text(encoding="utf-8")
        for old in (
            "target/debug/trnm-external_bft_engine-app",
            "target/debug/trnm-poco_consensus-app",
            "target/debug/trnm-cometbft-app",
            "target/debug/trnm-native-application",
        ):
            text = text.replace(old, "target/debug/trnm-poco-node")
        for old in (
            "../trillionnium/target/debug/trnm-cli",
            "../trillionnium/target/debug/trnm-node-cli",
        ):
            text = text.replace(old, "../trillionnium/target/debug/trnm-poco-node-cli")
        relative_test.write_text(text, encoding="utf-8")

    default_test = ROOT / "scripts/v2/collect_release_operator_preflight_workspace_root_default_test.sh"
    if default_test.is_file():
        text = default_test.read_text(encoding="utf-8")
        text = re.sub(
            r'binary_path=\$EXPECTED_WORKSPACE_ROOT/target/debug/[^\s"\']+',
            'binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-poco-node',
            text,
        )
        text = re.sub(
            r'cli_binary_path=\$EXPECTED_WORKSPACE_ROOT/target/debug/[^\s"\']+',
            'cli_binary_path=$EXPECTED_WORKSPACE_ROOT/target/debug/trnm-poco-node-cli',
            text,
        )
        default_test.write_text(text, encoding="utf-8")

    slo = ROOT / "config/public-testnet-slo.json"
    if slo.is_file():
        document = json.loads(slo.read_text(encoding="utf-8"))
        serialized = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
        replacements = {
            "local_monotonic_time_after_application_commit_and_external_bft_engine_state_persistence_complete":
                "local_monotonic_time_after_native_poco_application_commit_and_state_persistence_complete",
            "local_monotonic_time_after_application_commit_and_poco_consensus_state_persistence_complete":
                "local_monotonic_time_after_native_poco_application_commit_and_state_persistence_complete",
            "external_bft_engine_blockstore_and_state":
                "native_poco_consensus_store_and_application_state",
            "poco_consensus_blockstore_and_state":
                "native_poco_consensus_store_and_application_state",
        }
        for old, new in replacements.items():
            serialized = serialized.replace(old, new)
        slo.write_text(serialized, encoding="utf-8")


def repair_product() -> int:
    remove_trailing_orphan_test_attribute()
    harden_raw_key_gate()
    normalize_snapshot_codec_version()
    repair_operator_defaults()
    return 0


def prepare() -> int:
    if SHELL.is_file() and TRANSFORMER.is_file():
        patch_transformer()
        patch_shell()
        print("transform")
    else:
        print("product")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "postfix", "repair-product"))
    command = parser.parse_args().command
    if command == "prepare":
        return prepare()
    return repair_product()


if __name__ == "__main__":
    raise SystemExit(main())
