#!/usr/bin/env python3
"""Idempotent one-shot correction applied after the native PoCO purge transform.

The helper is deleted before the candidate product tree is committed. It does
not restore any retired package, route, protocol, workflow, or executable.
"""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def harden_raw_key_gate() -> None:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    text = path.read_text(encoding="utf-8")
    start_marker = '        if relative == "src/recovery_tests.rs" {'
    end_marker = '        if relative.starts_with("src/bin/") {'
    start = text.find(start_marker)
    end = text.find(end_marker, start + 1)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("raw-key recovery assertion block drift")
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
    text = path.read_text(encoding="utf-8")
    identifier = "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0"
    definition = f"const {identifier}: u16 = 1;"
    definition_count = text.count(definition)
    if definition_count > 1:
        raise RuntimeError("duplicate authenticated-tree snapshot codec definitions")
    if definition_count == 1:
        text = text.replace(definition, "", 1)
    text = text.replace(identifier, "1u16")
    if identifier in text:
        raise RuntimeError("authenticated-tree snapshot codec identifier remains")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    harden_raw_key_gate()
    normalize_snapshot_codec_version()
    pathlib.Path(__file__).unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
