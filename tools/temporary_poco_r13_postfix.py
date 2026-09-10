#!/usr/bin/env python3
"""One-shot R13 post-transform corrections; self-deletes before product commit."""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]


def harden_raw_key_gate() -> None:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(
        r'''        if relative == "src/recovery_tests\.rs" \{\n.*?            continue;\n        \}\n''',
        re.DOTALL,
    )
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
    text, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise RuntimeError("raw-key recovery assertion block drift")
    path.write_text(text, encoding="utf-8")


def repair_native_store_after_obsolete_import_removal() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    text = path.read_text(encoding="utf-8")

    obsolete = (
        "#[cfg(test)]\n"
        "const AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0: u16 = 1;\n"
    )
    if text.count(obsolete) != 1:
        raise RuntimeError("obsolete authenticated-tree codec attribute/constant drift")
    text = text.replace(obsolete, "", 1)
    if re.search(r"\bAUTH_TREE_SNAPSHOT_CODEC_VERSION_V0\b", text):
        raise RuntimeError("obsolete authenticated-tree codec identifier still referenced")

    orphaned_comment = (
        "    /// Reconstructs the fixed excluded-legacy vector parent for differential\n"
        "\n"
        "    pub fn apply_seed_v0("
    )
    if text.count(orphaned_comment) != 1:
        raise RuntimeError("obsolete differential doc-comment boundary drift")
    text = text.replace(orphaned_comment, "    pub fn apply_seed_v0(", 1)

    native = "NATIVE_AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0"
    definitions = re.findall(
        rf"(?m)^const\s+{native}\s*:\s*u16\s*=\s*1\s*;\s*$",
        text,
    )
    if len(definitions) != 1:
        raise RuntimeError("native authenticated-tree codec definition drift")

    encode_start = text.find("fn encode_authenticated_snapshot_v0")
    decode_start = text.find("fn decode_authenticated_snapshot_v0")
    validate_start = text.find("fn validate_snapshot_v0")
    if not (0 <= encode_start < decode_start < validate_start):
        raise RuntimeError("native authenticated-tree snapshot function ordering drift")
    if native not in text[encode_start:decode_start]:
        raise RuntimeError("native authenticated-tree snapshot encoder lost codec binding")
    if native not in text[decode_start:validate_start]:
        raise RuntimeError("native authenticated-tree snapshot decoder lost codec validation")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    harden_raw_key_gate()
    repair_native_store_after_obsolete_import_removal()
    pathlib.Path(__file__).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
