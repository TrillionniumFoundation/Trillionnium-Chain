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


def remove_obsolete_codec_constant() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    text = path.read_text(encoding="utf-8")
    line = "const AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0: u16 = 1;\n"
    if text.count(line) != 1:
        raise RuntimeError("obsolete authenticated-tree codec constant drift")
    text = text.replace(line, "", 1)
    if "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0" in text:
        raise RuntimeError("authenticated-tree codec constant still referenced")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    harden_raw_key_gate()
    remove_obsolete_codec_constant()
    pathlib.Path(__file__).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
