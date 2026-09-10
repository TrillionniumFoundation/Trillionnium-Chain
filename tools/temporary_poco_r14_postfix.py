#!/usr/bin/env python3
"""One-shot R14 post-transform corrections; self-deletes before product commit."""
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


def normalize_snapshot_codec_version() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    text = path.read_text(encoding="utf-8")
    identifier = "AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0"
    definition = f"const {identifier}: u16 = 1;\n"
    if text.count(definition) != 1:
        raise RuntimeError("authenticated-tree snapshot codec definition drift")
    text = text.replace(definition, "", 1)

    normalized: list[str] = []
    for line in text.splitlines(keepends=True):
        if identifier not in line:
            normalized.append(line)
            continue
        stripped = line.lstrip()
        if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
            normalized.append(
                line.replace(identifier, "authenticated-tree snapshot codec version 1")
            )
        else:
            normalized.append(line.replace(identifier, "1u16"))
    text = "".join(normalized)
    if identifier in text:
        raise RuntimeError("authenticated-tree snapshot codec identifier remains")
    path.write_text(text, encoding="utf-8")


def main() -> int:
    harden_raw_key_gate()
    normalize_snapshot_codec_version()
    pathlib.Path(__file__).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
