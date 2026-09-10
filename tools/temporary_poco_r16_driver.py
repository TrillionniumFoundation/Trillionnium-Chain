#!/usr/bin/env python3
"""Prepare or repair the final native PoCO convergence run.

This driver is one-shot machinery. The product candidate removes it and every
related temporary workflow before qualification and publication.
"""
from __future__ import annotations

import argparse
import pathlib

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
            raise RuntimeError("R16 obsolete-test cleanup insertion point drift")
        text = text.replace(write_line, repair + write_line, 1)
        TRANSFORMER.write_text(text, encoding="utf-8")


def patch_shell() -> None:
    script = SHELL.read_text(encoding="utf-8")
    transform_call = "python3 tools/temporary_poco_native_convergence_r13.py\n"
    postfix_call = "python3 tools/temporary_poco_r16_driver.py postfix\n"
    if postfix_call not in script:
        if script.count(transform_call) != 1:
            raise RuntimeError("R16 native-transform call drift")
        script = script.replace(transform_call, transform_call + postfix_call, 1)

    anchor = "  .github/workflows/nonexistent " + BACKSLASH + "\n"
    entries = (
        "tools/temporary_poco_r13_postfix.py",
        "tools/temporary_poco_r14_postfix.py",
        "tools/temporary_poco_r15_postfix.py",
        "tools/temporary_poco_r16_driver.py",
        ".github/workflows/poco-only-convergence-r14-once-20260910.yml",
        ".github/workflows/poco-only-convergence-r15-once-20260910.yml",
        ".github/workflows/poco-only-convergence-r16-once-20260910.yml",
    )
    for entry in entries:
        rendered = f"  {entry} " + BACKSLASH + "\n"
        if rendered in script:
            continue
        if anchor not in script:
            raise RuntimeError("R16 product-cleanup anchor drift")
        script = script.replace(anchor, rendered + anchor, 1)
    SHELL.write_text(script, encoding="utf-8")


def remove_trailing_orphan_test_attribute() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/tests.rs"
    text = path.read_text(encoding="utf-8")
    stripped = text.rstrip()
    orphan = "#[test]"
    if stripped.endswith(orphan):
        path.write_text(stripped[: -len(orphan)].rstrip() + "\n", encoding="utf-8")


def harden_raw_key_gate() -> None:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    text = path.read_text(encoding="utf-8")
    start_marker = '        if relative == "src/recovery_tests.rs" {'
    end_marker = '        if relative.starts_with("src/bin/") {'
    start = text.find(start_marker)
    end = text.find(end_marker, start + 1)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("R16 raw-key recovery assertion block drift")
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
    if text.count(definition) > 1:
        raise RuntimeError("duplicate authenticated-tree snapshot codec definitions")
    text = text.replace(definition, "", 1)
    text = text.replace(identifier, "1u16")
    if identifier in text:
        raise RuntimeError("authenticated-tree snapshot codec identifier remains")
    path.write_text(text, encoding="utf-8")


def prepare() -> int:
    if SHELL.is_file() and TRANSFORMER.is_file():
        patch_transformer()
        patch_shell()
        print("transform")
    else:
        print("validate")
    return 0


def postfix() -> int:
    remove_trailing_orphan_test_attribute()
    harden_raw_key_gate()
    normalize_snapshot_codec_version()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("prepare", "postfix"))
    arguments = parser.parse_args()
    return prepare() if arguments.command == "prepare" else postfix()


if __name__ == "__main__":
    raise SystemExit(main())
