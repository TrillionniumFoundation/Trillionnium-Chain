#!/usr/bin/env python3
"""Patch the retained R13 materializer deterministically for R20."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
NATIVE = ROOT / "tools/temporary_poco_native_convergence_r13.py"
SHELL = ROOT / "tools/temporary_poco_convergence_r13.sh"
POSTFIX = ROOT / "tools/temporary_poco_r13_postfix.py"

POSTFIX_SOURCE = r"""#!/usr/bin/env python3
from __future__ import annotations
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]


def patch_raw_key_boundary() -> None:
    path = ROOT / "trillionnium/crates/trnm-poco-node/tests/raw_key_boundary.rs"
    text = path.read_text(encoding="utf-8")
    begin = text.find('        if relative == "src/recovery_tests.rs" {')
    marker = "            continue;\n        }\n"
    end = text.find(marker, begin)
    if begin < 0 or end < 0:
        raise RuntimeError("recovery raw-key assertion block drift")
    end += len(marker)
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
    path.write_text(text[:begin] + replacement + text[end:], encoding="utf-8")


def remove_unused_codec_constant() -> None:
    path = ROOT / "trillionnium/crates/trnm-native-execution-v0/src/store.rs"
    text = path.read_text(encoding="utf-8")
    definition = "const AUTH_TREE_SNAPSHOT_CODEC_VERSION_V0: u16 = 1;\n"
    if text.count(definition) != 1:
        raise RuntimeError("snapshot codec definition drift")
    path.write_text(text.replace(definition, "", 1), encoding="utf-8")


def main() -> int:
    patch_raw_key_boundary()
    remove_unused_codec_constant()
    pathlib.Path(__file__).unlink()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
"""


def write_postfix() -> None:
    POSTFIX.write_text(POSTFIX_SOURCE, encoding="utf-8")


def patch_native_helper() -> None:
    text = NATIVE.read_text(encoding="utf-8")
    write = '    tests_path.write_text(text, encoding="utf-8")\n'
    repair = (
        '    stripped = text.rstrip()\n'
        '    orphan = "#[test]"\n'
        '    if stripped.endswith(orphan):\n'
        '        text = stripped[: -len(orphan)].rstrip() + "\\n"\n'
    )
    if repair not in text:
        if text.count(write) != 1:
            raise RuntimeError("obsolete differential test cleanup drift")
        text = text.replace(write, repair + write, 1)
    NATIVE.write_text(text, encoding="utf-8")


def patch_shell() -> None:
    text = SHELL.read_text(encoding="utf-8")
    native_call = "python3 tools/temporary_poco_native_convergence_r13.py\n"
    postfix_call = "python3 tools/temporary_poco_r13_postfix.py\n"
    if postfix_call not in text:
        if text.count(native_call) != 1:
            raise RuntimeError("native-transform invocation drift")
        text = text.replace(native_call, native_call + postfix_call, 1)

    anchor = "  .github/workflows/poco-only-convergence-r13-once-20260910.yml \\\n"
    temporary_paths = (
        ".github/workflows/poco-only-convergence-r14-once-20260910.yml",
        ".github/workflows/poco-only-convergence-r15-once-20260910.yml",
        ".github/workflows/poco-repository-gap-convergence-r16-once-20260910.yml",
        ".github/workflows/poco-exact-gap-convergence-r17-once-20260910.yml",
        ".github/workflows/poco-qualified-external-orchestration-r18-once-20260910.yml",
        ".github/workflows/poco-qualified-gap-overlay-r19-once-20260910.yml",
        ".github/workflows/poco-qualified-gap-overlay-r20-once-20260910.yml",
        "tools/temporary_poco_gap_overlay_r19.py",
        "tools/temporary_poco_productize_r19.py",
        "tools/temporary_poco_productize_r20.py",
    )
    for relative in temporary_paths:
        line = f"  {relative} \\\n"
        if line in text:
            continue
        if anchor not in text:
            raise RuntimeError("temporary cleanup anchor drift")
        text = text.replace(anchor, anchor + line, 1)
    SHELL.write_text(text, encoding="utf-8")


def main() -> int:
    if not NATIVE.is_file() or not SHELL.is_file():
        return 0
    write_postfix()
    patch_native_helper()
    patch_shell()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
