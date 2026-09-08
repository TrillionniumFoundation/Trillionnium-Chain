#!/usr/bin/env python3
"""Reject stale workspace-package invocations of the excluded legacy node."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "trillionnium/scripts/legacy_node_cargo.sh"
MANIFEST = ROOT / "trillionnium/crates/trnm-node/Cargo.toml"
LOCKFILE = ROOT / "trillionnium/crates/trnm-node/Cargo.lock"

SEARCH_ROOTS = (ROOT / ".github/workflows", ROOT / "scripts", ROOT / "trillionnium/scripts")
SUFFIXES = {".sh", ".yml", ".yaml", ".py"}
FORBIDDEN = re.compile(r"\bcargo\s+(?:run|build|test|check|clippy)\b[^\n]*?(?:-p\s+trnm-node|--package(?:=|\s+)trnm-node)\b")


def fail(message: str) -> None:
    raise SystemExit(f"legacy node cargo boundary failed: {message}")


def main() -> int:
    for required in (HELPER, MANIFEST, LOCKFILE):
        if not required.is_file():
            fail(f"required file missing: {required.relative_to(ROOT)}")

    helper_text = HELPER.read_text(encoding="utf-8")
    required_fragments = (
        'MANIFEST="$TRILLIONNIUM_ROOT/crates/trnm-node/Cargo.toml"',
        'LOCKFILE="$TRILLIONNIUM_ROOT/crates/trnm-node/Cargo.lock"',
        'exec cargo "$subcommand" --manifest-path "$MANIFEST" --locked "$@"',
    )
    for fragment in required_fragments:
        if fragment not in helper_text:
            fail(f"helper lost required boundary fragment: {fragment}")

    violations: list[str] = []
    for search_root in SEARCH_ROOTS:
        for path in sorted(search_root.rglob("*")):
            if not path.is_file() or path.suffix not in SUFFIXES:
                continue
            text = path.read_text(encoding="utf-8", errors="strict")
            for match in FORBIDDEN.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                violations.append(f"{path.relative_to(ROOT)}:{line}: {match.group(0).strip()}")

    if violations:
        fail("stale active-workspace invocation(s):\n" + "\n".join(violations))

    with tempfile.TemporaryDirectory(prefix="trnm-legacy-cargo-boundary-") as tmp:
        tmp_path = Path(tmp)
        fake_bin = tmp_path / "bin"
        fake_bin.mkdir()
        capture = tmp_path / "capture.txt"
        fake_cargo = fake_bin / "cargo"
        fake_cargo.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            "printf '%s\\n' \"$CARGO_TARGET_DIR\" > \"$TRNM_CAPTURE\"\n"
            "printf '%s\\n' \"$@\" >> \"$TRNM_CAPTURE\"\n",
            encoding="utf-8",
        )
        fake_cargo.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{fake_bin}{os.pathsep}{env.get('PATH', '')}"
        env["TRNM_CAPTURE"] = str(capture)
        env.pop("CARGO_TARGET_DIR", None)
        result = subprocess.run(
            [str(HELPER), "run", "-q", "--features", "legacy-harness", "--bin", "trnm-sim", "--", "--max-blocks", "1"],
            cwd=ROOT / "trillionnium",
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            fail(f"helper fake-cargo probe failed: {result.stderr.strip()}")
        captured = capture.read_text(encoding="utf-8").splitlines()
        expected = [
            str(ROOT / "trillionnium/target"),
            "run",
            "--manifest-path",
            str(MANIFEST),
            "--locked",
            "-q",
            "--features",
            "legacy-harness",
            "--bin",
            "trnm-sim",
            "--",
            "--max-blocks",
            "1",
        ]
        if captured != expected:
            fail(f"helper cargo argv/target mismatch: expected={expected!r} actual={captured!r}")

        for package_selector in (("-p", "trnm-node"), ("-p=trnm-node",), ("--package=trnm-node",)):
            rejected = subprocess.run(
                [str(HELPER), "test", *package_selector],
                cwd=ROOT / "trillionnium",
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            if rejected.returncode == 0 or "do not select packages" not in rejected.stderr:
                fail(f"helper did not reject package selector: {package_selector!r}")

    print("legacy_node_cargo_boundary=ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
