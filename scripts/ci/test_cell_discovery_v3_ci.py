#!/usr/bin/env python3
"""Negative controls for the V3 workflow seam, not native execution evidence."""
from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/pon-next-architecture-security.yml"
VECTOR = '          bash "$OUT/run-command.sh" discovery-epoch-vector python3 -B scripts/cell_discovery_epoch_v3_vector.py --check || status=1\n'
GUARD = '          bash "$OUT/run-command.sh" discovery-workflow-controls python3 -B scripts/ci/test_cell_discovery_v3_ci.py || status=1\n'
NATIVE = '          bash "$OUT/run-command.sh" p2p-complete cargo +1.95.0 test --locked --release --manifest-path trillionnium/Cargo.toml -p trnm-data-availability -- --test-threads=1\n'
PYTHON_STEP = "Run all next-architecture Python controls and retained exact fixture"
NATIVE_STEP = "Run the complete default-feature P2P crate"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def step(text: str, name: str) -> str:
    marker = "      - name: " + name + "\n"
    require(text.count(marker) == 1, "missing/duplicate exact-source step")
    return text.split(marker, 1)[1].split("\n      - name:", 1)[0] + "\n"


def validate(text: str) -> None:
    for path in (
        "docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_DEV_V1.md",
        "docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md",
        "docs/development/specs/pon/CELL_STORAGE_NETWORK_ACCEPTANCE_V1.md",
        "scripts/cell_discovery_epoch_v3_vector.py",
        "formal/pon-nakamoto-v1/vectors/cell-discovery-epoch-v3.json",
        "trillionnium/crates/trnm-data-availability/**",
    ):
        trigger = "      - " + path + "\n"
        require(trigger in text.split("\npermissions:", 1)[0], "V3 path trigger missing")
    for marker in ("        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n",
                   "        source: [head, prospective-merge]\n",
                   "  cancel-in-progress: false\n"):
        require(text.count(marker) == 1, "source/architecture/failure preservation changed")
    python = step(text, PYTHON_STEP)
    native = step(text, NATIVE_STEP)
    for command in (VECTOR, GUARD):
        require(text.count(command) == 1 and python.count(command) == 1,
                "V3 Python control must execute once in its original step")
    require(python.count('          exit "$status"\n') == 1,
            "V3 Python failures must reject the step")
    require(text.count(NATIVE) == 1 and native.count(NATIVE) == 1,
            "complete native crate must execute once without a selector or no-run")
    for block in (python, native):
        require("continue-on-error:" not in block and "if false" not in block
                and "|| true" not in block, "V3 control bypass")
        require("        if: ${{ always() && steps.source.outcome == 'success' && steps.preflight.outcome == 'success'" in block,
                "original verified-source/preflight guard missing")
        require("          set -euo pipefail\n" in block, "shell failure boundary missing")


class CellDiscoveryV3CiControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text()

    def test_actual_source_and_complete_runtime_seam(self) -> None:
        validate(self.text)

    def test_missing_duplicate_stubbed_or_relocated_vectors_reject(self) -> None:
        for command in (VECTOR, GUARD):
            for change in ("", command * 2, command.replace("python3 -B", "true # python3 -B"),
                           command.replace("|| status=1", "|| true")):
                with self.subTest(command=command, change=change):
                    with self.assertRaises(ValueError):
                        validate(self.text.replace(command, change))
            moved = self.text.replace(command, "") + command
            with self.assertRaises(ValueError):
                validate(moved)

    def test_compile_only_filtered_or_bypassed_native_execution_rejects(self) -> None:
        for change in ("", NATIVE * 2, NATIVE.replace(" -- --test-threads=1", " --no-run -- --test-threads=1"),
                       NATIVE.replace(" -- --test-threads=1", " epoch -- --test-threads=1"),
                       NATIVE.rstrip() + " || true\n"):
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    validate(self.text.replace(NATIVE, change))

    def test_trigger_and_original_matrix_cannot_be_silently_dropped(self) -> None:
        for line in ("      - scripts/cell_discovery_epoch_v3_vector.py\n",
                     "      - docs/development/specs/pon/CELL_PROVIDER_DISCOVERY_AUTH_PQ_V3.md\n",
                     "        source: [head, prospective-merge]\n",
                     "        runner: [ubuntu-24.04, ubuntu-24.04-arm]\n",
                     "  cancel-in-progress: false\n"):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    validate(self.text.replace(line, ""))

    def test_python_failure_and_source_guard_bypasses_reject(self) -> None:
        python = step(self.text, PYTHON_STEP)
        for weakened in (python.replace('          exit "$status"\n', "          exit 0\n"),
                         python.replace("        if: ${{ always() &&", "        if: ${{ false &&"),
                         python.replace("        shell: bash\n", "        continue-on-error: true\n        shell: bash\n")):
            with self.assertRaises(ValueError):
                validate(self.text.replace(python.rstrip("\n"), weakened.rstrip("\n")))


if __name__ == "__main__":
    unittest.main()
