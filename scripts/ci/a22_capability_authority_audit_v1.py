#!/usr/bin/env python3
"""Plan v2 capability/authority convergence gate.

The historical A22 filename remains a workflow compatibility surface, but the
checks below are the current canonical Plan v2 authorities. This module does not
restore any external consensus engine, legacy authority path, or production
activation claim.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

CHECKS: tuple[tuple[str, ...], ...] = (
    (sys.executable, "scripts/ci/check_repository_truth_v1.py"),
    (sys.executable, "scripts/ci/check_module_coverage_v1.py"),
    (sys.executable, "scripts/ci/check_node_decomposition_v1.py"),
    (sys.executable, "scripts/ci/check_build_closures_v1.py", "--verify-cargo-tree"),
    ("bash", "scripts/ci/check_poco_bft_mainline_truth.sh", "--pre-cutover"),
)


def main() -> int:
    for command in CHECKS:
        print("[authority-gate]", " ".join(command), flush=True)
        completed = subprocess.run(command, cwd=ROOT, check=False)
        if completed.returncode != 0:
            print(
                f"[authority-gate][FAIL] command exited {completed.returncode}: "
                + " ".join(command),
                file=sys.stderr,
            )
            return completed.returncode
    print(
        "[authority-gate][PASS] Plan v2 repository/module/node/build/native-PoCO authority converged"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
