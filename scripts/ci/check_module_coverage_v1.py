#!/usr/bin/env python3
"""Pinned core module-coverage gate plus convergence binding checks."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = pathlib.Path("scripts/ci/check_module_coverage_core_v1.py")
CORE_BLOB = "13e45e7ac8df0bff25d35149c6ff25914fd38174"
BINDING = pathlib.Path("scripts/ci/technical_convergence_coverage_v1.py")
BINDING_BLOB = "791da0546d30a214925fcff7eaa144fe3617d9e9"
SPECS = {
    "M04": "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md",
    "M05": "docs/modules/M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md",
    "M08": "docs/modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md",
    "M14": "docs/modules/M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md",
    "M15": "docs/modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md",
    "M16": "docs/modules/M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md",
    "M17": "docs/modules/M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md",
}


class CoverageWrapperError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CoverageWrapperError(message)


def blob(path: pathlib.Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def load(relative: pathlib.Path, expected: str) -> ModuleType:
    path = ROOT / relative
    require(path.is_file(), f"pinned module coverage input missing: {relative}")
    require(blob(path) == expected, f"pinned module coverage input drift: {relative}")
    spec = importlib.util.spec_from_file_location("trnm_" + relative.stem, path)
    require(spec is not None and spec.loader is not None, f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    core = load(CORE, CORE_BLOB)
    binding = load(BINDING, BINDING_BLOB)
    result = core.main()
    require(result == 0, "core module coverage gate did not return success")
    supplement = binding.validate(ROOT, SPECS, require)
    print(json.dumps({
        "schema": "trnm-module-coverage-convergence-binding-v1",
        "core_blob": CORE_BLOB,
        "binding_blob": BINDING_BLOB,
        **supplement,
        "production_authority": False,
        "result": "PASS",
    }, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CoverageWrapperError, RuntimeError, OSError, UnicodeError) as error:
        print(f"module coverage wrapper failed: {error}", file=sys.stderr)
        raise SystemExit(2)
