#!/usr/bin/env python3
"""Module-coverage checks from the reviewed checkout; report input fingerprints."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import sys
from types import ModuleType

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = pathlib.Path("scripts/ci/check_module_coverage_core_v1.py")
BINDING = pathlib.Path("scripts/ci/technical_convergence_coverage_v1.py")
SPECS = {
    "M00": "docs/modules/M00_FOUNDATION_PROTOCOL_TECHNICAL_SPEC_V1.md",
    "M01": "docs/modules/M01_CRYPTO_IDENTITY_TECHNICAL_SPEC_V1.md",
    "M02": "docs/modules/M02_CONSENSUS_CORE_TECHNICAL_SPEC_V1.md",
    "M03": "docs/modules/M03_SAFETY_SIGNER_TECHNICAL_SPEC_V1.md",
    "M04": "docs/modules/M04_P2P_TECHNICAL_SPEC_V1.md",
    "M05": "docs/modules/M05_TX_LIFECYCLE_TECHNICAL_SPEC_V1.md",
    "M06": "docs/modules/M06_EXECUTION_TECHNICAL_SPEC_V1.md",
    "M07": "docs/modules/M07_STATE_STORAGE_TECHNICAL_SPEC_V1.md",
    "M08": "docs/modules/M08_FINALITY_RECOVERY_TECHNICAL_SPEC_V1.md",
    "M09": "docs/modules/M09_DATA_AVAILABILITY_TECHNICAL_SPEC_V1.md",
    "M10": "docs/modules/M10_AGENT_MARKET_TECHNICAL_SPEC_V1.md",
    "M11": "docs/modules/M11_VERIFICATION_CHALLENGE_TECHNICAL_SPEC_V1.md",
    "M12": "docs/modules/M12_SETTLEMENT_TECHNICAL_SPEC_V1.md",
    "M13": "docs/modules/M13_STATE_SYNC_MIGRATION_TECHNICAL_SPEC_V1.md",
    "M14": "docs/modules/M14_CLIENT_PLATFORM_TECHNICAL_SPEC_V1.md",
    "M15": "docs/modules/M15_NODE_RELEASE_TECHNICAL_SPEC_V1.md",
    "M16": "docs/modules/M16_CONTROL_PLANE_TECHNICAL_SPEC_V1.md",
    "M17": "docs/modules/M17_EVIDENCE_SECURITY_TECHNICAL_SPEC_V1.md"
}


class CoverageWrapperError(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise CoverageWrapperError(message)


def blob(path: pathlib.Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()


def load(relative: pathlib.Path) -> ModuleType:
    path = ROOT / relative
    require(path.is_file(), f"module coverage input missing: {relative}")
    require(not path.is_symlink() and path.resolve().is_relative_to(ROOT.resolve()),
            f"module coverage helper must be a repository file: {relative}")
    spec = importlib.util.spec_from_file_location("trnm_" + relative.stem, path)
    require(spec is not None and spec.loader is not None, f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    core = load(CORE)
    binding = load(BINDING)
    result = core.main()
    require(result == 0, "core module coverage gate did not return success")
    supplement = binding.validate(ROOT, SPECS, require)
    print(json.dumps({
        "schema": "trnm-module-coverage-convergence-binding-v1",
        "core_blob": blob(ROOT / CORE),
        "binding_blob": blob(ROOT / BINDING),
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
