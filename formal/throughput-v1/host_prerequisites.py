#!/usr/bin/env python3
"""Observe the unchanged original Host prerequisite; never run or qualify a campaign."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "ci"))
import public_host_ci_observation as original  # noqa: E402


def observe() -> dict:
    sample = original.capture("outside-before-throughput-campaign", "not-started")
    violations = original.validate(sample, inside=False, uid=os.getuid(),
                                   gid=os.getgid(), cwd=str(Path.cwd()))
    return {
        "schema": "trnm-throughput-original-host-prerequisites-v1",
        "scope": "read-only prerequisites, not a pressure campaign or enforcement certificate",
        "original_observer_sha256": hashlib.sha256(Path(original.__file__).read_bytes()).hexdigest(),
        "collector_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "required_contract": {
            "cpu_cores": "0.25", "memory_bytes": 2147483648, "swap_bytes": 0,
            "pids": 256, "deadline_ns": 4_000_000_000, "hostile_inputs": 16,
            "required_depth": 6, "required_work_multiplier": 6,
            "deadline_comparison": "strictly_before",
        },
        "original_observation": sample,
        "prerequisite_violations": violations,
        "observed_parent_prerequisites_match": not violations,
        "native_pressure_campaign_started": False,
        "native_pressure_campaign_status": "NOT_RUN",
        "valid_admissions": None,
        "cryptographic_refusals": None,
        "original_resource_contract_enforced": False,
        "qualified_confirmed_tps": None,
        "qualified_wan_tps": None,
        "production_activation": False,
        "qualification": "HOLD",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = observe()
    raw = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open("x", encoding="utf-8") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    print(raw, end="")
    return 1  # The observation cannot qualify a campaign, even if the parent exists.


if __name__ == "__main__":
    raise SystemExit(main())
