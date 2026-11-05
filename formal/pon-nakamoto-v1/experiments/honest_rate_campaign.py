#!/usr/bin/env python3
"""Report same-horizon honest-rate arithmetic; never native consensus evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

FORMAL = Path(__file__).resolve().parents[1]
ROOT = FORMAL.parents[1]
sys.path.insert(0, str(FORMAL))

from honest_rate_model import (  # noqa: E402
    ASSUMPTIONS, confirmations, floor_ns, load_profile, ratio, simulate, standard_cases,
)

SOURCE_FILES = (
    "config/pon/devnet-v1.json",
    "formal/pon-nakamoto-v1/reference.py",
    "formal/pon-nakamoto-v1/honest_rate_model.py",
    "formal/pon-nakamoto-v1/test_honest_rate_model.py",
    "formal/pon-nakamoto-v1/experiments/honest_rate_campaign.py",
)


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def campaign(horizon: int = 7200, include_events: bool = False) -> dict:
    profile = load_profile(ROOT / SOURCE_FILES[0])
    probes = (horizon // 4, horizon // 3, 2 * horizon // 3, horizon - 1)
    records = []
    for name, phases in standard_cases(horizon).items():
        result = simulate(profile, phases, horizon)
        events = [event.record() for event in result.events]
        starts = [0] + [phase.until_second for phase in phases[:-1]]
        phase_rows = []
        for start, phase in zip(starts, phases):
            # Right-closed observations assign a completion exactly on a rate
            # boundary to the supply interval that completed its last work.
            observed = [event for event in result.events if start < event.elapsed <= phase.until_second]
            phase_rows.append({"start_second": start, "until_second": phase.until_second,
                               "rate_multiplier": ratio(phase.rate_multiplier),
                               "modeled_events": len(observed),
                               "target_at_last_event_hex": None if not observed else f"{observed[-1].target:064x}"})
        prior = 0
        gaps = []
        for event in result.events:
            gaps.append(event.elapsed - prior)
            prior = event.elapsed
        row = {"case": name, "horizon_seconds": horizon, "phases": phase_rows,
               "modeled_events": len(events),
               "baseline_complete_legal_attempts_per_second": ratio(profile.baseline_rate),
               "complete_legal_attempt_budget": ratio(result.total_complete_attempt_budget),
               "unfinished_success_hazard": ratio(result.unfinished_hazard),
               "cumulative_required_work": "0" if not events else events[-1]["chainwork"],
               "last_event_elapsed_ns_floor": None if not events else events[-1]["elapsed_ns_floor"],
               "longest_completed_interevent_ns_floor": None if not gaps else floor_ns(max(gaps)),
               "unfinished_tail_ns_floor": floor_ns(horizon - prior),
               "markers": confirmations(result, profile, probes),
               "event_records_sha256": hashlib.sha256(canonical(events)).hexdigest()}
        if include_events:
            row["events"] = events
        records.append(row)
    return {"schema": "pon-honest-rate-sensitivity-v1", "status": "CONDITIONAL_ARITHMETIC_ONLY",
            "same_modeled_wall_clock_horizon": True, "same_total_attempt_budget": False,
            "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                              for name in SOURCE_FILES},
            "assumptions": ASSUMPTIONS, "cases": records,
            "native_work_executed": False, "native_consensus_exercised": False,
            "work_hardness_qualified": False, "public_network_qualified": False,
            "production_activation": False, "finalized": False, "execution_authority": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--horizon-seconds", type=int, default=7200)
    parser.add_argument("--include-events", action="store_true")
    parser.add_argument("--output", type=Path, help="Create a new receipt; never replace an existing file.")
    args = parser.parse_args()
    try:
        report = campaign(args.horizon_seconds, args.include_events)
        raw = canonical(report)
        if args.output is None:
            sys.stdout.buffer.write(raw)
        else:
            with args.output.open("xb") as stream:
                stream.write(raw)
            print(json.dumps({"schema": report["schema"], "status": report["status"],
                              "output": str(args.output), "bytes": len(raw),
                              "sha256": hashlib.sha256(raw).hexdigest(),
                              "cases": [{"case": row["case"], "modeled_events": row["modeled_events"]}
                                        for row in report["cases"]]}))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(json.dumps({"schema": "pon-honest-rate-sensitivity-v1", "status": "REFUSE",
                          "error": str(error)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
