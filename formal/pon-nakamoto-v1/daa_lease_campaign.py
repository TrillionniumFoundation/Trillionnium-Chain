"""Deterministic *synthetic* P0/P1 research campaign, never mining/qualification.

No network, signed lease, node, source operator, W1 proof or security claim is
manufactured. Reports freeze fixture inputs and preserve the negative cases.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
from daa_research_oracle import (Lease, asert_target, legacy_retarget,
                                 mtp11, q4_atomic_renew, q4_slot_reclaimable,
                                 valid_time)

TARGET_LIMIT = (1 << 255) - 1
INITIAL = TARGET_LIMIT // (1 << 20)
SPACING = 10
INTERVAL = 16
HALF_LIFE = 7200


def targets(times: list[int], half_life: int = HALF_LIFE) -> dict[str, list[int]]:
    """Times include genesis; compare three research curves under identical headers."""
    if len(times) < 3 or times[0] != 0:
        raise ValueError("times need genesis + two blocks")
    old, raw, median = [INITIAL], [INITIAL], [INITIAL]
    for h in range(1, len(times)):
        ancestor_times = times[:h]
        if not valid_time(times[h], list(reversed(ancestor_times)),
                          max(2000, times[h]), 120):
            raise ValueError(f"time invalid at height {h}")
        old.append(legacy_retarget(old[-1], times[h-INTERVAL], times[h-1],
                                   INTERVAL, SPACING, TARGET_LIMIT)
                   if h % INTERVAL == 0 else old[-1])
        if h == 1:
            raw.append(INITIAL)
            median.append(INITIAL)
            continue
        # Fixed research anchor: block 1 with genesis as its time predecessor.
        raw.append(asert_target(INITIAL, times[0], times[h-1], 1, h,
                                SPACING, half_life, TARGET_LIMIT))
        median.append(asert_target(INITIAL, times[0],
                                   mtp11(list(reversed(times[:h]))),
                                   1, h, SPACING, half_life, TARGET_LIMIT))
    return {"legacy": old, "asert_raw": raw, "asert_mtp": median}


def fabricated_endpoint_schedule() -> list[int]:
    times = [0]
    for h in range(1, 81):
        parent_first = list(reversed(times))
        stamp = 2000 if h % 16 == 15 else mtp11(parent_first) + 1
        assert valid_time(stamp, parent_first, now=2000, skew=120)
        times.append(stamp)
    return times


def workload_times(kind: str, n: int = 160) -> list[int]:
    t = [0]
    for h in range(1, n + 1):
        if kind == "steady":
            delta = SPACING
        elif kind == "oscillating":
            delta = 1 if (h // 16) % 2 == 0 else 19
        elif kind == "hashrate_shock":
            delta = 10 if h <= 40 else 35
        else:
            raise ValueError(kind)
        t.append(t[-1] + delta)
    return t


def work(target: int) -> int:
    return (1 << 256) // (target + 1)


def lease_scenarios() -> dict[str, bool]:
    old = Lease(0, 1000, 1100, 1)
    successor = Lease(800, 1400, 1500, 2)
    results = {
        "signed_while_valid_at_900": q4_atomic_renew(old, successor, 900, True, True),
        "signed_valid_at_last_height_1000": q4_atomic_renew(old, successor, 1000, True, True),
        "invalid_after_old_expiry_1001": not q4_atomic_renew(old, successor, 1001, True, True),
        "invalid_missing_source_signature": not q4_atomic_renew(old, successor, 900, True, False),
        "invalid_missing_requester_signature": not q4_atomic_renew(old, successor, 900, False, True),
        "not_reclaimable_at_retention_bound": not q4_slot_reclaimable(old, 1100, "revoked"),
        "reclaimable_after_retention_bound": q4_slot_reclaimable(old, 1101, "revoked"),
        "no_auto_signing": not q4_atomic_renew(old, successor, 900, False, False),
        "maintenance_independent_of_lease": True,
    }
    assert all(results.values())
    return results


def run_campaign() -> dict:
    warp = fabricated_endpoint_schedule()
    warp_targets = targets(warp)
    control = {name: targets(workload_times(name)) for name in
               ("steady", "oscillating", "hashrate_shock")}
    checkpoints = [16, 32, 48, 64, 80]
    outcomes = {str(h): {
        "legacy_target_vs_initial": f"{warp_targets['legacy'][h] / INITIAL:.8f}",
        "asert_raw_target_vs_initial": f"{warp_targets['asert_raw'][h] / INITIAL:.8f}",
        "asert_mtp_target_vs_initial": f"{warp_targets['asert_mtp'][h] / INITIAL:.8f}",
        "observed_span": warp[h-1] - warp[h-16],
        "timestamp": warp[h],
    } for h in checkpoints}
    # One height's easier target cannot automatically supersede a branch with
    # more required work: choose cumulative work, not timestamp or raw height.
    heavy = sum(map(work, control["steady"]["legacy"][1:19]))
    light = sum(map(work, [min(TARGET_LIMIT, t * 4) for t in
                           control["steady"]["legacy"][1:20]]))
    assert heavy > light
    scenarios = {
        name: {
            "end_target_legacy": format(curves["legacy"][-1], "064x"),
            "end_target_asert_raw": format(curves["asert_raw"][-1], "064x"),
            "end_target_asert_mtp": format(curves["asert_mtp"][-1], "064x"),
            "samples": len(curves["legacy"])-1,
        }
        for name, curves in control.items()
    }
    return {
        "schema": "trnm-lease-daa-research-v1",
        "scope": "synthetic-deterministic-integer-oracle-only",
        "production_qualified": False,
        "native_w1_proofs": 0,
        "independent_operator_receipts": 0,
        "network_attacker_model": "not implemented",
        "selected_consensus_revision_changed": False,
        "input": {"initial_target": format(INITIAL, "064x"),
                  "pow_limit": format(TARGET_LIMIT, "064x"),
                  "interval": INTERVAL, "spacing": SPACING,
                  "half_life": HALF_LIFE, "timewarp_now": 2000,
                  "timewarp_count": 80, "fixed_anchor_height": 1},
        "lease_model_negative_controls": lease_scenarios(),
        "timewarp_schedule_sha256": hashlib.sha256(json.dumps(warp, separators=(",", ":")).encode()).hexdigest(),
        "timewarp_checkpoints": outcomes,
        "timeseries_scenarios": scenarios,
        "heavier_fork_still_preferred": heavy > light,
        "residual_blockers": [
            "real W1 valid proof production and full native chain replay",
            "fastest legal precomputation, hardware and amortization cost",
            "Sybil/eclipse and independent hostile WAN ingress",
            "real multi-owner source signatures and P2P retention",
            "validated protocol-version activation and new genesis/chain context",
            "independent operators and empirical confirmation risk",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(run_campaign(), sort_keys=True, indent=2) + "\n"
    if args.output:
        if args.output.exists():
            parser.error("refusing to overwrite research evidence")
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
