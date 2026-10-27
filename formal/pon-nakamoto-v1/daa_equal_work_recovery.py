"""Isolated PoN equal-chainwork reorganization research; NEVER a consensus selector.

The frozen v1 Poisson fork screen artificially chose operator A on an equal-work
healing boundary. This additive v2 model preserves both independently admitted
tips until a *strictly heavier*, branch-valid simulated successor is found.

It contains NO native W1 verifier, authenticated peer messages, protocol upgrade,
operator independence, economic attack proof, or production confirmation claim.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from daa_fork_outage_research import (
    ForkSimulator, Parameters, ALGORITHMS, TIMESTAMP_POLICIES,
)


class EqualWorkForkSimulator(ForkSimulator):
    """Research-only extension that does not rewrite the v1 recorded campaign."""

    def __init__(self, parameters: Parameters):
        super().__init__(parameters)
        self.equal_work_pending = False
        self.equal_work_seen = False
        self.equal_work_resolution_discoveries = 0
        self.equal_work_unresolved_attempts = 0
        self.equal_work_resolved_by: str | None = None

    def heal(self) -> None:
        if self.healed:
            raise ValueError("HEAL_ALREADY_OBSERVED")
        a, b = self.blocks[self.tip_a], self.blocks[self.tip_b]
        if self.tip_a != self.tip_b and a.chainwork == b.chainwork:
            # A healed communication channel is not a consensus tie-breaker.
            # Each previously isolated observer retains their OWN current tip.
            self.work_at_heal_a = a.chainwork
            self.work_at_heal_b = b.chainwork
            self.equal_work_pending = True
            self.equal_work_seen = True
            self.heal_preferred = "equal_work_unresolved"
            self.healed = True
            return
        super().heal()

    def _resolve_if_heavier(self) -> None:
        a, b = self.blocks[self.tip_a], self.blocks[self.tip_b]
        if a.chainwork == b.chainwork:
            # Even different heights are not tie-breakers for PoN chainwork.
            return
        winner_a = a.chainwork > b.chainwork
        winner = self.tip_a if winner_a else self.tip_b
        loser = self.tip_b if winner_a else self.tip_a
        winner_ancestors = {x.key for x in self.ancestry(winner)}
        orphaned = [x for x in self.ancestry(loser) if x.key not in winner_ancestors]
        losing_height = self.blocks[loser].height
        self.reorg_removed = len(orphaned)
        self.reorg_confirmed_depth6 = sum(
            1 for x in orphaned if losing_height - x.height >= 6
        )
        self.equal_work_pending = False
        self.equal_work_resolved_by = "A" if winner_a else "B"
        self.heal_preferred = self.equal_work_resolved_by
        self.tip_a = self.tip_b = winner

    def round(self, phase: str) -> bool:
        if phase != "healed" or not self.equal_work_pending:
            return super().round(phase)
        # The surviving peer views are different even though the partition is
        # physically healed. Both miners use their own current tip until a valid
        # successor creates STRICT extra cumulative work on either branch.
        ra = self.rate("A", self.tip_a)
        rb = self.rate("B", self.tip_b)
        total = ra + rb
        if total <= 0:
            self.stopped = True
            self.stop_reason = "no_assumed_work_capacity"
            return False
        self.wall += self.rng.expovariate(total)
        if self.wall - self.p.genesis_time > self.p.max_clock_seconds:
            self.stopped = True
            self.stop_reason = "bounded_wall_window_exhausted"
            return False
        winner = "A" if self.rng.random() * total < ra else "B"
        new_tip = self.mine(winner, self.tip_a if winner == "A" else self.tip_b)
        if new_tip is None:
            self.equal_work_unresolved_attempts += 1
            return True
        self.equal_work_resolution_discoveries += 1
        if winner == "A":
            self.tip_a = new_tip
        else:
            self.tip_b = new_tip
        self._resolve_if_heavier()
        return True

    def verify_all(self) -> None:
        if not self.equal_work_pending:
            return super().verify_all()
        # Do not call v1's healed-same-tip assertion while the original
        # equal-work fork is unresolved. Independently verify every simulated
        # header, its branch-local DAA and cumulative verified-work arithmetic.
        from daa_fork_outage_research import required_work
        from daa_research_oracle import mtp11
        for key in range(1, self.next_id):
            block = self.blocks[key]
            assert block.parent is not None
            parent = self.blocks[block.parent]
            assert block.height == parent.height + 1
            assert block.chainwork == parent.chainwork + required_work(block.target)
            assert block.timestamp <= int(block.found_wall) + 120
            assert block.timestamp > mtp11(
                [h.timestamp for h in self.ancestry(block.parent)[:11]])
            assert block.target == self.next_target(block.parent)
        assert self.healed and self.tip_a != self.tip_b
        assert self.blocks[self.tip_a].chainwork == self.blocks[self.tip_b].chainwork

    def report(self) -> dict:
        if self.equal_work_pending or (not self.healed and self.tip_a != self.tip_b):
            self.verify_all()
            return {
                "schema": "pon-daa-equal-work-recovery-v2",
                "assumptions": asdict(self.p),
                "partition_healed": self.healed,
                "partition_converged": False,
                "tip_a": self.tip_a,
                "tip_b": self.tip_b,
                "work_a": str(self.blocks[self.tip_a].chainwork),
                "work_b": str(self.blocks[self.tip_b].chainwork),
                "chosen_global_tip": None,
                "claimed_global_confirmations": None,
                "equal_work_unresolved": (
                    self.blocks[self.tip_a].chainwork == self.blocks[self.tip_b].chainwork
                ),
                "equal_work_resolution_discoveries": self.equal_work_resolution_discoveries,
                "equal_work_unresolved_attempts": self.equal_work_unresolved_attempts,
                "terminal_stopped": self.stopped,
                "stop_reason": self.stop_reason,
                "actual_w1_proofs": 0,
                "real_network_transmissions": 0,
                "independently_operated_nodes": 0,
                "consensus_activated": False,
                "claim": "synthetic equal-work tie, not authoritative consensus",
            }
        result = super().report()
        result.update({
            "schema": "pon-daa-equal-work-recovery-v2",
            "partition_converged": self.healed and self.tip_a == self.tip_b,
            "equal_work_seen": self.equal_work_seen,
            "equal_work_unresolved": False,
            "equal_work_resolution_discoveries": self.equal_work_resolution_discoveries,
            "equal_work_unresolved_attempts": self.equal_work_unresolved_attempts,
            "equal_work_resolved_by": self.equal_work_resolved_by,
            "claim": "synthetic equal-work tie resolution, not consensus qualification",
        })
        return result


def force_equal_fork(p: Parameters, depth: int) -> EqualWorkForkSimulator:
    """Research fixture: both operator tips acquire actual modeled equal work."""
    if type(depth) is not int or not 1 <= depth <= 12:
        raise ValueError("INVALID_BOUNDED_EQUAL_FORK_DEPTH")
    if (p.timestamp_policy_a, p.timestamp_policy_b) != ("mtp_min", "mtp_min"):
        raise ValueError("EQUAL_FORK_REQUIRES_FIXED_MTP_MIN_POLICY")
    simulator = EqualWorkForkSimulator(p)
    # No timewarp or DAA change across this <=12-height single-period test.
    # Each independently mined header still follows its own validated ancestor.
    for miner in ("A", "B"):
        parent = 0
        for _ in range(depth):
            simulator.wall += 11
            next_tip = simulator.mine(miner, parent)
            if next_tip is None:
                raise AssertionError("unexpected development timestamp refusal")
            parent = next_tip
        if miner == "A":
            simulator.tip_a = parent
        else:
            simulator.tip_b = parent
    if simulator.blocks[simulator.tip_a].chainwork != simulator.blocks[simulator.tip_b].chainwork:
        raise AssertionError("fixture failed to construct equal-work branches")
    return simulator


def campaign() -> dict:
    """Fixed, bounded 18-case synthetic matrix; includes no real miner or WAN."""
    cases = []
    for algo in ALGORITHMS:
        for depth in (1, 7, 12):
            for lost_all_work in (False, True):
                p = Parameters(algorithm=algo, timestamp_policy_a="mtp_min",
                               timestamp_policy_b="mtp_min", seed=20261026,
                               task_outage_at=1000,
                               a_maintenance_fraction=1.0,
                               b_maintenance_fraction=1.0)
                s = force_equal_fork(p, depth)
                if lost_all_work:
                    # Real historical modeled work precedes the announced outage.
                    from dataclasses import replace
                    s.p = replace(s.p, task_outage_at=0,
                                  a_maintenance_fraction=0.0,
                                  b_maintenance_fraction=0.0)
                s.heal()
                before = s.report()
                assert before["chosen_global_tip"] is None
                advanced = s.round("healed")
                after = s.report()
                cases.append({
                    "algorithm": algo, "depth": depth, "source_outage": lost_all_work,
                    "healed_status": before["partition_converged"],
                    "advanced": advanced,
                    "resolved": after["partition_converged"],
                    "remaining_unresolved": after["equal_work_unresolved"],
                    "orphaned_after_resolution": after.get("losing_branch_blocks_removed"),
                    "simulated_depth6_orphaned": after.get("losing_branch_depth6_blocks_removed"),
                    "work_a_at_heal": before["work_a"],
                    "work_b_at_heal": before["work_b"],
                })
    encoded = json.dumps(cases, sort_keys=True, separators=(",", ":")).encode()
    return {
        "schema": "pon-daa-equal-work-tie-campaign-v2",
        "cases": len(cases),
        "sha256": hashlib.sha256(encoded).hexdigest(),
        "rows": cases,
        "qualification": {"native_W1": False, "production_daa": False,
                          "independent_wan": False, "chain_finality": False},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = campaign()
    with args.output.open("x", encoding="utf8") as fp:
        json.dump(report, fp, sort_keys=True, indent=2)
        fp.write("\n")
    print(json.dumps({"schema": report["schema"], "cases": report["cases"],
                      "sha256": report["sha256"]}, sort_keys=True))


if __name__ == "__main__":
    main()
