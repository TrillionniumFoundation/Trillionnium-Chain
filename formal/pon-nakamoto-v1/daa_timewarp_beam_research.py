"""Bounded adversarial timestamp *research*, NOT native PoN/W1/security evidence.

Enumerate candidate timestamp schedules under the installed MTP11 and local future
skew predicate. Use exactly the existing 16-block endpoint DAA or the separately
specified non-activated ASERT integer reference. Every sample is a *hypothetical*
valid header: no W1 puzzle is solved, and time schedules give no mining probability.
The search maximizes final target, NOT chainwork or attacker revenue. It makes no
claim to globally optimal timestamp manipulation.
"""
from __future__ import annotations
import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from daa_research_oracle import asert_target, legacy_retarget, mtp11, valid_time

POW_LIMIT = (1 << 255) - 1
INITIAL = POW_LIMIT // (1 << 24)
ALGOS = ("legacy16", "asert_raw", "asert_mtp11")

@dataclass(frozen=True)
class Settings:
    algorithm: str
    blocks: int = 80
    beam_width: int = 64
    spacing: int = 10
    future_skew: int = 120
    half_life: int = 7200
    initial_target: int = INITIAL
    pow_limit: int = POW_LIMIT

    def validate(self) -> None:
        if self.algorithm not in ALGOS:
            raise ValueError("unknown algorithm")
        fields = (self.blocks, self.beam_width, self.spacing, self.future_skew,
                  self.half_life, self.initial_target, self.pow_limit)
        if any(type(x) is not int for x in fields):
            raise ValueError("integer settings required")
        if not (16 <= self.blocks <= 256 and 1 <= self.beam_width <= 256
                and 1 <= self.spacing <= 3600 and 0 <= self.future_skew <= 3600
                and 1 <= self.half_life <= 86_400 and 1 <= self.initial_target <= self.pow_limit < (1 << 256)):
            raise ValueError("unsafe campaign limits")

@dataclass(frozen=True)
class PathState:
    times: tuple[int, ...]
    targets: tuple[int, ...]
    work: int
    trace: tuple[str, ...]


def chain_work(target: int) -> int:
    if not (1 <= target <= (1 << 256) - 1):
        raise ValueError("target")
    return (1 << 256) // (target + 1)


def target_at(settings: Settings, times: tuple[int, ...], previous: int) -> int:
    height = len(times)  # append height when times holds genesis + previous blocks
    if settings.algorithm == "legacy16":
        if height % 16:
            return previous
        return legacy_retarget(previous, times[height-16], times[height-1],
                               16, settings.spacing, settings.pow_limit)
    if height == 1:
        return settings.initial_target  # anchor block itself is on original rule
    selected = times[-1] if settings.algorithm == "asert_raw" else mtp11(tuple(reversed(times[-11:])))
    return asert_target(settings.initial_target, times[0], selected,
                        1, height, settings.spacing, settings.half_life, settings.pow_limit)


def permitted_options(settings: Settings, times: tuple[int, ...]) -> tuple[tuple[int, str], ...]:
    height = len(times)
    clock = height * settings.spacing
    lower = mtp11(tuple(reversed(times[-11:]))) + 1
    upper = clock + settings.future_skew
    if lower > upper:
        return ()
    options = {
        "mtp-min": lower,
        "parent": times[-1],
        "parent-plus": times[-1] + 1,
        "wall": clock,
        "future-max": upper,
        "future-minus": max(0, upper - 1),
        "mid-range": (lower + upper) // 2,
    }
    kept = {}
    for label, stamp in options.items():
        if lower <= stamp <= upper:
            kept.setdefault(stamp, label)
    return tuple(sorted(((stamp, label) for stamp, label in kept.items()), key=lambda v: v[0]))


def _extend(state: PathState, settings: Settings, stamp: int, label: str) -> PathState:
    height = len(state.times)
    if not valid_time(stamp, tuple(reversed(state.times[-11:])),
                      height * settings.spacing, settings.future_skew):
        raise AssertionError("generated illegal timestamp")
    target = target_at(settings, state.times, state.targets[-1])
    return PathState(state.times + (stamp,), state.targets + (target,),
                     state.work + chain_work(target), state.trace + (label,))


def audit_path(settings: Settings, path: PathState) -> None:
    settings.validate()
    if path.times[0] != 0 or len(path.times) != len(path.targets):
        raise AssertionError("genesis mismatch")
    if len(path.times) != settings.blocks + 1 or len(path.trace) != settings.blocks:
        raise AssertionError("incomplete schedule")
    sum_work = chain_work(settings.initial_target) # genesis excluded below
    for height in range(1, settings.blocks + 1):
        if not valid_time(path.times[height],
                          tuple(reversed(path.times[max(0, height-11):height])),
                          height * settings.spacing, settings.future_skew):
            raise AssertionError(f"illegal timestamp at {height}")
        actual = target_at(settings, path.times[:height], path.targets[height-1])
        if path.targets[height] != actual:
            raise AssertionError(f"target mismatch at {height}")
        sum_work += chain_work(actual)
    if sum_work - chain_work(settings.initial_target) != path.work:
        raise AssertionError("noncanonical cumulative chainwork")


def honest_path(settings: Settings) -> PathState:
    settings.validate()
    path = PathState((0,), (settings.initial_target,), 0, ())
    for height in range(1, settings.blocks+1):
        path = _extend(path, settings, height * settings.spacing, "honest")
    audit_path(settings, path)
    return path


def find_high_target(settings: Settings) -> dict:
    settings.validate()
    pool = [PathState((0,), (settings.initial_target,), 0, ())]
    evaluated = 0
    pruned = 0
    for height in range(1, settings.blocks + 1):
        successors = []
        seen = set()
        for path in pool:
            for stamp, label in permitted_options(settings, path.times):
                next_path = _extend(path, settings, stamp, label)
                # Keep distinct 16-timestamp environments; don't promote a
                # peer's asserted target as a state key or trust the pool order.
                key = (next_path.targets[-1], next_path.times[-16:])
                evaluated += 1
                if key in seen:
                    continue
                seen.add(key)
                successors.append(next_path)
        if not successors:
            raise ValueError(f"no admissible synthetic successor at height {height}")
        # Preserve both maximum target progress and the lowest stamped states
        # that may create more exploitable next-period endpoints. This is a
        # bounded heuristic, not a global optimiser or PoN mining algorithm.
        by_target = sorted(successors, key=lambda p: (p.targets[-1], -p.work, p.times), reverse=True)
        by_clock = sorted(successors, key=lambda p: (p.times[-1], -p.targets[-1], p.times))
        selected = []
        retained = set()
        for group, ceiling in [(by_target, (settings.beam_width+1)//2),
                               (by_clock, settings.beam_width)]:
            for candidate in group:
                if len(selected) >= (settings.beam_width if group is by_clock else ceiling):
                    break
                identity = (candidate.targets[-1], candidate.times[-16:])
                if identity not in retained:
                    selected.append(candidate)
                    retained.add(identity)
        pruned += len(successors) - len(selected)
        pool = selected
    winner = max(pool, key=lambda p: (p.targets[-1], -p.work))
    normal = honest_path(settings)
    audit_path(settings, winner)
    # Hold both proven arithmetic targets AND the reduced cumulative work in
    # separate fields: easy target does not imply a heavier fork or double spend.
    specimen = {
        "schema":"pon-daa-timewarp-beam-research-v1", "algorithm":settings.algorithm,
        "blocks":settings.blocks, "beam_width":settings.beam_width,
        "spacing":settings.spacing, "future_skew":settings.future_skew,
        "half_life":settings.half_life, "initial_target":str(settings.initial_target),
        "pow_limit":str(settings.pow_limit), "evaluated_legal_candidates":evaluated,
        "pruned_candidates":pruned, "time_stamps":list(winner.times),
        "target_values":[str(t) for t in winner.targets],
        "chosen_edges":list(winner.trace),
        "target_multiplier_numerator":str(winner.targets[-1]),
        "target_multiplier_denominator":str(settings.initial_target),
        "honest_final_target":str(normal.targets[-1]),
        "honest_chainwork":str(normal.work),
        "searched_chainwork":str(winner.work),
        "full_w1_proofs":0, "independent_operators":0,
        "status":"hypothetical-time-valid-only-no-mined-blocks",
    }
    # freeze a fingerprint independent of JSON indentation; no invented source SHA
    digest = hashlib.sha256(json.dumps(specimen,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    specimen["case_sha256"] = digest
    return specimen


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--blocks", type=int, default=80)
    parser.add_argument("--beam-width", type=int, default=64)
    ns = parser.parse_args()
    cases = [find_high_target(Settings(algorithm=a, blocks=ns.blocks, beam_width=ns.beam_width))
             for a in ALGOS]
    report = {"schema":"pon-daa-timewarp-screen-v1", "cases":cases,
              "actual_W1":False, "production_acceptance":False}
    with ns.output.open("x", encoding="utf8") as file:
        json.dump(report, file, indent=2, sort_keys=True)
        file.write("\n")
    for case in cases:
        x = int(case["target_multiplier_numerator"])/int(case["target_multiplier_denominator"])
        print(case["algorithm"], "max beam target/initial", format(x,'.6f'),
              "work/honest", format(int(case["searched_chainwork"])/int(case["honest_chainwork"]),'.6f'))


if __name__ == "__main__": main()
