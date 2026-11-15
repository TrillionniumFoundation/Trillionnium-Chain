"""Bounded, deterministic honest-rate sensitivity for the development DAA.

This is an arithmetic fluid path, NOT a stochastic mining simulation or the
expected trajectory of a nonlinear random process. One modeled event occurs
when the integral of assumed complete-legal-attempt rate times (T+1)/2**256
reaches one. No W1 proof, packet, network request, fork or effect is created.
All participants are assumed honest and all completed attempts equal-cost.
"""
from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction
import json
from pathlib import Path
import re

from reference import retarget, timestamp_state, work

U256 = 1 << 256
NS = 1_000_000_000
MAX_SECONDS = 86_400
MAX_EVENTS = 10_000
MAX_PHASES = 32


def integer(value: object, lower: int, upper: int, name: str) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(name)
    return value


def floor_ns(seconds: Fraction) -> int:
    """Presentation only: nanosecond flooring is not measurement precision."""
    return seconds.numerator * NS // seconds.denominator


def ratio(value: Fraction) -> dict:
    return {"numerator": value.numerator, "denominator": value.denominator}


@dataclass(frozen=True)
class Profile:
    initial_target: int
    pow_limit: int
    genesis_time: int
    interval: int
    spacing: int
    future_skew: int
    confirmation_depth: int
    confirmation_work_multiplier: int

    @classmethod
    def from_config(cls, config: dict) -> "Profile":
        if (type(config) is not dict or config.get("schema") != "pon-devnet-2"
                or config.get("production_activation") is not False
                or config.get("not_mainnet") is not True):
            raise ValueError("DISABLED_DEVELOPMENT_PROFILE_REQUIRED")
        if (type(config.get("median_time_width")) is not int
                or config["median_time_width"] != 11
                or type(config.get("retarget_factor")) is not int
                or config["retarget_factor"] != 4):
            raise ValueError("UNMODELED_DAA_RULES")

        def target(key):
            value = config.get(key)
            if type(value) is not str or re.fullmatch("[0-9a-f]{64}", value) is None:
                raise ValueError(key)
            return int(value, 16)

        profile = cls(
            target("initial_target_hex"), target("pow_limit_hex"),
            config.get("genesis_timestamp"), config.get("retarget_interval"),
            config.get("target_spacing_seconds"), config.get("future_skew_seconds"),
            config.get("confirmation_depth"), config.get("confirmation_work_multiplier"),
        )
        profile.validate()
        return profile

    def validate(self) -> None:
        integer(self.initial_target, 1, U256 - 1, "INITIAL_TARGET")
        integer(self.pow_limit, self.initial_target, U256 - 1, "POW_LIMIT")
        integer(self.genesis_time, 0, (1 << 63) - 1 - MAX_SECONDS, "GENESIS_TIME")
        # Keep this supplemental model on the existing development timing rule.
        integer(self.interval, 16, 16, "INTERVAL")
        integer(self.spacing, 10, 10, "SPACING")
        integer(self.future_skew, 0, 86_400, "FUTURE_SKEW")
        integer(self.confirmation_depth, 1, 4096, "CONFIRMATION_DEPTH")
        integer(self.confirmation_work_multiplier, 1, 4096, "CONFIRMATION_WORK")

    @property
    def baseline_rate(self) -> Fraction:
        # Assumed complete legal attempts/second giving one hazard unit per
        # nominal spacing at the installed initial target. No FLOP conversion.
        return Fraction(U256, self.spacing * (self.initial_target + 1))


def load_profile(path: Path) -> Profile:
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("DUPLICATE_CONFIG_KEY")
            value[key] = item
        return value

    def nonfinite(_):
        raise ValueError("NONFINITE_CONFIG")

    with path.open("rb") as stream:
        raw = stream.read(65_537)
    if len(raw) > 65_536:
        raise ValueError("CONFIG_SIZE")
    return Profile.from_config(json.loads(raw, object_pairs_hook=unique,
                                         parse_constant=nonfinite))


@dataclass(frozen=True)
class Phase:
    until_second: int
    rate_multiplier: Fraction


@dataclass(frozen=True)
class Event:
    height: int
    elapsed: Fraction
    timestamp: int
    target: int
    chainwork: int

    def record(self) -> dict:
        return {"height": self.height, "elapsed_ns_floor": floor_ns(self.elapsed),
                "timestamp": self.timestamp, "target_hex": f"{self.target:064x}",
                "required_work": str(work(self.target)), "chainwork": str(self.chainwork)}


@dataclass(frozen=True)
class PathResult:
    events: tuple[Event, ...]
    total_complete_attempt_budget: Fraction
    unfinished_hazard: Fraction
    horizon_seconds: int


def simulate(profile: Profile, phases: tuple[Phase, ...], horizon: int) -> PathResult:
    profile.validate()
    integer(horizon, 1, MAX_SECONDS, "HORIZON")
    if not isinstance(phases, tuple) or not 1 <= len(phases) <= MAX_PHASES:
        raise ValueError("PHASE_COUNT")
    previous = 0
    for phase in phases:
        if not isinstance(phase, Phase):
            raise ValueError("PHASE")
        integer(phase.until_second, previous + 1, horizon, "PHASE_BOUNDARY")
        if (type(phase.rate_multiplier) is not Fraction
                or not 0 <= phase.rate_multiplier <= 4
                or phase.rate_multiplier.denominator > 1_000_000):
            raise ValueError("RATE_MULTIPLIER")
        previous = phase.until_second
    if previous != horizon:
        raise ValueError("INCOMPLETE_HORIZON")

    history = [Event(0, Fraction(0), profile.genesis_time, profile.initial_target, 0)]
    phase_index, now, hazard, attempts = 0, Fraction(0), Fraction(0), Fraction(0)
    target = profile.initial_target
    while now < horizon:
        if now == phases[phase_index].until_second:
            phase_index += 1
        phase = phases[phase_index]
        rate = profile.baseline_rate * phase.rate_multiplier
        available = Fraction(phase.until_second) - now
        intensity = rate * Fraction(target + 1, U256)
        possible = intensity * available
        if intensity == 0 or hazard + possible < 1:
            # Work already paid before a rate change is carried across it.
            attempts += rate * available
            hazard += possible
            now += available
            continue
        elapsed = (1 - hazard) / intensity
        now += elapsed
        attempts += rate * elapsed
        hazard = Fraction(0)
        if len(history) - 1 >= MAX_EVENTS:
            raise ValueError("EVENT_LIMIT")
        timestamp = profile.genesis_time + now.numerator // now.denominator
        if timestamp_state(timestamp, [item.timestamp for item in history[-11:]],
                           timestamp, profile.future_skew) != "admissible":
            # Never manufacture a later timestamp or free computation to make
            # an unmodeled high-rate sequence appear admissible.
            raise ValueError("ASSUMED_EVENT_FAILS_TIMESTAMP_RULES")
        history.append(Event(len(history), now, timestamp, target,
                             history[-1].chainwork + work(target)))
        next_height = len(history)
        if next_height % profile.interval == 0:
            target = retarget(target, history[-profile.interval].timestamp,
                              history[-1].timestamp, profile.interval,
                              profile.spacing, profile.pow_limit)
    return PathResult(tuple(history[1:]), attempts, hazard, horizon)


def confirmations(result: PathResult, profile: Profile, probe_times: tuple[int, ...]) -> list[dict]:
    """Hypothetical markers; never transaction inclusion or execution permission."""
    if not isinstance(probe_times, tuple) or not 1 <= len(probe_times) <= 16:
        raise ValueError("PROBE_COUNT")
    for probe in probe_times:
        integer(probe, 0, result.horizon_seconds, "PROBE_TIME")
    if len(set(probe_times)) != len(probe_times):
        raise ValueError("DUPLICATE_PROBE")
    rows = []
    for probe in probe_times:
        included = next((event for event in result.events if event.elapsed >= probe), None)
        row = {"requested_elapsed_seconds": probe, "status": "pending_inclusion",
               "included_height": None, "included_elapsed_ns_floor": None,
               "required_depth": profile.confirmation_depth, "required_work_delta": None,
               "depth_satisfied_elapsed_ns_floor": None, "work_satisfied_elapsed_ns_floor": None,
               "confirmed_elapsed_ns_floor": None, "confirmation_wait_ns_floor": None,
               "finalized": False, "execution_authority": False}
        if included is not None:
            threshold = work(included.target) * profile.confirmation_work_multiplier
            depth_at = next((event for event in result.events
                             if event.height >= included.height + profile.confirmation_depth), None)
            work_at = next((event for event in result.events
                            if event.chainwork >= included.chainwork + threshold), None)
            row.update(status="pending_confirmation", included_height=included.height,
                       included_elapsed_ns_floor=floor_ns(included.elapsed),
                       required_work_delta=str(threshold),
                       depth_satisfied_elapsed_ns_floor=None if depth_at is None else floor_ns(depth_at.elapsed),
                       work_satisfied_elapsed_ns_floor=None if work_at is None else floor_ns(work_at.elapsed))
            if depth_at is not None and work_at is not None:
                at = max(depth_at.elapsed, work_at.elapsed)
                row.update(status="conditionally_confirmed", confirmed_elapsed_ns_floor=floor_ns(at),
                           confirmation_wait_ns_floor=floor_ns(at - included.elapsed))
        rows.append(row)
    return rows


def standard_cases(horizon: int = 7200) -> dict[str, tuple[Phase, ...]]:
    integer(horizon, 60, MAX_SECONDS, "CAMPAIGN_HORIZON")
    first, second = horizon // 3, 2 * horizon // 3
    return {
        "steady": (Phase(horizon, Fraction(1)),),
        "fourfold_step_and_restore": (Phase(first, Fraction(1)), Phase(second, Fraction(4)),
                                       Phase(horizon, Fraction(1))),
        "quarter_rate_and_restore": (Phase(first, Fraction(1)), Phase(second, Fraction(1, 4)),
                                     Phase(horizon, Fraction(1))),
        "outage_and_restore": (Phase(first, Fraction(1)), Phase(first + max(1, horizon // 24), Fraction(0)),
                               Phase(horizon, Fraction(1))),
    }


ASSUMPTIONS = [
    "All aggregate participants are honest; complete legal attempts have equal cost and uniform independent target hits by assumption.",
    "Each hypothetical event consumes one integrated success-hazard unit; this deterministic fluid path is not a random mining sample or the expectation of the nonlinear stochastic process.",
    "Rates mean complete legal attempts per modeled second, not machines, CPUs, nominal FLOPs, parameter counts, or measured hardware throughput.",
    "Every case uses the same horizon and installed starting profile; total assumed attempt budgets differ when the declared supply changes.",
    "Rate steps carry unfinished hazard and charge all available attempt supply through the horizon, including its unfinished tail.",
    "Timestamps are the floor of the honest modeled completion clock; targets and work use existing reference.py integer rules.",
    "Displayed times are floored to nanoseconds from exact Fraction arithmetic; they are not physical timing observations.",
    "Markers use both installed depth and required-work thresholds. Unfinished inclusion and confirmation remain explicitly censored at the horizon.",
    "No W1 verification, model-learning value, fork, network partition, latency, queue, validation service, quantum computation, or independence is modeled.",
]
