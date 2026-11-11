"""Bounded, seeded event experiments over conditional classical/Grover miners.

This is not a W1 oracle, node, network implementation or security proof. The
prefix and required-target arithmetic come from quantum_daa_model. Mining
clocks and successful predicates are explicit premises; native verification,
physical qubits, fault correction and useful-work soundness are not simulated.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from fractions import Fraction
import hashlib
import heapq
import json
import math
import random
import time
from typing import Any

from quantum_daa_model import (
    Header, POW_LIMIT, Scenario, common_history, probability, required, uint,
)
from reference import retarget, timestamp_state, work
from quantum_adversarial_search import (
    ADVERSARIAL_ASSUMPTIONS, MAX_CLOCK_SECONDS, MAX_DOMAIN_SIZE,
    MAX_EXACT_BINOMIAL_SIZE, TrialCosts, bounded_throughput_choice,
    finite_domain_success, sample_marked_count, upward_float, validate_candidates,
)

WORK_MAX = (1 << 512) - 1
PROFILE = "conditional-w1-lottery-dev-profile-v1"
POLICIES = ("periodic-target", "asert-raw", "asert-mtp11")
UNAVAILABLE_BACKENDS = {
    "fast-daa-2026": "UNIMPLEMENTED: full parallel-chain protocol and parameter mapping required",
}
ASSUMPTIONS = {
    "schema": "trnm-quantum-network-assumptions-v1",
    "model": "finite discrete events; arithmetic prefix; abstract successful lottery predicates",
    "classical": "independent Poisson winner arrivals; query equivalents are assumed rate times elapsed",
    "quantum": "finite Grover trials with float64 sin^2 probability; no monotone success approximation",
    "quantum_trial_policy": "fixed iterations or capped first probability peak; not optimal cost/throughput or cheapest miner",
    "quantum_tip_policy": "default discard/restart; opt-in latch on adopted tip, finish current iteration, measure once; no arbitrary-gate interruption model",
    "timing_inputs": "synthetic conditional rate and latency premises, not W1/hardware measurements",
    "private_future_parents": "private mining may continue on time-deferred parents; each receiver independently defers future imports",
    "marked_fraction_assumed_equal_uniform_ticket_probability": True,
    "actual_w1_marked_count": None,
    "bounded_nonce_no_marked_solution_and_bbht": "not modeled; assumed marked fraction may not hold",
    "asert_scope": "isolated required-target arithmetic; not a full alternative consensus protocol",
    "quantum_parallelism": "independent synchronous processors, at most one block per successful batch",
    "shock_semantics": "classical clocks resample; quantum speed changes cancel and restart coherent trials",
    "proof_semantics": "one post-success proof per batch; serial with mining; stale proofs still finish",
    "candidate_recheck": "every measured quantum candidate is checked, failed candidates too; P parallel checks charge P processor-seconds; stale partial checks cancel",
    "network": "fixed delay per receiver; complete ancestor bundle; no bandwidth, eclipse or W1 validation model",
    "transaction": "one public probe, frozen into a candidate at search start; private miner may omit it",
    "fork_choice": "strictly greater compatible integer required work; ties retain current tip; checked u512",
    "timestamp": "frozen before search; upper median last 11; future bound inclusive now+120",
    "observation_scope": "finite sampled events and configured seeds; empirical metrics are not security proofs",
    "receipt_scope": "source-consistent replay, not authenticated execution attestation",
    "logical_qubits": None,
    "logical_gate_count": None,
    "logical_gate_depth": None,
    "physical_error_rate": None,
    "error_correction_overhead": None,
    "quantum_hardware_executed": False,
    "native_w1_verified": False,
    "production_consensus_activation": False,
    "security_theorem": False,
    "release_ready": False,
    "unavailable_backends": UNAVAILABLE_BACKENDS,
}


def finite(value: float, name: str, lower: float = 0.0,
           upper: float = 86400.0) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or not lower <= value <= upper:
        raise ValueError(name)
    return float(value)


def checked_chainwork(parent: int, added: int) -> int:
    uint(parent, "PARENT_CHAINWORK", WORK_MAX)
    uint(added, "ADDED_CHAINWORK", WORK_MAX)
    if parent > WORK_MAX - added:
        raise OverflowError("CHAINWORK_U512_OVERFLOW")
    return parent + added


def grover_success(p: float, iterations: int, processors: int = 1) -> float:
    """Finite-round probability, including overshoot, then independent batches."""
    finite(p, "PROBABILITY", 0, 1)
    uint(iterations, "GROVER_ITERATIONS", 100_000_000)
    uint(processors, "QUANTUM_PROCESSORS", 1024)
    if processors == 0:
        raise ValueError("QUANTUM_PROCESSORS")
    single = math.sin((2 * iterations + 1) * math.asin(math.sqrt(p))) ** 2
    if single >= 1:
        return 1.0
    return -math.expm1(processors * math.log1p(-single))


@dataclass(frozen=True)
class ParticipationShock:
    at_seconds: float
    classical_factor: float
    quantum_factor: float


@dataclass(frozen=True)
class TimestampPhase:
    blocks: int
    step_seconds: int


@dataclass(frozen=True)
class NetworkScenario:
    name: str
    seed: int = 1
    policy: str = "periodic-target"
    profile: str = PROFILE
    duration_seconds: float = 1200.0
    half_life: int = 160
    classical_block_rate_at_initial_target: float = 0.1
    classical_shares: tuple[float, ...] = (0.5, 0.5)
    quantum_strategy: str = "honest-tip"
    quantum_initial_factor: float = 1.0
    quantum_iteration_seconds: float = 0.15
    quantum_prepare_seconds: float = 0.02
    quantum_measure_seconds: float = 0.01
    quantum_candidate_check_seconds: float = 0.05
    quantum_fixed_iterations: int | None = None
    quantum_max_iterations: int = 1_000_000
    quantum_processors: int = 1
    quantum_trial_policy: str = "first-peak"
    quantum_iteration_candidates: tuple[int, ...] = ()
    quantum_domain_size: int | None = None
    quantum_domain_marked_count: int | None = None
    quantum_domain_trials_before_refresh: int = 0
    quantum_domain_setup_seconds: float = 0.0
    quantum_clock_rounding: str = "nearest"
    classical_proof_seconds: float = 0.1
    quantum_proof_seconds: float = 1.0
    propagation_seconds: float = 0.5
    private_release_seconds: float | None = None
    quantum_timestamp_mode: str = "wall"
    private_timestamp_step: int = 5
    private_timestamp_schedule: tuple[TimestampPhase, ...] = ()
    private_release_policy: str = "scheduled"
    private_release_work_lead: int = 1
    private_release_min_blocks: int = 1
    private_release_max_wait_seconds: float | None = None
    private_censors_probe: bool = True
    probe_arrival_seconds: float = 1.0
    confirmation_depth: int = 6
    confirmation_work_multiplier: int = 6
    shocks: tuple[ParticipationShock, ...] = ()
    max_events: int = 20_000
    max_blocks: int = 4_000
    max_trace_rows: int = 80_000
    max_pending_events: int = 20_000
    cpu_limit_seconds: float = 10.0
    quantum_tip_policy: str = "discard-restart"

    def validate(self) -> None:
        if self.policy in UNAVAILABLE_BACKENDS:
            raise NotImplementedError(UNAVAILABLE_BACKENDS[self.policy])
        if self.policy not in POLICIES or self.profile != PROFILE:
            raise ValueError("POLICY_OR_PROFILE")
        if type(self.name) is not str or not self.name or len(self.name) > 100 or any(
                c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in self.name):
            raise ValueError("SCENARIO_NAME")
        uint(self.seed, "SEED", (1 << 64) - 1)
        uint(self.half_life, "HALF_LIFE", 1 << 24)
        if not self.half_life:
            raise ValueError("HALF_LIFE")
        finite(self.duration_seconds, "DURATION", 0.001, 86400)
        finite(self.classical_block_rate_at_initial_target, "CLASSICAL_RATE", 0, 1000)
        if 0 < self.classical_block_rate_at_initial_target < 1e-9:
            raise ValueError("CLASSICAL_RATE_PRECISION")
        if type(self.classical_shares) is not tuple or not 1 <= len(self.classical_shares) <= 8:
            raise ValueError("CLASSICAL_SHARES")
        for share in self.classical_shares:
            finite(share, "CLASSICAL_SHARE", 1e-9, 1)
        if abs(sum(self.classical_shares) - 1) > 1e-12:
            raise ValueError("CLASSICAL_SHARE_SUM")
        if self.quantum_strategy not in ("honest-tip", "private-branch"):
            raise ValueError("QUANTUM_STRATEGY")
        if self.quantum_tip_policy not in ("discard-restart", "measure-on-tip"):
            raise ValueError("QUANTUM_TIP_POLICY")
        if self.quantum_tip_policy == "measure-on-tip":
            if self.quantum_strategy != "honest-tip":
                raise ValueError("MEASURE_ON_TIP_REQUIRES_HONEST_TIP")
            if self.quantum_clock_rounding != "upward":
                raise ValueError("MEASURE_ON_TIP_REQUIRES_UPWARD_CLOCK")
        if self.quantum_timestamp_mode not in ("wall", "compressed", "mtp-min",
                                               "future-bound", "retarget-extremes"):
            raise ValueError("TIMESTAMP_MODE")
        if self.quantum_strategy != "private-branch" and self.quantum_timestamp_mode != "wall":
            raise ValueError("HONEST_TIMESTAMP_MODE")
        for value, name in ((self.quantum_initial_factor, "QUANTUM_FACTOR"),):
            finite(value, name, 0, 1000)
            if 0 < value < 1e-9:
                raise ValueError("QUANTUM_FACTOR_PRECISION")
        finite(self.quantum_iteration_seconds, "ITERATION_SECONDS", 1e-9, MAX_CLOCK_SECONDS)
        finite(self.quantum_measure_seconds, "MEASURE_SECONDS", 1e-9, MAX_CLOCK_SECONDS)
        finite(self.quantum_candidate_check_seconds, "CANDIDATE_CHECK_SECONDS", 1e-9, MAX_CLOCK_SECONDS)
        for name in ("quantum_prepare_seconds", "quantum_proof_seconds", "quantum_domain_setup_seconds"):
            finite(getattr(self, name), name, 0, MAX_CLOCK_SECONDS)
        for name in ("classical_proof_seconds", "propagation_seconds"):
            finite(getattr(self, name), name)
        uint(self.quantum_max_iterations, "MAX_ITERATIONS", 100_000_000)
        if not self.quantum_max_iterations:
            raise ValueError("MAX_ITERATIONS")
        if self.quantum_fixed_iterations is not None:
            uint(self.quantum_fixed_iterations, "FIXED_ITERATIONS", self.quantum_max_iterations)
        uint(self.quantum_processors, "PROCESSORS", 1024)
        if self.quantum_processors == 0:
            raise ValueError("PROCESSORS")
        if self.quantum_clock_rounding not in ("nearest", "upward"):
            raise ValueError("QUANTUM_CLOCK_ROUNDING")
        if self.quantum_trial_policy not in ("first-peak", "bounded-throughput"):
            raise ValueError("QUANTUM_TRIAL_POLICY")
        if self.quantum_trial_policy == "bounded-throughput":
            if self.quantum_fixed_iterations is not None:
                raise ValueError("AMBIGUOUS_ITERATION_POLICY")
            validate_candidates(self.quantum_iteration_candidates, self.quantum_max_iterations)
        elif self.quantum_iteration_candidates != ():
            raise ValueError("UNUSED_ITERATION_CANDIDATES")
        uint(self.quantum_domain_trials_before_refresh, "DOMAIN_REFRESH_TRIALS", 100_000)
        if self.quantum_domain_size is None:
            if (self.quantum_domain_marked_count is not None or self.quantum_domain_trials_before_refresh
                    or self.quantum_domain_setup_seconds):
                raise ValueError("DOMAIN_PARAMETERS_WITHOUT_DOMAIN")
        else:
            uint(self.quantum_domain_size, "DOMAIN_SIZE", MAX_DOMAIN_SIZE)
            if not self.quantum_domain_size:
                raise ValueError("DOMAIN_SIZE")
            if self.quantum_domain_marked_count is not None:
                uint(self.quantum_domain_marked_count, "DOMAIN_MARKED_COUNT", self.quantum_domain_size)
            if self.quantum_trial_policy == "bounded-throughput":
                if (self.quantum_domain_trials_before_refresh != 1
                        or self.quantum_domain_marked_count is not None):
                    raise ValueError("FINITE_THROUGHPUT_REQUIRES_FRESH_BINOMIAL_DOMAINS")
                if self.quantum_domain_size > MAX_EXACT_BINOMIAL_SIZE:
                    raise ValueError("EXACT_BINOMIAL_SUPPORT")
        uint(self.private_timestamp_step, "STAMP_STEP", 120)
        if type(self.private_timestamp_schedule) is not tuple or len(self.private_timestamp_schedule) > 16:
            raise ValueError("TIMESTAMP_SCHEDULE")
        total = 0
        for phase in self.private_timestamp_schedule:
            if not isinstance(phase, TimestampPhase):
                raise ValueError("TIMESTAMP_PHASE")
            uint(phase.blocks, "PHASE_BLOCKS", 10000)
            uint(phase.step_seconds, "PHASE_STEP", 120)
            if not phase.blocks or not phase.step_seconds:
                raise ValueError("TIMESTAMP_PHASE")
            total += phase.blocks
        uint(self.max_blocks, "max_blocks", 10000)
        if total > self.max_blocks or (total and (self.quantum_strategy != "private-branch"
                                                 or self.quantum_timestamp_mode != "compressed")):
            raise ValueError("TIMESTAMP_PHASE_SCOPE")
        if self.private_timestamp_step == 0 or type(self.private_censors_probe) is not bool:
            raise ValueError("PRIVATE_PARAMETERS")
        for value, name in ((self.probe_arrival_seconds, "PROBE_ARRIVAL"),
                            (self.private_release_seconds, "PRIVATE_RELEASE")):
            if value is not None:
                finite(value, name, 0, self.duration_seconds)
            elif name == "PROBE_ARRIVAL":
                raise ValueError(name)
        if self.private_release_seconds is not None and self.quantum_strategy != "private-branch":
            raise ValueError("RELEASE_WITHOUT_PRIVATE_BRANCH")
        if self.private_release_policy not in ("scheduled", "observed-work-lead"):
            raise ValueError("RELEASE_POLICY")
        uint(self.private_release_work_lead, "RELEASE_WORK_LEAD", 10000)
        uint(self.private_release_min_blocks, "RELEASE_MIN_BLOCKS", 10000)
        if not self.private_release_work_lead or not self.private_release_min_blocks:
            raise ValueError("RELEASE_THRESHOLD")
        if self.private_release_policy == "observed-work-lead":
            if self.quantum_strategy != "private-branch" or self.private_release_seconds is not None:
                raise ValueError("ADAPTIVE_RELEASE_SCOPE")
            if self.private_release_max_wait_seconds is not None:
                finite(self.private_release_max_wait_seconds, "RELEASE_MAX_WAIT", 1e-9, self.duration_seconds)
        elif (self.private_release_work_lead != 1 or self.private_release_min_blocks != 1
              or self.private_release_max_wait_seconds is not None):
            raise ValueError("UNUSED_RELEASE_PARAMETERS")
        uint(self.confirmation_depth, "CONFIRMATION_DEPTH", 1000)
        uint(self.confirmation_work_multiplier, "CONFIRMATION_WORK_MULTIPLIER", 1000)
        if self.confirmation_depth == 0 or self.confirmation_work_multiplier == 0:
            raise ValueError("CONFIRMATION_PARAMETERS")
        if type(self.shocks) is not tuple or len(self.shocks) > 64:
            raise ValueError("SHOCKS")
        previous = -1.0
        for shock in self.shocks:
            if not isinstance(shock, ParticipationShock):
                raise ValueError("SHOCK_TYPE")
            finite(shock.at_seconds, "SHOCK_TIME", 0, self.duration_seconds)
            finite(shock.classical_factor, "SHOCK_CLASSICAL", 0, 1000)
            finite(shock.quantum_factor, "SHOCK_QUANTUM", 0, 1000)
            if any(0 < value < 1e-9 for value in (shock.classical_factor, shock.quantum_factor)):
                raise ValueError("SHOCK_FACTOR_PRECISION")
            if shock.at_seconds <= previous:
                raise ValueError("SHOCK_ORDER")
            previous = shock.at_seconds
        for name, cap in (("max_events", 100_000), ("max_blocks", 10_000),
                          ("max_trace_rows", 300_000), ("max_pending_events", 100_000)):
            uint(getattr(self, name), name, cap)
            if not getattr(self, name):
                raise ValueError(name)
        finite(self.cpu_limit_seconds, "CPU_LIMIT", 0.001, 30)


@dataclass(frozen=True)
class Block:
    block_id: str
    parent: str | None
    height: int
    timestamp: int
    target: int
    chainwork: int
    profile: str
    miner: str
    contains_probe: bool = False


@dataclass(frozen=True)
class Trial:
    serial: int
    miner: str
    parent: str
    timestamp: int
    target: int
    contains_probe: bool
    started: float
    finishes: float
    iterations: int
    success_probability: float
    query_rate: float
    iteration_seconds: float
    domain_setup_seconds: float = 0.0
    domain_id: str | None = None
    tip_measurement: bool = False


@dataclass
class DomainTemplate:
    """Evaluator state; its marked count must not be passed to trial selection."""
    domain_id: str
    parent: str
    timestamp: int
    target: int
    contains_probe: bool
    marked_count: int
    completed_batches: int = 0
    # Classical template setup can resume after interruption. Its sampled
    # marked set already exists conceptually, but is not usable until paid.
    setup_remaining_seconds: Fraction = Fraction(0)


@dataclass
class View:
    tip: str
    known: set[str] = field(default_factory=set)


class SimulationLimit(RuntimeError):
    pass


class Simulator:
    """One observer, classical miners, one finite-trial quantum miner.

    start()/step() expose deterministic event controls for independent tests.
    Block registration assumes a successful predicate; it is never native PoN
    admission. Imported targets, times, profiles and chainwork are still checked.
    """
    def __init__(self, case: NetworkScenario):
        case.validate()
        self.case = case
        history = common_history()
        initial = retarget(history[-1].target, history[-16].timestamp,
                           history[-1].timestamp, 16, 10, POW_LIMIT)
        self.initial_target = initial
        self.base_probability = float(probability(initial))
        self.start_timestamp = history[-1].timestamp
        self.anchor = Header(history[-1].height + 1, self.start_timestamp + 10, initial)
        self.anchor_clock = (sorted(h.timestamp for h in history[-11:])[5]
                             if case.policy == "asert-mtp11" else self.start_timestamp)
        self.daa = Scenario(case.name, case.policy, "quantum-search", half_life=case.half_life)
        profile_input = [case.profile, case.policy, case.half_life,
                         [asdict(h) for h in history]]
        self.profile = hashlib.sha256(json.dumps(profile_input, sort_keys=True).encode()).hexdigest()
        self.base = Block("prefix", None, history[-1].height, history[-1].timestamp,
                          history[-1].target, sum(work(h.target) for h in history), self.profile, "prefix")
        self.blocks = {self.base.block_id: self.base}
        self.tails = {self.base.block_id: tuple(history[-16:])}
        self.classical_miners = tuple(f"c{i}" for i in range(len(case.classical_shares)))
        self.miners = self.classical_miners + ("q",)
        self.views = {name: View("prefix", {"prefix"}) for name in self.miners + ("observer",)}
        self.rngs = {name: random.Random(int.from_bytes(hashlib.sha256(
            f"{case.seed}:{name}".encode()).digest(), "big")) for name in self.miners}
        self.domain_rng = random.Random(int.from_bytes(hashlib.sha256(
            f"{case.seed}:q-domain".encode()).digest(), "big"))
        self.quantum_domain: DomainTemplate | None = None
        self.domain_count = 0
        self.zero_marked_domains = 0
        self.domain_setup_seconds_charged = 0.0
        self.iteration_choices: dict[tuple[int, float], Any] = {}
        self.active: dict[str, Trial] = {}
        self.proofs: dict[str, tuple[Trial, float, float]] = {}
        self.proof_completed: set[str] = set()
        self.deferred: dict[tuple[str, str], list[str]] = {}
        self.private_tip = "prefix"
        self.released = False
        self.public_q_tip = "prefix"
        self.public_q_delivery_tips: set[str] = set()
        self.last_published_private_tip = "prefix"
        self.private_wait_started: float | None = None
        self.adaptive_next_check: float | None = None
        self.adaptive_releases = 0
        self.classical_factor = 1.0
        self.quantum_factor = case.quantum_initial_factor
        self.now = 0.0
        self.events: list[tuple[float, int, str, Any]] = []
        self.event_serial = 0
        self.trial_serial = 0
        self.events_processed = 0
        self.started = False
        self.finished = False
        self.stop_reason: str | None = None
        self.trace: list[dict] = []
        self.trace_limit_reached = False
        self.counts = {name: {
            "searches_started": 0, "searches_completed": 0, "searches_failed": 0,
            "candidate_checks_started": 0, "candidate_checks_completed": 0,
            "candidate_checks_cancelled": 0, "candidate_checks_censored": 0,
            "candidate_check_seconds": 0.0, "candidate_check_processor_seconds": 0.0,
            "searches_cancelled": 0, "searches_censored": 0,
            "cancelled_on_tip": 0, "cancelled_on_shock": 0,
            "private_public_tip_updates_ignored": 0,
            "proofs_started": 0, "proofs_completed": 0, "proofs_censored": 0,
            "blocks_created": 0, "stale_proofs_completed": 0,
            "private_future_blocks_created": 0,
            "logical_iterations_completed": 0, "wasted_logical_iterations": 0,
            "search_seconds": 0.0, "wasted_search_seconds": 0.0,
            "censored_search_seconds": 0.0, "proof_seconds": 0.0,
            "future_timestamp_wait_seconds": 0.0, "future_waits_censored": 0,
            "future_timestamp_wait_scheduled_seconds": 0.0,
            "classical_query_equivalents": 0.0,
        } for name in self.miners}
        if case.quantum_tip_policy == "measure-on-tip":
            self.counts["q"].update(tip_measurement_requests=0, measurement_seconds=0.0,
                                    measurement_processor_seconds=0.0)
        self.observer_reorgs = 0
        self.observer_max_reorg_depth = 0
        self.observer_prefix_violations = 0
        self.prefix_samples = 0
        self.prefix_disagreements = 0
        self.probe_first_inclusion: float | None = None
        self.probe_first_confirmation: float | None = None
        self.probe_confirmed = False
        self.probe_confirmation_reversals = 0
        self.obsolete_events = 0

    def _emit(self, kind: str, **fields: Any) -> None:
        if len(self.trace) >= self.case.max_trace_rows:
            self.trace_limit_reached = True
            self.stop_reason = self.stop_reason or "trace-limit"
            return
        self.trace.append({"row": len(self.trace), "at_seconds": self.now, "kind": kind, **fields})

    def _schedule(self, at: float, kind: str, payload: Any) -> None:
        if not math.isfinite(at) or at < self.now:
            raise ValueError("EVENT_CLOCK")
        if len(self.events) >= self.case.max_pending_events:
            raise SimulationLimit("pending-event-limit")
        self.event_serial += 1
        heapq.heappush(self.events, (at, self.event_serial, kind, payload))

    def target_for(self, parent: str) -> int:
        return required(list(self.tails[parent]), self.daa, self.anchor,
                        self.anchor_clock, self.initial_target)[0]

    def path(self, tip: str) -> list[str]:
        output = []
        while tip != "prefix":
            output.append(tip)
            tip = self.blocks[tip].parent
        output.reverse()
        return output

    def validate_block(self, block: Block) -> str:
        if block.profile != self.profile:
            raise ValueError("INCOMPATIBLE_PROFILE")
        if block.parent not in self.blocks or block.miner not in self.miners:
            raise ValueError("BLOCK_PARENT_OR_MINER")
        if type(block.block_id) is not str or not block.block_id or len(block.block_id) > 100:
            raise ValueError("BLOCK_ID")
        for value, name in ((block.height, "HEIGHT"), (block.timestamp, "TIMESTAMP")):
            uint(value, name)
        uint(block.target, "TARGET", POW_LIMIT)
        uint(block.chainwork, "CHAINWORK", WORK_MAX)
        if type(block.contains_probe) is not bool:
            raise ValueError("PROBE_FLAG")
        parent = self.blocks[block.parent]
        if block.height != parent.height + 1 or block.target != self.target_for(block.parent):
            raise ValueError("REQUIRED_HEIGHT_OR_TARGET")
        if block.chainwork != checked_chainwork(parent.chainwork, work(block.target)):
            raise ValueError("REQUIRED_CHAINWORK")
        state = timestamp_state(block.timestamp, [h.timestamp for h in self.tails[block.parent]],
                                self.start_timestamp + int(self.now), 120)
        if state == "invalid-median":
            raise ValueError("TIMESTAMP_MEDIAN")
        return state

    def register_block(self, block: Block) -> None:
        self.validate_block(block)
        if block.block_id in self.blocks:
            if self.blocks[block.block_id] != block:
                raise ValueError("BLOCK_ID_COLLISION")
            return
        if len(self.blocks) - 1 >= self.case.max_blocks:
            raise SimulationLimit("block-limit")
        self.blocks[block.block_id] = block
        self.tails[block.block_id] = (self.tails[block.parent] + (
            Header(block.height, block.timestamp, block.target),))[-16:]

    def _probe(self, tip: str) -> tuple[bool, int, int, int]:
        """Native arithmetic: descendants and work exclude the inclusion block."""
        for depth, block_id in enumerate(reversed(self.path(tip))):
            block = self.blocks[block_id]
            if block.contains_probe:
                delta = self.blocks[tip].chainwork - block.chainwork
                minimum = work(block.target) * self.case.confirmation_work_multiplier
                return True, depth, delta, minimum
        return False, 0, 0, 0

    def _sample_prefix(self) -> None:
        honest = list(self.classical_miners)
        if self.case.quantum_strategy == "honest-tip":
            honest.append("q")
        paths = [self.path(self.views[name].tip) for name in honest]
        self.prefix_samples += 1
        violation = False
        for i, first in enumerate(paths):
            for second in paths[i + 1:]:
                comparable = max(0, min(len(first), len(second)) - self.case.confirmation_depth)
                violation |= first[:comparable] != second[:comparable]
        self.prefix_disagreements += int(violation)

    def _adopt(self, recipient: str, candidate: str) -> None:
        view = self.views[recipient]
        old = view.tip
        if self.blocks[candidate].profile != self.blocks[old].profile:
            raise ValueError("INCOMPATIBLE_PROFILE")
        if self.blocks[candidate].chainwork <= self.blocks[old].chainwork:
            return
        before, after = self.path(old), self.path(candidate)
        shared = 0
        while shared < min(len(before), len(after)) and before[shared] == after[shared]:
            shared += 1
        removed = len(before) - shared
        view.tip = candidate
        self._emit("adopt", recipient=recipient, previous=old, tip=candidate, removed=removed,
                   chainwork=str(self.blocks[candidate].chainwork))
        if recipient == "observer":
            self.observer_reorgs += int(removed > 0)
            self.observer_max_reorg_depth = max(self.observer_max_reorg_depth, removed)
            self.observer_prefix_violations += int(removed > self.case.confirmation_depth)
            included, depth, work_delta, work_minimum = self._probe(candidate)
            confirmed = (included and depth >= self.case.confirmation_depth
                         and work_delta >= work_minimum)
            if included and self.probe_first_inclusion is None:
                self.probe_first_inclusion = self.now
            if confirmed and self.probe_first_confirmation is None:
                self.probe_first_confirmation = self.now
            if self.probe_confirmed and not confirmed:
                self.probe_confirmation_reversals += 1
            self.probe_confirmed = confirmed
        elif recipient == "q" and self.case.quantum_strategy == "private-branch":
            if self.blocks[candidate].miner != "q":
                self.counts["q"]["private_public_tip_updates_ignored"] += 1
        elif not (recipient == "q" and self.case.quantum_tip_policy == "measure-on-tip"
                  and self._measure_on_tip()):
            self._cancel(recipient, "tip")
            self._start_miner(recipient)
        self._sample_prefix()


    def _measure_on_tip(self) -> bool:
        """Latch one old-context readout at the next complete iteration boundary.

        Preparation is not a usable Grover state. Once prepared, an in-flight
        iteration finishes and is paid before readout. Already-started readout
        and candidate checking finish unchanged. Later tips update the view
        without measuring the same state again. A reschedule is the same search,
        with a fresh event serial solely to invalidate its original completion.
        """
        trial = self.active.get("q")
        if trial is None:
            return False
        if trial.tip_measurement:
            return True
        elapsed = Fraction.from_float(float(self.now)) - Fraction.from_float(float(trial.started))
        prepare = (Fraction.from_float(float(self.case.quantum_prepare_seconds))
                   + Fraction.from_float(float(trial.domain_setup_seconds)))
        if elapsed < prepare:
            return False
        iteration = Fraction.from_float(trial.iteration_seconds)
        depth = min(trial.iterations, max(0, math.ceil((elapsed - prepare) / iteration)))
        original_serial = trial.serial
        readout_started = elapsed >= prepare + trial.iterations * iteration
        if depth < trial.iterations:
            if trial.domain_id is None:
                chance = grover_success(float(probability(trial.target)), depth,
                                        self.case.quantum_processors)
            else:
                domain = self.quantum_domain
                if domain is None or domain.domain_id != trial.domain_id:
                    raise ValueError("ACTIVE_DOMAIN_MISMATCH")
                chance = finite_domain_success(self.case.quantum_domain_size, domain.marked_count,
                                               depth, self.case.quantum_processors)
            finish = upward_float(
                Fraction.from_float(float(trial.started)) + prepare + depth * iteration
                + Fraction.from_float(float(self.case.quantum_measure_seconds))
                + Fraction.from_float(float(self.case.quantum_candidate_check_seconds)))
            self.trial_serial += 1
            trial = replace(trial, serial=self.trial_serial, finishes=finish,
                            iterations=depth, success_probability=chance, tip_measurement=True)
            self.active["q"] = trial
            self._schedule(finish, "search", ("q", trial.serial))
        else:
            trial = replace(trial, tip_measurement=True)
            self.active["q"] = trial
        self.counts["q"]["tip_measurement_requests"] += 1
        boundary_wait = max(Fraction(0), prepare + depth * iteration - elapsed)
        self._emit("search-tip-measurement", miner="q", trial=trial.serial,
                   original_trial=original_serial, parent=trial.parent,
                   target_hex=f"{trial.target:064x}", timestamp=trial.timestamp,
                   contains_probe=trial.contains_probe, domain_id=trial.domain_id,
                   iterations=depth, success_probability=trial.success_probability,
                   boundary_wait_seconds=upward_float(boundary_wait),
                   readout_already_started=readout_started,
                   scheduled_finish_seconds=trial.finishes)
        return True

    def _is_ancestor(self, ancestor: str, tip: str) -> bool:
        height = self.blocks[ancestor].height
        while self.blocks[tip].height > height:
            tip = self.blocks[tip].parent
        return tip == ancestor

    def _defer(self, recipient: str, first: str, tip: str, at: float) -> None:
        # Keep competing branches. A descendant bundle already carries all
        # eligible prefixes of its ancestor, so only that ancestry is coalesced.
        key = (recipient, first)
        existing = self.deferred.get(key)
        if existing is None:
            self.deferred[key] = [tip]
            self._schedule(at, "deferred", key)
            return
        if any(self._is_ancestor(tip, old) for old in existing):
            return
        self.deferred[key] = [old for old in existing if not self._is_ancestor(old, tip)] + [tip]

    def receive(self, recipient: str, tip: str, *, from_network: bool = True) -> None:
        """Deliver a complete ancestor bundle after its configured link delay."""
        if recipient not in self.views or tip not in self.blocks:
            raise ValueError("DELIVERY_IDENTITY")
        track_public = recipient == "q" and self.case.private_release_policy == "observed-work-lead"
        if track_public and from_network:
            self.public_q_delivery_tips.add(tip)
        public_message = track_public and tip in self.public_q_delivery_tips
        for block_id in self.path(tip):
            if block_id in self.views[recipient].known:
                continue
            block = self.blocks[block_id]
            if self.validate_block(block) == "deferred-future":
                self._adopt(recipient, block.parent)
                if public_message:
                    self._observe_public_tip(block.parent)
                self._defer(recipient, block_id, tip,
                            float(block.timestamp - 120 - self.start_timestamp))
                self._emit("future-delivery-deferred", recipient=recipient, block=block_id)
                return
            self.views[recipient].known.add(block_id)
        self._adopt(recipient, tip)
        if public_message:
            self._observe_public_tip(tip)

    def _observe_public_tip(self, candidate: str) -> None:
        """Only receive() calls this, after that miner's timestamp admission."""
        if self.blocks[candidate].chainwork > self.blocks[self.public_q_tip].chainwork:
            previous = self.public_q_tip
            self.public_q_tip = candidate
            self._emit("quantum-public-view", previous=previous, tip=candidate,
                       chainwork=str(self.blocks[candidate].chainwork))
        self._maybe_adaptive_release("public-message")

    def _schedule_adaptive_check(self, at: float) -> None:
        if at > self.now and (self.adaptive_next_check is None or at < self.adaptive_next_check):
            self.adaptive_next_check = at
            self._schedule(at, "adaptive-check", None)

    def _maybe_adaptive_release(self, reason: str) -> None:
        """Repeated publication decisions from own work and delayed public view.

        The release threshold is in initial-target required-work units. A timeout
        optionally publishes an eligible prefix without a work advantage. Neither
        the observer's tip nor another miner's undelivered block enters a choice.
        Future-dated ancestors defer even a locally preferred private prefix.
        """
        case = self.case
        if case.private_release_policy != "observed-work-lead":
            return
        if self.private_tip == self.last_published_private_tip:
            return
        eligible = "prefix"
        first_future = None
        ceiling = self.start_timestamp + int(self.now) + 120
        for block_id in self.path(self.private_tip):
            if self.blocks[block_id].timestamp > ceiling:
                first_future = block_id
                break
            eligible = block_id
        unpublished = (self.blocks[eligible].height
                       - self.blocks[self.last_published_private_tip].height)
        observed_work = self.blocks[self.public_q_tip].chainwork
        eligible_work = self.blocks[eligible].chainwork
        threshold = case.private_release_work_lead * work(self.initial_target)
        timed_out = (case.private_release_max_wait_seconds is not None
                     and self.private_wait_started is not None
                     and self.now - self.private_wait_started >= case.private_release_max_wait_seconds)
        release = unpublished > 0 and (timed_out or (
            unpublished >= case.private_release_min_blocks and eligible_work - observed_work >= threshold))
        self._emit("adaptive-release-check", reason=reason, public_tip=self.public_q_tip,
                   private_tip=self.private_tip, eligible_tip=eligible,
                   observed_public_work=str(observed_work), eligible_private_work=str(eligible_work),
                   required_lead=str(threshold), unpublished_blocks=unpublished,
                   timed_out=timed_out, release=release)
        if release:
            self._publish("q", eligible)
            self.last_published_private_tip = eligible
            self.adaptive_releases += 1
            self.private_wait_started = None if eligible == self.private_tip else self.now
            self.adaptive_next_check = None
        if first_future is not None:
            self._schedule_adaptive_check(float(self.blocks[first_future].timestamp - 120 - self.start_timestamp))
        if self.private_wait_started is not None and case.private_release_max_wait_seconds is not None:
            self._schedule_adaptive_check(self.private_wait_started + case.private_release_max_wait_seconds)

    def private_step(self) -> int:
        count = self.counts["q"]["blocks_created"]
        for phase in self.case.private_timestamp_schedule:
            if count < phase.blocks:
                return phase.step_seconds
            count -= phase.blocks
        return self.case.private_timestamp_step

    def _iterations(self, target: int) -> int:
        if self.case.quantum_fixed_iterations is not None:
            return self.case.quantum_fixed_iterations
        if self.case.quantum_trial_policy == "bounded-throughput":
            # Deliberately no DomainTemplate or sampled marked count is used.
            key = (target, self.quantum_factor)
            if key not in self.iteration_choices:
                case = self.case
                costs = TrialCosts(case.quantum_prepare_seconds, self._quantum_iteration_seconds(),
                                   case.quantum_measure_seconds, case.quantum_candidate_check_seconds,
                                   case.quantum_proof_seconds, case.quantum_domain_setup_seconds,
                                   case.quantum_clock_rounding)
                self.iteration_choices[key] = bounded_throughput_choice(
                    probability(target), case.quantum_iteration_candidates, case.quantum_processors,
                    costs, finite_domain_size=case.quantum_domain_size)
            choice = self.iteration_choices[key]
            self._emit("quantum-trial-policy", **asdict(choice))
            return choice.iterations
        theta = math.asin(math.sqrt(float(probability(target))))
        peak = math.pi / (4 * theta) - 0.5
        return min(self.case.quantum_max_iterations, max(0, int(round(peak))))

    def _quantum_iteration_seconds(self) -> float:
        if self.case.quantum_clock_rounding == "upward":
            return upward_float(Fraction.from_float(float(self.case.quantum_iteration_seconds))
                                / Fraction.from_float(float(self.quantum_factor)))
        return self.case.quantum_iteration_seconds / self.quantum_factor

    def _domain_template(self, parent: str, timestamp: int, target: int,
                         contains_probe: bool) -> tuple[DomainTemplate, float]:
        case, current = self.case, self.quantum_domain
        refresh = case.quantum_domain_trials_before_refresh
        if (current is not None and current.parent == parent and current.target == target
                and (not refresh or current.completed_batches < refresh)):
            return current, upward_float(current.setup_remaining_seconds)
        self.domain_count += 1
        identity = [self.profile, parent, timestamp, target, contains_probe, self.domain_count]
        domain_id = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
        marked = case.quantum_domain_marked_count
        if marked is None:
            marked = sample_marked_count(self.domain_rng, case.quantum_domain_size, target)
        current = DomainTemplate(
            domain_id, parent, timestamp, target, contains_probe, marked,
            setup_remaining_seconds=Fraction.from_float(float(case.quantum_domain_setup_seconds)))
        self.quantum_domain = current
        self.zero_marked_domains += int(marked == 0)
        self._emit("quantum-domain", domain_id=domain_id, domain_number=self.domain_count,
                   parent=parent, timestamp=timestamp, target_hex=f"{target:064x}", contains_probe=contains_probe,
                   size=case.quantum_domain_size, marked_count=marked,
                   marked_count_source="sampled-binomial" if case.quantum_domain_marked_count is None else "caller-conditioned",
                   marked_count_available_to_policy=False, setup_seconds=case.quantum_domain_setup_seconds)
        return current, case.quantum_domain_setup_seconds

    def _start_miner(self, miner: str) -> None:
        if miner in self.active or miner in self.proofs or self.finished:
            return
        case = self.case
        parent_id = self.private_tip if miner == "q" and case.quantum_strategy == "private-branch" else self.views[miner].tip
        parent = self.blocks[parent_id]
        target = self.target_for(parent_id)
        p = float(probability(target))
        mtp = sorted(h.timestamp for h in self.tails[parent_id][-11:])[5]
        stamp = max(self.start_timestamp + int(self.now), mtp + 1)
        if miner == "q" and case.quantum_timestamp_mode == "compressed":
            stamp = parent.timestamp + self.private_step()
        elif miner == "q" and case.quantum_timestamp_mode == "mtp-min":
            stamp = mtp + 1
        elif miner == "q" and case.quantum_timestamp_mode in ("future-bound", "retarget-extremes"):
            future = max(mtp + 1, self.start_timestamp + int(self.now) + 120)
            stamp = (mtp + 1 if case.quantum_timestamp_mode == "retarget-extremes"
                     and (parent.height + 1) % 16 else future)
        contains_probe = self.now >= case.probe_arrival_seconds and not self._probe(parent_id)[0]
        if miner == "q" and case.quantum_strategy == "private-branch" and case.private_censors_probe:
            contains_probe = False
        iterations, qrate, itime, setup, domain_id = 0, 0.0, 0.0, 0.0, None
        if miner == "q":
            if self.quantum_factor == 0:
                return
            if case.quantum_domain_size is not None:
                domain, setup = self._domain_template(parent_id, stamp, target, contains_probe)
                stamp, contains_probe, domain_id = domain.timestamp, domain.contains_probe, domain.domain_id
            iterations = self._iterations(target)
            itime = self._quantum_iteration_seconds()
            if case.quantum_clock_rounding == "upward":
                elapsed = TrialCosts(case.quantum_prepare_seconds, itime, case.quantum_measure_seconds,
                                     case.quantum_candidate_check_seconds, case.quantum_proof_seconds,
                                     setup, "upward").measured_batch_seconds(iterations)
            else:
                elapsed = (case.quantum_prepare_seconds + iterations * itime
                           + case.quantum_measure_seconds + case.quantum_candidate_check_seconds)
                if setup:
                    elapsed += setup
            success = (grover_success(p, iterations, case.quantum_processors) if domain_id is None else
                       finite_domain_success(case.quantum_domain_size, domain.marked_count,
                                             iterations, case.quantum_processors))
        else:
            share = case.classical_shares[self.classical_miners.index(miner)]
            qrate = case.classical_block_rate_at_initial_target * share * self.classical_factor / self.base_probability
            if qrate == 0:
                return
            elapsed = self.rngs[miner].expovariate(qrate * p)
            success = 1.0
        self.trial_serial += 1
        finishes = self.now + elapsed
        if miner == "q" and case.quantum_clock_rounding == "upward":
            finishes = upward_float(Fraction.from_float(float(self.now)) + Fraction.from_float(elapsed))
        trial = Trial(self.trial_serial, miner, parent_id, stamp, target, contains_probe,
                      self.now, finishes, iterations, success, qrate, itime, setup, domain_id)
        self.active[miner] = trial
        self.counts[miner]["searches_started"] += 1
        self._schedule(trial.finishes, "search", (miner, trial.serial))
        additional = {"domain_id": domain_id, "domain_setup_seconds": setup} if domain_id is not None else {}
        if miner == "q" and case.quantum_clock_rounding == "upward":
            additional.update(clock_rounding="upward", duration_seconds_upper=elapsed,
                              iteration_seconds_upper=itime)
        self._emit("search-start", miner=miner, trial=trial.serial, parent=parent_id,
                   target_hex=f"{target:064x}", timestamp=stamp, iterations=iterations,
                   success_probability=success, scheduled_finish_seconds=trial.finishes, **additional)

    def _charge_search(self, trial: Trial, status: str) -> None:
        counts = self.counts[trial.miner]
        elapsed = max(0.0, min(self.now, trial.finishes) - trial.started)
        counts["search_seconds"] += elapsed
        counts["classical_query_equivalents"] += elapsed * trial.query_rate
        logical = 0
        if trial.miner == "q":
            exact_elapsed = max(Fraction(0),
                                Fraction.from_float(float(min(self.now, trial.finishes)))
                                - Fraction.from_float(float(trial.started)))
            setup_elapsed = min(exact_elapsed, Fraction.from_float(float(trial.domain_setup_seconds)))
            self.domain_setup_seconds_charged += float(setup_elapsed)
            if trial.domain_id is not None:
                domain = self.quantum_domain
                if domain is None or domain.domain_id != trial.domain_id:
                    raise ValueError("ACTIVE_DOMAIN_MISMATCH")
                domain.setup_remaining_seconds = max(Fraction(0), domain.setup_remaining_seconds - setup_elapsed)
            if self.case.quantum_clock_rounding == "upward":
                exact_prepare = (Fraction.from_float(float(self.case.quantum_prepare_seconds))
                                 + Fraction.from_float(float(trial.domain_setup_seconds)))
                logical = min(trial.iterations, max(0, (exact_elapsed - exact_prepare)
                              // Fraction.from_float(trial.iteration_seconds)))
            else:
                logical = min(trial.iterations, max(0, int(math.floor(
                    (elapsed - (self.case.quantum_prepare_seconds + trial.domain_setup_seconds))
                    / trial.iteration_seconds + 1e-9))))
            logical *= self.case.quantum_processors
            counts["logical_iterations_completed"] += logical
            if self.case.quantum_clock_rounding == "upward":
                # Use the same exact stage boundaries as the resource-derived
                # search clock. Nearest-rounded sums can invent a candidate
                # check before readout ends, or omit one already in progress.
                exact_check_start = (exact_prepare
                                     + trial.iterations * Fraction.from_float(trial.iteration_seconds)
                                     + Fraction.from_float(float(self.case.quantum_measure_seconds)))
                exact_checked = min(Fraction.from_float(float(self.case.quantum_candidate_check_seconds)),
                                    max(Fraction(0), exact_elapsed - exact_check_start))
                checked_seconds = float(exact_checked)
                if self.case.quantum_tip_policy == "measure-on-tip":
                    measure_seconds = Fraction.from_float(float(self.case.quantum_measure_seconds))
                    measured = float(min(measure_seconds, max(
                        Fraction(0), exact_elapsed - (exact_check_start - measure_seconds))))
                    counts["measurement_seconds"] += measured
                    counts["measurement_processor_seconds"] += measured * self.case.quantum_processors
            else:
                check_starts_after = (self.case.quantum_prepare_seconds + trial.domain_setup_seconds
                                      + trial.iterations * trial.iteration_seconds
                                      + self.case.quantum_measure_seconds)
                checked_seconds = min(self.case.quantum_candidate_check_seconds,
                                      max(0, elapsed - check_starts_after))
            if checked_seconds > 0 or status in ("won", "failed"):
                counts["candidate_checks_started"] += self.case.quantum_processors
                if status in ("won", "failed"):
                    counts["candidate_checks_completed"] += self.case.quantum_processors
                    checked_seconds = self.case.quantum_candidate_check_seconds
                elif status in ("cancelled", "censored"):
                    counts["candidate_checks_" + status] += self.case.quantum_processors
            counts["candidate_check_seconds"] += checked_seconds
            counts["candidate_check_processor_seconds"] += checked_seconds * self.case.quantum_processors
        if status in ("failed", "cancelled"):
            counts["wasted_search_seconds"] += elapsed
            counts["wasted_logical_iterations"] += logical
        if status == "censored":
            counts["censored_search_seconds"] += elapsed
        self._emit("search-" + status, miner=trial.miner, trial=trial.serial,
                   elapsed_seconds=elapsed, logical_iterations=logical)

    def _cancel(self, miner: str, reason: str) -> None:
        trial = self.active.pop(miner, None)
        if trial is None:
            return
        self.counts[miner]["searches_cancelled"] += 1
        self.counts[miner]["cancelled_on_" + reason] += 1
        self._charge_search(trial, "cancelled")

    def _search_done(self, miner: str, serial: int) -> None:
        trial = self.active.get(miner)
        if trial is None or trial.serial != serial:
            self.obsolete_events += 1
            return
        del self.active[miner]
        self.counts[miner]["searches_completed"] += 1
        if trial.domain_id is not None:
            if self.quantum_domain is None or self.quantum_domain.domain_id != trial.domain_id:
                raise ValueError("ACTIVE_DOMAIN_MISMATCH")
            self.quantum_domain.completed_batches += 1
        won = miner != "q" or self.rngs[miner].random() < trial.success_probability
        if not won:
            self.counts[miner]["searches_failed"] += 1
            self._charge_search(trial, "failed")
            self._start_miner(miner)
            return
        self._charge_search(trial, "won")
        duration = self.case.quantum_proof_seconds if miner == "q" else self.case.classical_proof_seconds
        finish = self.now + duration
        if miner == "q" and self.case.quantum_clock_rounding == "upward":
            finish = upward_float(Fraction.from_float(float(self.now)) + Fraction.from_float(float(duration)))
        self.proof_completed.discard(miner)
        self.proofs[miner] = (trial, self.now, finish)
        self.counts[miner]["proofs_started"] += 1
        self._schedule(finish, "proof", miner)
        self._emit("proof-start", miner=miner, trial=serial, proof_seconds=duration)

    def _proof_done(self, miner: str) -> None:
        trial, started, finished = self.proofs[miner]
        self.counts[miner]["proofs_completed"] += 1
        self.proof_completed.add(miner)
        self.counts[miner]["proof_seconds"] += finished - started
        if miner == "q" and self.case.quantum_strategy == "private-branch":
            self._ready(miner)
            return
        ready = max(self.now, float(trial.timestamp - 120 - self.start_timestamp))
        self.counts[miner]["future_timestamp_wait_scheduled_seconds"] += ready - self.now
        if ready > self.now:
            self._schedule(ready, "ready", miner)
        else:
            self._ready(miner)

    def _publish(self, miner: str, block_id: str) -> None:
        self._emit("publish", miner=miner, tip=block_id)
        for recipient in self.views:
            if recipient != miner:
                self._schedule(self.now + self.case.propagation_seconds,
                               "delivery", (recipient, block_id))

    def _ready(self, miner: str) -> None:
        trial, _, proof_finished = self.proofs[miner]
        parent = self.blocks[trial.parent]
        block = Block(f"b{len(self.blocks):06d}", trial.parent, parent.height + 1,
                      trial.timestamp, trial.target,
                      checked_chainwork(parent.chainwork, work(trial.target)),
                      self.profile, miner, trial.contains_probe)
        state = self.validate_block(block)
        self.register_block(block)
        self.counts[miner]["future_timestamp_wait_seconds"] += max(0, self.now - proof_finished)
        if miner == "q" and self.case.quantum_strategy == "private-branch" and state == "deferred-future":
            self.counts[miner]["private_future_blocks_created"] += 1
        del self.proofs[miner]
        self.proof_completed.discard(miner)
        self.counts[miner]["blocks_created"] += 1
        self.counts[miner]["stale_proofs_completed"] += int(
            not (miner == "q" and self.case.quantum_strategy == "private-branch")
            and self.views[miner].tip != trial.parent)
        self._emit("block", block=block.block_id, parent=block.parent, height=block.height,
                   miner=miner, timestamp=block.timestamp, target_hex=f"{block.target:064x}",
                   required_work=str(work(block.target)), chainwork=str(block.chainwork),
                   profile=block.profile, contains_probe=block.contains_probe,
                   private_builder=(miner == "q" and self.case.quantum_strategy == "private-branch"),
                   future_at_creation=state == "deferred-future")
        private = miner == "q" and self.case.quantum_strategy == "private-branch"
        if private:
            self.private_tip = block.block_id
            if self.private_wait_started is None:
                self.private_wait_started = self.now
        self.receive(miner, block.block_id, from_network=False)
        if not private or self.released:
            self._publish(miner, block.block_id)
        if private:
            self._maybe_adaptive_release("private-block")
        self._start_miner(miner)

    def _shock(self, shock: ParticipationShock) -> None:
        old_c, old_q = self.classical_factor, self.quantum_factor
        self.classical_factor, self.quantum_factor = shock.classical_factor, shock.quantum_factor
        self._emit("shock", classical_factor=shock.classical_factor, quantum_factor=shock.quantum_factor)
        for miner in self.miners:
            changed = old_q != shock.quantum_factor if miner == "q" else old_c != shock.classical_factor
            if changed:
                self._cancel(miner, "shock")
                self._start_miner(miner)

    def start(self) -> None:
        if self.started:
            return
        self.started = True
        for shock in self.case.shocks:
            self._schedule(float(shock.at_seconds), "shock", shock)
        if self.case.private_release_seconds is not None:
            self._schedule(float(self.case.private_release_seconds), "release", None)
        self._schedule(float(self.case.probe_arrival_seconds), "probe", None)
        for miner in self.miners:
            self._start_miner(miner)

    def step(self) -> bool:
        if self.finished or self.stop_reason or not self.events:
            return False
        if self.events_processed >= self.case.max_events:
            self.stop_reason = "event-limit"
            return False
        if self.events[0][0] > self.case.duration_seconds:
            return False
        at, _, kind, payload = heapq.heappop(self.events)
        self.now = at
        self.events_processed += 1
        if kind == "search":
            self._search_done(*payload)
        elif kind == "proof":
            self._proof_done(payload)
        elif kind == "ready":
            self._ready(payload)
        elif kind == "delivery":
            self.receive(*payload)
        elif kind == "deferred":
            tips = self.deferred.pop(payload, [])
            for tip in tips:
                self.receive(payload[0], tip, from_network=False)
        elif kind == "shock":
            self._shock(payload)
        elif kind == "release":
            self.released = True
            self._publish("q", self.private_tip)
        elif kind == "adaptive-check":
            if self.adaptive_next_check == self.now:
                self.adaptive_next_check = None
                self._maybe_adaptive_release("local-timer")
            else:
                self.obsolete_events += 1
        elif kind == "probe":
            self._emit("probe-arrival")
        else:
            raise ValueError("EVENT_KIND")
        return True

    def run(self) -> tuple[dict, list[dict]]:
        if self.finished:
            raise ValueError("SIMULATION_ALREADY_FINISHED")
        cpu_start = time.process_time()
        try:
            self.start()
            while self.step():
                if time.process_time() - cpu_start >= self.case.cpu_limit_seconds:
                    self.stop_reason = "cpu-limit"
                    break
        except SimulationLimit as error:
            self.stop_reason = str(error)
        if self.stop_reason is None:
            self.now = float(self.case.duration_seconds)
            self.stop_reason = "horizon"
        for miner, trial in list(self.active.items()):
            self.counts[miner]["searches_censored"] += 1
            self._charge_search(trial, "censored")
        for miner, (trial, started, finished) in self.proofs.items():
            if miner not in self.proof_completed:
                self.counts[miner]["proofs_censored"] += 1
                self.counts[miner]["proof_seconds"] += max(0, min(self.now, finished) - started)
            else:
                self.counts[miner]["future_waits_censored"] += 1
                self.counts[miner]["future_timestamp_wait_seconds"] += max(0, self.now - finished)
        self.finished = True
        tip = self.views["observer"].tip
        chain = self.path(tip)
        included, depth, work_delta, work_minimum = self._probe(tip)
        honest = sum(self.blocks[b].miner != "q" or self.case.quantum_strategy == "honest-tip" for b in chain)
        summary = {
            "name": self.case.name, "seed": self.case.seed, "profile_digest": self.profile,
            "termination": self.stop_reason, "observation_seconds": self.now,
            "events_processed": self.events_processed, "events_unobserved": len(self.events),
            "future_bundles_unobserved": sum(len(tips) for tips in self.deferred.values()),
            "obsolete_events_skipped": self.obsolete_events, "trace_rows": len(self.trace),
            "trace_limit_reached": self.trace_limit_reached,
            "blocks_created": len(self.blocks) - 1, "observer_tip": tip,
            "observer_added_blocks": len(chain),
            "observer_added_chainwork": str(self.blocks[tip].chainwork - self.base.chainwork),
            "observer_reorgs": self.observer_reorgs,
            "observer_max_reorg_depth": self.observer_max_reorg_depth,
            "observer_reorg_beyond_confirmation_depth": self.observer_prefix_violations,
            "pairwise_prefix_samples": self.prefix_samples,
            "pairwise_prefix_disagreements_below_common_height_minus_k": self.prefix_disagreements,
            "empirical_chain_growth_blocks_per_second": len(chain) / self.now if self.now else None,
            "empirical_honest_block_fraction": honest / len(chain) if chain else None,
            "probe": {
                "arrival_observed": self.now >= self.case.probe_arrival_seconds,
                "currently_included": included, "current_depth": depth,
                "currently_confirmed": (included and depth >= self.case.confirmation_depth
                                        and work_delta >= work_minimum),
                "descendant_work": str(work_delta), "required_descendant_work": str(work_minimum),
                "confirmation_depth": self.case.confirmation_depth,
                "confirmation_work_multiplier": self.case.confirmation_work_multiplier,
                "first_inclusion_seconds": self.probe_first_inclusion,
                "first_confirmation_seconds": self.probe_first_confirmation,
                "confirmation_reversals": self.probe_confirmation_reversals,
                "right_censored_wait_seconds": (max(0, self.now - self.case.probe_arrival_seconds)
                    if self.now >= self.case.probe_arrival_seconds and not self.probe_confirmed else None),
            },
            "miners": self.counts,
            "security_theorem": False, "native_w1_verified": False,
            "quantum_hardware_executed": False, "production_consensus_activation": False,
            "release_ready": False,
        }
        if (self.case.quantum_trial_policy != "first-peak" or self.case.quantum_domain_size is not None
                or self.case.private_release_policy != "scheduled"
                or self.case.quantum_timestamp_mode not in ("wall", "compressed")):
            summary["adversarial"] = {
                "assumptions": ADVERSARIAL_ASSUMPTIONS,
                "domains_created": self.domain_count,
                "zero_marked_domains": self.zero_marked_domains,
                "domain_setup_seconds_charged": self.domain_setup_seconds_charged,
                "domain_setup_processor_seconds_charged": self.domain_setup_seconds_charged * self.case.quantum_processors,
                "adaptive_releases": self.adaptive_releases,
                "quantum_observed_public_tip": self.public_q_tip,
                "quantum_last_published_private_tip": self.last_published_private_tip,
                "iteration_candidates_are_global_optimum": False,
            }
        return summary, self.trace


def run_network_scenario(case: NetworkScenario) -> tuple[dict, list[dict]]:
    return Simulator(case).run()


def standard_network_scenarios() -> list[NetworkScenario]:
    from dataclasses import replace
    base = NetworkScenario("periodic_honest_grover", seed=4101)
    private = replace(base, name="periodic_private_grover", quantum_strategy="private-branch",
                      quantum_timestamp_mode="compressed", private_release_seconds=900)
    shock = (ParticipationShock(300, 0.1, 1), ParticipationShock(600, 2, 0.25),
             ParticipationShock(900, 1, 1))
    return [base,
            replace(base, name="classical_control", quantum_initial_factor=0),
            private,
            replace(private, name="private_fast_oracle_sensitivity", quantum_iteration_seconds=0.01),
            replace(base, name="periodic_participation_shocks", shocks=shock),
            replace(base, name="long_proof_and_network_delay", quantum_proof_seconds=20,
                    classical_proof_seconds=5, propagation_seconds=8),
            replace(private, name="asert_raw_private", policy="asert-raw"),
            replace(private, name="asert_mtp_private", policy="asert-mtp11"),
            replace(base, name="fixed_round_overshoot_sensitivity", quantum_fixed_iterations=540,
                    classical_block_rate_at_initial_target=0),
            replace(private, name="private_timestamp_phases_sensitivity", duration_seconds=3600,
                    quantum_iteration_seconds=0.01, private_release_seconds=3000,
                    private_timestamp_schedule=(TimestampPhase(32, 5), TimestampPhase(16, 10),
                                                TimestampPhase(96, 20)),
                    private_timestamp_step=10, max_events=60000, max_trace_rows=200000,
                    cpu_limit_seconds=30)]
