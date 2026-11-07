"""Finite-horizon search over independently replayed, literal W1 nonce domains.

The schedule is fixed before the evaluator reads the marked sets. All processors
search the same domain; a restricted oracle uses its own subset of winners.
After measurement the full legal predicate is checked, so a legal winner that
the restricted phase oracle did not mark can still produce a valid proof.
Every started phase is paid, including partial iterations and classical checks.
A sampled nonce is not a completed proof or a natively admitted block.

Clocks are explicit assumptions. This module executes scalar census replay and
samples the ideal search model, never a quantum machine. A separate construction
binding may supply clocks derived from real circuit counts and hypothetical
physical parameters. It does not turn them into hardware measurements.
"""
from __future__ import annotations

from dataclasses import asdict
from decimal import Decimal, InvalidOperation
from fractions import Fraction
import hashlib
import math
import random

from quantum_adversarial_search import TrialCosts, batch_success, sample_binary_probability
from w1_marked_domain import (
    MAX_DOMAINS, MAX_ITERATIONS, MAX_PROCESSORS, MAX_TRIALS, replay_domain,
)
from w1_quantum_oracle import canonical

SCHEMA = "trnm-w1-bounded-literal-search-v1"
PREDICATES = ("full", "prefix-restricted")
PHASES = ("domain_setup", "prepare", "iterations", "measurement",
          "candidate_checks", "proof", "propagation")


def ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def integer(value, name, maximum, minimum=0):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(name)
    return value


def horizon(value):
    """Exact user-declared decimal deadline, not a nearest binary64 clock."""
    if type(value) is not str or not 1 <= len(value) <= 100:
        raise ValueError("SEARCH_HORIZON")
    try:
        number = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("SEARCH_HORIZON") from error
    if (not number.is_finite() or not 0 <= number <= Decimal("1e30")
            or (number and number.adjusted() < -100)):
        raise ValueError("SEARCH_HORIZON")
    return Fraction(number)


def simulate_bounded_measurements(domains, schedule, processors, seed, costs,
                                  horizon_seconds, *, predicate="full",
                                  propagation_seconds=None):
    """Pay a predeclared schedule until delivery, exhaustion or an exact horizon.

    ``costs`` contains one TrialCosts per domain. Setup is paid on first use or
    after replacing the single resident template. Every batch has new coherent
    preparation and readout. All P candidates are checked serially, even when
    an early candidate wins. At most one proof and delivery is produced.

    No measurement is sampled before readout completes. Only completed checks
    reveal winner flags; an unfinished proof or propagation earns no success.
    Completion exactly at the deadline is allowed. Source-bound census replay
    is observer work outside these assumed mining clocks, not free miner advice.
    """
    limit = horizon(horizon_seconds)
    if type(predicate) is not str or predicate not in PREDICATES:
        raise ValueError("SEARCH_PREDICATE")
    if type(domains) is not tuple or not 1 <= len(domains) <= MAX_DOMAINS:
        raise ValueError("SEARCH_DOMAINS")
    if type(schedule) is not tuple or not 1 <= len(schedule) <= MAX_TRIALS:
        raise ValueError("SEARCH_SCHEDULE")
    integer(processors, "SEARCH_PROCESSORS", MAX_PROCESSORS, 1)
    integer(seed, "SEARCH_SEED", (1 << 64) - 1)
    if (type(costs) is not tuple or len(costs) != len(domains)
            or any(type(item) is not TrialCosts for item in costs)):
        raise ValueError("SEARCH_COSTS")
    for item in costs:
        item.validate()
    for entry in schedule:
        if type(entry) is not tuple or len(entry) != 2:
            raise ValueError("SEARCH_SCHEDULE_ENTRY")
        integer(entry[0], "SEARCH_DOMAIN_INDEX", len(domains) - 1)
        integer(entry[1], "SEARCH_ITERATIONS", MAX_ITERATIONS)
    if propagation_seconds is None:
        propagation_seconds = (0,) * len(domains)
    if type(propagation_seconds) is not tuple or len(propagation_seconds) != len(domains):
        raise ValueError("SEARCH_PROPAGATION")
    for value in propagation_seconds:
        if (type(value) not in (int, float) or not math.isfinite(value)
                or not 0 <= value <= 1e40):
            raise ValueError("SEARCH_PROPAGATION")

    # Recompute complete scalar relations before trusting any membership or hash.
    # These observer censuses are never passed to a strategy or used to retune q.
    checked = tuple(replay_domain(record) for record in domains)
    numbers = tuple({name: Fraction(value) for name, value in asdict(item).items()
                     if name != "clock_rounding"} for item in costs)
    propagation = tuple(Fraction(value) for value in propagation_seconds)
    rng = random.Random(seed)
    elapsed = Fraction(0)
    phase_totals = {name: Fraction(0) for name in PHASES}
    processor_time = Fraction(0)
    resident = None
    trials = []
    setup_charges = completed_checks = iterations_completed = 0
    delivered = False

    for index, (domain_index, iterations) in enumerate(schedule):
        if elapsed >= limit:
            break
        domain, clock = checked[domain_index], numbers[domain_index]
        marked = [row["nonce"] for row in domain["outcomes"]
                  if row["winner"] and (predicate == "full" or row["prefix_all_accepted"])]
        marked_set = set(marked)
        legal_count = domain["marked_count"]
        unmarked = [nonce for nonce in range(domain["domain_size"]) if nonce not in marked_set]
        setup = resident != domain["domain_sha256"]
        setup_charges += int(setup)
        start = elapsed
        phases = []
        trial = {
            "schedule_index": index, "domain_index": domain_index,
            "domain_sha256": domain["domain_sha256"], "predicate": predicate,
            "planned_iterations": iterations, "evaluator_marked_count": len(marked),
            "evaluator_legal_winner_count": legal_count,
            "domain_size": domain["domain_size"], "domain_setup_charged": setup,
            "started_seconds_exact": ratio(start), "phases": phases,
            "grover_iterations_completed_per_processor": 0,
            "partial_iteration_seconds_exact": ratio(Fraction(0)),
            "measurement_complete": False, "measurements": [],
            "candidate_checks_completed": 0,
            "partial_candidate_check_seconds_exact": ratio(Fraction(0)),
            "verified_winner_observed": False, "proof_complete": False,
            "propagation_complete": False, "success": False,
            "censored_phase": None,
        }

        def pay(name, planned):
            nonlocal elapsed, processor_time
            paid = min(planned, limit - elapsed)
            elapsed += paid
            phase_totals[name] += paid
            if name in ("prepare", "iterations", "measurement"):
                processor_time += processors * paid
            complete = paid == planned
            phases.append({"phase": name, "planned_seconds_exact": ratio(planned),
                           "paid_seconds_exact": ratio(paid), "complete": complete})
            if not complete:
                trial["censored_phase"] = name
            return complete, paid

        complete, _ = pay("domain_setup", int(setup) * clock["domain_setup_seconds"])
        if complete:
            resident = domain["domain_sha256"]
            complete, _ = pay("prepare", clock["prepare_seconds"])
        if complete:
            complete, paid = pay("iterations", iterations * clock["iteration_seconds"])
            finished, partial = divmod(paid, clock["iteration_seconds"])
            trial["grover_iterations_completed_per_processor"] = finished
            trial["partial_iteration_seconds_exact"] = ratio(partial)
            iterations_completed += processors * finished
        if complete:
            complete, _ = pay("measurement", clock["measurement_seconds"])
            trial["measurement_complete"] = complete
        if complete:
            probability = batch_success(len(marked) / domain["domain_size"], iterations)
            sampled = []
            for _ in range(processors):
                hit = sample_binary_probability(rng, probability)
                nonce = rng.choice(marked if hit else unmarked)
                sampled.append({"nonce": nonce, "candidate_check_completed": False,
                                "winner": None})
            trial["measurements"] = sampled
            trial["conditional_batch_phase_mark_probability"] = batch_success(
                len(marked) / domain["domain_size"], iterations, processors)
            # Grover gives a uniform amplitude within each of the marked and
            # unmarked sets. The latter may contain other perfectly legal W1
            # winners. Discarding them would understate this legal strategy.
            phase_probability = Fraction(probability)
            valid_probability = (phase_probability if len(marked) == domain["domain_size"] else
                                 phase_probability + (1 - phase_probability)
                                 * Fraction(legal_count - len(marked), domain["domain_size"] - len(marked)))
            trial["conditional_batch_valid_candidate_probability"] = float(
                1 - (1 - valid_probability) ** processors)
            complete, paid = pay("candidate_checks", processors * clock["candidate_check_seconds"])
            finished, partial = divmod(paid, clock["candidate_check_seconds"])
            trial["candidate_checks_completed"] = finished
            trial["partial_candidate_check_seconds_exact"] = ratio(partial)
            completed_checks += finished
            for measurement in sampled[:finished]:
                measurement["candidate_check_completed"] = True
                measurement["winner"] = domain["outcomes"][measurement["nonce"]]["winner"]
            trial["verified_winner_observed"] = any(row["winner"] is True for row in sampled)
        if complete and trial["verified_winner_observed"]:
            complete, _ = pay("proof", clock["proof_seconds"])
            trial["proof_complete"] = complete
            if complete:
                complete, _ = pay("propagation", propagation[domain_index])
                trial["propagation_complete"] = complete
                trial["success"] = complete
                delivered = complete
        trial["paid_seconds_exact"] = ratio(elapsed - start)
        trial["finished_seconds_exact"] = ratio(elapsed)
        trials.append(trial)
        if delivered or not complete:
            break

    termination = ("delivered" if delivered else
                   "horizon" if elapsed == limit else "schedule-exhausted")
    plan = {
        "domain_sha256": [record["domain_sha256"] for record in checked],
        "schedule": [list(entry) for entry in schedule], "predicate": predicate,
        "processors": processors, "seed": seed, "horizon_seconds": horizon_seconds,
        "costs": [asdict(item) for item in costs],
        "propagation_seconds": list(propagation_seconds),
    }
    return {
        "schema": SCHEMA, "plan": plan,
        "plan_sha256": hashlib.sha256(canonical(plan)).hexdigest(),
        "termination": termination, "success": delivered, "trials": trials,
        "trials_started": len(trials), "unstarted_predeclared_trials": len(schedule) - len(trials),
        "domain_setup_charges": setup_charges,
        "completed_measurement_batches": sum(row["measurement_complete"] for row in trials),
        "candidate_checks_completed": completed_checks,
        "grover_iterations_completed_all_processors": iterations_completed,
        "elapsed_seconds_exact": ratio(elapsed), "unused_horizon_seconds_exact": ratio(limit - elapsed),
        "phase_paid_seconds_exact": {name: ratio(value) for name, value in phase_totals.items()},
        "quantum_processor_seconds_exact": ratio(processor_time),
        "quantum_processor_clock_scope": "preparation, iterations and reset/readout; all P processors",
        "template_setup_policy": "single-resident-template; fixed inputs must be available before setup",
        "candidate_check_policy": "all P candidates serially checked before any proof",
        "candidate_predicate": "full legal W1 winner, including legal unmarked candidates",
        "measurement_sampler": "exact-dyadic-Bernoulli-of-computed-binary64-probability",
        "strategy_reads_marked_count": False,
        "schedule_precommitment_externally_attested": False,
        "success_probabilities_use_actual_predicate_marked_set": True,
        "partial_iteration_time_is_not_partial_gate_execution": True,
        "proof_completion_scope": "completion of assumed proof clock; scalar proof checks are offline observer work",
        "online_proofs_generated": 0,
        "census_is_offline_observer_work": True, "independent_ticket_prior_used": False,
        "quantum_hardware_executed": False, "physical_clock_calibrated": False,
        "native_blocks_admitted": 0, "consensus_security_theorem": False,
        "attacker_optimality_proved": False, "production_consensus_activation": False,
    }
