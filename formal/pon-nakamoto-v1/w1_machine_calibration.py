"""Finite calibration evidence for a source-bound W1 machine allocation.

The existing architecture manifest checks provenance, not numerical claims.
This companion checks complete event samples, units, epochs and confidence
accounting. It computes conservative finite-sample bounds using exact rational
arithmetic. An iid Bernoulli observation does not establish a fault bound
conditional on arbitrary execution history. All physical qualification claims
therefore remain false, even when a numerical comparison passes.

For zero observed faults, m = ceil(log2(1/alpha)) gives p <= m/n with
confidence at least 1-alpha: (1-p)**n <= exp(-n*p) < 2**(-m) <= alpha.
For other counts use Hoeffding with radius sqrt(m/(2*n)), rounded upwards.
The requirement that samples are independent and stationary is an explicit,
unverified sampling premise, never inferred from the bytes of a ledger.
"""
from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from math import isqrt
from pathlib import Path
import re

from w1_machine_architecture import (
    CALIBRATION_REQUIREMENTS, SOURCES as ARCHITECTURE_SOURCES,
    verify_service_architecture,
)
from w1_quantum_oracle import canonical

SCHEMA = "trnm-w1-finite-calibration-gap-review-v1"
SAMPLE_SCHEMA = "trnm-w1-physical-event-samples-v1"
SAMPLING_PREMISE = "predeclared-independent-stationary-bernoulli-trials-v1"
ROOT = Path(__file__).resolve().parents[2]
SOURCES = ARCHITECTURE_SOURCES + ("formal/pon-nakamoto-v1/w1_machine_calibration.py",)
MAX_SAMPLE_BYTES = 8 * 1024 * 1024
MAX_SAMPLE_ROWS = 65536
MAX_INTEGER = (1 << 256) - 1
COMPONENTS = {
    "initialization": ("initialization_patches", "initialized-patch", "physical-quantum"),
    "readout": ("readout_bits", "measured-bit", "physical-quantum"),
    "transfer": ("transfer_bytes", "transferred-byte", "physical-controller"),
    "controller": ("controller_commands", "controller-command", "physical-controller"),
    "accepted_magic_state_service": ("magic_state_services", "accepted-magic-state-service", "physical-quantum"),
    "factory_attempts_exhausted": ("magic_state_services", "complete-finite-factory-service", "physical-quantum"),
    "host_calls": ("host_calls_including_reserved_proofs", "complete-host-call-including-proofs", "physical-classical"),
    "propagation": ("propagations", "complete-propagation", "physical-network"),
    "live_data_patch_cycles": (None, "live-data-patch-code-cycle", "physical-quantum"),
}


def _integer(value, code, lower=0, upper=MAX_INTEGER):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError(code)
    return value


def _sha(value, code="CALIBRATION_SHA256"):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(code)
    return value


def _label(value, code):
    if type(value) is not str or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
        raise ValueError(code)
    return value


def _ratio(value):
    return {"numerator": value.numerator, "denominator": value.denominator}


def _fraction(value, code, *, probability=False):
    if type(value) is not dict or set(value) != {"numerator", "denominator"}:
        raise ValueError(code)
    # Outward probability arithmetic deliberately uses denominators wider
    # than event-count integers. Do not truncate a tiny positive fault bound.
    numerator, denominator = value["numerator"], value["denominator"]
    if (type(numerator) is not int or type(denominator) is not int
            or numerator < 0 or denominator < 1
            or numerator.bit_length() > 8192 or denominator.bit_length() > 8192):
        raise ValueError(code)
    result = Fraction(numerator, denominator)
    if probability and not 0 < result < 1:
        raise ValueError(code)
    return result


def _hash(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def _sources():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def strict_load(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_SAMPLE_BYTES:
        raise ValueError("CALIBRATION_SAMPLE_BYTES")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("CALIBRATION_DUPLICATE_JSON_KEY")
            result[key] = value
        return result

    def forbidden(_):
        raise ValueError("CALIBRATION_NONINTEGER_JSON_NUMBER")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=forbidden,
                          parse_constant=forbidden)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise ValueError("CALIBRATION_JSON") from error


def confidence_power(alpha):
    """Smallest m with 2**(-m) <= alpha; no floating point logarithm."""
    if type(alpha) is not Fraction or not 0 < alpha < 1:
        raise ValueError("CALIBRATION_CONFIDENCE")
    if alpha.numerator.bit_length() > 256 or alpha.denominator.bit_length() > 256:
        raise ValueError("CALIBRATION_CONFIDENCE_SIZE")
    m = 0
    while alpha.numerator * (1 << m) < alpha.denominator:
        m += 1
    return m


def _sqrt_upper(value, bits=96):
    scale = 1 << bits
    numerator = value.numerator * scale * scale
    root = isqrt(numerator // value.denominator)
    if root * root * value.denominator < numerator:
        root += 1
    return Fraction(root, scale)


def finite_failure_upper(trials, faults, alpha):
    """Conservative conditional iid confidence bound; never zero for finite n."""
    _integer(trials, "CALIBRATION_TRIALS", 1)
    _integer(faults, "CALIBRATION_FAULTS", 0, trials)
    m = confidence_power(alpha)
    if faults == 0:
        return min(Fraction(1), Fraction(m, trials))
    return min(Fraction(1), Fraction(faults, trials) + _sqrt_upper(Fraction(m, 2 * trials)))


def zero_fault_sample_requirement(rate, alpha):
    """Necessary finite-n lower bound and a sufficient n for our chosen bound.

    For 0 < rate < 1, Bernoulli's inequality gives (1-rate)**n >= 1-n*rate. No
    direct zero-fault iid tail inversion can exclude that rate at tail alpha unless
    n >= ceil((1-alpha)/rate). This necessary bound is not claimed sharp.
    A zero target rate needs a non-statistical argument, regardless of n.
    """
    if type(rate) is not Fraction or not 0 <= rate <= 1:
        raise ValueError("CALIBRATION_TARGET_RATE")
    m = confidence_power(alpha)
    if rate == 0:
        return {"necessary_trials_lower_bound": None,
                "sufficient_trials_for_this_bound": None,
                "zero_target_requires_nonstatistical_argument": True}
    if rate == 1:
        # Probability <= 1 is a tautology, with no sampling requirement.
        return {"necessary_trials_lower_bound": 0,
                "sufficient_trials_for_this_bound": 0,
                "zero_target_requires_nonstatistical_argument": False}

    def ceiling(value):
        return (value.numerator + value.denominator - 1) // value.denominator

    return {"necessary_trials_lower_bound": ceiling((1 - alpha) / rate),
            "sufficient_trials_for_this_bound": ceiling(Fraction(m) / rate),
            "zero_target_requires_nonstatistical_argument": False}


def _sample_summary(raw, component, target_binding, hardware_id, hardware_epoch,
                    instrument_sha256, now, maximum_age):
    sample = strict_load(raw)
    keys = {"schema", "target_binding_sha256", "hardware_id", "hardware_epoch",
            "instrument_sha256", "component", "unit", "execution_kind", "sampling_premise",
            "started_at_unix_seconds", "finished_at_unix_seconds", "valid_until_unix_seconds",
            "predeclared_trials", "clock_threshold_ns", "rows"}
    if type(sample) is not dict or set(sample) != keys or sample["schema"] != SAMPLE_SCHEMA:
        raise ValueError("CALIBRATION_SAMPLE_SCHEMA")
    if (_sha(sample["target_binding_sha256"]) != target_binding
            or sample["hardware_id"] != hardware_id or sample["hardware_epoch"] != hardware_epoch
            or _sha(sample["instrument_sha256"]) != instrument_sha256):
        raise ValueError("CALIBRATION_SAMPLE_IDENTITY")
    if sample["component"] != component or sample["unit"] != COMPONENTS[component][1]:
        raise ValueError("CALIBRATION_EVENT_UNIT_OR_SCOPE")
    if sample["execution_kind"] != COMPONENTS[component][2]:
        raise ValueError("CALIBRATION_PHYSICAL_EVENT_KIND")
    if sample["sampling_premise"] != SAMPLING_PREMISE:
        raise ValueError("CALIBRATION_SAMPLING_PREMISE")
    begin, end, expiry = (sample[k] for k in ("started_at_unix_seconds", "finished_at_unix_seconds",
                                            "valid_until_unix_seconds"))
    for number in (begin, end, expiry):
        _integer(number, "CALIBRATION_SAMPLE_TIME", 0, (1 << 63) - 1)
    if not begin <= end <= now <= expiry or now - begin > maximum_age:
        raise ValueError("CALIBRATION_STALE_FUTURE_OR_EXPIRED")
    n = _integer(sample["predeclared_trials"], "CALIBRATION_DECLARED_TRIALS", 1, MAX_SAMPLE_ROWS)
    threshold = _integer(sample["clock_threshold_ns"], "CALIBRATION_MEASUREMENT_CLOCK", 1)
    rows = sample["rows"]
    if type(rows) is not list or len(rows) != n:
        raise ValueError("CALIBRATION_MISSING_ATTEMPTS")
    identities, durations, faults, incomplete, overruns = set(), [], 0, 0, 0
    for index, row in enumerate(rows):
        if type(row) is not dict or set(row) != {"index", "event_id", "fault", "completed", "duration_ns"}:
            raise ValueError("CALIBRATION_SAMPLE_ROW")
        if type(row["index"]) is not int or row["index"] != index:
            raise ValueError("CALIBRATION_SAMPLE_ORDER")
        event_id = _label(row["event_id"], "CALIBRATION_EVENT_ID")
        if event_id in identities:
            raise ValueError("CALIBRATION_REUSED_SAMPLE")
        identities.add(event_id)
        if type(row["fault"]) is not bool or type(row["completed"]) is not bool:
            raise ValueError("CALIBRATION_SAMPLE_OUTCOME")
        duration = _integer(row["duration_ns"], "CALIBRATION_DURATION")
        durations.append(duration)
        incomplete += int(not row["completed"])
        overruns += int(duration > threshold)
        faults += int(row["fault"] or not row["completed"] or duration > threshold)
    return {"artifact_sha256": hashlib.sha256(raw).hexdigest(), "artifact_bytes": len(raw),
            "trials": n, "faults_including_incomplete_and_clock_overruns": faults,
            "incomplete_attempts": incomplete, "clock_overruns": overruns,
            "duration_ns_sum": sum(durations), "duration_ns_maximum_observed": max(durations),
            "measurement_clock_threshold_ns": threshold,
            "measurement_threshold_is_matched_execution_clock": False,
            "sample_maximum_is_runtime_upper_bound": False}


def review_machine_calibration(report, domains, observations, *, hardware_id, hardware_epoch,
                               instrument_sha256, now_unix_seconds, maximum_age_seconds):
    """Replay the allocation and account for every active event class.

    ``observations`` maps component names to immutable complete JSON bytes.
    Missing observations receive worst-case unit fault probability, never zero.
    The caller pins the external device, epoch and measurement instrument; the
    reader cannot authenticate physical execution or establish transfer from
    iid calibration trials to arbitrary histories. No document can turn those
    limitations into qualification through a boolean claim.
    """
    sources = _sources()
    report = verify_service_architecture(report, domains)
    if type(observations) is not dict or any(key not in COMPONENTS for key in observations):
        raise ValueError("CALIBRATION_COMPONENT_SET")
    if any(type(value) is not bytes for value in observations.values()):
        raise ValueError("CALIBRATION_SAMPLE_BYTES")
    if sum(map(len, observations.values())) > 16 * 1024 * 1024:
        raise ValueError("CALIBRATION_TOTAL_SAMPLE_BYTES")
    _label(hardware_id, "CALIBRATION_HARDWARE_ID")
    _label(hardware_epoch, "CALIBRATION_HARDWARE_EPOCH")
    _sha(instrument_sha256)
    _integer(now_unix_seconds, "CALIBRATION_NOW", 0, (1 << 63) - 1)
    _integer(maximum_age_seconds, "CALIBRATION_MAXIMUM_AGE", 1, 366 * 24 * 3600)
    machine = report["machine_record"]
    envelope = machine["envelope"]
    event_counts = envelope["events_all_processors"]
    counts = {name: (envelope["live_data_patch_cycles_all_processors"] if data[0] is None
                     else event_counts[data[0]]) for name, data in COMPONENTS.items()}
    budget = Fraction(envelope["unchanged_declared_failure_budget"])
    active = sum(count > 0 for count in counts.values())
    if active == 0:
        raise ValueError("CALIBRATION_EMPTY_MACHINE")
    # Half of the original failure budget is set aside for calibration error.
    # No caller may loosen the original machine budget to make this pass.
    alpha = budget / (2 * active)
    confidence_power(alpha)
    entries, execution_sum, confidence_sum, missing = [], Fraction(0), Fraction(0), []
    for component, (_, unit, kind) in COMPONENTS.items():
        count = counts[component]
        contribution = _fraction(envelope["failure_union_components_upper"][component],
                                 "CALIBRATION_MACHINE_COMPONENT")
        rate = contribution / count if count else Fraction(0)
        row = {"component": component, "event_unit": unit, "required_execution_kind": kind,
               "reserved_events": count, "declared_fault_upper_per_event": _ratio(rate),
               "declared_failure_contribution": _ratio(contribution),
               "confidence_failure_allocation": _ratio(alpha if count else Fraction(0)),
               "zero_fault_sample_requirement": zero_fault_sample_requirement(rate, alpha) if count else None}
        raw = observations.get(component)
        if raw is not None:
            sample = _sample_summary(raw, component, report["calibration_binding_sha256"],
                hardware_id, hardware_epoch, instrument_sha256, now_unix_seconds, maximum_age_seconds)
            upper = finite_failure_upper(sample["trials"],
                sample["faults_including_incomplete_and_clock_overruns"], alpha)
            row.update(status="FINITE_SAMPLES_CHECKED_CONDITIONALLY", observation=sample,
                       finite_sample_fault_upper=_ratio(upper), declared_rate_supported_numerically=upper <= rate)
            if count:
                confidence_sum += alpha
        elif count:
            upper = Fraction(1)
            row.update(status="MISSING_PHYSICAL_EVENT_SAMPLES", finite_sample_fault_upper=None,
                       declared_rate_supported_numerically=False)
            missing.append(component)
        else:
            upper = Fraction(0)
            row.update(status="NO_EVENTS_IN_THIS_ALLOCATION", finite_sample_fault_upper=None,
                       declared_rate_supported_numerically=None)
        execution_sum += count * upper
        row["fault_union_contribution_if_transfer_premises_hold"] = _ratio(count * upper)
        entries.append(row)
    risk = min(Fraction(1), execution_sum + confidence_sum)
    result = {
        "schema": SCHEMA, "status": "HOLD",
        "source_sha256": sources, "architecture_record_sha256": report["record_sha256"],
        "target_binding_sha256": report["calibration_binding_sha256"],
        "hardware_id": hardware_id, "hardware_epoch": hardware_epoch,
        "instrument_sha256": instrument_sha256, "checked_at_unix_seconds": now_unix_seconds,
        "maximum_age_seconds": maximum_age_seconds, "components": entries,
        "missing_active_event_components": missing,
        "original_machine_failure_budget": _ratio(budget),
        "calibration_confidence_failure_union": _ratio(confidence_sum),
        "execution_fault_union_uncapped_if_transfer_premises_hold": _ratio(execution_sum),
        "combined_risk_upper_if_sampling_and_transfer_premises_hold": _ratio(risk),
        "numerical_budget_comparison_passes": not missing and risk <= budget,
        "remaining_external_coverage": list(CALIBRATION_REQUIREMENTS),
        "limitations": [
            "iid Bernoulli sampling and a predeclared stopping rule are unverified premises",
            "direct logical-event sampling is not the only possible calibration method; verified error-correction transformations could use measured physical rates, but none are supplied here",
            "no transfer to history-conditional execution faults or ideal-trace coupling is proved",
            "measurement thresholds are not certified per-event execution-clock contracts",
            "hashes and metadata bind bytes; physical authenticity and clock truth remain external",
            "compiled layout, controller memory, complete energy and capital costs remain unmeasured",
        ],
        "claims": {"zero_observed_faults_imply_zero_risk": False,
                   "sampling_independence_established": False,
                   "history_conditional_fault_coupling_established": False,
                   "physical_artifact_authenticity_verified": False,
                   "physical_parameters_calibrated": False,
                   "complete_machine_cost_closed": False,
                   "quantum_hardware_executed_by_reader": False,
                   "quantum_mining_qualified": False, "production_activation": False},
    }
    if _sources() != sources:
        raise ValueError("CALIBRATION_SOURCE_CHANGED")
    result["record_sha256"] = _hash(result)
    return result


def verify_machine_calibration(record, architecture, domains, observations):
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("CALIBRATION_REVIEW_SCHEMA")
    rebuilt = review_machine_calibration(architecture, domains, observations,
        hardware_id=record["hardware_id"], hardware_epoch=record["hardware_epoch"],
        instrument_sha256=record["instrument_sha256"],
        now_unix_seconds=record["checked_at_unix_seconds"],
        maximum_age_seconds=record["maximum_age_seconds"])
    if canonical(record) != canonical(rebuilt):
        raise ValueError("CALIBRATION_REVIEW_REPLAY_MISMATCH")
    return rebuilt
