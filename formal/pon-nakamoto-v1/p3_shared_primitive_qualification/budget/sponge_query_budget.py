#!/usr/bin/env python3
"""Exact conditional arithmetic for arXiv:2609.28469v1, Theorem 5.5.

This is not a proof or a security certificate for a concrete permutation,
Merkle commitment, transcript, or protocol. All admitted results keep
``qualified`` false. Runtime: Python 3.10+, standard library only.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import json
from pathlib import Path
import re
import sys
from typing import Any


SCHEMA = "p3.sponge.query_budget.v1"
RESULT_SCHEMA = "p3.sponge.query_budget.result.v1"
SOURCE_URL = "https://arxiv.org/html/2609.28469v1"
DEFAULT_PARAMETERS = {"rate_bits": 576, "capacity_bits": 1024, "digest_bits": 512}
REQUIRED_ROLES = frozenset({"leaf", "branch", "transcript", "other"})
PHASES = ("precomputation", "online")
DIRECTIONS = ("forward", "inverse")
COVERAGE = (
    "all_roles_and_unlisted_uses",
    "all_forward_and_inverse_calls",
    "all_precomputation",
    "failed_aborted_offline_and_cross_session",
    "all_permutation_dependent_side_information",
)

# Local input limits, not cryptographic assumptions. They also bound the size
# of the exact decimal output and keep malformed CLI requests inexpensive.
MAX_INPUT_BYTES = 128 * 1024
MAX_STATE_BITS = 4096
MAX_COUNT_BITS = 2048
MAX_ROLES = 64
ROLE_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
DECIMAL_COUNT = re.compile(r"(?:0|[1-9][0-9]*)\Z")


class Unsupported(ValueError):
    def __init__(self, code: str, path: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.path = path
        self.message = message


def _reject(code: str, path: str, message: str) -> None:
    raise Unsupported(code, path, message)


def _object(
    value: Any,
    path: str,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        _reject("INVALID_OBJECT", path, "A plain JSON object is required.")
    if any(type(key) is not str for key in value):
        _reject("INVALID_KEY", path, "All object keys must be strings.")
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        _reject("MISSING_FIELD", path, "Missing required field(s): " + ", ".join(sorted(missing)))
    if unknown:
        _reject("UNKNOWN_FIELD", path, "Unknown fields are not interpreted or ignored.")
    return value


def _expect(value: Any, expected: Any, path: str) -> None:
    if type(value) is not type(expected) or value != expected:
        _reject("UNSUPPORTED_ASSUMPTION", path, "Required explicit assumption: " + repr(expected))


def _count(value: Any, path: str, minimum: int = 0) -> int:
    # Canonical decimal strings prevent loss when a caller uses a JSON runtime
    # whose numeric representation cannot hold integers beyond 2**53 exactly.
    if type(value) is str:
        if len(value) > 620 or DECIMAL_COUNT.fullmatch(value) is None:
            _reject("INVALID_INTEGER", path, "Use a nonnegative integer or canonical decimal string.")
        number = int(value)
    elif type(value) is int:
        number = value
    else:
        _reject("INVALID_INTEGER", path, "Floats, booleans, null and noncanonical integers are unsupported.")
    if number < minimum:
        _reject("INVALID_INTEGER", path, f"The integer must be at least {minimum}.")
    if number.bit_length() > MAX_COUNT_BITS:
        _reject("INPUT_LIMIT", path, "Integer exceeds this calculator's local input limit.")
    return number


def _parameter(value: Any, path: str) -> int:
    if type(value) is not int or not 1 <= value <= MAX_STATE_BITS:
        _reject("INVALID_PARAMETER", path, "A positive integer of at most 4096 bits of state is required.")
    return value


def _fraction(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def _unsupported(error: Unsupported) -> dict[str, Any]:
    return {
        "schema": RESULT_SCHEMA,
        "status": "unsupported",
        "qualified": False,
        "reason": {"code": error.code, "path": error.path, "message": error.message},
    }


def _terms(kind: str, total: int, digest_bits: int, capacity_bits: int, state_bits: int) -> dict[str, Fraction]:
    # Equations (94) and (95), not the square-root bounds (92) and (93).
    digest = (64 * total**2) if kind == "preimage" else (32 * total**3)
    return {
        "digest": Fraction(digest, 1 << digest_bits),
        "capacity": Fraction(128 * total**3, 1 << capacity_bits),
        "permutation_simulation": Fraction(32768 * total**2, 1 << state_bits),
    }


def evaluate(request: Any) -> dict[str, Any]:
    """Return exact conditional bounds, or an unsupported result with no bounds.

    Coverage and independence declarations are user assumptions, not verified
    properties. An observed honest-process ledger is deliberately unsupported.
    """
    try:
        return _evaluate(request)
    except Unsupported as error:
        return _unsupported(error)


def _evaluate(request: Any) -> dict[str, Any]:
    request = _object(
        request, "$",
        {"schema", "claim", "construction", "queries", "initial_state", "candidate_outputs", "targets"},
        {"parameters"},
    )
    _expect(request["schema"], SCHEMA, "$.schema")
    _expect(request["claim"], "sponge_preimage_and_collision_only", "$.claim")

    parameters = _object(
        request.get("parameters", DEFAULT_PARAMETERS), "$.parameters",
        {"rate_bits", "capacity_bits", "digest_bits"},
    )
    r = _parameter(parameters["rate_bits"], "$.parameters.rate_bits")
    c = _parameter(parameters["capacity_bits"], "$.parameters.capacity_bits")
    d = _parameter(parameters["digest_bits"], "$.parameters.digest_bits")
    b = r + c
    if b > MAX_STATE_BITS:
        _reject("INPUT_LIMIT", "$.parameters", "The local state-width limit is 4096 bits.")
    if d > r:
        _reject("DIGEST_EXCEEDS_RATE", "$.parameters.digest_bits", "Theorem 5.5 requires 1 <= d <= r.")

    construction = _object(
        request["construction"], "$.construction",
        {"model", "sponge_mode", "message_encoding", "padding", "padded_messages_nonempty", "output"},
    )
    assumptions = {
        "model": "uniform_random_bitstring_permutation",
        "sponge_mode": "fixed_output_sponge",
        "message_encoding": "injective",
        "padding": "injective",
        "padded_messages_nonempty": True,
        "output": "first_d_bits_of_first_squeeze_block",
    }
    for key, expected in assumptions.items():
        _expect(construction[key], expected, "$.construction." + key)

    initial = _object(
        request["initial_state"], "$.initial_state",
        {"at_start_of_counted_lifetime", "construction_dependent_advice", "later_permutation_dependent_state"},
    )
    _expect(initial["at_start_of_counted_lifetime"], "permutation_independent", "$.initial_state.at_start_of_counted_lifetime")
    _expect(initial["construction_dependent_advice"], "none", "$.initial_state.construction_dependent_advice")
    _expect(initial["later_permutation_dependent_state"], "only_from_counted_queries", "$.initial_state.later_permutation_dependent_state")

    queries = _object(
        request["queries"], "$.queries", {"basis", "scope", "unit", "coverage", "by_role"}
    )
    _expect(queries["basis"], "hypothetical_adversary_upper_bound", "$.queries.basis")
    _expect(queries["scope"], "entire_shared_primitive_lifetime", "$.queries.scope")
    unit = queries["unit"]
    if type(unit) is not str or unit not in {"swap", "standard_xor"}:
        _reject("UNSUPPORTED_QUERY_UNIT", "$.queries.unit", "Only swap and standard_xor permutation-query units are supported.")
    coverage = _object(queries["coverage"], "$.queries.coverage", set(COVERAGE))
    for key in COVERAGE:
        _expect(coverage[key], True, "$.queries.coverage." + key)

    # These are conservative accounting buckets, not observables. A coherent
    # query may span several domains: allocate it to "other", or count it
    # repeatedly as an upper bound. The single shared q is what the bound uses.
    roles = queries["by_role"]
    if type(roles) is not dict or not REQUIRED_ROLES <= roles.keys():
        _reject("MISSING_ROLES", "$.queries.by_role", "Explicit leaf, branch, transcript and other buckets are required, including zeros.")
    if len(roles) > MAX_ROLES:
        _reject("INPUT_LIMIT", "$.queries.by_role", "There may be at most 64 role buckets.")
    if any(type(role) is not str or ROLE_NAME.fullmatch(role) is None for role in roles):
        _reject("INVALID_ROLE", "$.queries.by_role", "Role names must be short lowercase identifiers.")

    q = 0
    phase_totals = {phase: 0 for phase in PHASES}
    direction_totals = {direction: 0 for direction in DIRECTIONS}
    role_totals = {}
    for role, entry in sorted(roles.items()):
        path = "$.queries.by_role." + role
        entry = _object(entry, path, set(PHASES))
        role_total = 0
        for phase in PHASES:
            phase_entry = _object(entry[phase], path + "." + phase, set(DIRECTIONS))
            for direction in DIRECTIONS:
                count = _count(phase_entry[direction], path + "." + phase + "." + direction)
                q += count
                role_total += count
                phase_totals[phase] += count
                direction_totals[direction] += count
        role_totals[role] = role_total

    # Section 5 before Lemma 5.1 explicitly gives a 2-swap simulation of one
    # standard XOR query. Only q is converted; the theorem's 2L is already swap.
    factor = 1 if unit == "swap" else 2
    q_swap = factor * q

    outputs = _object(
        request["candidate_outputs"], "$.candidate_outputs",
        {"preimage_total_padded_blocks_bound", "collision_pair_total_padded_blocks_bound"},
    )
    l_pre = _count(outputs["preimage_total_padded_blocks_bound"], "$.candidate_outputs.preimage_total_padded_blocks_bound", 1)
    # This supported interface requires nonempty padding for every message;
    # the collision bound covers the SUM for both candidate messages.
    l_col = _count(outputs["collision_pair_total_padded_blocks_bound"], "$.candidate_outputs.collision_pair_total_padded_blocks_bound", 2)

    targets = _object(request["targets"], "$.targets", {"fixed_preimage_target_count", "selection", "budget_per_event"})
    target_count = _count(targets["fixed_preimage_target_count"], "$.targets.fixed_preimage_target_count", 1)
    _expect(targets["selection"], "fixed_independently_of_permutation", "$.targets.selection")
    _expect(targets["budget_per_event"], "same_entire_lifetime_q", "$.targets.budget_per_event")

    totals = {"preimage": q_swap + 2 * l_pre, "collision": q_swap + 2 * l_col}
    n = 1 << b
    for kind, total in totals.items():
        # The integer inequality is exactly T <= 2**(b/2)/4, including odd b.
        if not 1 <= total or 16 * total * total > n:
            _reject("OUTSIDE_SIMPLIFIED_BOUND_DOMAIN", "$.candidate_outputs." + kind,
                    "Equations (94)/(95) require 1 <= T and 16*T*T <= 2**(r+c).")
        if 3 * total - 1 > n:
            _reject("OUTSIDE_THEOREM_DOMAIN", "$.candidate_outputs." + kind,
                    "Theorem 5.5 requires 3*T - 1 <= 2**(r+c).")

    bounds = {}
    for kind, total in totals.items():
        terms = _terms(kind, total, d, c, b)
        raw = sum(terms.values(), Fraction(0))
        entry = {
            "equation": "94" if kind == "preimage" else "95",
            "total_padded_blocks_bound": str(l_pre if kind == "preimage" else l_col),
            "T_swap_queries": str(total),
            "terms": {name: _fraction(value) for name, value in terms.items()},
            "unclipped_upper_bound": _fraction(raw),
            "upper_bound": _fraction(min(Fraction(1), raw)),
        }
        if kind == "preimage":
            union_raw = target_count * raw
            entry["fixed_target_union"] = {
                "target_count": str(target_count),
                "same_entire_lifetime_q_for_each_event": True,
                "unclipped_upper_bound": _fraction(union_raw),
                "upper_bound": _fraction(min(Fraction(1), union_raw)),
            }
        bounds[kind] = entry

    return {
        "schema": RESULT_SCHEMA,
        "status": "conditional_model_only",
        "qualified": False,
        "assumption_status": "caller_assertions_not_verified",
        "claim": request["claim"],
        "model": construction["model"],
        "source": {"url": SOURCE_URL, "theorem": "5.5", "equations": ["94", "95"], "query_convention": "Section 5 opening paragraph"},
        "parameters": {"rate_bits": r, "capacity_bits": c, "digest_bits": d, "state_bits": b},
        "query_accounting": {
            "scope": queries["scope"],
            "input_unit": unit,
            "input_queries_total": str(q),
            "swap_conversion_factor": factor,
            "q_swap_upper_bound": str(q_swap),
            "input_queries_by_phase": {key: str(value) for key, value in phase_totals.items()},
            "input_queries_by_direction": {key: str(value) for key, value in direction_totals.items()},
            "input_queries_by_role": {key: str(value) for key, value in role_totals.items()},
            "honest_measurements_are_not_adversary_upper_bounds": True,
        },
        "bounds": bounds,
        "not_established": [
            "Concrete Keccak or Poseidon2 behaves as a uniform random permutation.",
            "The asserted adversary lifetime query bound holds in a deployed system.",
            "Free construction-dependent classical or quantum advice is covered.",
            "Merkle binding, multi-stage Fiat-Shamir, extraction or recursive W1 security.",
            "A physical work lower bound, security-bit qualification or protocol admission.",
        ],
    }


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            _reject("DUPLICATE_JSON_KEY", "$", "Duplicate JSON keys are unsupported.")
        result[key] = value
    return result


def _noninteger_json(_: str) -> None:
    _reject("NONINTEGER_JSON_NUMBER", "$", "JSON floating-point and non-finite numbers are unsupported.")


def evaluate_json(data: bytes) -> dict[str, Any]:
    """Parse bounded UTF-8 JSON without duplicate keys or floating numbers."""
    try:
        if len(data) > MAX_INPUT_BYTES:
            _reject("INPUT_LIMIT", "$", "JSON input exceeds 128 KiB.")
        request = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_float=_noninteger_json, parse_constant=_noninteger_json,
        )
    except Unsupported as error:
        return _unsupported(error)
    except (UnicodeError, ValueError, RecursionError):
        return _unsupported(Unsupported("INVALID_JSON", "$", "Input must be bounded, well-formed UTF-8 JSON."))
    return evaluate(request)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", nargs="?", default="-", help="UTF-8 JSON file, or - for stdin")
    args = parser.parse_args(argv)
    try:
        if args.request == "-":
            data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        else:
            with Path(args.request).open("rb") as handle:
                data = handle.read(MAX_INPUT_BYTES + 1)
        result = evaluate_json(data)
    except OSError:
        result = _unsupported(Unsupported("INPUT_IO", "$", "Input file could not be read."))
    print(json.dumps(result, ensure_ascii=True, indent=2, sort_keys=True))
    return 0 if result["status"] == "conditional_model_only" else 2


if __name__ == "__main__":
    raise SystemExit(main())
