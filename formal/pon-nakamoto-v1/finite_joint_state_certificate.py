"""FJS1: exact finite cq initial-state domination, not physical attestation.

The complete Bernoulli oracle law and every conditional advice density matrix
are explicit inputs.  Exact rational PSD checks prove rho_f <= lambda*sigma
+ Delta_f in that declared model.  The same CPTP computation then transfers an
independent-state probability bound as lambda*B + sum_f pi_f*Tr(Delta_f).

This does not certify that a real worker has the supplied complete joint state,
that all future correlated help is mediated, or that SHA/Poseidon is an ideal
oracle.  No native scoring, signed byte domain, or production gate is changed.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
from datetime import datetime, timezone
from fractions import Fraction as F
import hashlib
import json
from math import comb, gcd, prod
from pathlib import Path
import re
from typing import Any

from mandatory_units_query import bernoulli_bounds


CERTIFICATE_SCHEMA = "pon-finite-cq-initial-state-certificate-v1"
REPORT_SCHEMA = "pon-finite-cq-initial-state-report-v1"
ORACLE_LAW = "complete-independent-bernoulli-truth-table-v1"
QUERY_INTERFACE = "coherent-mark-bit-xor-v1"
GLOBAL_SCOPE = "global-unconditioned-from-declared-complete-cq-state"
MAX_ADDRESSES = 8
MAX_DIMENSION = 16
MAX_REGISTERS = 8
MAX_BIT_QUERIES = 4096
MAX_OUTPUTS = 64
MAX_INPUT_BITS = 256
MAX_ARITHMETIC_BITS = 8192
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")

UNATTESTED = {
    "actual_initial_joint_state_attested": False,
    "actual_register_and_environment_coverage_attested": False,
    "all_future_oracle_correlated_channels_covered": False,
    "uniform_counterfactual_query_output_caps_attested": False,
    "actual_sha_or_poseidon_idealization_proved": False,
    "all_algorithm_physical_resource_loss_proved": False,
    "native_identity_and_weight_bridge_proved": False,
    "native_six_successor_risk_certified": False,
    "production_qualified": False,
}


class StateCertificateError(ValueError):
    pass


def need(condition: bool, code: str) -> None:
    if not condition:
        raise StateCertificateError(code)


def fields(value: Any, expected: set[str], code: str) -> dict:
    need(type(value) is dict and set(value) == expected, code)
    return value


def integer(value: Any, minimum: int, maximum: int, code: str) -> int:
    need(type(value) is int and minimum <= value <= maximum, code)
    return value


def rational(value: Any, code: str = "CANONICAL_RATIONAL") -> F:
    """Only reduced exact fractions; bools, floats and numeric strings refuse."""
    fields(value, {"numerator", "denominator"}, code)
    n, d = value["numerator"], value["denominator"]
    need(type(n) is int and type(d) is int and d > 0
         and n.bit_length() <= MAX_INPUT_BITS and d.bit_length() <= MAX_INPUT_BITS
         and gcd(n, d) == 1, code)
    return F(n, d)


def bounded(value: F) -> F:
    need(type(value) is F and value.numerator.bit_length() <= MAX_ARITHMETIC_BITS
         and value.denominator.bit_length() <= MAX_ARITHMETIC_BITS,
         "EXACT_ARITHMETIC_CHECK_LIMIT")
    return value


def rational_sum(values) -> F:
    result = F(0)
    for value in values:
        result = bounded(result + value)
    return result


def wire(value: Any) -> Any:
    if type(value) is F:
        return {"numerator": value.numerator, "denominator": value.denominator}
    if type(value) is dict:
        return {key: wire(item) for key, item in value.items()}
    if type(value) in (tuple, list):
        return [wire(item) for item in value]
    return value


def canonical(value: Any) -> bytes:
    try:
        return json.dumps(wire(value), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError, RecursionError) as error:
        raise StateCertificateError("CANONICAL_JSON") from error


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


Matrix = tuple[tuple[F, ...], ...]


def matrix(value: Any, dimension: int, code: str) -> Matrix:
    need(type(value) is list and len(value) == dimension
         and all(type(row) is list and len(row) == dimension for row in value),
         code + "_SHAPE")
    result = tuple(tuple(rational(item, code + "_ENTRY") for item in row) for row in value)
    need(all(result[i][j] == result[j][i]
             for i in range(dimension) for j in range(i)), code + "_SYMMETRY")
    return result


def psd_rank(value: Matrix, code: str = "MATRIX_PSD") -> int:
    """Exact Schur elimination, including singular and zero-pivot matrices.

    A zero diagonal in a PSD matrix forces its entire row to zero, by its
    2-by-2 principal minors.  For a strictly positive pivot, PSD is equivalent
    to PSD of the Schur complement.  No eigenvalue tolerance is used.
    """
    need(type(value) is tuple and 1 <= len(value) <= MAX_DIMENSION
         and all(type(row) is tuple and len(row) == len(value)
                 and all(type(entry) is F for entry in row) for row in value),
         code + "_SHAPE")
    n = len(value)
    need(all(value[i][j] == value[j][i] for i in range(n) for j in range(i)),
         code + "_SYMMETRY")
    a = [list(row) for row in value]
    rank = 0
    for k in range(n):
        pivot = bounded(a[k][k])
        need(pivot >= 0, code)
        if pivot == 0:
            need(all(a[k][j] == 0 for j in range(k + 1, n)), code)
            continue
        rank += 1
        for i in range(k + 1, n):
            for j in range(i, n):
                entry = bounded(a[i][j] - a[i][k] * a[k][j] / pivot)
                a[i][j] = a[j][i] = entry
    return rank


def trace(value: Matrix) -> F:
    return rational_sum(value[i][i] for i in range(len(value)))


def density(value: Matrix, code: str) -> int:
    rank = psd_rank(value, code + "_PSD")
    need(trace(value) == 1, code + "_TRACE")
    return rank


def bernoulli_tail(addresses: int, required: int, p: F) -> F:
    """Small complete finite law, used independently of the recording bound."""
    if required == 0:
        return F(1)
    if required > addresses:
        return F(0)
    return rational_sum(F(comb(addresses, j)) * p ** j * (1 - p) ** (addresses - j)
                        for j in range(required, addresses + 1))


def independent_search_bound(*, addresses: int, p: F, queries: int,
                             outputs: int, required: int) -> dict:
    """Uniform finite marked-list bound for oracle-independent initial advice.

    q counts coherent Bernoulli bit queries.  All computation and the final
    external test are free.  Actual online oracle-dependent feedback is not.
    This is not a full-value SHA query budget or an actual MU1/native score.
    """
    integer(addresses, 1, MAX_ADDRESSES, "ORACLE_ADDRESS_COUNT")
    need(type(p) is F and 0 < p < 1, "MARK_PROBABILITY")
    bounded(p)
    integer(queries, 0, MAX_BIT_QUERIES, "BIT_QUERY_CAP")
    integer(outputs, 0, MAX_OUTPUTS, "COMPLETE_OUTPUT_CAP")
    integer(required, 0, MAX_OUTPUTS, "REQUIRED_DISTINCT_MARKS")
    slots = min(outputs, addresses)
    existence = bernoulli_tail(addresses, required, p)
    structural = existence if required <= slots else F(0)
    if required == 0:
        candidate, kind = F(1), "zero-threshold"
    elif required > slots:
        candidate, kind = F(0), "impossible-output-capacity"
    elif queries == 0:
        candidate = bernoulli_tail(slots, required, p)
        kind = "exact-zero-query-independent-list"
    else:
        candidate = min(F(1), bounded(F(comb(slots, required))
                                     * bernoulli_bounds(queries, required, p)["bound"]))
        kind = "fixed-index-union-of-recording-bounds"
    return {
        "model": "finite-ideal-bernoulli-marked-list-independent-state-v1",
        "oracle_query_interface": QUERY_INTERFACE,
        "addresses": addresses, "mark_probability": p,
        "bit_queries": queries, "complete_outputs": outputs,
        "effective_distinct_output_slots": slots,
        "required_distinct_marked": required,
        "list_bound_method": kind, "list_bound": candidate,
        "oracle_existence_bound": existence,
        "structural_bound_for_any_initial_advice": structural,
        "bound": min(structural, candidate),
        "virtual_verification_queries_added": 0,
    }


def verify_certificate(document: Any) -> dict:
    """Recompute complete model coverage, PSD witnesses and the transferred bound.

    PASS proves facts about the entire supplied finite model, not the origin
    of the supplied state.  The API has no flag that can promote that origin.
    """
    fields(document, {"schema", "oracle", "advice_registers", "reference_state",
                      "multiplier", "excess_allowance", "tables", "search_contract"},
           "CERTIFICATE_FIELDS")
    need(document["schema"] == CERTIFICATE_SCHEMA, "CERTIFICATE_NAMESPACE")
    oracle = fields(document["oracle"], {"law", "addresses", "mark_probability"},
                    "ORACLE_FIELDS")
    need(oracle["law"] == ORACLE_LAW, "ORACLE_LAW_NAMESPACE")
    addresses = integer(oracle["addresses"], 1, MAX_ADDRESSES, "ORACLE_ADDRESS_COUNT")
    p = rational(oracle["mark_probability"], "MARK_PROBABILITY")
    need(0 < p < 1, "MARK_PROBABILITY")

    registers = document["advice_registers"]
    need(type(registers) is list and 1 <= len(registers) <= MAX_REGISTERS,
         "ADVICE_REGISTERS")
    names, dimensions = [], []
    for register in registers:
        fields(register, {"name", "dimension"}, "ADVICE_REGISTER_FIELDS")
        name = register["name"]
        need(type(name) is str and NAME.fullmatch(name) is not None and name not in names,
             "ADVICE_REGISTER_NAME")
        names.append(name)
        dimensions.append(integer(register["dimension"], 1, MAX_DIMENSION,
                                  "ADVICE_REGISTER_DIMENSION"))
    dimension = prod(dimensions)
    need(dimension <= MAX_DIMENSION, "JOINT_ADVICE_DIMENSION_LIMIT")
    sigma = matrix(document["reference_state"], dimension, "REFERENCE_STATE")
    sigma_rank = density(sigma, "REFERENCE_STATE")
    multiplier = rational(document["multiplier"], "MULTIPLIER")
    need(multiplier >= 1, "MULTIPLIER")
    allowance = rational(document["excess_allowance"], "EXCESS_ALLOWANCE")
    need(0 <= allowance <= 1, "EXCESS_ALLOWANCE")

    contract = fields(document["search_contract"], {
        "probability_scope", "oracle_query_interface", "bit_queries", "complete_outputs",
        "required_distinct_marked"}, "SEARCH_CONTRACT_FIELDS")
    need(contract["probability_scope"] == GLOBAL_SCOPE, "GLOBAL_SCOPE_REQUIRED")
    need(contract["oracle_query_interface"] == QUERY_INTERFACE, "QUERY_INTERFACE_NAMESPACE")
    fresh = independent_search_bound(addresses=addresses, p=p,
        queries=contract["bit_queries"], outputs=contract["complete_outputs"],
        required=contract["required_distinct_marked"])

    tables = document["tables"]
    need(type(tables) is list and len(tables) == 1 << addresses,
         "COMPLETE_ORACLE_TABLE_COVERAGE")
    epsilon = F(0)
    total_prior = F(0)
    checked = []
    for index, row in enumerate(tables):
        fields(row, {"index", "probability", "advice_state", "positive_excess"},
               "ORACLE_TABLE_FIELDS")
        need(type(row["index"]) is int and row["index"] == index,
             "CANONICAL_COMPLETE_TABLE_INDEX")
        mass = rational(row["probability"], "ORACLE_TABLE_PROBABILITY")
        ones = index.bit_count()
        expected_mass = bounded(p ** ones * (1 - p) ** (addresses - ones))
        need(mass == expected_mass, "COMPLETE_BERNOULLI_PRIOR_MISMATCH")
        total_prior = bounded(total_prior + mass)
        rho = matrix(row["advice_state"], dimension, "ADVICE_STATE")
        rho_rank = density(rho, "ADVICE_STATE")
        delta = matrix(row["positive_excess"], dimension, "POSITIVE_EXCESS")
        delta_rank = psd_rank(delta, "POSITIVE_EXCESS_PSD")
        slack = tuple(tuple(bounded(multiplier * sigma[i][j] + delta[i][j] - rho[i][j])
                            for j in range(dimension)) for i in range(dimension))
        slack_rank = psd_rank(slack, "JOINT_STATE_DOMINATION_PSD")
        delta_trace = trace(delta)
        epsilon = bounded(epsilon + mass * delta_trace)
        checked.append({"index": index, "prior_probability": mass,
                        "advice_rank": rho_rank, "positive_excess_rank": delta_rank,
                        "domination_slack_rank": slack_rank,
                        "positive_excess_trace": delta_trace})
    need(total_prior == 1, "COMPLETE_PRIOR_NORMALIZATION")
    need(epsilon <= allowance, "POSITIVE_EXCESS_ALLOWANCE_EXCEEDED")
    transferred = bounded(multiplier * fresh["bound"] + epsilon)
    result = min(F(1), fresh["structural_bound_for_any_initial_advice"], transferred)
    report = {
        "schema": REPORT_SCHEMA, "certificate_sha256": digest(document),
        "probability_scope": GLOBAL_SCOPE,
        "state_format": "complete-cq-law-with-real-rational-conditional-density-matrices-v1",
        "oracle_law": ORACLE_LAW, "oracle_addresses": addresses,
        "oracle_tables_checked": len(tables), "oracle_prior_recomputed": True,
        "joint_advice_dimension": dimension, "advice_registers": registers,
        "common_reference_state_sha256": digest(document["reference_state"]),
        "common_reference_state_rank": sigma_rank,
        "multiplier": multiplier, "declared_excess_allowance": allowance,
        "weighted_positive_excess_trace": epsilon,
        "domination_with_positive_excess_verified_in_declared_model": True,
        "exact_domination_without_excess": epsilon == 0,
        "checked_oracle_blocks": checked,
        "independent_reference_search_bound": fresh,
        "unclipped_transferred_bound": transferred,
        "bound": result,
        "bound_is_conditional_at_selected_start": False,
        "oracle_independence_of_actual_advice_claimed": False,
        **UNATTESTED,
    }
    # Detach the output from caller-owned lists and use one exact JSON shape.
    return json.loads(canonical(report))


def recheck_report(document: Any, report: Any) -> dict:
    """No report field, probability, status or source hash is trusted alone."""
    need(type(report) is dict, "REPORT_FIELDS")
    recomputed = verify_certificate(document)
    need(canonical(report) == canonical(recomputed), "REPORT_RECOMPUTATION_MISMATCH")
    return recomputed


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "DUPLICATE_JSON_KEY")
        result[key] = value
    return result


def read_json(path: Path) -> Any:
    need(path.is_file() and not path.is_symlink()
         and path.stat().st_size <= MAX_DOCUMENT_BYTES, "JSON_FILE")
    raw = path.read_bytes()
    need(len(raw) <= MAX_DOCUMENT_BYTES, "JSON_FILE_SIZE")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(
                              StateCertificateError("NONFINITE_JSON_NUMBER")))
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if type(error) is StateCertificateError:
            raise
        raise StateCertificateError("JSON_ENCODING") from error


def write_new(path: Path, value: Any) -> None:
    raw = canonical(value) + b"\n"
    with path.open("xb") as target:
        target.write(raw)


def diagonal(values: tuple[F, ...]) -> Matrix:
    return tuple(tuple(value if i == j else F(0) for j in range(len(values)))
                 for i, value in enumerate(values))


def basis_state(dimension: int, index: int) -> Matrix:
    return diagonal(tuple(F(int(i == index)) for i in range(dimension)))


def _example(*, addresses: int, p: F, sigma: Matrix, states: list[Matrix],
             multiplier: F, allowance: F = F(0), excesses: list[Matrix] | None = None,
             registers: list[dict] | None = None, queries: int = 0,
             outputs: int = 1, required: int = 1) -> dict:
    dimension = len(sigma)
    zero = diagonal((F(0),) * dimension)
    return wire({
        "schema": CERTIFICATE_SCHEMA,
        "oracle": {"law": ORACLE_LAW, "addresses": addresses, "mark_probability": p},
        "advice_registers": registers or [{"name": "complete_advice", "dimension": dimension}],
        "reference_state": sigma, "multiplier": multiplier, "excess_allowance": allowance,
        "tables": [{"index": index,
                    "probability": p ** index.bit_count() * (1 - p) ** (addresses - index.bit_count()),
                    "advice_state": states[index],
                    "positive_excess": excesses[index] if excesses is not None else zero}
                   for index in range(1 << addresses)],
        "search_contract": {"probability_scope": GLOBAL_SCOPE,
                            "oracle_query_interface": QUERY_INTERFACE,
                            "bit_queries": queries, "complete_outputs": outputs,
                            "required_distinct_marked": required},
    })


def example_certificates() -> dict[str, dict]:
    """Complete mathematical models; no native execution or quantum hardware."""
    p = F(1, 16)
    plus = ((F(1, 2), F(1, 2)), (F(1, 2), F(1, 2)))
    minus = ((F(1, 2), F(-1, 2)), (F(-1, 2), F(1, 2)))
    mixed2 = diagonal((F(1, 2),) * 2)
    independent = _example(addresses=4, p=p, sigma=plus, states=[plus] * 16,
                           multiplier=F(1))
    noise, dimension = F(1, 8), 4
    mixed4 = diagonal((F(1, dimension),) * dimension)
    noisy_states = []
    for table in range(16):
        first = next((i for i in range(4) if table & (1 << i)), 0)
        noisy_states.append(diagonal(tuple((1 - noise) / dimension + noise * int(i == first)
                                           for i in range(dimension))))
    noisy = _example(addresses=4, p=p, sigma=mixed4, states=noisy_states,
                     multiplier=1 + noise * (dimension - 1))
    coherent = _example(addresses=2, p=p, sigma=mixed2,
        states=[plus if table & 1 else minus for table in range(4)], multiplier=F(2))
    full_table = _example(addresses=4, p=p, sigma=diagonal((F(1, 16),) * 16),
        states=[basis_state(16, table) for table in range(16)], multiplier=F(16))
    zero2 = diagonal((F(0),) * 2)
    rare = _example(addresses=2, p=p, sigma=basis_state(2, 0),
        states=[basis_state(2, int(table == 2)) for table in range(4)], multiplier=F(1),
        allowance=p * (1 - p),
        excesses=[basis_state(2, 1) if table == 2 else zero2 for table in range(4)])
    return {"independent-singular": independent, "noisy-first-winner": noisy,
            "coherent-first-bit": coherent, "full-truth-table-advice": full_table,
            "rare-positive-excess": rare}


def _measurement_success(document: dict, measurement: tuple[Matrix, ...],
                         addresses_by_outcome: tuple[int, ...]) -> F:
    """Independent exact Born-rule witness for the zero-query examples only."""
    dimension = len(document["reference_state"])
    need(len(measurement) == len(addresses_by_outcome), "EXAMPLE_MEASUREMENT")
    for effect in measurement:
        psd_rank(effect, "EXAMPLE_MEASUREMENT_PSD")
    need(all(rational_sum(effect[i][j] for effect in measurement) == int(i == j)
             for i in range(dimension) for j in range(dimension)),
         "EXAMPLE_MEASUREMENT_NORMALIZATION")
    count = document["oracle"]["addresses"]
    need(all(type(a) is int and 0 <= a < count for a in addresses_by_outcome),
         "EXAMPLE_MEASUREMENT_ADDRESS")
    value = F(0)
    for row in document["tables"]:
        rho = matrix(row["advice_state"], dimension, "EXAMPLE_ADVICE")
        hit = rational_sum(
            rational_sum(effect[i][j] * rho[j][i] for i in range(dimension)
                         for j in range(dimension))
            for effect, address in zip(measurement, addresses_by_outcome)
            if row["index"] & (1 << address))
        need(0 <= hit <= 1, "EXAMPLE_MEASUREMENT_PROBABILITY")
        value = bounded(value + rational(row["probability"]) * hit)
    return value


def _source_paths() -> tuple[Path, ...]:
    here = Path(__file__).resolve().parent
    return (here / "finite_joint_state_certificate.py", here / "finite_joint_state_tests.py",
            here / "FINITE_JOINT_STATE_CERTIFICATE_V1.md", here / "mandatory_units_query.py")


def _source_bindings() -> list[dict]:
    return [{"path": "formal/pon-nakamoto-v1/" + path.name,
             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in _source_paths()]


def retain_evidence(directory: Path) -> dict:
    """Retain complete examples, recomputed reports and actual refusal codes."""
    directory.mkdir(parents=True, exist_ok=False)
    started = datetime.now(timezone.utc).isoformat()
    stage = "initializing"
    try:
        stage = "source-bindings-start"
        sources_at_start = _source_bindings()
        write_new(directory / "source-bindings-start.json", sources_at_start)
        models = example_certificates()
        plus = ((F(1, 2), F(1, 2)), (F(1, 2), F(1, 2)))
        minus = ((F(1, 2), F(-1, 2)), (F(-1, 2), F(1, 2)))
        measurements = {
            "noisy-first-winner": (tuple(basis_state(4, i) for i in range(4)), tuple(range(4))),
            "coherent-first-bit": ((plus, minus), (0, 1)),
            "full-truth-table-advice": (tuple(basis_state(16, i) for i in range(16)),
                tuple(next((i for i in range(4) if table & (1 << i)), 0) for table in range(16))),
            "rare-positive-excess": ((basis_state(2, 0), basis_state(2, 1)), (0, 1)),
        }
        outcomes = []
        for name, document in models.items():
            stage = name
            write_new(directory / (name + ".certificate.json"), document)
            report = verify_certificate(document)
            recheck_report(document, json.loads(canonical(report)))
            write_new(directory / (name + ".report.json"), report)
            row = {"name": name, "bound": report["bound"],
                   "multiplier": report["multiplier"],
                   "weighted_positive_excess_trace": report["weighted_positive_excess_trace"]}
            if name in measurements:
                actual = _measurement_success(document, *measurements[name])
                need(actual <= F(**report["bound"]), "EXAMPLE_SUCCESS_EXCEEDS_BOUND")
                row["exact_success_of_explicit_zero_query_measurement"] = actual
            outcomes.append(row)
        stage = "negative-controls"
        negatives = []
        mutant = deepcopy(models["coherent-first-bit"])
        mutant["multiplier"] = wire(F(1))
        negatives.append(("coherent-advice-falsely-fresh", mutant, "JOINT_STATE_DOMINATION_PSD"))
        mutant = deepcopy(models["noisy-first-winner"])
        mutant["tables"].pop()
        negatives.append(("incomplete-oracle-law", mutant, "COMPLETE_ORACLE_TABLE_COVERAGE"))
        mutant = deepcopy(models["rare-positive-excess"])
        mutant["excess_allowance"] = wire(F(0))
        negatives.append(("unpaid-positive-excess", mutant, "POSITIVE_EXCESS_ALLOWANCE_EXCEEDED"))
        mutant = deepcopy(models["independent-singular"])
        mutant["search_contract"]["probability_scope"] = "conditional-on-selected-start"
        negatives.append(("selected-start-scope-substitution", mutant, "GLOBAL_SCOPE_REQUIRED"))
        refusals = []
        for name, document, expected in negatives:
            write_new(directory / (name + ".rejected-certificate.json"), document)
            try:
                verify_certificate(document)
            except StateCertificateError as error:
                need(str(error) == expected, "NEGATIVE_CONTROL_WRONG_REFUSAL")
                refusals.append({"name": name, "refusal": str(error)})
            else:
                raise StateCertificateError("NEGATIVE_CONTROL_ACCEPTED")
        stage = "source-bindings-end"
        sources_at_end = _source_bindings()
        write_new(directory / "source-bindings-end.json", sources_at_end)
        need(sources_at_end == sources_at_start, "SOURCE_BINDINGS_CHANGED_DURING_EVIDENCE")
        summary = {"schema": "pon-finite-cq-state-evidence-v1", "started_at_utc": started,
                   "result": "PASS", "scope": "exact-explicit-finite-mathematical-models",
                   "examples": outcomes, "negative_controls": refusals,
                   "source_bindings": sources_at_start,
                   "source_files_equal_at_start_and_end": True,
                   "loaded_module_execution_attested": False,
                   "actual_quantum_hardware_executed": False, **UNATTESTED}
        write_new(directory / "summary.json", summary)
        manifest = [{"name": path.name, "bytes": path.stat().st_size,
                     "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                    for path in sorted(directory.iterdir()) if path.is_file()]
        write_new(directory / "manifest.json", {"schema": "pon-finite-cq-evidence-manifest-v1",
                                                  "files": manifest})
        return json.loads(canonical(summary))
    except Exception as error:
        write_new(directory / "failed-attempt.json", {
            "schema": "pon-finite-cq-state-attempt-v1", "started_at_utc": started,
            "result": "FAIL", "stage": stage, "error_type": type(error).__name__,
            "error": str(error), "production_qualified": False})
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--certificate", type=Path)
    action.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--report", type=Path, help="Recompute and compare an existing report.")
    parser.add_argument("--output", type=Path, help="Write a new complete report file.")
    args = parser.parse_args()
    if args.evidence_dir is not None:
        if args.report is not None or args.output is not None:
            parser.error("--report/--output require --certificate")
        result = retain_evidence(args.evidence_dir)
    else:
        document = read_json(args.certificate)
        result = (recheck_report(document, read_json(args.report)) if args.report is not None
                  else verify_certificate(document))
        if args.output is not None:
            write_new(args.output, result)
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
