#!/usr/bin/env python3
"""Separate a rebuilt W1 construction from accounting and security evidence.

The retained v1 accountant is intentionally unable to establish a caller's
predicate. Its ``full_W1_oracle_constructed=False`` field is local to that
accounting operation, not a repository-wide assertion that no construction
exists. This separately versioned projection preserves those v1 bytes and
rebuilds an optional full or prefix-restricted circuit from its fixed template.

Rebuilding a schedule establishes neither execution of that schedule nor a
mathematical equivalence proof, physical calibration, native-node admission,
an optimal attacker, a work lower bound, or mining-security qualification.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
from typing import Any

import quantum_oracle_resources as resources

SCHEMA = "trnm-w1-quantum-evidence-scope-v1"
MAX_BYTES = 2_000_000
ROOT = Path(__file__).resolve().parents[2]
OWN_PATH = "formal/pon-nakamoto-v1/w1_quantum_evidence_scope.py"
ACCOUNTING_PATH = "formal/pon-nakamoto-v1/quantum_oracle_resources.py"
PREDICATES = ("full", "prefix-restricted")

# This immutable pointer explains the historical construction record. It is
# not loaded, authenticated, or counted as execution by this reporting tool.
HISTORICAL_CONSTRUCTION_REFERENCE = {
    "repository": "TrillionniumFoundation/Trillionnium-Chain",
    "commit": "e4abb172147e941b62483652b0ceabaae4317624",
    "path": "evidence/pon-quantum-construction-20261104/README.md",
    "git_blob_sha1": "ef68c6f3dad7fc90ae7b4effd60c807de897cedd",
    "read_or_verified_by_this_invocation": False,
    "used_as_current_execution_or_qualification": False,
}


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def plain(value: Any) -> Any:
    """Convert internal tuples to their exact serialized JSON representation."""
    return json.loads(canonical(value))


def source_files(predicate: str | None) -> tuple[str, ...]:
    names = (OWN_PATH, ACCOUNTING_PATH)
    if predicate is not None:
        from w1_quantum_oracle import SOURCE_FILES
        names += SOURCE_FILES
        if predicate == "prefix-restricted":
            names += ("formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py",)
    return tuple(dict.fromkeys(names))


def source_fingerprint(predicate: str | None) -> dict[str, str]:
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in source_files(predicate)}


def build_report(request: resources.Request, construction_spec: dict | None = None,
                 predicate: str | None = None) -> dict:
    """Rebuild every stage when a specification is supplied; never trust labels.

    Only workload grouping and explicitly supplied classical/physical premises
    survive a reconstruction. In the generic path every circuit budget remains
    a caller assertion, even when its provenance resembles a construction ID.
    This function constructs/censuses circuits; it does not execute an oracle.
    """
    if type(request) is not resources.Request:
        raise ValueError("RESOURCE_REQUEST_TYPE")
    request.validate()
    if construction_spec is None:
        if predicate is not None:
            raise ValueError("CONSTRUCTION_SPEC_REQUIRED")
    elif predicate not in PREDICATES:
        raise ValueError("CONSTRUCTION_PREDICATE_REQUIRED")
    before = source_fingerprint(predicate)
    supplied_request = plain({"schema": resources.SCHEMA, **asdict(request)})
    construction = None
    native = False
    if construction_spec is not None:
        from w1_quantum_oracle import OracleProgram, template_from_spec
        template = template_from_spec(construction_spec)
        if predicate == "prefix-restricted":
            from w1_quantum_restricted_oracle import PrefixRestrictedProgram
            program = PrefixRestrictedProgram(template)
        else:
            program = OracleProgram(template)
        construction = program.resources()
        native = program.shape.native
        request = program.resource_request(request.workload, request.classical,
                                           request.physical_models)
        # Reject a source change while the construction's own identities are
        # collected; the source manifest is scoped, not a full-tree assertion.
        if any(before.get(name) != expected
               for name, expected in construction["source_sha256"].items()):
            raise ValueError("CONSTRUCTION_SOURCE_CHANGED")
    legacy = resources.account(request)
    if source_fingerprint(predicate) != before:
        raise ValueError("SOURCE_CHANGED_DURING_REPORT")

    rebuilt = construction is not None
    cost_kind = ("CONSTRUCTIVE_SCHEDULE_UPPER_BOUND" if rebuilt else
                 "UNKNOWN_MISSING_STAGES" if legacy["missing_circuit_stages"] else
                 "CALLER_ASSERTED_BUDGET_TOTAL")
    if not rebuilt:
        scope = "GENERIC_CONDITIONAL_ACCOUNTING"
    elif not native:
        scope = "REDUCED_SHAPE_CONSTRUCTION_CONTROL"
    elif predicate == "prefix-restricted":
        scope = "NATIVE_SHAPE_FIXED_CONTEXT_LEGAL_SUBSET_CONSTRUCTION"
    else:
        scope = "NATIVE_SHAPE_FIXED_CONTEXT_FULL_PREDICATE_CONSTRUCTION"

    result = {
        "schema": SCHEMA,
        "input": {"request": supplied_request,
                  "construction_spec": plain(construction_spec), "predicate": predicate},
        "scope": scope,
        "source_sha256": before,
        "source_identity_scope": "declared file bytes; not a complete Git tree or execution attestation",
        "historical_construction_reference": dict(HISTORICAL_CONSTRUCTION_REFERENCE),
        "construction": construction,
        "construction_status": {
            "schedule_rebuilt_from_source": rebuilt,
            "exact_native_shape_construction": rebuilt and native,
            "full_fixed_context_construction": rebuilt and native and predicate == "full",
            "legal_subset_construction": rebuilt and native and predicate == "prefix-restricted",
            "reduced_shape_control": rebuilt and not native,
            "all_bounded_noise_branches_in_selected_construction": rebuilt and predicate == "full",
            "full_legal_predicate_equivalence_proved": False,
            "caller_provenance_can_establish_construction": False,
            "native_eligibility_checked_by_this_report": False,
        },
        "accounting": {
            "original_schema": resources.SCHEMA,
            "original_report_sha256": digest(legacy),
            "legacy_false_field_name": "full_W1_oracle_constructed",
            "legacy_false_field_value": legacy["full_W1_oracle_constructed"],
            "legacy_false_field_scope": "this generic accountant does not construct or verify its caller's predicate",
            "legacy_field_is_repository_wide_absence_claim": False,
            "status": legacy["status"],
            "cost_evidence_kind": cost_kind,
            "caller_circuit_budgets_replaced_by_reconstruction": rebuilt,
            "bound_request_sha256": digest({"schema": resources.SCHEMA, **asdict(request)}),
            "circuit_inputs": legacy["circuit_inputs"],
            "missing_circuit_stages": legacy["missing_circuit_stages"],
            "complete_quantum_cost": legacy["complete_quantum_cost"],
            "classical_costs": legacy["classical_costs"],
            "physical_sensitivity": legacy["physical_sensitivity"],
        },
        "execution_by_this_invocation": {
            "native_shape_macro_interpreter_executed": False,
            "reduced_shape_leaf_gates_executed": False,
            "native_node_executed": False,
            "quantum_hardware_executed": False,
        },
        "qualification": {
            "attacker_optimality_proved": False,
            "quantum_work_lower_bound_proved": False,
            "physical_hardware_calibrated": False,
            "native_node_admission_verified": False,
            "marked_probability_bound_to_constructed_predicate": False,
            "quantum_mining_security_qualified": False,
            "production_activation": False,
        },
    }
    result["report_sha256"] = digest(result)
    return plain(result)


def verify_report(record: dict) -> dict:
    """Recompute the report; a digest alone cannot certify supplied assertions."""
    if type(record) is not dict or record.get("schema") != SCHEMA:
        raise ValueError("EVIDENCE_SCOPE_SCHEMA")
    inputs = record.get("input")
    if type(inputs) is not dict or set(inputs) != {"request", "construction_spec", "predicate"}:
        raise ValueError("EVIDENCE_SCOPE_INPUT")
    request = resources.load_request(canonical(inputs["request"]))
    rebuilt = build_report(request, inputs["construction_spec"], inputs["predicate"])
    if canonical(record) != canonical(rebuilt):
        raise ValueError("EVIDENCE_SCOPE_REBUILD_MISMATCH")
    return {"schema": SCHEMA, "result": "REBUILD_MATCH",
            "report_sha256": rebuilt["report_sha256"],
            "scope": rebuilt["scope"],
            "construction_schedule_rebuilt": rebuilt["construction_status"]["schedule_rebuilt_from_source"],
            "native_node_admission_verified": False,
            "quantum_hardware_executed": False,
            "quantum_mining_security_qualified": False}


def strict_load(raw: bytes) -> Any:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError("EVIDENCE_SCOPE_BYTE_BOUND")
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("DUPLICATE_JSON_KEY")
            value[key] = item
        return value
    def reject(value):
        raise ValueError("JSON_NONINTEGER_OR_NONFINITE:" + value)
    def bounded_integer(value):
        number = int(value)
        if not -(1 << 256) < number < (1 << 256):
            raise ValueError("JSON_INTEGER_BOUND")
        return number
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                      parse_int=bounded_integer, parse_float=reject,
                      parse_constant=reject)


def read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("EVIDENCE_SCOPE_INPUT_FILE")
    with path.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("EVIDENCE_SCOPE_BYTE_BOUND")
    return raw


def write_atomic(path: Path, value: dict) -> None:
    raw = canonical(value) + b"\n"
    if len(raw) > MAX_BYTES or path.exists() or path.is_symlink():
        raise ValueError("EVIDENCE_SCOPE_OUTPUT_EXISTS_OR_BOUND")
    temporary = path.with_name(path.name + ".partial")
    with temporary.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.link(temporary, path)
    temporary.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--request", type=Path)
    action.add_argument("--verify", type=Path)
    parser.add_argument("--oracle-spec", type=Path)
    parser.add_argument("--predicate", choices=PREDICATES)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.verify:
        if args.oracle_spec is not None or args.predicate is not None:
            parser.error("--verify does not accept construction overrides")
        result = verify_report(strict_load(read(args.verify)))
    else:
        spec = strict_load(read(args.oracle_spec)) if args.oracle_spec else None
        result = build_report(resources.load_request(read(args.request)), spec, args.predicate)
    if args.output:
        write_atomic(args.output, result)
        print(json.dumps({"path": str(args.output), "schema": SCHEMA,
                          "sha256": hashlib.sha256(read(args.output)).hexdigest()}, sort_keys=True))
    else:
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
