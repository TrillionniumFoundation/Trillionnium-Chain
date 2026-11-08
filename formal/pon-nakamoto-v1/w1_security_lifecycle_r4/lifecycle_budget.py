#!/usr/bin/env python3
"""Replay actual P3 challenger calls and combine one shared primitive's lifetime.

This program proves arithmetic consequences of its inputs, not missing crypto
hypotheses. Actual W1 noninteractive / quantum / lifetime security bits stay null.
Only the separately labelled abstract adaptive-game union lemma has a bound.
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import subprocess
from typing import Any

BASE = "cc836dfc13ef0006eb0878abd8cb5eca9a76bec0"
PROFILE5_BASE = "eb944645cc3e30af5955edf9dbbcb43488fa38c1"
P = 18446744069414584321
SCHEMA = "trnm-w1-shared-permutation-lifecycle-v1"
SOURCE_CONTRACT_SHA256 = "abf3c8c931bac92c17ca6d217c4f813a1212dcadb0c150110fc74e7cf78eee8e"
PROFILES = {1: 13, 2: 17, 3: 17, 4: 14, 5: 13}
ROLES = ("leaf_sponge", "branch_compressor", "transcript")
UNKNOWN_ITEMS = (
    "restricted_mmcs_opening_binding_and_extraction_with_shared_permutation",
    "complete_fixed_air_pcs_iop_rbr_reduction_with_concrete_constants",
    "actual_length_tagged_duplex_fs_compiler_in_the_same_oracle_game",
    "concrete_poseidon2_instantiation_from_ideal_permutation",
    "quantum_extraction_compiler_with_concrete_constants",
)


class Refusal(ValueError):
    """An unsupported input fails closed instead of producing a security claim."""


def natural(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise Refusal(f"{label}: expected a nonnegative integer")
    return value


def exact_keys(value: Any, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise Refusal(f"{label}: expected exactly {sorted(keys)}")


def ratio(value: Fraction) -> dict[str, Any]:
    bits = None if value == 0 else max(0.0, math.log2(value.denominator) - math.log2(value.numerator))
    return {"numerator": str(value.numerator), "denominator": str(value.denominator),
            "negative_log2_display_only": bits}


def replay_duplex(operations: list[dict[str, Any]], rate: int = 4) -> dict[str, int]:
    """Exact count semantics of pinned DuplexChallenger, independent of values.

    An observation discards buffered outputs; every full rate block permutes.
    A sample permutes iff input is pending or output is empty. Empty observation
    does nothing. No hash idealization, probability or independence is used.
    """
    natural(rate, "rate")
    if rate == 0:
        raise Refusal("rate must be positive")
    pending = output = calls = absorbed = sampled = 0
    for operation in operations:
        exact_keys(operation, {"kind", "fields"}, "operation")
        fields = natural(operation["fields"], "fields")
        if operation["kind"] == "absorb":
            absorbed += fields
            if fields:
                # A full block refills the output buffer, but another observation
                # immediately invalidates it. This distinction matters at boundaries.
                total = pending + fields
                full, pending = divmod(total, rate)
                calls += full
                output = rate if full and pending == 0 else 0
        elif operation["kind"] == "squeeze":
            sampled += fields
            if fields:
                if pending or not output:
                    calls += 1
                    pending = 0
                    output = rate
                taken = min(fields, output)
                fields -= taken
                output -= taken
                if fields:
                    full = (fields + rate - 1) // rate
                    calls += full
                    output = full * rate - fields
        else:
            raise Refusal("unknown transcript operation")
    return {"permutation_evaluations": calls, "absorbed_base_fields": absorbed,
            "sampled_base_fields": sampled, "pending_inputs": pending,
            "buffered_outputs": output}


def query_law(bits: int) -> dict[str, Any]:
    """Exact low-bit law conditional on a uniform canonical Goldilocks sample."""
    natural(bits, "query bits")
    if not 0 < bits <= 32:
        raise Refusal("fixed Goldilocks profiles require 1 <= bits <= 32")
    size = 1 << bits
    quotient, remainder = divmod(P, size)
    if remainder != 1:
        raise Refusal("this specialized law requires p = 1 mod 2^bits")
    return {"bits": bits, "alphabet_size": size, "exceptional_index": 0,
            "probability_zero": ratio(Fraction(quotient + 1, P)),
            "probability_each_nonzero": ratio(Fraction(quotient, P)),
            "total_variation_from_uniform": ratio(Fraction(size - 1, size * P)),
            "maximum_density_ratio": ratio(Fraction(size * (quotient + 1), P)),
            "condition": "uniform canonical base-field sample; not established for fixed Poseidon2"}


def adaptive_bad_event_bound(opportunities: list[tuple[int, Fraction]]) -> Fraction:
    """Union bound for conditional hazards, valid under adaptive choices/stopping.

    Hypothesis: at each possible opportunity of a class, conditional on the
    complete preceding history and no prior bad event, its hazard is at most e.
    At most n such opportunities occur almost surely. Then Pr[any bad] <= sum n e.
    This does not require independence. It does not justify the hazard hypothesis.
    """
    result = Fraction(0)
    for count, error in opportunities:
        natural(count, "opportunities")
        if not isinstance(error, Fraction) or not 0 <= error <= 1:
            raise Refusal("conditional error must be an exact probability")
        result += count * error
    return min(Fraction(1), result)


def restricted_leaf_collision_bound(queries: int, half_alphabet_size: int = P ** 4) -> Fraction:
    """Classical ideal-permutation bound for H(m)=left(Pi(m,0)).

    Pi is uniformly random on X x X, |X|=N. All adaptive forward AND inverse
    calls, across roles and epochs, are charged to queries. The adversary then
    returns two different m; verification adds at most two fresh forward calls.
    With T=queries+2, the bound is N*T*(T-1)/(2*(N*N-T+1)), capped at one.
    See THEOREM.md for the lazy-sampling proof and the deliberately narrow game.
    """
    natural(queries, "shared permutation queries")
    natural(half_alphabet_size, "half alphabet size")
    if half_alphabet_size < 2:
        raise Refusal("the nontrivial collision game requires N >= 2")
    total = queries + 2
    n = half_alphabet_size
    if total > n * n:
        return Fraction(1)
    return min(Fraction(1), Fraction(n * total * (total - 1), 2 * (n * n - total + 1)))


def source_check(manifest: dict[str, Any], repo: Path, registry: Path) -> dict[str, Any]:
    if manifest.get("base") != BASE:
        raise Refusal("source manifest base mismatch")
    if not isinstance(manifest.get("files"), list) or not manifest["files"]:
        raise Refusal("empty source contract")
    failures = []
    checked = []
    for item in manifest["files"]:
        exact_keys(item, {"root", "revision", "path", "sha256"}, "source pin")
        if item["root"] not in ("repo", "registry"):
            raise Refusal("unknown source root")
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise Refusal("source pin escapes its root")
        base = repo if item["root"] == "repo" else registry
        path = base / relative
        try:
            if item["revision"] is not None:
                if item["root"] != "repo" or item["revision"] not in (BASE, PROFILE5_BASE):
                    raise Refusal("unregistered source revision")
                data = subprocess.run(["git", "-C", str(repo), "show", f'{item["revision"]}:{item["path"]}'],
                                      capture_output=True, check=True).stdout
            else:
                data = path.read_bytes()
            actual = hashlib.sha256(data).hexdigest()
        except (OSError, subprocess.CalledProcessError) as error:
            failures.append({"path": str(path), "error": str(error)})
            continue
        checked.append({"root": item["root"], "revision": item["revision"], "path": item["path"], "sha256": actual})
        if actual != item["sha256"]:
            failures.append({"path": str(path), "expected": item["sha256"], "actual": actual})
    return {"ok": not failures, "checked": checked, "failures": failures}


def validate_receipt(receipt: dict[str, Any]) -> dict[str, Any]:
    if receipt.get("schema") != "trnm-w1-native-lifecycle-probe-v1" or receipt.get("source_base") not in (BASE, PROFILE5_BASE):
        raise Refusal("receipt namespace/source mismatch")
    component = receipt.get("component")
    if type(component) is not int or component not in PROFILES:
        raise Refusal("unregistered component")
    if component == 5 and receipt.get("source_base") != PROFILE5_BASE:
        raise Refusal("component 5 is absent from the historical R3 source")
    degree = PROFILES[component]
    if receipt.get("degree_bits") != degree or receipt.get("fri_rounds") != degree:
        raise Refusal("fixed FRI shape mismatch")
    for key in ("native_positive_verified", "instrumented_positive_verified",
                "instrumented_serialization_identical", "preprocessed_commitment_identical",
                "repeated_challenge_values_identical", "repeated_evaluation_counts_identical"):
        if receipt.get(key) is not True:
            raise Refusal(f"native check not passed: {key}")
    for key in ("adversary_query_upper_bound", "concrete_noninteractive_bits", "quantum_bits"):
        if receipt.get(key) is not None:
            raise Refusal(f"native measurement cannot assert {key}")
    tape = receipt["transcript_including_initialization"]
    if tape["pow_check_bits"]:
        raise Refusal("a grinding step was executed outside the fixed zero-grinding profile")
    replay = replay_duplex(tape["operations"])
    if replay["absorbed_base_fields"] != tape["observed_base_fields"]:
        raise Refusal("absorption replay mismatch")
    if replay["sampled_base_fields"] != tape["sampled_base_fields_including_index_samples"]:
        raise Refusal("sample replay mismatch")
    # alpha, zeta, PCS batching alpha, one FRI beta per round; degree-two extension.
    expected_samples = 2 * (degree + 3) + 64
    if replay["sampled_base_fields"] != expected_samples:
        raise Refusal("challenge inventory changed")
    indices = tape["index_samples"]
    if len(indices) != 64 or any(b != degree + 2 or type(i) is not int or not 0 <= i < (1 << b) for b, i in indices):
        raise Refusal("query index inventory changed")
    phases = receipt["permutation_evaluations"]
    for phase, counts in phases.items():
        exact_keys(counts, {*ROLES, "shared_total"}, phase)
        if sum(natural(counts[r], r) for r in ROLES) != counts["shared_total"]:
            raise Refusal("role counts do not sum")
    if phases["same_proof_reverification"] != phases["one_verification"]:
        raise Refusal("repeat count mismatch")
    for role in (*ROLES, "shared_total"):
        if sum(phases[p][role] for p in ("config_initialization", "independent_preprocessing", "one_verification")) != phases["cold_verification_total"][role]:
            raise Refusal("phase counts do not sum")
    if replay["permutation_evaluations"] != phases["cold_verification_total"]["transcript"]:
        raise Refusal("actual P3 permutation count differs from replay")
    controls = receipt["negative_controls"]
    if {c["field"] for c in controls} != {"ood", "batch", "commit-first", "commit-last", "query"} or len(controls) != 5:
        raise Refusal("canonical PoW negative controls incomplete")
    for control in controls:
        if control["value"] != 1 or control["structural_admission"] is not True or control["native_rejected"] is not True or control["panic"] is not False:
            raise Refusal("canonical PoW hypothesis was not falsified cleanly")
    return {"component": component, "source_base": receipt["source_base"],
            "replay": replay, "query_law": query_law(degree + 2),
            "measurements": phases, "proof_sha256": receipt["proof_sha256"]}


def merge_lifetime(receipts: dict[str, dict[str, Any]], scenario: dict[str, Any]) -> dict[str, Any]:
    exact_keys(scenario, {"schema", "name", "epochs", "abstract_conditional_opportunities"}, "scenario")
    if scenario["schema"] != "trnm-w1-lifetime-scenario-v1":
        raise Refusal("scenario namespace mismatch")
    totals = {role: 0 for role in ROLES}
    forward = inverse = other = 0
    records = []
    labels = set()
    for epoch in scenario["epochs"]:
        exact_keys(epoch, {"label", "runs", "offline_forward_queries", "offline_inverse_queries", "other_honest_evaluations"}, "epoch")
        if not isinstance(epoch["label"], str) or epoch["label"] in labels:
            raise Refusal("epoch labels must be distinct strings")
        labels.add(epoch["label"])
        counts = {role: 0 for role in ROLES}
        for run in epoch["runs"]:
            exact_keys(run, {"receipt", "config_initializations", "preprocessing_builds", "verification_calls"}, "run")
            receipt_key = run["receipt"]
            if not isinstance(receipt_key, str) or receipt_key not in receipts:
                raise Refusal("run has no verified native receipt")
            for count_name, phase in (("config_initializations", "config_initialization"),
                                      ("preprocessing_builds", "independent_preprocessing"),
                                      ("verification_calls", "one_verification")):
                count = natural(run[count_name], count_name)
                for role in ROLES:
                    counts[role] += count * receipts[receipt_key]["measurements"][phase][role]
        for role in ROLES:
            totals[role] += counts[role]
        f = natural(epoch["offline_forward_queries"], "offline forward queries")
        i = natural(epoch["offline_inverse_queries"], "offline inverse queries")
        o = natural(epoch["other_honest_evaluations"], "other honest evaluations")
        forward += f
        inverse += i
        other += o
        records.append({"label": epoch["label"], "receipt_keys": [run["receipt"] for run in epoch["runs"]],
                        "measured_roles": counts,
                        "declared_unmeasured_queries": f + i + o,
                        "same_primitive_epoch_total": sum(counts.values()) + f + i + o})
    total = sum(totals.values()) + forward + inverse + other
    separated_square = sum(x * x for x in (*totals.values(), forward, inverse, other))
    hypothetical = []
    for event in scenario["abstract_conditional_opportunities"]:
        exact_keys(event, {"count", "error_numerator", "error_denominator"}, "abstract event")
        n = natural(event["error_numerator"], "error numerator")
        d = natural(event["error_denominator"], "error denominator")
        if d == 0:
            raise Refusal("zero error denominator")
        hypothetical.append((natural(event["count"], "abstract count"), Fraction(n, d)))
    return {
        "scenario": scenario["name"], "primitive_scope": "one fixed Poseidon2Goldilocks<8> across components, roles and epochs",
        "epochs": records, "measured_role_evaluations": totals,
        "declared_offline_forward_queries": forward, "declared_offline_inverse_queries": inverse,
        "declared_other_honest_evaluations": other, "merged_total_evaluations_and_queries": total,
        "query_count_is_an_assumption_for_unmeasured_part": True,
        "complete_experiment_query_budget_established": False,
        "prover_and_diagnostic_run_queries_measured_here": False,
        "measured_workload_scope": "exact repeated retained proofs; not a worst-case bound for arbitrary accepted or malformed proofs",
        "other_hash_functions_measured": False,
        "restricted_fri_leaf_subtheorem": {
            "game": "fixed four-field input H4(m)=first4(Pi(m||0^4)); classical adaptive forward/inverse ideal-permutation queries",
            "half_alphabet_size": str(P ** 4),
            "total_queries_including_two_final_checks": str(total + 2),
            "conditional_collision_probability_upper_bound": ratio(restricted_leaf_collision_bound(total)),
            "concrete_poseidon2_instantiation_proved": False,
            "covers_internal_compressor": False, "covers_other_leaf_widths": False,
            "covers_merkle_opening_binding_or_extraction": False,
            "covers_quantum_queries": False, "is_w1_noninteractive_bound": False},
        "quadratic_accounting_only": {
            "merged_square": str(total * total), "incorrect_separate_role_square_sum": str(separated_square),
            "omitted_cross_terms": str(total * total - separated_square),
            "is_a_collision_bound": False,
            "reason": "raw truncated-permutation arbitrary-input collision resistance is already falsified; no birthday theorem is applied here"},
        "abstract_adaptive_bad_event_lemma": {
            "conditional_failure_upper_bound": ratio(adaptive_bad_event_bound(hypothetical)),
            "is_p3_noninteractive_bound": False,
            "conditional_hazard_hypotheses_proved_here": False,
            "independence_required": False,
            "opportunities_not_inferred_from_proof_count": True},
        "unclosed_crypto_items": list(UNKNOWN_ITEMS),
        "actual_w1_lifetime_failure_probability": None, "actual_w1_noninteractive_bits": None,
        "actual_w1_quantum_bits": None, "pq128": False, "qualification": "HOLD_NO_GO",
    }


def admit_manifest(raw: bytes) -> dict[str, Any]:
    if hashlib.sha256(raw).hexdigest() != SOURCE_CONTRACT_SHA256:
        raise Refusal("source contract bytes are not the reviewed sealed manifest")
    manifest = json.loads(raw)
    if manifest.get("schema") != "trnm-w1-r4-lifecycle-source-contract-v1":
        raise Refusal("source contract namespace mismatch")
    return manifest


def admit_receipt(raw: bytes, manifest: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    digest = hashlib.sha256(raw).hexdigest()
    matches = [(key, pin) for key, pin in manifest["native_receipts"].items()
               if pin["sha256"] == digest]
    if len(matches) != 1:
        raise Refusal("native receipt bytes are not a unique pinned observation")
    key, pin = matches[0]
    checked = validate_receipt(json.loads(raw))
    if any(checked[field] != pin[field] for field in ("source_base", "component", "proof_sha256")):
        raise Refusal("native receipt source/proof attribution differs from its pin")
    return key, checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", action="append", required=True, type=Path)
    parser.add_argument("--scenarios", required=True, type=Path)
    parser.add_argument("--source-manifest", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--registry-root", required=True, type=Path)
    args = parser.parse_args()
    try:
        manifest = admit_manifest(args.source_manifest.read_bytes())
        sources = source_check(manifest, args.repo_root, args.registry_root)
        if not sources["ok"]:
            print(json.dumps({"schema": SCHEMA, "status": "SOURCE_REFUSED", "sources": sources, "qualification": "HOLD_NO_GO"}, indent=2))
            return 2
        receipts = {}
        for path in args.receipt:
            key, checked = admit_receipt(path.read_bytes(), manifest)
            if key in receipts:
                raise Refusal("duplicate native observation")
            receipts[key] = checked
        scenarios = json.loads(args.scenarios.read_text())
        reports = [merge_lifetime(receipts, scenario) for scenario in scenarios]
        print(json.dumps({"schema": SCHEMA, "source_base": BASE, "source_check": sources,
                          "native_receipt_replays": receipts, "scenarios": reports,
                          "qualification": "HOLD_NO_GO"}, indent=2))
        return 0
    except (Refusal, OSError, KeyError, TypeError, ValueError) as error:
        print(json.dumps({"schema": SCHEMA, "status": "REFUSED", "error": str(error), "qualification": "HOLD_NO_GO"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
