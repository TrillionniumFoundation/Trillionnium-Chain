#!/usr/bin/env python3
"""Reproduce three fixed STARK source maps without granting soundness.

The registry is compared with pinned implementation bytes, locked dependency
bytes and the retained RISC Zero source snapshot. It is not its own evidence.
Finite-field algebra, source identity and retained manuscript progress have
separate scopes. This reader performs no native proof or production action.
"""
from __future__ import annotations

import argparse
import ast
import gzip
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import sys
import tomllib
from typing import Any

SCHEMA = "TRNM-W1-STARK-ROUTE-REGISTRY1"
REPORT_SCHEMA = "TRNM-W1-STARK-ROUTE-AUDIT1"
BASE_COMMIT = "e2a02f9271b49f146e70806c8a66e161b5973971"
REGISTRY_PATH = "config/pon/w1-stark-route-registry-v1.json"
P3 = "formal/pon-nakamoto-v1/w1_public_stark_research"
P3_PRIMITIVE_CONTRACT = "formal/pon-nakamoto-v1/p3_shared_primitive_qualification/SECURITY_CONTRACT.md"
QROM_MAPPING = "config/pon/w1-qrom-implementation-current-v2.json"
RISC_SNAPSHOT = "evidence/pon-w1-qrom-implementation-20261107/upstream-sources.json.gz"
HARDENED = "formal/pon-nakamoto-v1/w1_hardened_verifier/src/profile.rs"
V2 = "formal/pon-nakamoto-v1/w1_v2_verifier"
PROOF_CHAIN = "evidence/pon-w1-qrom-proof-chain-20261108/proof-chain-status.json"
LITERATURE = "config/pon/w1-stark-literature-evidence-v1.json"
PDF_HISTORY = "evidence/pon-w1-qrom-proof-chain-20261108/manuscript-pdf-manifest.json"
MAX_REGISTRY_BYTES = 128 * 1024
MAX_SOURCE_BYTES = 2 * 1024 * 1024
# A source plus its JSON pin cannot be silently updated together. A different
# source roster requires a separately reviewed mapping update in this reader.
# Current QROM mapping reviewed at 975ab093 (140 selected local inputs).
# BASE_COMMIT remains the retained historical/literature baseline. Route
# parameters, literature identities and security qualification are unchanged.
FROZEN_SOURCE_SET_SHA256 = "494d2d9fc72cfdae473c7b9c7f53cbeed19eea42a14b991ff83b369e4390d927"
SOURCE_SCOPE = "selected_route_inputs_not_full_repository_or_dependency_closure"
ROUTE_IDS = ("risc0_poseidon2_fixed_v2", "plonky3_poseidon2_w1_r1",
             "plonky3_tagged_sha3_512_w1_r1")
SMALL_FIELD_OBLIGATION = "small_base_field_extension_domain_and_list_size_applicability"
P3_OPEN = (
    "full_relation_and_compiler_refinement", "concrete_round_by_round_knowledge_soundness",
    "actual_mmcs_quantum_commitment_extraction", "pcs_fri_deep_soundness_and_list_size",
    "fiat_shamir_in_the_actual_joint_shared_oracle_model",
    "quantum_state_restoration_and_initial_advice", "recursive_programs_and_composition_loss",
    "lifetime_adversary_query_budget", "complete_resource_and_service_qualification",
    "production_ingress_and_admission", SMALL_FIELD_OBLIGATION,
)


class RouteAuditError(ValueError):
    """A source identity, parameter map or claim boundary did not match."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RouteAuditError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def same(first: Any, second: Any) -> bool:
    # Unlike Python equality, canonical JSON distinguishes false from 0.
    return canonical(first) == canonical(second)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key: " + key)
        result[key] = value
    return result


def noninteger_json(value: str) -> None:
    raise RouteAuditError("floating/nonfinite JSON number is unsupported: " + value)


def strict_json(data: bytes, maximum: int = MAX_REGISTRY_BYTES) -> Any:
    require(len(data) <= maximum, "JSON input exceeds reader limit")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique_object,
                          parse_float=noninteger_json, parse_constant=noninteger_json)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise RouteAuditError(str(error)) from error


def qualification() -> dict[str, Any]:
    return {
        "status": "HOLD_NO_GO", "complete_noninteractive_security_bits": None,
        "quantum_security_bits": None, "lifecycle_security_bits": None,
        "concrete_primitive_security_qualified": False, "quantum_extractor_qualified": False,
        "fiat_shamir_knowledge_soundness_qualified": False, "recursive_composition_qualified": False,
        "lifetime_adversary_budget_established": False, "production_qualified": False,
        "consensus_admission": False,
    }


def regular_file(root: Path, relative: str) -> Path:
    require(type(relative) is str, "source path must be text")
    parts = PurePosixPath(relative)
    require(not parts.is_absolute() and bool(parts.parts) and parts.as_posix() == relative
            and all(part not in (".", "..") for part in parts.parts), "noncanonical source path")
    current = root
    for part in parts.parts:
        current /= part
        require(not current.is_symlink(), "symlink in source path: " + relative)
    require(current.is_file(), "missing regular source: " + relative)
    return current


def read_inputs(root: Path, pins: Any) -> dict[str, bytes]:
    require(type(pins) is list and 1 <= len(pins) <= 128, "source pins must be a bounded list")
    require(sha256(canonical(pins)) == FROZEN_SOURCE_SET_SHA256,
            "frozen source roster/pin changed; a new source map is required")
    result = {}
    for pin in pins:
        require(type(pin) is dict and set(pin) == {"path", "bytes", "sha256"}, "invalid source pin")
        path, size = pin["path"], pin["bytes"]
        require(type(size) is int and 0 <= size <= MAX_SOURCE_BYTES, "invalid source size")
        require(path not in result, "duplicate source path")
        source = regular_file(root, path)
        require(source.stat().st_size == size, "source size differs: " + path)
        with source.open("rb") as stream:
            data = stream.read(size + 1)
        require(len(data) == size and sha256(data) == pin["sha256"], "source bytes differ: " + path)
        result[path] = data
    return result


def exactly_one(pattern: str, source: str, label: str) -> str:
    matches = re.findall(pattern, source, re.MULTILINE)
    require(len(matches) == 1, "missing/ambiguous frozen source field: " + label)
    return matches[0]


def uint(source: str, name: str) -> int:
    return int(exactly_one(r"^(?:pub )?const " + re.escape(name)
                          + r": (?:u32|u64|usize) = ([0-9_]+);(?:[ \t]*//[^\n]*)?$",
                          source, name).replace("_", ""))


def string(source: str, name: str) -> str:
    return exactly_one(r"^(?:pub )?const " + re.escape(name)
                       + r': &str = "([^"\\]*)";', source, name)


def byte_string(source: str, name: str) -> bytes:
    body = exactly_one(r"^(?:pub )?const " + re.escape(name)
                       + r': &\[u8(?:; [0-9]+)?\] = b"((?:[^"\\]|\\.)*)";', source, name)
    value = ast.literal_eval('b"' + body + '"')
    require(type(value) is bytes, "unsupported byte literal")
    return value


def contains(source: str, *fragments: str) -> None:
    for fragment in fragments:
        require(fragment in source, "frozen implementation anchor missing: " + fragment)


def snapshot_sources(data: bytes) -> dict[str, str]:
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
        raw = handle.read(MAX_SOURCE_BYTES + 1)
    snapshot = strict_json(raw, MAX_SOURCE_BYTES)
    require(snapshot["repository"] == "risc0/risc0"
            and snapshot["commit"] == "8c215e2f4ccdd935f0517bf05d90f1ae032840a9",
            "RISC upstream source identity differs")
    sources = {}
    for row in snapshot["files"]:
        require(row["path"] not in sources, "duplicate upstream snapshot source")
        source = row["content"].encode("utf-8")
        require(len(source) == row["bytes"] and sha256(source) == row["sha256"],
                "upstream snapshot inner bytes differ: " + row["path"])
        sources[row["path"]] = row["content"]
    return sources


def field_parameters(certificate: dict[str, Any]) -> dict[str, Any]:
    return {name: certificate[name] for name in (
        "characteristic", "extension_degree", "extension_polynomial_low_to_high", "base_two_adicity",
    )}


def dktz_direct_domain_cardinality(characteristic: int, base_two_adicity: int,
                                  fixed_evaluation_log2: list[int] | None = None) -> dict[str, Any]:
    """Check a necessary direct-domain hypothesis using a separately certified prime.

    The theorem's full-field or hyperplane cardinality is divisible by its
    characteristic. An odd-characteristic multiplicative two-adic domain is
    coprime to it. This says nothing about restrictions, padding or other results.
    """
    require(type(characteristic) is int and characteristic > 2 and characteristic % 2 == 1,
            "direct-domain check requires the certified odd characteristic")
    require(type(base_two_adicity) is int and 0 <= base_two_adicity <= 64,
            "invalid certified two-adicity")
    require(fixed_evaluation_log2 is None or
            (type(fixed_evaluation_log2) is list and bool(fixed_evaluation_log2)
             and all(type(value) is int and 0 <= value <= base_two_adicity
                     for value in fixed_evaluation_log2)
             and len(set(fixed_evaluation_log2)) == len(fixed_evaluation_log2)),
            "invalid fixed evaluation domain exponents")
    coprime = math.gcd(characteristic, 2)
    nonzero = all(pow(2, exponent, characteristic) != 0
                  for exponent in range(base_two_adicity + 1))
    require(coprime == 1 and nonzero, "two-adic direct-domain obstruction did not reproduce")
    return {
        "source_id": "dktz_tr26_237_revision_1", "theorem": "5.22", "printed_page": 50,
        "necessary_theorem_hypotheses": {
            "base_field_size": "b=p^a", "extension_degree": "m=2n",
            "evaluation_domain": "B_or_Fb_hyperplane", "h": [0, 1],
            "parameter_range": "2<=t<=n-h", "domain_exponent": "d=2n-h>=4",
            "domain_cardinality": "b^d", "cardinality_divisible_by_characteristic": True,
        },
        "candidate_domain": "multiplicative_two_adic_subgroup_or_coset",
        "certified_characteristic": str(characteristic),
        "coprimality_witness": {
            "gcd_characteristic_two": coprime,
            "checked_evaluation_log2_min": 0,
            "checked_evaluation_log2_max": base_two_adicity,
            "all_checked_power_of_two_residues_nonzero": nonzero,
            "scope": "base_field_algebraic_capacity_not_proved_reachable_trace_or_evaluation_sizes",
        },
        "fixed_tagged_evaluation_log2": fixed_evaluation_log2,
        "direct_domain_hypothesis_matched": False,
        "obstruction": "theorem_cardinality_divisible_by_characteristic_but_candidate_cardinality_coprime",
        "padding_restriction_or_other_result_applicability": "OPEN",
        "all_proximity_gap_results_excluded": False,
        "fri_soundness_inferred": False,
    }


def proximity_scope(field: dict[str, Any],
                    fixed_evaluation_log2: list[int] | None = None) -> dict[str, Any]:
    return {
        "evaluation_domain_kind": "multiplicative_two_adic",
        "characteristic_two_additive_hypothesis_matched": False,
        "small_base_field_and_list_size_review": "OPEN",
        "all_proximity_gap_results_excluded": False,
        "fri_soundness_inferred_from_field_algebra": False,
        "dktz_theorem_5_22_direct_domain": dktz_direct_domain_cardinality(
            int(field["characteristic"]), int(field["base_two_adicity"]), fixed_evaluation_log2),
    }


def poseidon_primitive_premises(source: str, contract: str) -> dict[str, Any]:
    """Retain the existing limited negative result, without inferring a W1 attack."""
    contains(contract,
             "failures of an *unrestricted compressor collision-resistance*",
             "an *independent leaf/branch function* model.",
             "They do not establish\ntwo accepted conflicting W1 openings, a valid false W1 proof",
             "does not cover\nquantum queries, a fixed concrete Poseidon2, actual P3 pruned multi-openings")
    contains(source,
             '"hash_collision_bits_assumption_scope": "conditional_estimator_input_only_not_raw_compressor_security"',
             '"concrete_shared_permutation_restricted_tree_binding_bits": Value::Null')
    return {
        "evidence": [P3_PRIMITIVE_CONTRACT, P3 + "/src/proof_config.rs"],
        "scope": "retained_source_findings_not_new_native_execution_or_security_proof",
        "unrestricted_compressor_collision_resistance": "REFUTED",
        "independent_leaf_branch_function_model": "REFUTED",
        "actual_pruned_mmcs_binding": "OPEN",
        "concrete_restricted_tree_binding_bits": None,
        "conditional_estimator_is_raw_compressor_bound": False,
        "fixed_w1_conflicting_opening_inferred": False,
        "false_w1_proof_inferred": False,
    }


def tagged_transcript_premises(source: str) -> dict[str, Any]:
    """Distinguish input-role framing from the inherited challenger history."""
    contains(source,
             '"p3_message_schedule":"unchanged frozen P3 transcript order; no new per-message semantic tags"',
             '"inherited_state_alias":"HashChallenger does not encode observe-call boundaries or count of bytes already popped within an output block before a new observation; generic transcript-history injectivity is not claimed"')
    return {
        "evidence": P3 + "/src/tagged_sha3.rs",
        "scope": "retained_source_metadata_not_new_native_execution_or_security_proof",
        "fixed_p3_observation_schedule": "UNCHANGED",
        "per_message_semantic_tags": False,
        "observe_call_boundaries_encoded": False,
        "consumed_output_byte_count_encoded_before_observe": False,
        "generic_transcript_history_injectivity_claimed": False,
        "input_role_framing_is_transcript_history_proof": False,
        "actual_schedule_knowledge_soundness": "OPEN",
        "fixed_w1_forgery_inferred": False,
    }


def retained_progress(inputs: dict[str, bytes], mapping: dict[str, Any]) -> dict[str, Any]:
    progress = strict_json(inputs[PROOF_CHAIN])
    require(progress["historical_report"]["open_obligation_count"] == 15
            and progress["version_subobligations_closed"] == 1
            and progress["other_historical_obligations_remaining"] == 14
            and progress["full_security_obligation_count_discharged"] == 0,
            "retained progress levels changed")
    require([row["id"] for row in progress["obligations"]] == mapping["proof_obligations"]
            and all(row["full_security_obligation_discharged"] is False for row in progress["obligations"]),
            "retained obligation identity/scope differs")
    require(len(progress["eight_interfaces"]) == 8
            and all(row["closed"] is False for row in progress["eight_interfaces"]),
            "retained security interface was promoted")
    return {
        "historical_obligation_count": 15, "pinned_revision_subobligations_closed": 1,
        "other_historical_obligations_remaining": 14,
        "full_security_obligation_count_discharged": 0,
        "eight_interfaces_closed": {row["interface"]: row["closed"] for row in progress["eight_interfaces"]},
        "evidence": PROOF_CHAIN,
        "scope": "readback_of_pinned_prior_observation_not_a_new_PDF_comparison_or_security_proof",
    }


def literature_review(inputs: dict[str, bytes]) -> dict[str, Any]:
    review = strict_json(inputs[LITERATURE])
    history = strict_json(inputs[PDF_HISTORY])
    require(review["schema"] == "TRNM-W1-STARK-LITERATURE-EVIDENCE1"
            and review["repository_baseline"] == BASE_COMMIT,
            "literature review baseline/schema differs")
    require(all(value is False or value is None for value in review["qualification"].values()),
            "literature review grants implementation qualification")
    sources = {row["id"]: row for row in review["sources"]}
    require(len(sources) == len(review["sources"]) == 4, "literature review roster differs")
    cdhz = sources["cdhz_2025_2166"]
    require(cdhz["latest_pdf_bytes_retrieved_this_review"] is False
            and cdhz["latest_pdf_sha256_computed_this_review"] is None,
            "fresh CDHZ PDF retrieval was inferred from historical evidence")
    historical = cdhz["historical_pdf_identity"]
    march = [row for row in history["pdfs"] if row["name"] == "march"]
    require(len(march) == 1 and historical["path"] == PDF_HISTORY
            and same({key: historical[key] for key in ("version_id", "sha256", "pages")},
                     {key: march[0][key] for key in ("version_id", "sha256", "pages")})
            and type(historical["bytes"]) is int and historical["bytes"] == march[0]["byte_size"],
            "historical PDF identity does not match its retained source")
    for source_id in ("dktz_tr26_237_revision_1", "fenzi_sanso_cic_20261026"):
        source = sources[source_id]
        require(source["pdf_bytes_retrieved_this_review"] is False
                and source["pdf_sha256_computed_this_review"] is None
                and source["complete_mathematical_proof_independently_audited"] is False,
                "selected web-reader sections were promoted to complete byte/proof review")
    accounting = review["historical_obligation_accounting"]
    require(same({key: accounting[key] for key in (
        "implementation_contract_roster_count", "later_disposition_roster_count",
        "pinned_version_subobligations_closed", "other_historical_obligations_remaining",
        "full_security_obligations_discharged")}, {
        "implementation_contract_roster_count": 15, "later_disposition_roster_count": 15,
        "pinned_version_subobligations_closed": 1, "other_historical_obligations_remaining": 14,
        "full_security_obligations_discharged": 0}), "literature obligation accounting changed")
    return {
        "manifest_path": LITERATURE, "manifest_sha256": sha256(inputs[LITERATURE]),
        "observation_date": review["observation_date"],
        "provenance": "new review record; cryptographic and historical source_base_commit remains separate",
        "source_ids": list(sources),
        "fresh_pdf_bytes_or_pdf_hashes_established": False,
        "historical_cdhz_pdf_identity": historical,
        "historical_obligation_accounting": accounting,
        "small_base_field_and_nonbinary_proximity_obligations_open": True,
        "full_proofs_or_fixed_profile_instantiations_verified": False,
        "qualification": review["qualification"],
    }


def derive_routes(root: Path, inputs: dict[str, bytes]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    from w1_stark_field_certificates import build_report

    algebra = build_report(root)
    require(algebra["schema"] == "TRNM-W1-STARK-FIELD-CERTIFICATES1"
            and algebra["status"] == "FIXED_FIELD_ALGEBRA_CERTIFIED_SECURITY_HOLD",
            "field certificate schema/status changed")
    expected_algebra_qualification = {
        "prime_moduli_certified": True, "extension_irreducibility_certified": True,
        "source_root_table_orders_certified": True,
        **{key: False for key in (
            "compiled_field_arithmetic_equivalence_proved", "complete_build_source_closure_verified",
            "native_binary_executed", "fri_soundness_qualified", "rbr_knowledge_soundness_qualified",
            "quantum_extractor_qualified", "post_quantum_soundness_qualified",
            "recursive_composition_qualified", "production_qualified", "consensus_admission")},
        "security_bits_quantum": None, "whole_lifetime_failure_bound": None,
    }
    require(same(algebra["qualification"], expected_algebra_qualification),
            "field certificate algebra/security scope changed")
    fields = algebra["fields"]
    sources = snapshot_sources(inputs[RISC_SNAPSHOT])
    mapping = strict_json(inputs[QROM_MAPPING])
    require(len(mapping["proof_obligations"]) == 15 and len(set(mapping["proof_obligations"])) == 15,
            "original QROM obligation roster differs")
    require(all(value is False or value is None for value in mapping["qualification"].values()),
            "current QROM mapping grants qualification")
    require(mapping["lifetime_budget"]["policy_adopted"] is False
            and all(value is None for name, value in mapping["lifetime_budget"].items()
                    if name != "policy_adopted"), "unproved lifetime budget was populated")
    zkp = sources["risc0/zkp/src/lib.rs"]
    profile = inputs[HARDENED].decode()
    main = inputs[V2 + "/src/main.rs"].decode()
    image = inputs[V2 + "/src/image.rs"].decode()
    body = exactly_one(r"pub const IMAGE_ID: \[u32; 8\] = \[([^\]]+)\];", image, "v2 image")
    image_words = [int(item.strip()) for item in body.split(",") if item.strip()]
    require(len(image_words) == 8, "unexpected v2 image shape")
    contains(main, "profile::verify_image(receipt, image::IMAGE_ID)",
             "public(header, expected, &receipt.journal.bytes)")
    contains(profile, "VerifierContext::empty()", "parameters.inner_control_root.is_none()")
    risc_lock = tomllib.loads(inputs[V2 + "/Cargo.lock"].decode())
    sdk = [row for row in risc_lock["package"] if row["name"] == "risc0-zkvm"]
    require(len(sdk) == 1 and sdk[0]["version"] == "3.0.6", "RISC SDK drift")
    require(mapping["profile_id"] == string(main, "PROFILE_ID"), "RISC profile mismatch")
    control_source = sources["risc0/circuit/recursion/src/control_id.rs"]
    control_root = exactly_one(r'pub const ALLOWED_CONTROL_ROOT: Digest =\s*digest!\("([0-9a-f]{64})"\);',
                               control_source, "allowed control root")
    control_body = exactly_one(r"pub const ALLOWED_CONTROL_IDS: &\[Digest\] = &\[([\s\S]*?)\];",
                               control_source, "allowed control roster")
    allowed_controls = re.findall(r'digest!\("([0-9a-f]{64})"\)', control_body)
    require(len(allowed_controls) == len(set(allowed_controls)) == 27
            and string(profile, "CONTROL_ID") in allowed_controls,
            "allowed control roster/final control mismatch")
    risc = {
        "route_id": ROUTE_IDS[0], "profile_id": string(main, "PROFILE_ID"),
        "backend": {"name": "RISC Zero", "version": sdk[0]["version"]},
        "field": field_parameters(fields["risc0_babybear_fp4"]),
        "fri": {"queries": uint(zkp, "QUERIES"), "inverse_rate": uint(zkp, "INV_RATE"),
                "fold_log2": uint(zkp, "FRI_FOLD_PO2"), "minimum_degree": uint(zkp, "FRI_MIN_DEGREE"),
                "upstream_trace_log2_min": uint(zkp, "MIN_CYCLES_PO2"),
                "upstream_trace_log2_max": uint(zkp, "MAX_CYCLES_PO2"),
                "reachable_recursive_trace_sizes_proved": False},
        "primitive_model": {"name": string(profile, "HASH_SUITE"),
                            "independent_role_oracles_qualified": False},
        "statement_identity": {"guest_image_u32": image_words,
                               "final_control_id": string(profile, "CONTROL_ID"),
                               "allowed_control_root": control_root,
                               "allowed_control_ids": allowed_controls,
                               "allowed_program_semantics_proved": False,
                               "verifier_parameters_digest": string(profile, "PARAMETERS"),
                               "control_merkle_depth": uint(profile, "CONTROL_MERKLE_DEPTH")},
        "proximity_scope": proximity_scope(fields["risc0_babybear_fp4"]),
        "historical_obligation_roster": mapping["proof_obligations"],
        "retained_obligation_progress": retained_progress(inputs, mapping),
        "additional_open_obligations": [SMALL_FIELD_OBLIGATION],
        "source_closure_is_a_security_theorem": False, "qualification": qualification(),
    }
    lock = tomllib.loads(inputs[P3 + "/Cargo.lock"].decode())
    packages = [row for row in lock["package"] if row["name"].startswith("p3-")]
    require(bool(packages) and all(row["version"] == "0.8.0" for row in packages), "P3 lock version drift")
    sha3 = [row for row in lock["package"] if row["name"] == "sha3"]
    require(len(sha3) == 1 and sha3[0]["version"] == "0.10.9", "SHA3 dependency drift")
    old, new, wire = [inputs[P3 + "/src/" + name].decode()
                      for name in ("proof_config.rs", "tagged_sha3.rs", "tagged_sha3_wire.rs")]
    for source in (old, new):
        contains(source, "pub type Val = Goldilocks;",
                 "pub type Challenge = BinomialExtensionField<Val, 2>;",
                 "TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>",
                 "pub type Dft = Radix2DitParallel<Val>;", "log_blowup: LOG_BLOWUP",
                 "num_queries: NUM_QUERIES", "log_final_poly_len: LOG_FINAL_POLY_LEN",
                 "max_log_arity: MAX_LOG_ARITY", "batch_proof_of_work_bits: 0",
                 "commit_proof_of_work_bits: 0", "query_proof_of_work_bits: 0",
                 ".with_ood_proof_of_work_bits(0)", ".with_lookup_proof_of_work_bits(0)")
        require(str(uint(source, "GOLDILOCKS_ORDER")) == fields["plonky3_goldilocks_fp2"]["characteristic"],
                "P3 source modulus does not match certificate")

    def fri(source: str) -> dict[str, Any]:
        return {"log_blowup": uint(source, "LOG_BLOWUP"), "log_final_poly_len": uint(source, "LOG_FINAL_POLY_LEN"),
                "max_log_arity": uint(source, "MAX_LOG_ARITY"), "queries": uint(source, "NUM_QUERIES"),
                "all_grinding_bits": 0, "zero_knowledge": False}

    contains(old, "pub type Perm = Poseidon2Goldilocks<8>;", "PaddingFreeSponge<Perm, 8, 4, 4>",
             "TruncatedPermutation<Perm, 2, 4, 8>", "DuplexChallenger<Val, Perm, 8, 4>",
             "ValMmcs::new(hash, compress, 0)", '"quantum_security_bits": Value::Null',
             '"complete_noninteractive_security_bits": Value::Null')
    domains = {name: uint(old, const) for name, const in (
        ("sha", "SHA_COMPONENT"), ("quotient_remainder", "ARITH_COMPONENT"),
        ("carry", "CARRY_COMPONENT"), ("packed_carry", "PACKED_CARRY_COMPONENT"),
        ("public_schedule_sha", "SCHEDULE_SHA_COMPONENT"))}
    p3_old = {
        "route_id": ROUTE_IDS[1], "profile_id": byte_string(old, "RESEARCH_DOMAIN").rstrip(b"\0").decode("ascii"),
        "backend": {"name": "Plonky3", "version": "0.8.0"},
        "field": field_parameters(fields["plonky3_goldilocks_fp2"]), "fri": fri(old),
        "primitive_model": {"name": "Goldilocks Poseidon2", "width": 8, "leaf_rate_elements": 4,
                            "digest_field_elements": 4, "mmcs_arity": 2, "mmcs_cap_height": 0,
                            "challenger": "DuplexChallenger<Goldilocks,Poseidon2Goldilocks<8>,8,4>",
                            "independent_role_oracles_qualified": False},
        "transcript_domain_hex": byte_string(old, "RESEARCH_DOMAIN").hex(), "component_domains": domains,
        "conditional_estimator": {"modulus_bits_floor": uint(old, "CONSERVATIVE_MODULUS_BITS"),
                                  "assumed_hash_collision_bits": uint(old, "ASSUMED_HASH_COLLISION_BITS"),
                                  "assumed_hash_strength_proved": False,
                                  "complete_noninteractive_or_quantum_bound": False},
        "primitive_premises": poseidon_primitive_premises(
            old, inputs[P3_PRIMITIVE_CONTRACT].decode()),
        "proximity_scope": proximity_scope(fields["plonky3_goldilocks_fp2"]),
        "open_obligations": list(P3_OPEN),
        "qualification": qualification(),
    }
    contains(new, "Sha3_512::new()", "HashChallenger::new(", "TranscriptHasher::new(component, context)",
             '"concrete_binding_bits":Value::Null', '"quantum_security_bits":Value::Null',
             '"new_recursive_sha3_air":false', '"independent_role_oracle_claim":false')
    descriptor = byte_string(new, "DESCRIPTOR").decode("ascii")
    parts = {}
    for part in descriptor.split(";"):
        key, _, value = part.partition("=")
        require(key not in parts, "duplicate tagged descriptor field")
        parts[key] = value
    expected = {"p3": "0.8.0", "sha3": "512", "r": "576", "c": "1024",
                "F": str(uint(new, "GOLDILOCKS_ORDER")), "E": "X^2-7", "binary": "", "cap": "0",
                "log_blowup": str(uint(new, "LOG_BLOWUP")), "log_final_poly": str(uint(new, "LOG_FINAL_POLY_LEN")),
                "max_log_arity": str(uint(new, "MAX_LOG_ARITY")), "queries": str(uint(new, "NUM_QUERIES")),
                "pow": "0", "zk": "0",
                "sha": f"d{uint(new, 'SHA_DEGREE_BITS')},w{uint(new, 'SHA_WIDTH')},p{uint(new, 'SHA_PRE_WIDTH')},q2,next1",
                "carry": f"d{uint(new, 'PACKED_CARRY_DEGREE_BITS')},w{uint(new, 'PACKED_CARRY_WIDTH')},p{uint(new, 'PACKED_CARRY_PRE_WIDTH')},q1,next0"}
    require(parts == expected, "tagged descriptor disagrees with implementation constants")
    components = []
    for name, prefix, magic in (("sha", "SHA", "SHA_MAGIC"), ("packed_carry", "PACKED_CARRY", "PACKED_CARRY_MAGIC")):
        trace = uint(new, prefix + "_DEGREE_BITS")
        components.append({"name": name, "trace_log2": trace, "evaluation_log2": trace + uint(new, "LOG_BLOWUP"),
                           "main_width": uint(new, prefix + "_WIDTH"), "preprocessed_width": uint(new, prefix + "_PRE_WIDTH"),
                           "proof_magic_hex": byte_string(wire, magic).hex()})
    p3_new = {
        "route_id": ROUTE_IDS[2], "profile_id": byte_string(new, "PROFILE_ID").decode("ascii"),
        "backend": {"name": "Plonky3", "version": "0.8.0"},
        "field": field_parameters(fields["plonky3_goldilocks_fp2"]), "fri": fri(new),
        "primitive_model": {"name": "SHA3-512", "implementation": "RustCrypto sha3 0.10.9",
                            "parameter_source_scope": "fixed Rust descriptor and Sha3_512 type selection; implementation equivalence is not proved here",
                            "rate_bits": int(parts["r"]), "capacity_bits": int(parts["c"]),
                            "digest_bytes": uint(new, "DIGEST_BYTES"),
                            "digest_encoding": "eight_raw_u64le_words_without_field_reduction",
                            "mmcs_arity": 2, "mmcs_cap_height": 0,
                            "challenger": "SerializingChallenger64<Goldilocks,HashChallenger<u8,TranscriptHasher,64>>",
                            "independent_role_oracles_qualified": False},
        "descriptor": descriptor, "frame_magic_hex": byte_string(new, "FRAME_MAGIC").hex(),
        "full_w1_fixed_components": components,
        "transcript_model": tagged_transcript_premises(new),
        "trace_shape_scope": "fixed_tagged_full_W1_profile_not_arbitrary_AIR_or_all_P3_variants",
        "structural_mmcs_result": {"scope": "two_existing_accepted_conflicting_classical_openings_to_a_framed_hash_collision",
                                   "geometry": "binary_cap_zero_fixed_ordered_power_of_two_matrix_heights",
                                   "shared_context": "same profile, component, statement context, ordered dimensions and root; conflicting values at one shared matrix-row coordinate",
                                   "quantum_commitment_extractor": False, "complete_pcs_or_fiat_shamir_result": False},
        "proximity_scope": proximity_scope(fields["plonky3_goldilocks_fp2"],
                                             [row["evaluation_log2"] for row in components]),
        "open_obligations": list(P3_OPEN), "qualification": qualification(),
    }
    require(len({r["profile_id"] for r in (risc, p3_old, p3_new)}) == 3, "profile identities alias")
    return [risc, p3_old, p3_new], algebra


def audit(root: Path, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    root = root.resolve(strict=True)
    if registry is None:
        with regular_file(root, REGISTRY_PATH).open("rb") as stream:
            registry = strict_json(stream.read(MAX_REGISTRY_BYTES + 1))
    require(type(registry) is dict and set(registry) == {
        "schema", "source_base_commit", "source_scope", "source_inputs", "routes", "literature_review", "qualification"
    }, "unsupported registry fields")
    require(registry["schema"] == SCHEMA and registry["source_base_commit"] == BASE_COMMIT, "registry schema/base differs")
    require(registry["source_scope"] == SOURCE_SCOPE, "source inspection scope changed")
    require(same(registry["qualification"], qualification()), "registry claims unsupported qualification")
    inputs = read_inputs(root, registry["source_inputs"])
    routes, algebra = derive_routes(root, inputs)
    literature = literature_review(inputs)
    require(same(registry["routes"], routes), "route declarations differ from pinned implementation/obligation derivation")
    require(same(registry["literature_review"], literature), "literature review/provenance declaration differs")
    return {
        "schema": REPORT_SCHEMA, "status": "ROUTE_MAPPING_REPRODUCED_SECURITY_HOLD",
        "source_base_commit": BASE_COMMIT, "source_scope": SOURCE_SCOPE,
        "source_input_count": len(inputs), "source_set_sha256": FROZEN_SOURCE_SET_SHA256,
        "route_count": len(routes), "routes": routes,
        "literature_review": literature,
        "source_base_commit_scope": "implementation and historical records; new literature observation is separately identified",
        "field_certificate_status": algebra["status"], "field_certificate_sha256": sha256(canonical(algebra)),
        "route_fingerprints": {row["route_id"]: sha256(canonical(row)) for row in routes},
        "registry_sha256": sha256(canonical(registry)), "source_mapping_reproduced": True,
        "full_dependency_closure_reproduced": False, "native_proofs_generated_or_verified": False,
        "source_to_binary_refinement_proved": False, "security_bits_transferred_between_routes": False,
        "qualification": qualification(),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        report, code = audit(args.repository), 0
    except (RouteAuditError, OSError, KeyError, TypeError, ValueError, RecursionError) as error:
        report = {"schema": REPORT_SCHEMA, "status": "INPUT_REJECTED", "error": str(error),
                  "source_mapping_reproduced": False, "qualification": qualification()}
        code = 2
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
