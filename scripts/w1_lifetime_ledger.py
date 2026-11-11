#!/usr/bin/env python3
"""Exact conditional lifetime accounting and three independent acceptance lines.

This is a ledger and a fixed-source survey, not a receipt/signature verifier,
quantum-resource measurement, QROM instantiation, or admission policy. Counts
are caller-supplied upper-bound premises. No elapsed time, successful proof
count, FRI query count or native permutation count is converted into a quantum
query budget. Unknowns survive even multiplication by a known zero.

The purpose roster is SELECTED IMPLEMENTATION COVERAGE, never an assertion
that all hash uses have been found. Shared primitive uses are kept in one
accounting group; this grouping does not prove an ideal-oracle model. Classical
control labels do not split a superposition query into independent oracles.

The conditional union expression requires a uniform bound at every opportunity,
over admissible quantum auxiliary states and all prior history, offline
information and the SAME lifetime query envelope. It needs no independence.
A bound for one fixed statement,
one successful receipt, or a fresh oracle is not accepted in that slot.
Even a fully populated hypothetical input cannot qualify any project gate.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[1]
INPUT_SCHEMA = "TRNM-W1-LIFETIME-LEDGER-INPUT1"
OUTPUT_SCHEMA = "TRNM-W1-LIFETIME-LEDGER-REPORT1"
# Exact Git source for the twenty selected SOURCE_PINS, reviewed independently
# of the child commit containing this ledger and its successor report. This is
# selected source identity only; it does not identify an executed binary or
# establish any proof, lifetime, consensus, or production qualification.
SOURCE_BASE = "622c402c273f6a9f433eb8b63cd501fd1db486e5"
MAX_INPUT_BYTES = 262144
MAX_INTEGER_BITS = 512
PHASES = (
    "offline_preprocessing",
    "accepted_root_attempts",
    "failed_aborted_root_attempts",
    "recursive_subproof_nodes",
    "adaptive_restart_batches",
    "delegated_service_batches",
    "cross_protocol_unclassified_batches",
)
LIFETIME_FIELDS = (
    "online_seconds",
    "processors_max",
    "offline_batches_per_processor_max",
    "accepted_root_attempts_per_processor_max",
    "failed_aborted_root_attempts_per_processor_max",
    "recursive_nodes_per_root_attempt_max",
    "adaptive_restart_batches_per_processor_max",
    "delegated_service_batches_per_processor_max",
    "cross_protocol_batches_per_processor_max",
)
OVERHEADS = ("extractor", "relation_decider", "oracle_simulator")
MASSES = ("fiat_shamir_online", "vector_commitment_online")
UNIFORM_CONDITIONING = (
    "all_prior_history_offline_information_quantum_auxiliary_states_and_same_lifetime_query_envelope"
)
EVENTS = (
    "authorization_admission_opportunities",
    "complete_relation_verification_opportunities",
    "work_weight_acceptance_opportunities",
)
GROUPS = {
    "poseidon2_shared": {
        "primitive": "Poseidon2 over BabyBear; concrete-to-ideal interface unresolved",
        "selected_roles": [
            "STARK Merkle leaves", "STARK Merkle internal nodes",
            "recursion control-tree internal nodes", "transcript message hashing",
            "stateful Fiat-Shamir RNG permutation",
        ],
    },
    "sha256_shared": {
        "primitive": "SHA-256; per-role assumptions and joint oracle model unresolved",
        "selected_roles": [
            "native W1 challenge/task/noise/ticket domains",
            "native ordered arithmetic transcript", "work/artifact/journal identities",
            "zkVM image/receipt/claim/verifier-parameter commitments",
            "TPQ1 canonical SPKI key identity",
        ],
    },
    "sha384_shared": {
        "primitive": "SHA-384; mapping and cross-use assumptions unresolved",
        "selected_roles": ["TPQ1 length-framed payload commitment"],
    },
    "sha512_shared": {
        "primitive": "SHA-512; mapping and cross-use assumptions unresolved",
        "selected_roles": [
            "crypto profile configuration identity",
            "separate candidate profile commitments",
        ],
    },
    "mldsa_xof": {
        "primitive": "ML-DSA XOF calls; dependency/model boundary not expanded here",
        "selected_roles": [
            "ML-DSA-65 internal XOF use (locked ml-dsa depends on shake)",
        ],
    },
    "other_unmapped": {
        "primitive": "Unsurveyed or unclassified primitive interfaces",
        "selected_roles": ["remaining protocol/authorization/application hash uses"],
    },
}
SOURCE_PINS = {
    "trillionnium/crates/trnm-crypto-primitives/Cargo.toml": "410cfe7ac27b90887b1e2bac49ed1928b66fd4c70d0747e733df0bfeb9fb27e3",
    "trillionnium/Cargo.lock": "759c42c62d7b9a72d93c533039b5bf47f3508efabf1f1ee63f5eee59b9b9e55f",
    "trillionnium/crates/trnm-crypto-primitives/src/pq_auth.rs": "536270dab4fd54a243a10c90eff2a4269911ad1537196dc937b6e3a33082929b",
    "trillionnium/crates/trnm-protocol/src/pq_frame.rs": "9fd553c520759f05e0f81b5d740a25a045a8c0424349aa94ff786f74b881a429",
    "trillionnium/crates/trnm-protocol/src/crypto_profile.rs": "1913065a325e540797df6bf1b7319b331d76ac1c7c2ea1920d19a822e702654a",
    "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs": "7c404502cbcc358b95cbf4f5ae88a1582e144562790913266eba599e5da8341d",
    "trillionnium/crates/trnm-pon-node/src/pq_application_v6.rs": "7591e929cd32bc7fff51710c5e585eb8f557f18077c8997b89832793ff300d20",
    "trillionnium/crates/trnm-pon-node/src/store.rs": "108621f304255841ea2e1a7353858c3f0f5d8cb70a235f6a4aef6d57ebe0c554",
    "trillionnium/crates/trnm-pon-node/src/consensus.rs": "a5600aeb8287cce30ae3075b675082df4e6e5569a80f23e9a2e381f8202a8f62",
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs": "33cb571d1338a949677092d0dc3f6c955cd8ad6d3524cee0cd5b528e1c146d03",
    "config/pon/devnet-v1.json": "4491b96ead11a020e8d71f27713368b65e663eef5cfc6fd0800a166b0c2a20d4",
    "formal/pon-nakamoto-v1/work_query_bound.py": "d6b5c3b25f6cd8287de5b927f271d0436ffe736470eb914d02a8a17497ea0909",
    "formal/pon-nakamoto-v1/w1_quantum_oracle.py": "5a1a250680299561cb83b0b7d17ab57cf180e64277f981f5130cdf04e70aeb99",
    "formal/pon-nakamoto-v1/w1_quantum_restricted_oracle.py": "b590ed91d491577c494a667a9271410b420dc35b7088705ef99982c2abd3b702",
    "formal/pon-nakamoto-v1/quantum_oracle_resources.py": "72879d40ff1583b514cb43ab10f1fd69edb60522f9c67997dfd200747977279f",
    "formal/pon-nakamoto-v1/quantum_resource_clock.py": "8d7257c315da4590e463b6bdb49434d284c0239681d6d8e50759dafda42c456a",
    "formal/pon-nakamoto-v1/quantum_daa_model.py": "4dd08a40f9719b6a8e310c65b63fc3af44b6d4fb6a6db83af296600334da747b",
    "formal/pon-nakamoto-v1/w1_hardened_verifier/src/main.rs": "53048b6a7fd413bfb25abee86c4b7868be1c28364d43f53dc1bb2e40b14ae4b5",
    "scripts/w1_fri_transcript_audit.py": "12cc991999f68d925f078888d1e18302739171ee6187bbeb2f3bfb17c19a88fc",
    "scripts/w1_qrom_implementation_audit.py": "c6fc6c36e4c2ce198c1dad465a7d36495253f844438f46df652715ea6dc8b354",
}


class LedgerError(ValueError):
    """Unsupported accounting input or source identity; never a verifier error."""


def require(condition, message):
    if not condition:
        raise LedgerError(message)


def exact(value, keys, name):
    require(type(value) is dict and set(value) == set(keys),
            name + ": exact required field set missing or extended")
    return value


def integer(value, name, minimum=0):
    if value is None:
        return None
    if type(value) is str and re.fullmatch(r"0|[1-9][0-9]*", value):
        require(len(value) <= 155, name + ": integer size limit")
        value = int(value)
    require(type(value) is int, name + ": exact integer required, not bool/float")
    require(value >= minimum and value.bit_length() <= MAX_INTEGER_BITS,
            name + ": integer outside supported range")
    return value


def rational(value, name, probability=False):
    if value is None:
        return None
    exact(value, ("numerator", "denominator"), name)
    numerator = integer(value["numerator"], name + ".numerator")
    denominator = integer(value["denominator"], name + ".denominator", 1)
    require(numerator is not None and denominator is not None,
            name + ": represent an unknown whole fraction with null")
    result = Fraction(numerator, denominator)
    require(not probability or result <= 1, name + ": probability exceeds one")
    return result


def reference(value, name):
    require(value is None or (type(value) is str and 1 <= len(value) <= 1000),
            name + ": reference must be null or nonempty text")
    return value


def known(function, *values):
    return None if any(value is None for value in values) else function(*values)


def exact_sum(values):
    values = list(values)
    return None if any(value is None for value in values) else sum(values)


def serializable(value):
    if isinstance(value, Fraction):
        return {"numerator": str(value.numerator), "denominator": str(value.denominator)}
    if type(value) is int:
        return str(value)
    if type(value) is dict:
        return {key: serializable(item) for key, item in value.items()}
    if type(value) in (list, tuple):
        return [serializable(item) for item in value]
    return value


def strict_json(data):
    require(type(data) is bytes and len(data) <= MAX_INPUT_BYTES, "input byte limit/type")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key: " + key)
            result[key] = value
        return result

    def invalid(value):
        raise LedgerError("floating/nonfinite JSON numbers are unsupported: " + value)

    try:
        value = json.loads(data, object_pairs_hook=unique, parse_float=invalid,
                           parse_constant=invalid,
                           parse_int=lambda value: integer(value, "JSON integer"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise LedgerError("invalid JSON") from error
    require(type(value) is dict, "input must be an object")
    return value


def template():
    """Explicit unknown project input; no hidden value substitutes."""
    return {
        "schema": INPUT_SCHEMA,
        "input_kind": "project_unqualified",
        "scope": {
            "pre_deployment_queries_included": True,
            "all_identities_processors_and_reorganizations_share_budget": True,
            "protocol_upgrades_do_not_reset_budget": True,
            "query_unit": "abstract_quantum_oracle_invocation_not_native_permutation_count",
            "coverage": "selected_implementation_coverage_not_exhaustive",
        },
        "lifetime": dict.fromkeys(LIFETIME_FIELDS),
        "lifetime_bound_reference": None,
        "groups": {
            name: {
                "queries_per_occurrence_upper": dict.fromkeys(PHASES),
                "query_bound_reference": None,
                "additional_reduction_queries_upper": dict.fromkeys(OVERHEADS),
                "online_mass_upper": dict.fromkeys(MASSES),
            } for name in GROUPS
        },
        "uniform_event_bounds": {
            name: {
                "opportunities_max": None,
                "error_per_opportunity_upper": None,
                "assumed_bound_valid_up_to_joint_queries": None,
                "conditioning": UNIFORM_CONDITIONING,
                "bound_reference": None,
            } for name in EVENTS
        },
        "total_target_error": None,
    }


def phase_occurrences(lifetime):
    """All counts include every independent processor, with no per-block reset."""
    processors = lifetime["processors_max"]
    roots_per_processor = exact_sum((
        lifetime["accepted_root_attempts_per_processor_max"],
        lifetime["failed_aborted_root_attempts_per_processor_max"],
    ))
    counts = {
        "offline_preprocessing": lifetime["offline_batches_per_processor_max"],
        "accepted_root_attempts": lifetime["accepted_root_attempts_per_processor_max"],
        "failed_aborted_root_attempts": lifetime["failed_aborted_root_attempts_per_processor_max"],
        "recursive_subproof_nodes": known(
            lambda a, b: a * b, roots_per_processor,
            lifetime["recursive_nodes_per_root_attempt_max"]),
        "adaptive_restart_batches": lifetime["adaptive_restart_batches_per_processor_max"],
        "delegated_service_batches": lifetime["delegated_service_batches_per_processor_max"],
        "cross_protocol_unclassified_batches": lifetime["cross_protocol_batches_per_processor_max"],
    }
    return {key: known(lambda a, b: a * b, processors, value)
            for key, value in counts.items()}


def evaluate(raw):
    """Return exact arithmetic under explicit, UNVERIFIED numerical premises."""
    base = template()
    exact(raw, base, "input")
    require(raw["schema"] == INPUT_SCHEMA, "unsupported schema")
    require(raw["input_kind"] in ("project_unqualified", "hypothetical"), "input kind")
    exact(raw["scope"], base["scope"], "scope")
    require(all(type(raw["scope"][key]) is type(expected)
                and raw["scope"][key] == expected
                for key, expected in base["scope"].items()),
            "lifetime/coverage/query-unit scope changed")
    exact(raw["lifetime"], LIFETIME_FIELDS, "lifetime")
    life = {key: integer(value, "lifetime." + key,
                         1 if key in ("online_seconds", "processors_max") else 0)
            for key, value in raw["lifetime"].items()}
    life_ref = reference(raw["lifetime_bound_reference"], "lifetime_bound_reference")
    require(not any(value is not None for value in life.values()) or life_ref is not None,
            "numerical lifetime assumptions need a reference (not a proof certificate)")
    occurrences = phase_occurrences(life)
    exact(raw["groups"], GROUPS, "groups")
    groups = {}
    for name in GROUPS:
        item = exact(raw["groups"][name], base["groups"][name], "group." + name)
        exact(item["queries_per_occurrence_upper"], PHASES, name + ".phases")
        per = {key: integer(value, name + "." + key)
               for key, value in item["queries_per_occurrence_upper"].items()}
        qref = reference(item["query_bound_reference"], name + ".query_bound_reference")
        exact(item["additional_reduction_queries_upper"], OVERHEADS, name + ".overheads")
        overhead = {key: integer(value, name + ".overheads." + key)
                    for key, value in item["additional_reduction_queries_upper"].items()}
        exact(item["online_mass_upper"], MASSES, name + ".online_mass")
        masses = {key: rational(value, name + ".mass." + key)
                  for key, value in item["online_mass_upper"].items()}
        require(not any(v is not None for v in (*per.values(), *overhead.values(), *masses.values()))
                or qref is not None, name + ": numerical query/mass premises need a reference")
        phase = {key: known(lambda a, b: a * b, occurrences[key], per[key]) for key in PHASES}
        attack = exact_sum(phase.values())
        shifted = exact_sum((attack, *overhead.values()))
        for key, value in masses.items():
            require(value is None or attack is None or value <= attack,
                    name + "." + key + ": mass exceeds declared adversary query envelope")
        groups[name] = {
            **GROUPS[name],
            "queries_by_phase_upper": phase,
            "adversary_queries_upper": attack,
            "additional_reduction_queries_upper": overhead,
            "additive_query_envelope_with_declared_overheads": shifted,
            "online_mass_upper": masses,
            "query_bound_reference_unverified": qref,
            "mapped_to_cdhz_t_or_w": False,
        }
    all_queries = exact_sum(group["adversary_queries_upper"] for group in groups.values())
    all_shifted = exact_sum(group["additive_query_envelope_with_declared_overheads"]
                            for group in groups.values())
    exact(raw["uniform_event_bounds"], EVENTS, "uniform_event_bounds")
    event_terms = {}
    for name in EVENTS:
        item = exact(raw["uniform_event_bounds"][name],
                     base["uniform_event_bounds"][name], "event." + name)
        require(item["conditioning"] == UNIFORM_CONDITIONING,
                name + ": marginal/fresh-instance/accepted-only bounds do not compose here")
        count = integer(item["opportunities_max"], name + ".opportunities_max")
        error = rational(item["error_per_opportunity_upper"], name + ".error", probability=True)
        query_limit = integer(item["assumed_bound_valid_up_to_joint_queries"],
                              name + ".assumed_bound_valid_up_to_joint_queries")
        require(query_limit is None or all_shifted is None or query_limit >= all_shifted,
                name + ": bound query domain does not cover the declared lifetime envelope")
        ref = reference(item["bound_reference"], name + ".bound_reference")
        require(error is None or ref is not None,
                name + ": a numerical conditional error needs an explicit premise reference")
        event_terms[name] = {
            "opportunities_max": count,
            "error_per_opportunity_upper": error,
            "assumed_bound_valid_up_to_joint_queries": query_limit,
            "union_addend": known(lambda a, b: a * b, count, error),
            "bound_reference_unverified": ref,
        }
    root_attempts = exact_sum((occurrences["accepted_root_attempts"],
                               occurrences["failed_aborted_root_attempts"]))
    relation_opportunities = event_terms["complete_relation_verification_opportunities"]["opportunities_max"]
    require(root_attempts is None or relation_opportunities is None
            or relation_opportunities >= root_attempts,
            "complete-relation opportunity envelope omits accepted/failed root attempts")
    target = rational(raw["total_target_error"], "total_target_error", probability=True)
    require(target is None or target > 0, "total target must be positive")
    raw_union = exact_sum(item["union_addend"] for item in event_terms.values())
    probability_union = known(lambda value: min(Fraction(1), value), raw_union)
    # A conditional expression cannot meet even a hypothetical target until the
    # SAME lifetime/query/overhead/mass premises have all been supplied.
    all_cells = [
        *life.values(), target, all_queries, all_shifted, raw_union,
        *(value for group in groups.values() for value in group["online_mass_upper"].values()),
        *(item["assumed_bound_valid_up_to_joint_queries"] for item in event_terms.values()),
    ]
    numeric_complete = all(value is not None for value in all_cells)
    comparison = (probability_union <= target
                  if numeric_complete and raw["input_kind"] == "hypothetical" else None)
    return {
        "input_kind": raw["input_kind"],
        "scope": dict(raw["scope"]),
        "lifetime": life,
        "lifetime_bound_reference_unverified": life_ref,
        "occurrences_all_processors_upper": occurrences,
        "groups": groups,
        "sum_of_group_adversary_query_envelopes": all_queries,
        "sum_with_declared_additional_reduction_queries": all_shifted,
        "all_required_numerical_cells_supplied": numeric_complete,
        "coverage_exhaustiveness_proved": False,
        "quantum_query_unit_instantiated": False,
        "conditional_union": {
            "conditioning": UNIFORM_CONDITIONING,
            "events": event_terms, "unclipped_expression": raw_union,
            "probability_expression": probability_union, "target": target,
            "hypothetical_expression_meets_target": comparison,
            "project_total_error_upper": None,
            "project_target_met": None,
            "uniform_conditional_premises_verified": False,
            "composition_theorem_instantiated": False,
        },
        "boundary": [
            "Phase envelopes may conservatively overlap; no purpose-level query independence is inferred.",
            "One coherent invocation may address several purpose tags; retain the shared oracle and pay its actual invocation cost.",
            "The sums are caller-premised upper envelopes, not measured adversarial queries or CDHZ shifted-budget substitutions.",
            "Missing failed, offline, recursive, delegated or unclassified phases are rejected; explicit null stays unknown.",
            "Mass is separate from query count; no w=t default and no unproved sum-of-masses identity.",
            "Extractor, relation-decider and oracle-simulator costs need the actual composition theorem and may be correlated.",
            "Local request/signature CPU limits do not cap an adversary's independent quantum computations.",
            "Accepted top-level receipts alone bound neither abandoned search nor the size of internal recursive trees.",
        ],
    }


def work_lottery(target, bits=256):
    """Inclusive ticket arithmetic, conditional on an ideal uniform ticket."""
    bits = integer(bits, "bits", 2)
    require(bits is not None and bits <= 256, "bits range")
    target = integer(target, "target", 1)
    require(target is not None and target < (1 << bits), "target range")
    modulus = 1 << bits
    work = modulus // (target + 1)
    return {
        "target": target, "bits": bits, "weight": work,
        "ideal_hit_probability": Fraction(target + 1, modulus),
        "ideal_expected_credit_per_distinct_classical_first_query":
            Fraction((target + 1) * work, modulus),
    }


def counterexamples():
    """Exact examples of invalid inferences; none is a live Chain attack."""
    partitions = [10, 10]
    power = {
        str(degree): {
            "shared_total_power": sum(partitions) ** degree,
            "incorrect_sum_of_reset_powers": sum(value ** degree for value in partitions),
            "understatement_factor": Fraction(sum(partitions) ** degree,
                                               sum(value ** degree for value in partitions)),
        } for degree in (2, 3)
    }
    outcomes = range(16)
    fixed_failure = Fraction(sum(r == 0 for r in outcomes), 16)
    adaptive_failure = Fraction(sum(r == r for r in outcomes), 16)
    ordinary = work_lottery((1 << 248) - 1)
    harder = work_lottery((1 << 244) - 1)
    weight_ratio = Fraction(harder["weight"], ordinary["weight"])
    return {
        "query_reset": {
            "partitions": partitions, "powers": power,
            "scope": "Polynomial accounting counterexample, not a concrete QROM bound.",
        },
        "adaptive_statement_selection": {
            "experiment": "Uniform R in 0..15; statement x fails exactly when x=R. History reveals R before x is selected.",
            "failure_for_fixed_statement_zero": fixed_failure,
            "failure_for_adaptively_selected_statement_R": adaptive_failure,
            "scope": "A fixed-statement marginal bound is not uniform conditional soundness.",
        },
        "per_event_target": {
            "opportunities": 64,
            "per_opportunity_error": Fraction(1, 1 << 128),
            "union_expression": Fraction(64, 1 << 128),
            "whole_lifetime_target": Fraction(1, 1 << 128),
            "meets_whole_lifetime_target": False,
        },
        "difficulty_weight_cost": {
            "ordinary": ordinary, "harder": harder, "weight_ratio": weight_ratio,
            "hypothetical_quantum_cost_ratio": 4,
            "hypothetical_weight_per_cost_advantage": weight_ratio / 4,
            "scope": "Assumes equal full-oracle cost and square-root search scaling; no reachability, quantum clock, attack or finality theorem.",
        },
    }


def bounded_source(root, relative):
    path = root
    require(not path.is_symlink(), "root symlink")
    for part in Path(relative).parts:
        path = path / part
        require(not path.is_symlink(), "source symlink: " + relative)
    try:
        with path.open("rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                    "nonregular source: " + relative)
            value = stream.read(2 * 1024 * 1024 + 1)
    except OSError as error:
        raise LedgerError("unreadable source: " + relative) from error
    require(len(value) <= 2 * 1024 * 1024, "source size bound: " + relative)
    return value


def source_survey(sources):
    """Verify selected source identities; do not execute or verify these programs."""
    exact(sources, SOURCE_PINS, "selected sources")
    records = []
    texts = {}
    for path, expected in SOURCE_PINS.items():
        value = sources[path]
        require(type(value) is bytes and len(value) <= 2 * 1024 * 1024, "source bytes: " + path)
        require(hashlib.sha256(value).hexdigest() == expected, "source identity mismatch: " + path)
        texts[path] = value.decode("utf-8")
        records.append({"path": path, "sha256": expected, "bytes": len(value)})
    lock = tomllib.loads(texts["trillionnium/Cargo.lock"])
    mldsa = [item for item in lock["package"] if item["name"] == "ml-dsa"]
    require(len(mldsa) == 1 and mldsa[0]["version"] == "0.1.1"
            and "shake" in mldsa[0]["dependencies"], "locked ML-DSA graph")
    node = "trillionnium/crates/trnm-pon-node/src/"
    crypto = "trillionnium/crates/trnm-crypto-primitives/src/"
    protocol = "trillionnium/crates/trnm-protocol/src/"
    formal = "formal/pon-nakamoto-v1/"
    anchors = (
        ("canonical_mldsa_verifier", crypto + "pq_auth.rs", "pub fn verify_exact_message",
         "One RustCrypto MlDsa65 message verifier; optional OpenSSL is a signing source, not an OR-verification fallback."),
        ("application_authority_and_failed_attempt_charge",
         "trillionnium/crates/trnm-mvcc-fee/src/pon_executor/pq_accounts_v2.rs",
         "pub fn prepare_signature_metered",
         "Resolve current witness authority, charge the shared signature counter, then verify the role/context/generation/nonce-bound TPQ1."),
        ("key_identity_sha256", protocol + "pq_frame.rs", "pub fn ml_dsa_65_key_id_from_spki",
         "Canonical ML-DSA-65 SPKI identity remains domain-separated SHA-256."),
        ("payload_sha384", protocol + "pq_frame.rs", "pub fn payload_commitment",
         "TPQ1 payload uses SHA-384 with domain and big-endian length."),
        ("profile_identity_sha512", protocol + "crypto_profile.rs",
         "bound.id = CryptoProfileId(Sha512::digest",
         "Profile configuration ID uses SHA-512; separate candidates do not migrate native W1 hashes."),
        ("native_work_verifier", node + "store.rs",
         "let work = pon_work::verify(h.challenge(), h.work_task, h.target, &packet.proof)",
         "The selected ordinary Node path obtains VerifiedWork from native PNW1, not a STARK receipt."),
        ("npq6_packet_native_work_length", node + "pq_application_v6.rs",
         "packet.proof.len() == pon_work::PROOF_BYTES",
         "PQ packet encoding retains the native complete witness length."),
        ("required_work_formula", node + "consensus.rs", "pub fn required_work(",
         "Required work is floor(2^256/(T+1)), using checked 512-bit arithmetic."),
        ("cumulative_weight", node + "store.rs",
         ".checked_add(consensus::required_work(h.target)?)",
         "Each admitted block adds branch-target required work; no quantum resource meter replaces this weight."),
        ("actual_target_rule", node + "consensus.rs", "pub fn retarget(",
         "Periodic branch-window retarget, not ASERT; arithmetic limits are not an economic security theorem."),
        ("legal_task_reuse", crypto + "pon_work.rs", "let product = producer_mul(a, b, N, N, N);",
         "PreparedTask computes public A B once and retains canonical proof prefix; challenge-specific transcript still must be produced."),
        ("classical_query_bound", formal + "work_query_bound.py", "First moment.",
         "Expected credit <= first ideal distinct classical queries under predictable target; not quantum or physical-resource security."),
        ("constructive_quantum_oracle", formal + "w1_quantum_oracle.py",
         "Constructive, deliberately nonoptimal reversible W1 winner phase oracle.",
         "A full fixed-template reversible winner construction exists; native eligibility is a classical precondition and costs are construction upper bounds."),
        ("restricted_quantum_strategy", formal + "w1_quantum_restricted_oracle.py",
         "Circuit\nresources must be coupled to THIS subset's marked count",
         "A legal prefix-restricted search strategy exists; use its own marked set, not the full predicate's success probability."),
        ("resource_accounting", formal + "quantum_oracle_resources.py",
         "Each completed measurement is followed by a classical recheck",
         "Resource model charges compute/inverse, independent processors, preprocessing, and failed-candidate rechecks; inputs are premises."),
        ("physical_clock", formal + "quantum_resource_clock.py",
         "trials = bounded(1 + case.max_events * case.max_blocks)",
         "Campaign envelope is conservative and pays all processors; serial physical clock depends on caller hardware/error assumptions."),
        ("sqrt_cost_is_assumption", formal + "quantum_daa_model.py", "def cost_ratio(",
         "Square-root cost scaling is a model choice, not a measured complete W1 oracle rate."),
        ("isolated_stark_verifier", formal + "w1_hardened_verifier/src/main.rs",
         "fn verify(",
         "Isolated hardened succinct verifier is separate from native Node admission; this survey does not rerun cryptographic verification."),
        ("fri_geometry_only", "scripts/w1_fri_transcript_audit.py",
         "This is NOT a receipt verifier or a QROM instantiation.",
         "Saved-seal geometry and native RNG permutation counts are not lifetime adversary queries."),
        ("implementation_map_only", "scripts/w1_qrom_implementation_audit.py",
         "or consensus authority.",
         "Fixed-source mapping leaves QROM reduction, lifetime policy and authority unestablished."),
    )
    observations = {}
    for name, path, needle, statement in anchors:
        require(needle in texts[path], "reviewed source anchor missing: " + name)
        position = texts[path].index(needle)
        observations[name] = {
            "path": path, "sha256": SOURCE_PINS[path],
            "anchor_line": texts[path][:position].count("\n") + 1,
            "observation": statement,
            "evidence_kind": "reviewed_fixed_source_not_fresh_execution",
        }
    config = strict_json(sources["config/pon/devnet-v1.json"])
    desired = (config["retarget_interval"] - 1) * config["target_spacing_seconds"]
    return {
        "base_commit": SOURCE_BASE,
        "coverage": "selected_implementation_coverage_not_exhaustive",
        "all_selected_source_bytes_match": True,
        "whole_repository_build_or_behavior_verified": False,
        "sources": records,
        "observations": observations,
        "canonical_signature": {
            "algorithm": "ML-DSA-65", "crate_version": mldsa[0]["version"],
            "crate_checksum": mldsa[0]["checksum"],
            "public_key_bytes": 1952, "canonical_spki_bytes": 1974, "signature_bytes": 3309,
            "message_interface": "pure ML-DSA, empty context; versioned application bytes",
        },
        "native_development_arithmetic": {
            "initial_target_lottery": work_lottery(int(config["initial_target_hex"], 16)),
            "retarget_interval": config["retarget_interval"],
            "target_spacing_seconds": config["target_spacing_seconds"],
            "desired_span_seconds": desired, "clamp_lower_seconds": (desired + 3) // 4,
            "clamp_upper_seconds": 4 * desired,
            "median_time_width": config["median_time_width"],
            "future_skew_seconds": config["future_skew_seconds"],
            "native_daa_or_chain_attack_proved": False,
        },
    }


def independent_acceptance_lines(survey):
    """Source observations never issue cross-line or within-line qualifications."""
    lines = {
        "pq_authorization": {
            "protected_claim": "The currently authorized owner approved these exact domain-bound bytes.",
            "source_observation_ids": [
                "canonical_mldsa_verifier", "application_authority_and_failed_attempt_charge",
                "key_identity_sha256", "payload_sha384", "profile_identity_sha512",
            ],
            "unclosed": [
                "Independent implementation/side-channel assessment and algorithm security assumptions.",
                "Complete authority-producing entry-point coverage and current external trust-root/custody evidence.",
                "Migration, revocation, replay, rollback and deployment composition across actual effect paths.",
                "Lifetime multi-user authorization failure bound; local signature meters are not adversary query limits.",
            ],
        },
        "complete_computation_relation": {
            "protected_claim": "The exact allowed computation relation, images, public values and recursion family are satisfied.",
            "source_observation_ids": [
                "native_work_verifier", "npq6_packet_native_work_length", "isolated_stark_verifier",
                "fri_geometry_only", "implementation_map_only",
            ],
            "unclosed": [
                "Separate native full replay from the isolated succinct-proof candidate.",
                "Whole implemented relation, RBR/state-restoration and vector-commitment extraction assumptions.",
                "Concrete shared hash/sponge/transcript model, recursive composition and all permitted control programs.",
                "A complete theorem-derived lifetime bound; current record is not fresh receipt verification.",
            ],
        },
        "quantum_work_and_chain_weight": {
            "protected_claim": "Adversarial resource expenditure corresponds to lottery wins and credited branch weight under the actual fork rule.",
            "source_observation_ids": [
                "required_work_formula", "cumulative_weight", "actual_target_rule", "legal_task_reuse",
                "classical_query_bound", "constructive_quantum_oracle", "restricted_quantum_strategy",
                "resource_accounting", "physical_clock", "sqrt_cost_is_assumption",
            ],
            "unclosed": [
                "Cheapest legal attacker strategy, preprocessing/task reuse, subset marked counts and all query costs.",
                "Physical clock/error correction/data-access assumptions and hardware calibration.",
                "Adaptive target/timestamp/withholding/restart/propagation behavior under actual branch reachability.",
                "Common-prefix/confirmation or other named security definition at equal additive resource budgets.",
            ],
        },
    }
    for line in lines.values():
        require(all(key in survey["observations"] for key in line["source_observation_ids"]),
                "acceptance line lacks its selected source observations")
        line.update({
            "status": "SOURCE_OBSERVATIONS_PRESENT_SECURITY_UNQUALIFIED",
            "qualified": False, "security_error_upper": None, "security_bits": None,
            "qualification_inferred_from_another_line": False,
        })
    return {
        "lines": lines, "all_three_qualified": False,
        "whole_chain_post_quantum_qualified": False, "production_activation": False,
        "rule": "Each claim requires its own evidence; signature validity, relation correctness and resource security do not imply one another.",
    }


def make_report(raw, root=ROOT):
    ledger = evaluate(raw)
    sources = {path: bounded_source(root, path) for path in SOURCE_PINS}
    survey = source_survey(sources)
    return serializable({
        "schema": OUTPUT_SCHEMA,
        "status": "CONDITIONAL_ACCOUNTING_AND_SELECTED_SOURCE_SURVEY_SECURITY_HOLD",
        "lifetime_ledger": ledger, "selected_source_survey": survey,
        "independent_acceptance": independent_acceptance_lines(survey),
        "counterexamples": counterexamples(),
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", help="strict ledger JSON, or - for stdin; default is all unknown")
    parser.add_argument("--template", action="store_true", help="emit all-unknown input only")
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        require(not (args.template and args.input), "choose --template or --input")
        if args.template:
            output = template()
        else:
            if args.input:
                if args.input == "-":
                    data = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
                else:
                    path = Path(args.input)
                    require(not path.is_symlink(), "input symlink")
                    with path.open("rb") as stream:
                        data = stream.read(MAX_INPUT_BYTES + 1)
                raw = strict_json(data)
            else:
                raw = template()
            output = make_report(raw, args.root)
        print(json.dumps(output, indent=2, sort_keys=True, allow_nan=False))
    except (LedgerError, OSError, tomllib.TOMLDecodeError) as error:
        print(json.dumps({"status": "REFUSED", "error": str(error)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
