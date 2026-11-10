#!/usr/bin/env python3
"""Exact conditional sampling accounting for the two frozen P3 W1 routes.

This is an adapter/distribution certificate under explicitly ideal source-stream
assumptions. It establishes no concrete hash, Fiat-Shamir, FRI, or QROM bound.
"""
from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import io
import json
from math import prod
from pathlib import Path
import sys
import tarfile
import tomllib

P3 = "formal/pon-nakamoto-v1/w1_public_stark_research"
VENDOR = P3 + "/security_model_audit/vendor_primary"
CHECKSUMS = {
    "p3-challenger": "92cccaed1c107ad279e76dfd10aa71cff1c1898eb282f406288ad556e65e5a8f",
    "p3-fri": "9571ee760e131fc7f63115ded567d3b3d0f6d587c35b16818e266c9d6bd3bc9d",
}
MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024


class SamplingAuditError(ValueError):
    """A pinned sampler source or a distribution premise did not match."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SamplingAuditError(message)


def rational(value: Fraction) -> dict[str, str]:
    return {"numerator": str(value.numerator), "denominator": str(value.denominator)}


def mask_distribution(source_cardinality: int, bits: int) -> dict:
    """Count preimages of x -> x mod 2**bits, without enumerating the field."""
    require(type(source_cardinality) is int and source_cardinality > 0, "invalid source cardinality")
    require(type(bits) is int and 1 <= bits <= 32, "unsupported mask width")
    size = 1 << bits
    quotient, remainder = divmod(source_cardinality, size)
    require(quotient > 0, "mask range exceeds source range")
    require(remainder * (quotient + 1) + (size - remainder) * quotient == source_cardinality,
            "preimage partition identity failed")
    return {
        "source_cardinality": str(source_cardinality), "bits": bits, "index_cardinality": str(size),
        "lower_preimage_count": str(quotient), "higher_preimage_count": str(quotient + bool(remainder)),
        "higher_count_indices": str(remainder), "higher_count_index_range": "0 <= index < remainder",
        "minimum_atom": rational(Fraction(quotient, source_cardinality)),
        "maximum_atom": rational(Fraction(quotient + bool(remainder), source_cardinality)),
        "total_variation_from_uniform": rational(Fraction(remainder * (size - remainder), size * source_cardinality)),
        "exactly_uniform": remainder == 0,
    }


def with_replacement(size: int, draws: int) -> dict:
    require(type(size) is int and type(draws) is int and 0 < draws <= size, "invalid draw count")
    distinct = Fraction(prod(range(size - draws + 1, size + 1)), size ** draws)
    pairs = Fraction(draws * (draws - 1), 2 * size)
    return {
        "draws": draws, "index_cardinality": str(size), "sampling": "with_replacement",
        "draws_are_guaranteed_distinct": False,
        "probability_at_least_one_duplicate": rational(1 - distinct),
        "expected_colliding_pairs": rational(pairs),
        "duplicate_probability_union_bound": rational(min(Fraction(1), pairs)),
        "probability_scope": "independent_uniform_index_draws_only_not_a_FRI_failure_probability",
    }


def archive_sources(root: Path, package: str, members: list[str], lock: dict) -> tuple[dict[str, str], dict]:
    from w1_stark_route_audit import regular_file

    selected = [row for row in lock["package"] if row["name"] == package]
    require(len(selected) == 1 and selected[0]["version"] == "0.8.0"
            and selected[0]["source"] == "registry+https://github.com/rust-lang/crates.io-index"
            and selected[0]["checksum"] == CHECKSUMS[package], "locked sampler dependency differs")
    relative = VENDOR + "/" + package + "-0.8.0.crate"
    path = regular_file(root, relative)
    require(path.stat().st_size <= MAX_ARCHIVE_BYTES, "sampler dependency archive too large")
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == CHECKSUMS[package], "sampler dependency checksum differs")
    output, pins = {}, []
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        roster = archive.getmembers()
        require(len(roster) <= 4096, "sampler dependency member count exceeds limit")
        for member in members:
            name = package + "-0.8.0/" + member
            matches = [row for row in roster if row.name == name]
            require(len(matches) == 1 and matches[0].isfile()
                    and 0 < matches[0].size <= MAX_MEMBER_BYTES, "missing/invalid selected sampler member: " + name)
            handle = archive.extractfile(matches[0])
            require(handle is not None, "missing selected sampler bytes")
            data = handle.read(MAX_MEMBER_BYTES + 1)
            require(len(data) == matches[0].size, "selected sampler member length differs")
            output[member] = data.decode("utf-8")
            pins.append({"member": member, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return output, {"path": relative, "bytes": len(raw), "sha256": CHECKSUMS[package], "members": pins}


def contains(source: str, *anchors: str) -> None:
    for anchor in anchors:
        require(anchor in source, "selected sampler anchor absent: " + anchor)


def build_report(root: Path) -> dict:
    from w1_stark_route_audit import audit, regular_file

    routes = audit(root)
    lock = tomllib.loads(regular_file(root, P3 + "/Cargo.lock").read_text())
    challenger, challenger_pin = archive_sources(root, "p3-challenger", [
        "src/hash_challenger.rs", "src/serializing_challenger.rs", "src/duplex_challenger.rs",
        "src/fs/state/prover.rs", "src/fs/state/verifier.rs"], lock)
    fri, fri_pin = archive_sources(root, "p3-fri", ["src/transcript.rs", "src/prover.rs",
                                              "src/verifier.rs", "src/two_adic_pcs.rs"], lock)
    contains(challenger["src/hash_challenger.rs"], "self.output_buffer", ".pop()", "self.flush()")
    serial = challenger["src/serializing_challenger.rs"]
    contains(serial, "CanSample<EF> for SerializingChallenger64<F, Inner>",
             "u64::from_le_bytes(inner.sample_array())", "if value < modulus",
             "EF::from_basis_coefficients_fn(|_| sample_base(&mut self.inner))",
             "let rand_u64 = u64::from_le_bytes(self.inner.sample_array());",
             "(rand_u64 & ((1u64 << bits) - 1)) as usize")
    contains(challenger["src/duplex_challenger.rs"], "let rand_f: F = self.sample();",
             "rand_usize & ((1 << bits) - 1)")
    for side in ("prover", "verifier"):
        contains(challenger[f"src/fs/state/{side}.rs"],
                 ".map(|_| TranscriptBound::wrap(self.challenger.sample_bits(width)))")
    contains(fri["src/transcript.rs"],
             ".challenge_bits(QUERY_INDICES, self.shape.index_bits, self.shape.num_queries)")
    contains(fri["src/two_adic_pcs.rs"], "fn extra_query_index_bits(&self) -> usize {\n        0\n    }")
    contains(fri["src/prover.rs"], "let index_bits = log_global_max_height + folding.extra_query_index_bits();",
             '"log_global_max_height must match the largest input length"')
    contains(fri["src/verifier.rs"], "log_global_max_height + folding.extra_query_index_bits(),")
    old, tagged = routes["routes"][1:]
    require(old["fri"]["queries"] == tagged["fri"]["queries"] == 64, "query count differs")
    p = int(tagged["field"]["characteristic"])
    require(p == (1 << 64) - (1 << 32) + 1 and int(tagged["field"]["extension_degree"]) == 2,
            "fixed sampling field differs")
    raw_size = 1 << 64
    reject = Fraction(raw_size - p, raw_size)
    components = []
    for component in tagged["full_w1_fixed_components"]:
        bits = component["evaluation_log2"]
        require(bits in (15, 16), "fixed tagged query index width differs")
        raw_mask, field_mask = mask_distribution(raw_size, bits), mask_distribution(p, bits)
        components.append({
            "name": component["name"], "index_bits": bits,
            "index_width_derivation": "fixed_registry_evaluation_log2_plus_TwoAdicFriFolding_extra_bits_zero",
            "tagged_raw_byte_sampler": raw_mask,
            "legacy_field_mask_comparison_at_same_width": field_mask,
            "legacy_comparison_scope": "same_width_adapter_comparison_not_all_legacy_AIR_shapes",
            "tagged_iid_index_draw_accounting": with_replacement(1 << bits, 64),
            "legacy_iid_field_mask_64_draw_total_variation_union_bound": rational(
                min(Fraction(1), 64 * Fraction(p % (1 << bits) * ((1 << bits) - p % (1 << bits)), (1 << bits) * p))),
        })
    return {
        "schema": "TRNM-W1-P3-CONDITIONAL-SAMPLING1",
        "status": "PINNED_ADAPTERS_AND_CONDITIONAL_COUNTS_REPRODUCED_SECURITY_HOLD",
        "route_audit_registry_sha256": routes["registry_sha256"],
        "source_scope": "two_package_archives_and_selected_sampling_call_path_not_full_build_closure",
        "dependency_sources": [challenger_pin, fri_pin],
        "route_ids": [old["route_id"], tagged["route_id"]],
        "conditional_source_models": {
            "tagged": "unbounded independent uniform bytes; no claim actual shared SHA3 stream is ideal",
            "legacy": "independent uniform Goldilocks elements; no claim actual shared Poseidon2 stream is ideal",
            "adaptivity": "fixed pinned sampling schedule; adversarial selection and QROM programming not accounted",
        },
        "tagged_field_sampling": {
            "candidate_bytes": 8, "candidate_byte_order": "little_endian_in_reverse_digest_pop_order",
            "candidate_cardinality": str(raw_size), "field_cardinality": str(p),
            "rejected_candidate_count": str(raw_size - p), "single_candidate_rejection_probability": rational(reject),
            "accepted_base_value_probability": rational(Fraction(1, p)),
            "extension_degree": 2, "accepted_extension_value_probability": rational(Fraction(1, p * p)),
            "expected_candidates_per_extension": rational(Fraction(2 * raw_size, p)),
            "first_four_candidates_all_rejected_probability": rational(reject ** 4),
            "finite_worst_case_candidate_limit_in_adapter": None,
            "all_probabilities_scope": "ideal_independent_uniform_candidate_bytes_only",
        },
        "components": components,
        "qualification": {
            "sampler_integer_identities_checked": True, "concrete_hash_uniformity_proved": False,
            "fixed_transcript_schedule_soundness_proved": False, "native_sampler_executed_by_this_reader": False,
            "complete_fri_or_pcs_soundness_proved": False, "fiat_shamir_knowledge_soundness_proved": False,
            "quantum_extraction_proved": False, "recursive_composition_proved": False,
            "quantum_security_bits": None, "whole_lifetime_failure_bound": None,
            "production_qualified": False, "consensus_admission": False,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        result, code = build_report(args.repository.resolve(strict=True)), 0
    except (ValueError, OSError, KeyError, TypeError, UnicodeError, tarfile.TarError) as error:
        result, code = {"schema": "TRNM-W1-P3-CONDITIONAL-SAMPLING1", "status": "INPUT_REJECTED",
                        "error": str(error), "production_qualified": False, "consensus_admission": False}, 2
    print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
