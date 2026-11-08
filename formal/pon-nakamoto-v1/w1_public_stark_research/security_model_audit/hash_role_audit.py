#!/usr/bin/env python3
"""Exact arithmetic audit of P3 0.8.0's shared width-eight hash construction.

This is a counterexample to two *primitive models*, not a Merkle or W1 forgery.
No soundness, ROM, QROM, or PQ security number is certified by this program.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

P = 18446744069414584321
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "source_inputs"
WIDTH = 8
RATE = 4
M4 = ((2, 3, 1, 1), (1, 2, 3, 1), (1, 1, 2, 3), (3, 1, 1, 2))


def checked_sources() -> dict[str, str]:
    manifest = json.loads((SOURCE / "manifest.json").read_text())
    result = {}
    for entry in manifest["files"]:
        path = SOURCE / entry["file"]
        body = path.read_bytes()
        actual = hashlib.sha256(body).hexdigest()
        if actual != entry["sha256"]:
            raise ValueError(f"source digest mismatch: {entry['file']}")
        result[entry["file"]] = body.decode("utf-8")
    return result


def numbers_in_constant(source: str, symbol: str, count: int) -> list[int]:
    # Stop at the declaration terminator; arrays contain only explicit hex constants.
    expression = source.split(f"pub const {symbol}:", 1)[1].split(";\n", 1)[0]
    values = [int(x, 16) for x in re.findall(r"0x[0-9a-fA-F]+", expression)]
    if len(values) != count or any(x >= P for x in values):
        raise ValueError(f"unexpected constant shape: {symbol}")
    return values


def mat_vec(matrix: list[list[int]], state: list[int]) -> list[int]:
    return [sum(a * b for a, b in zip(row, state)) % P for row in matrix]


def inverse_matrix(matrix: list[list[int]]) -> list[list[int]]:
    n = len(matrix)
    rows = [row[:] + [int(i == j) for j in range(n)] for i, row in enumerate(matrix)]
    for column in range(n):
        pivot = next((i for i in range(column, n) if rows[i][column] % P), None)
        if pivot is None:
            raise ValueError("singular matrix")
        rows[column], rows[pivot] = rows[pivot], rows[column]
        scale = pow(rows[column][column], -1, P)
        rows[column] = [v * scale % P for v in rows[column]]
        for i in range(n):
            if i != column:
                scale = rows[i][column]
                rows[i] = [(a - scale * b) % P for a, b in zip(rows[i], rows[column])]
    inverse = [row[n:] for row in rows]
    for i in range(n):
        for j in range(n):
            if sum(matrix[i][k] * inverse[k][j] for k in range(n)) % P != int(i == j):
                raise AssertionError("inverse matrix certificate failed")
    return inverse


class Poseidon2:
    """Scalar reference for the exact official width-eight parameter set."""

    def __init__(self, sources: dict[str, str]):
        source = sources["goldilocks_poseidon2.rs"]
        self.initial = numbers_in_constant(source, "GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_INITIAL", 32)
        self.final = numbers_in_constant(source, "GOLDILOCKS_POSEIDON2_RC_8_EXTERNAL_FINAL", 32)
        self.internal = numbers_in_constant(source, "GOLDILOCKS_POSEIDON2_RC_8_INTERNAL", 22)
        diagonal = numbers_in_constant(source, "MATRIX_DIAG_8_GOLDILOCKS", 8)
        # Upstream mds_light_permutation: [[2M, M], [M, 2M]].
        self.external_matrix = [
            [M4[i % 4][j % 4] * (2 if i // 4 == j // 4 else 1) for j in range(8)]
            for i in range(8)
        ]
        self.internal_matrix = [[(1 + (diagonal[i] if i == j else 0)) % P for j in range(8)] for i in range(8)]
        self.external_inverse = inverse_matrix(self.external_matrix)
        self.internal_inverse = inverse_matrix(self.internal_matrix)
        self.inverse_sbox_exponent = pow(7, -1, P - 1)
        if 7 * self.inverse_sbox_exponent % (P - 1) != 1:
            raise AssertionError("S-box inverse certificate failed")

    @staticmethod
    def validate(state: list[int]) -> None:
        if len(state) != WIDTH or any(type(x) is not int or not 0 <= x < P for x in state):
            raise ValueError("expected eight canonical Goldilocks elements")

    def permute(self, state: list[int]) -> list[int]:
        self.validate(state)
        out = mat_vec(self.external_matrix, state)
        for i in range(0, 32, 8):
            out = mat_vec(self.external_matrix, [pow(x + c, 7, P) for x, c in zip(out, self.initial[i:i + 8])])
        for constant in self.internal:
            out[0] = pow(out[0] + constant, 7, P)
            out = mat_vec(self.internal_matrix, out)
        for i in range(0, 32, 8):
            out = mat_vec(self.external_matrix, [pow(x + c, 7, P) for x, c in zip(out, self.final[i:i + 8])])
        return out

    def invert(self, state: list[int]) -> list[int]:
        self.validate(state)
        out = state[:]
        for i in reversed(range(0, 32, 8)):
            out = mat_vec(self.external_inverse, out)
            out = [(pow(x, self.inverse_sbox_exponent, P) - c) % P for x, c in zip(out, self.final[i:i + 8])]
        for constant in reversed(self.internal):
            out = mat_vec(self.internal_inverse, out)
            out[0] = (pow(out[0], self.inverse_sbox_exponent, P) - constant) % P
        for i in reversed(range(0, 32, 8)):
            out = mat_vec(self.external_inverse, out)
            out = [(pow(x, self.inverse_sbox_exponent, P) - c) % P for x, c in zip(out, self.initial[i:i + 8])]
        return mat_vec(self.external_inverse, out)


def compress(perm: Poseidon2, left: list[int], right: list[int]) -> list[int]:
    if len(left) != 4 or len(right) != 4:
        raise ValueError("compress requires two four-element children")
    return perm.permute(left + right)[:4]


def hash_leaf(perm: Poseidon2, values: list[int]) -> tuple[list[int], list[list[int]]]:
    if any(type(x) is not int or not 0 <= x < P for x in values):
        raise ValueError("leaf values must be canonical Goldilocks elements")
    state = [0] * 8
    calls = []
    for offset in range(0, len(values), 4):
        block = values[offset:offset + 4]
        state[:len(block)] = block
        calls.append(state[:])
        state = perm.permute(state)
    return state[:4], calls


def check_vectors(perm: Poseidon2) -> dict:
    # Official p3-goldilocks 0.8.0 test_default_goldilocks_poseidon2_width_8.
    kat_in = list(range(8))
    kat_out = [int(x, 16) for x in (
        "020cf04a1b214d14", "84e14aaaeacaed25", "1ae0f640e81c7457", "a4d204cbaeb0d8a5",
        "0cf637b627b3a7ff", "788d304d948b486b", "7327133ea1949af4", "f415abb924da395b",
    )]
    if perm.permute(kat_in) != kat_out or perm.invert(kat_out) != kat_in:
        raise AssertionError("official known-answer test mismatch")
    for state in ([0] * 8, [P - 1] * 8, [(i * i * 17 + 91) % P for i in range(8)]):
        if perm.permute(perm.invert(state)) != state or perm.invert(perm.permute(state)) != state:
            raise AssertionError("inverse roundtrip mismatch")

    digest = [0, 1, 2, 3]
    post_a = digest + [4, 5, 6, 7]
    post_b = digest + [4, 5, 6, 8]
    pre_a, pre_b = perm.invert(post_a), perm.invert(post_b)
    if pre_a == pre_b or compress(perm, pre_a[:4], pre_a[4:]) != digest or compress(perm, pre_b[:4], pre_b[4:]) != digest:
        raise AssertionError("arbitrary-input compression collision certificate failed")

    leaf_four = [11, 22, 33, 44]
    h4, calls4 = hash_leaf(perm, leaf_four)
    if h4 != compress(perm, leaf_four, [0] * 4):
        raise AssertionError("leaf-compression overlap certificate failed")
    h2, calls2 = hash_leaf(perm, [11, 22])
    h4zero, calls4zero = hash_leaf(perm, [11, 22, 0, 0])
    if h2 != h4zero or calls2 != calls4zero:
        raise AssertionError("fixed-role cross-length overlap certificate failed")

    rows = []
    for width in (2, 4, 18, 27, 516, 7728):
        values = [(i * 19 + 31) % P for i in range(width)]
        leaf, calls = hash_leaf(perm, values)
        final = calls[-1]
        if leaf != compress(perm, final[:4], final[4:]):
            raise AssertionError("last-call relation failed")
        rows.append({"base_field_width": width, "permutation_calls_per_leaf": len(calls), "tail_elements": width % 4 or 4, "leaf_equals_compression_of_last_state": True})

    return {
        "schema": "trnm-p3-shared-permutation-audit-v1",
        "qualification": "HOLD_NO_GO",
        "claims": {
            "official_known_answer_matched": True,
            "reference_inverse_roundtrip_matched": True,
            "arbitrary_input_compression_collision_constructed": True,
            "independent_leaf_compressor_random_functions_model_refuted": True,
            "fixed_role_h2_h4_inputs_overlap": True,
            "merkle_binding_attack_demonstrated": False,
            "false_w1_proof_constructed": False,
            "complete_noninteractive_bound_established": False,
            "qrom_or_pq128_established": False,
        },
        "collision": {"preimage_a": pre_a, "preimage_b": pre_b, "full_output_a": post_a, "full_output_b": post_b, "common_compression_digest": digest, "construction_cost": {"inverse_permutations": 2, "search_trials": 0}},
        "h4_compression_overlap": {"leaf": leaf_four, "left_child": leaf_four, "right_child": [0] * 4, "common_digest": h4, "permutation_input": calls4[0]},
        "h2_h4_overlap": {"short_leaf": [11, 22], "long_leaf": [11, 22, 0, 0], "common_digest": h2, "permutation_input": calls2[0]},
        "fixed_width_last_call_relations": rows,
        "independent_ro_equality_probability": {"numerator": "1", "denominator": str(P ** 4)},
        "lifecycle_budget_effect": {
            "shared_primitive": "default_goldilocks_poseidon2_8",
            "merge_forward_and_inverse_access_across_roles": True,
            "standalone_independent_oracle_role_bounds_applicable": False,
            "union_bound_requires_independence": False,
            "adversarial_offline_queries_bounded_by_verifier_count": False,
            "numeric_lifetime_soundness_bound": None,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    sources = checked_sources()
    result = check_vectors(Poseidon2(sources))
    result["source_manifest_sha256"] = hashlib.sha256((SOURCE / "manifest.json").read_bytes()).hexdigest()
    encoded = json.dumps(result, indent=2) + "\n"
    if args.out:
        args.out.write_text(encoded)
    print(encoded, end="")


if __name__ == "__main__":
    main()
