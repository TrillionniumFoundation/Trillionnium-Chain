#!/usr/bin/env python3
"""Read-only exact W1 prefix algebra audit; no native generation or timing claim.

The NumPy object arrays use Python arbitrary-precision integers, never floating
point or overflowing uint64 products. Only the JSON output is written.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys

os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")
import numpy as np

Q = 4_294_967_291
N = 64
R = 8
BLOCKS = N // R
CELLS = N * N
PROOF_BYTES = 4 + 3 * CELLS * 4 + 32
EXPECTED_HEAD = "eeedfe33f9c7cd27a1855b865e7faa458047dcd1"
EXPECTED_MATERIAL = [
    "36335a31bfcde0ecdf7b7b13601ac1094b25d4c76adc1be31f598e2395d3a7c7",
    "0f1607af113b101e81a04976419b0d3f14378d29cc8587576ccb7260b351fcce",
    "233a96c663c32e769fd952f023a0aae34ab5e59f6b8fa916ac8ec09af7df084c",
    "f8fe8b6fe6e7b06c2583df08fd5441472297cc53107395770a51ceb95be31a93",
    "981fcbc8b7eee42bf0558b4bf1205489f5ae6e933140367dd054e6188b06b52b",
]
SOURCES = [
    "trillionnium/crates/trnm-crypto-primitives/src/pon_work.rs",
    *[
        "trillionnium/crates/trnm-crypto-primitives/src/pon_work/" + name
        for name in (
            "structured.rs", "blocked_zero.rs", "blocked_zero_paired.rs",
            "blocked_one_zero.rs", "maintenance_prefix.rs",
            "maintenance_periodic.rs", "paired_product.rs", "integer_paired.rs",
            "legal_attempt.rs",
        )
    ],
    "trillionnium/crates/trnm-crypto-primitives/examples/pon_shared_material_v1.rs",
]


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def load_json(data: bytes):
    return json.loads(data, object_pairs_hook=unique_object)


def pon_hash(tag: bytes, *parts: bytes) -> bytes:
    h = hashlib.sha256(b"TRNM-PON1\0" + struct.pack("<H", len(tag)) + tag)
    for part in parts:
        h.update(struct.pack("<I", len(part)))
        h.update(part)
    return h.digest()


def expand(challenge: bytes, label: int):
    values = []
    counter = 0
    rejected = 0
    while len(values) < N * R:
        if counter >= 128:
            raise ValueError("original W1 noise budget exhausted")
        chunk = pon_hash(b"noise", challenge, bytes([label]), struct.pack("<I", counter))
        counter += 1
        for (word,) in struct.iter_unpack("<I", chunk):
            if word < Q:
                values.append(word)
                if len(values) == N * R:
                    break
            else:
                rejected += 1
    return np.array(values, dtype=object), {"label": label, "hash_chunks": counter, "rejected_words": rejected}


def field_bytes(matrix) -> bytes:
    words = [int(value) for value in matrix.flat]
    assert all(0 <= value < Q for value in words)
    return struct.pack("<" + "I" * len(words), *words)


def rank_mod_q(matrix) -> int:
    a = [[int(x) for x in row] for row in matrix]
    rows, columns = matrix.shape
    rank = 0
    for column in range(columns):
        pivot = next((row for row in range(rank, rows) if a[row][column]), None)
        if pivot is None:
            continue
        a[rank], a[pivot] = a[pivot], a[rank]
        inverse = pow(a[rank][column], Q - 2, Q)
        a[rank] = [(v * inverse) % Q for v in a[rank]]
        for row in range(rank + 1, rows):
            factor = a[row][column]
            if factor:
                a[row] = [(x - factor * y) % Q for x, y in zip(a[row], a[rank])]
        rank += 1
        if rank == rows:
            break
    return rank


def transcript(challenge, prefixes):
    h = hashlib.sha256(b"TRNM-PON-TRACE1\0" + challenge)
    hashes = []
    for bi in range(BLOCKS):
        for bj in range(BLOCKS):
            for bk, prefix in enumerate(prefixes):
                tile = prefix[bi * R:(bi + 1) * R, bj * R:(bj + 1) * R]
                raw = field_bytes(tile)
                assert len(raw) == R * R * 4
                h.update(raw)
                hashes.append([bi, bj, bk, sha(raw)])
    assert len(hashes) == 512
    return h.digest(), hashes


def git_snapshot(repo):
    def run(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()
    return {
        "head": run("rev-parse", "HEAD"),
        "dirty_porcelain": run("status", "--porcelain=v1"),
        "source_files_sha256": {name: sha((repo / name).read_bytes()) for name in SOURCES},
    }


def run_case(index, root, manifest):
    material_path = root / f"tile-{index}" / "material.bin"
    native_path = root / f"tile-{index}" / "native.stdout.jsonl"
    raw = material_path.read_bytes()
    native_raw = native_path.read_bytes()
    assert len(raw) == 2 * CELLS * 4
    assert sha(raw) == EXPECTED_MATERIAL[index]
    words = struct.unpack("<" + "I" * (2 * CELLS), raw)
    assert all(0 <= value < Q for value in words)
    a = np.array(words[:CELLS], dtype=object).reshape(N, N)
    b = np.array(words[CELLS:], dtype=object).reshape(N, N)
    records = []
    for line in native_raw.splitlines():
        assert len(line) <= 4 * 1024 * 1024
        records.append(load_json(line))
    winners = [record for record in records if record.get("kind") == "winner" and record.get("cycle") == 0]
    assert len(winners) == 1
    winner = winners[0]
    assert winner["product_source"] == "VerifiedWork.product"
    assert winner["scalar_reference_equal"] is True
    proof = bytes.fromhex(winner["proof_hex"])
    assert len(proof) == PROOF_BYTES and proof[:4] == b"PNW1"
    assert sha(proof) == winner["proof_sha256"]
    assert proof[4:4 + len(raw)] == raw
    product_raw = bytes.fromhex(winner["product_hex"])
    assert proof[4 + len(raw):-32] == product_raw
    assert sha(product_raw) == winner["product_sha256"]
    challenge = bytes.fromhex(winner["challenge"])
    assert len(challenge) == 32
    task = pon_hash(b"task", raw[:CELLS * 4], raw[CELLS * 4:])
    assert task.hex() == winner["task"] == manifest["tiles"][index]["task"]
    assert sha(raw) == manifest["tiles"][index]["material_sha256"]
    ticket = pon_hash(b"ticket", challenge, proof[-32:])
    assert ticket.hex() == winner["ticket"]
    target = bytes.fromhex(winner["target"])
    assert len(target) == 32 and any(target) and ticket <= target

    noise = [expand(challenge, label) for label in range(4)]
    el = noise[0][0].reshape(N, R)
    er = noise[1][0].reshape(R, N)
    fl = noise[2][0].reshape(N, R)
    fr = noise[3][0].reshape(R, N)
    ap = (a + el @ er) % Q
    bp = (b + fl @ fr) % Q
    direct = np.zeros((N, N), dtype=object)
    s = np.zeros((N, N), dtype=object)
    u = np.zeros((N, R), dtype=object)
    v = np.zeros((R, N), dtype=object)
    m = np.zeros((R, R), dtype=object)
    dense_prefixes, factor_prefixes, middle_prefixes = [], [], []
    prefix_records = []
    for block in range(BLOCKS):
        lo, hi = block * R, (block + 1) * R
        direct = (direct + ap[:, lo:hi] @ bp[lo:hi, :]) % Q
        s = (s + a[:, lo:hi] @ b[lo:hi, :]) % Q
        u = (u + a[:, lo:hi] @ fl[lo:hi, :]) % Q
        v = (v + er[:, lo:hi] @ b[lo:hi, :]) % Q
        m = (m + er[:, lo:hi] @ fl[lo:hi, :]) % Q
        # Reduce factors before reuse, as a bounded native implementation must.
        mixed_right = (v + m @ fr) % Q
        reconstructed = (s + (u @ fr) % Q + (el @ mixed_right) % Q) % Q
        assert np.array_equal(direct, reconstructed)
        dense_prefixes.append(direct.copy())
        factor_prefixes.append(reconstructed.copy())
        middle_prefixes.append(m.copy())
        prefix_records.append({"inner_prefix": hi, "words_compared": CELLS, "dense_equals_factorized": True, "canonical_prefix_sha256": sha(field_bytes(direct))})
    assert field_bytes(s) == product_raw
    dense_trace, dense_tiles = transcript(challenge, dense_prefixes)
    factor_trace, factor_tiles = transcript(challenge, factor_prefixes)
    assert dense_tiles == factor_tiles
    assert dense_trace == factor_trace == proof[-32:]
    assert pon_hash(b"ticket", challenge, factor_trace) == ticket
    assert proof[:-32] + factor_trace == proof

    nnz_a = int(np.count_nonzero(a))
    nnz_b = int(np.count_nonzero(b))
    active_rows = int(np.count_nonzero(np.any(a != 0, axis=1)))
    sparse_setup_products = sum(int(np.count_nonzero(a[:, k])) * int(np.count_nonzero(b[k, :])) for k in range(N))
    components = {
        "middle_prefix_increments": N * R * R,
        "u_sparse_prefix_increments": R * nnz_a,
        "v_sparse_prefix_increments": R * nnz_b,
        "middle_times_fr_all_prefixes": BLOCKS * R * R * N,
        "el_times_combined_right_all_prefixes": BLOCKS * N * N * R,
        "u_times_fr_active_rows_all_prefixes": BLOCKS * active_rows * R * N,
    }
    result = {
        "tile_index": index,
        "inputs": {
            "material": {"path": str(material_path), "bytes": len(raw), "sha256": sha(raw)},
            "retained_native_jsonl": {"path": str(native_path), "bytes": len(native_raw), "sha256": sha(native_raw)},
        },
        "task": task.hex(), "challenge": challenge.hex(), "target": target.hex(),
        "retained_proof_sha256": sha(proof), "retained_product_sha256": sha(product_raw),
        "ticket": ticket.hex(), "noise_expansion": [item[1] for item in noise],
        "rank_a_mod_q": rank_mod_q(a), "rank_b_mod_q": rank_mod_q(b),
        "nonzero_a": nnz_a, "nonzero_b": nnz_b, "active_a_rows": active_rows,
        "unique_b_columns": len({tuple(int(x) for x in b[:, j]) for j in range(N)}),
        "fixed_sparse_setup_nonzero_products": sparse_setup_products,
        "general_classical_schedule_products_excluding_fixed_setup": sum(components.values()),
        "general_classical_schedule_components": components,
        "prefix_comparisons": prefix_records,
        "dense_trace": dense_trace.hex(), "factorized_trace": factor_trace.hex(),
        "retained_native_trace": proof[-32:].hex(),
        "all_512_tile_words_equal_between_python_schedules": True,
        "full_trace_matches_retained_native": True,
        "fixed_full_product_matches_retained_verified_product": True,
        "full_proof_and_ticket_bytes_unchanged": True,
        "matching_tile_hash_columns": ["bi", "bj", "bk", "sha256_of_64_canonical_le_u32_words"],
        "matching_tile_hashes": dense_tiles,
    }
    if index == 4:
        assert np.all(a[:, 1:] == 0) and np.all(b[1:, :] == 0)
        assert np.all(b[0, :] == 8)
        bias_u = a[:, 0]
        g = (el @ er[:, 0]) % Q
        h = (fl[0, :] @ fr) % Q
        d = ((bias_u + g)[:, None] * 8 + bias_u[:, None] * h[None, :]) % Q
        bias_prefixes = []
        for middle, expected in zip(middle_prefixes, dense_prefixes):
            zero_component = (((el @ middle) % Q) @ fr) % Q
            actual = (d + zero_component) % Q
            assert np.array_equal(actual, expected)
            bias_prefixes.append(actual)
        bias_trace, bias_tiles = transcript(challenge, bias_prefixes)
        assert bias_trace == dense_trace and bias_tiles == dense_tiles
        result["bias_narrow_candidate"] = {
            "strict_domain": "A=u*e0^T; B=e0*(8*ones)^T; all emitted K>=8",
            "u_nonzero_rows": active_rows,
            "all_prefix_words_and_trace_match": True,
            "trace": bias_trace.hex(),
            "offset_sha256": sha(field_bytes(d)),
            "classical_existing_zero_core_products": 299008,
            "classical_offset_products": {"g": N * R, "h": N * R, "row_scale_by_8": N, "active_u_outer_h": active_rows * N},
            "classical_candidate_total_products": 299008 + 2 * N * R + N + active_rows * N,
            "integer_paired_existing_zero_core_products": 152832,
            "integer_paired_offset_products_reusing_existing_el_fr_factors": {"g_cross_plus_new_right_factor": N * R // 2 + R // 2, "h_cross_plus_new_left_factor": N * R // 2 + R // 2, "row_scale_by_8": N, "active_u_outer_h": active_rows * N},
            "integer_paired_candidate_total_products": 152832 + N * R + R + N + active_rows * N,
            "extra_prefix_word_additions": BLOCKS * N * N,
            "offset_factor_storage_u32_bytes": (active_rows * N + N) * 4,
            "full_offset_storage_u32_bytes": N * N * 4,
            "native_implementation": False, "native_benchmark": False,
        }
    assert material_path.read_bytes() == raw and native_path.read_bytes() == native_raw
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-root", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    before = git_snapshot(args.repo)
    assert before["head"] == EXPECTED_HEAD and before["dirty_porcelain"] == ""
    manifest_raw = (args.input_root / "manifest.json").read_bytes()
    manifest = load_json(manifest_raw)
    cases = []
    for i in range(5):
        case = run_case(i, args.input_root, manifest)
        cases.append(case)
        print(json.dumps({key: case[key] for key in ("tile_index", "rank_a_mod_q", "rank_b_mod_q", "general_classical_schedule_products_excluding_fixed_setup", "retained_native_trace", "all_512_tile_words_equal_between_python_schedules", "full_trace_matches_retained_native")}), flush=True)
    after = git_snapshot(args.repo)
    assert before == after
    assert (args.input_root / "manifest.json").read_bytes() == manifest_raw
    report = {
        "schema": "pon-readonly-prefix-factorization-audit-v1",
        "purpose": "Exact algebra and source audit on five retained winner transcripts; not a new native performance/security qualification",
        "runtime": {"python": platform.python_version(), "numpy": np.__version__, "integer_arithmetic": "Python arbitrary-precision integers via NumPy dtype=object"},
        "script": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__).read_bytes())},
        "command_argv": sys.argv,
        "audited_source_before": before, "audited_source_after": after,
        "retained_manifest": {"path": str(args.input_root / "manifest.json"), "bytes": len(manifest_raw), "sha256": sha(manifest_raw), "execution_source": manifest["execution_source"], "provenance": manifest["provenance"]},
        "parameters": {"q": Q, "n": N, "mask_rank": R, "inner_tile_width": R, "prefixes": BLOCKS, "prefix_words_per_challenge": BLOCKS * N * N, "tile_count_per_challenge": BLOCKS ** 3, "hashed_field_bytes_per_challenge": BLOCKS * N * N * 4, "trace_byte_order": "bi,bj,bk,i,j; canonical little-endian u32"},
        "identity": "C_K=S_K+U_K*FR+EL*(V_K+M_K*FR) mod q; S_K=A[:,:K]B[:K,:], U_K=A[:,:K]FL[:K,:], V_K=ER[:,:K]B[:K,:], M_K=ER[:,:K]FL[:K,:]",
        "dense_classical_challenge_products": 2 * N * N * R + N ** 3,
        "generic_paired_challenge_products_including_input_factors": 2 * (N * N * R // 2 + 2 * N * R // 2) + BLOCKS * N * N * R // 2 + 2 * N * BLOCKS * R // 2,
        "existing_zero_classical_challenge_products": 299008,
        "existing_zero_integer_paired_challenge_products": 152832,
        "counts_exclude": ["fixed S_K or AB preparation", "structure recognition and full input validation", "allocation/transposes/index construction", "modular addition and reduction", "noise hashes", "32768-word trace hashing", "proof/ticket hashing and serialization", "cancellation overhead", "all verifier work", "transport/load/restarts/stale/failed attempts"],
        "counts_are": "Scalar multiplication counts of explicit schedules, including factors and multiplication by constant 8; neither CPU timings nor lower bounds",
        "aggregate": {"cases": len(cases), "tile_comparisons": len(cases) * BLOCKS ** 3, "word_comparisons": len(cases) * BLOCKS * N * N, "all_native_trace_hashes_match": True, "fixed_sparse_setup_nonzero_products": sum(c["fixed_sparse_setup_nonzero_products"] for c in cases), "fixed_dense_setup_products": len(cases) * N ** 3},
        "limitations": ["Only one retained winning challenge per material was algebraically recomputed", "General sparse four-term schedule shown here has no scalar-multiplication advantage on these five materials", "The strict fifth bias candidate is mathematically checked, not implemented or benchmarked", "Other schedules, small integers, repeated columns, pair/Strassen combinations, and machines may change costs", "No global cheapest-legal-work or hardness lower-bound proof", "No net useful-compute gain, model adoption, reward or gate qualification is inferred"],
        "cases": cases,
    }
    with args.output.open("x") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(json.dumps({"result": "PASS", "output": str(args.output), "bytes": args.output.stat().st_size, "sha256": sha(args.output.read_bytes()), "aggregate": report["aggregate"]}), flush=True)


if __name__ == "__main__":
    main()
