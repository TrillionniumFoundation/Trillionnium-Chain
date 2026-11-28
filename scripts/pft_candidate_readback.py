"""Read a separately pinned HCSN PFT research candidate without native authority.

This reader imports no Hepta training module, NumPy, native model loader or
payment owner. It checks declared identity and weight bytes, not statistics
provenance, the linear solve, efficacy, adoption, payment or chain ancestry.
The independently retained expectations must not be synthesized here from the
submitted candidate. Exact JSON canonical strings preserve the producer's
float literals; weight identity uses IEEE-754 binary64 little-endian row order.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import stat
import struct

MODEL_FAMILY = "hcsn-pft-readout-research-v1"
EXPECTED_SCHEMA = "trnm-pft-candidate-expectations-v1"
REPORT_SCHEMA = "trnm-pft-candidate-review-v1"
MAX_BYTES = 16 * 1024 * 1024
MAX_BATCHES = 100000
DIGEST_FIELDS = (
    "parent_model_sha256", "feature_program_sha256", "normalization_sha256",
    "objective_sha256", "time_semantics_sha256",
)
EXPECTED_FIELDS = {
    "schema", "model_family", "candidate_sha256", "contract_sha256", "head",
    "weight_sha256", "parent_model_sha256",
}
CANDIDATE_FIELDS = {
    "schema", "contract", "contract_sha256", "contract_canonical_json", "head",
    "revision", "head_material_canonical_json", "count", "weight_shape",
    "weight", "weight_encoding", "weight_sha256",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      allow_nan=False, ensure_ascii=True).encode("ascii")


def fields(value, names, code):
    require(type(value) is dict and set(value) == set(names), code)


def hex_digest(value):
    require(type(value) is str and re.fullmatch("[0-9a-f]{64}", value) is not None,
            "PFT_DIGEST")
    return value


def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, "PFT_INTEGER")
    return value


def real(value):
    require(type(value) in (int, float), "PFT_REAL")
    try:
        result = float(value)
    except OverflowError as error:
        raise ValueError("PFT_REAL") from error
    require(math.isfinite(result), "PFT_REAL")
    return result


def decode(raw, maximum=MAX_BYTES):
    require(type(raw) is bytes and len(raw) <= maximum, "PFT_BYTE_LIMIT")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "PFT_DUPLICATE_KEY")
            result[key] = value
        return result

    def constant(_):
        raise ValueError("PFT_NONFINITE_JSON")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeError, RecursionError) as error:
        raise ValueError("PFT_JSON") from error


def canonical_text(value, maximum):
    require(type(value) is str, "PFT_CANONICAL_TEXT")
    try:
        raw = value.encode("ascii")
    except UnicodeError as error:
        raise ValueError("PFT_CANONICAL_TEXT") from error
    parsed = decode(raw, maximum)
    require(canonical(parsed) == raw, "PFT_NONCANONICAL_TEXT")
    return raw, parsed


def check_contract(value):
    fields(value, set(DIGEST_FIELDS) | {
        "schema", "model_family", "epoch", "dimension", "outputs", "regularizer",
        "dtype", "aggregation", "statistics_validation",
    }, "PFT_CONTRACT_FIELDS")
    for key in DIGEST_FIELDS:
        hex_digest(value[key])
    integer(value["epoch"], 0, 2**63 - 1)
    dimension = integer(value["dimension"], 1, 1024)
    outputs = integer(value["outputs"], 1, 32)
    require(real(value["regularizer"]) > 0, "PFT_REGULARIZER")
    require(value["schema"] == "pft-online-statistics-v1" and
            value["model_family"] == MODEL_FAMILY and value["dtype"] == "float64" and
            value["aggregation"] == "sum-f64-canonical-batch-id" and
            value["statistics_validation"] == "augmented-psd-rtol-1e-10-v1",
            "PFT_RESEARCH_CONTRACT")
    return dimension, outputs


def review_candidate(raw, expected):
    """Verify research statements against an independently retained exact tuple."""
    fields(expected, EXPECTED_FIELDS, "PFT_EXPECTED_FIELDS")
    require(expected["schema"] == EXPECTED_SCHEMA and expected["model_family"] == MODEL_FAMILY,
            "PFT_EXPECTED_RESEARCH_SCOPE")
    for key in EXPECTED_FIELDS - {"schema", "model_family"}:
        hex_digest(expected[key])
    require(type(raw) is bytes and len(raw) <= MAX_BYTES, "PFT_BYTE_LIMIT")
    require(sha(raw) == expected["candidate_sha256"], "PFT_CANDIDATE_PIN")
    candidate = decode(raw)
    fields(candidate, CANDIDATE_FIELDS, "PFT_CANDIDATE_FIELDS")
    require(candidate["schema"] == "pft-online-candidate-v1" and
            candidate["weight_encoding"] == "float64-le-c-rowmajor", "PFT_CANDIDATE_SCHEMA")
    contract_raw, contract = canonical_text(candidate["contract_canonical_json"], 4096)
    dimension, outputs = check_contract(contract)
    require(canonical(candidate["contract"]) == contract_raw, "PFT_CONTRACT_TEXT_MISMATCH")
    require(sha(contract_raw) == hex_digest(candidate["contract_sha256"]) == expected["contract_sha256"]
            and contract["parent_model_sha256"] == expected["parent_model_sha256"], "PFT_CONTRACT_PIN")

    head_raw, material = canonical_text(candidate["head_material_canonical_json"], MAX_BYTES)
    fields(material, {"contract_sha256", "batches"}, "PFT_HEAD_FIELDS")
    require(material["contract_sha256"] == candidate["contract_sha256"], "PFT_HEAD_CONTRACT")
    batches = material["batches"]
    revision = integer(candidate["revision"], 1, MAX_BATCHES)
    require(type(batches) is list and len(batches) == revision, "PFT_HEAD_REVISION")
    names = []
    for pair in batches:
        require(type(pair) is list and len(pair) == 2 and type(pair[0]) is str and
                re.fullmatch("[A-Za-z0-9_.-]{1,128}", pair[0]) is not None, "PFT_BATCH_IDENTITY")
        names.append(pair[0])
        hex_digest(pair[1])
    require(names == sorted(set(names)), "PFT_BATCH_ORDER_OR_DUPLICATE")
    require(sha(head_raw) == hex_digest(candidate["head"]) == expected["head"], "PFT_HEAD_PIN")
    count = integer(candidate["count"], revision, revision * 100000)

    shape = candidate["weight_shape"]
    require(type(shape) is list and len(shape) == 2 and all(type(n) is int for n in shape)
            and shape == [dimension, outputs], "PFT_WEIGHT_SHAPE")
    weight = candidate["weight"]
    require(type(weight) is list and len(weight) == dimension, "PFT_WEIGHT_ROWS")
    weight_hash = hashlib.sha256()
    for row in weight:
        require(type(row) is list and len(row) == outputs, "PFT_WEIGHT_COLUMNS")
        weight_hash.update(struct.pack("<" + "d" * outputs, *(real(value) for value in row)))
    require(weight_hash.hexdigest() == hex_digest(candidate["weight_sha256"]) == expected["weight_sha256"],
            "PFT_WEIGHT_PIN")

    return dict(
        schema=REPORT_SCHEMA, scope="pinned_hcsn_pft_research_candidate_identity_only",
        status="STRUCTURALLY_CONSISTENT_UNAUTHENTICATED", model_family=MODEL_FAMILY,
        candidate_sha256=expected["candidate_sha256"], contract_sha256=expected["contract_sha256"],
        head=expected["head"], weight_sha256=expected["weight_sha256"],
        parent_model_sha256=expected["parent_model_sha256"], revision=revision,
        sample_count_declared=count, weight_shape=shape, candidate_pin_tuple_matches=True,
        native_model_family_compatible=False, statistics_contributions_verified=False,
        normal_equations_verified=False, training_execution_authenticated=False,
        source_provenance_authenticated=False, independent_evaluation_verified=False,
        model_improvement_verified=False, replay_or_sybil_resistance_verified=False,
        current_adoption_verified=False, actual_consumer_use_verified=False,
        native_payment_verified=False, authorizes_native_adoption=False,
        authorizes_native_payment=False, consensus_credit_authorized=False,
        execution_authority=False, production_activation=False,
    )


def read_bounded(path, maximum):
    """Read one stable regular-file descriptor; final symlinks are refused.

    O_NONBLOCK prevents a FIFO open from waiting for a writer. It does not
    promise a hard deadline for arbitrary remote regular-file I/O. Independent
    expected digests remain required; metadata stability is not authentication.
    """
    require(type(maximum) is int and maximum >= 0, "PFT_BYTE_LIMIT")
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), "PFT_FILE_TYPE")
        require(before.st_size <= maximum, "PFT_BYTE_LIMIT")
        chunks, remaining = [], maximum + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        require(len(raw) <= maximum, "PFT_BYTE_LIMIT")
        attributes = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(len(raw) == before.st_size and
                all(getattr(before, name) == getattr(after, name) for name in attributes),
                "PFT_FILE_CHANGED")
        return raw
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate")
    parser.add_argument("expectations", help="independently retained research tuple; never derived by this reader")
    args = parser.parse_args()
    result = review_candidate(read_bounded(args.candidate, MAX_BYTES),
                              decode(read_bounded(args.expectations, 4096), 4096))
    print(canonical(result).decode())


if __name__ == "__main__":
    main()
