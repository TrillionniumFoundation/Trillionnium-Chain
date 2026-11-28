"""Check normal equations against supplied, SHA-bound PFT research statistics.

This is conditional numerical consistency, not proof of Gram provenance, PSD,
global optimality, useful learning, user identity or native authorization.
The numerical profile was committed before controls or historical residuals.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import re
import sys

import pft_candidate_readback as identity

PROTOCOL_SHA256 = "f45cd7d98f2a3367575ade2608e53ade1b02614ede0f001e3cf39ae7eef51353"
EXPECTED_SCHEMA = "trnm-pft-normal-equation-expectations-v1"
REPORT_SCHEMA = "trnm-pft-normal-equation-readback-v1"
BACKWARD_ERROR_LIMIT = 1e-10
SYMMETRY_LIMIT = 1e-11
MAX_BUNDLE_BYTES = 67108864
MAX_PACKETS = 256
MAX_TOTAL_SAMPLES = 1000000
MAX_NUMERIC_ELEMENTS = 4500000
MAX_PACKET_SAMPLES = 100000
FALSE_CLAIMS = (
    "source_provenance_authenticated raw_samples_verified positive_semidefiniteness_verified "
    "global_optimality_verified independent_evaluation_verified model_improvement_verified "
    "training_execution_authenticated replay_or_sybil_resistance_verified "
    "native_model_family_compatible current_adoption_verified actual_consumer_use_verified "
    "native_payment_verified authorizes_native_adoption authorizes_native_payment "
    "consensus_credit_authorized execution_authority production_activation"
).split()


def normal(value):
    value = identity.real(value)
    identity.require(value == 0 or abs(value) >= sys.float_info.min, "NEQ_NUMERIC_RANGE")
    return value


def summed(values):
    try:
        return normal(math.fsum(values))
    except (OverflowError, ValueError) as error:
        raise ValueError("NEQ_NUMERIC_RANGE") from error


def multiplied(left, right):
    result = normal(left * right)
    identity.require(result != 0 or left == 0 or right == 0, "NEQ_PRODUCT_UNDERFLOW")
    return result


def matrix(value, rows, columns):
    identity.require(type(value) is list and len(value) == rows, "NEQ_MATRIX_ROWS")
    result = []
    for row in value:
        identity.require(type(row) is list and len(row) == columns, "NEQ_MATRIX_COLUMNS")
        result.append([normal(number) for number in row])
    return result


def symmetric(value):
    for i in range(len(value)):
        for j in range(i):
            left, right = value[i][j], value[j][i]
            difference = abs(normal(left - right))
            limit = multiplied(SYMMETRY_LIMIT, max(1.0, abs(left), abs(right)))
            identity.require(difference <= limit, "NEQ_ASYMMETRIC_STATISTICS")


def packets_from(raw, candidate, expected_sha256):
    identity.require(type(raw) is bytes and len(raw) <= MAX_BUNDLE_BYTES, "NEQ_BUNDLE_LIMIT")
    identity.require(identity.sha(raw) == identity.hex_digest(expected_sha256), "NEQ_BUNDLE_PIN")
    supplied = identity.decode(raw, MAX_BUNDLE_BYTES)
    identity.require(type(supplied) is list and 1 <= len(supplied) <= MAX_PACKETS, "NEQ_PACKET_LIMIT")
    d, m = candidate["weight_shape"]
    identity.require(len(supplied) * (d * d + d * m + m * m) <= MAX_NUMERIC_ELEMENTS,
                     "NEQ_NUMERIC_ELEMENT_LIMIT")
    batches, samples, checked = set(), set(), []
    for packet in supplied:
        identity.fields(packet, {"body", "payload_sha256"}, "NEQ_PACKET_FIELDS")
        body = packet["body"]
        identity.fields(body, {"contract_sha256", "batch_id", "source_sha256", "sample_ids",
                               "count", "gram", "rhs", "yty"}, "NEQ_BODY_FIELDS")
        identity.require(identity.sha(identity.canonical(body)) == identity.hex_digest(packet["payload_sha256"]),
                         "NEQ_PAYLOAD_PIN")
        identity.require(body["contract_sha256"] == candidate["contract_sha256"], "NEQ_MIXED_CONTRACT")
        identity.hex_digest(body["source_sha256"])
        name = body["batch_id"]
        identity.require(type(name) is str and re.fullmatch("[A-Za-z0-9_.-]{1,128}", name) is not None,
                         "NEQ_BATCH_ID")
        identity.require(name not in batches, "NEQ_DUPLICATE_OR_CONFLICTING_BATCH")
        batches.add(name)
        count = identity.integer(body["count"], 1, MAX_PACKET_SAMPLES)
        ids = body["sample_ids"]
        identity.require(type(ids) is list and len(ids) == count, "NEQ_SAMPLE_COUNT")
        identity.require(len(samples) + count <= MAX_TOTAL_SAMPLES, "NEQ_SAMPLE_LIMIT")
        for sample in ids:
            identity.hex_digest(sample)
            identity.require(sample not in samples, "NEQ_SAMPLE_REUSE")
            samples.add(sample)
        identity.require(ids == sorted(ids), "NEQ_SAMPLE_ORDER")
        gram, rhs, yty = (matrix(body[key], rows, columns) for key, rows, columns in
                          (("gram", d, d), ("rhs", d, m), ("yty", m, m)))
        symmetric(gram)
        symmetric(yty)
        checked.append((name, packet["payload_sha256"], gram, rhs))
    checked.sort(key=lambda row: row[0])
    material = dict(contract_sha256=candidate["contract_sha256"], batches=[[p[0], p[1]] for p in checked])
    identity.require(identity.canonical(material).decode() == candidate["head_material_canonical_json"]
                     and identity.sha(identity.canonical(material)) == candidate["head"]
                     and len(checked) == candidate["revision"], "NEQ_INCOMPLETE_OR_DIFFERENT_HEAD")
    identity.require(len(samples) == candidate["count"], "NEQ_CANDIDATE_COUNT")
    return checked, len(samples)


def verify_normal_equations(candidate_raw, contributions_raw, expected):
    identity.fields(expected, {"schema", "protocol_sha256", "candidate", "contributions_sha256"},
                    "NEQ_EXPECTED_FIELDS")
    identity.require(expected["schema"] == EXPECTED_SCHEMA and expected["protocol_sha256"] == PROTOCOL_SHA256,
                     "NEQ_EXPECTED_PROFILE")
    identity.require(sys.float_info.radix == 2 and sys.float_info.mant_dig == 53
                     and sys.float_info.max_exp == 1024 and sys.float_info.min_exp == -1021,
                     "NEQ_BINARY64_PLATFORM")
    bound = identity.review_candidate(candidate_raw, expected["candidate"])
    candidate = identity.decode(candidate_raw)
    checked, count = packets_from(contributions_raw, candidate, expected["contributions_sha256"])
    d, m = candidate["weight_shape"]
    weight = matrix(candidate["weight"], d, m)
    regularizer = normal(candidate["contract"]["regularizer"])
    # One lambda term per aggregate diagonal; never one lambda per contribution.
    a = [[summed([packet[2][i][k] for packet in checked] + ([regularizer] if i == k else []))
          for k in range(d)] for i in range(d)]
    rhs = [[summed(packet[3][i][j] for packet in checked) for j in range(m)] for i in range(d)]
    a_norm = max(summed(abs(value) for value in row) for row in a)
    errors = []
    for j in range(m):
        residual = max(abs(summed([multiplied(a[i][k], weight[k][j]) for k in range(d)] + [-rhs[i][j]]))
                       for i in range(d))
        w_norm = max(abs(weight[i][j]) for i in range(d))
        h_norm = max(abs(rhs[i][j]) for i in range(d))
        denominator = summed((multiplied(a_norm, w_norm), h_norm))
        if denominator == 0:
            identity.require(residual == 0, "NEQ_ZERO_DENOMINATOR")
            error = 0.0
        else:
            error = residual / denominator
            identity.require(math.isfinite(error), "NEQ_NUMERIC_RANGE")
        errors.append(error)
    consistent = max(errors) <= BACKWARD_ERROR_LIMIT
    return dict(
        schema=REPORT_SCHEMA, protocol_sha256=PROTOCOL_SHA256,
        scope="normal equations consistent with supplied bound statistics only",
        status="CONSISTENT_WITH_SUPPLIED_BOUND_STATISTICS" if consistent else
               "INCONSISTENT_WITH_SUPPLIED_BOUND_STATISTICS",
        candidate_sha256=bound["candidate_sha256"], contract_sha256=bound["contract_sha256"],
        head=bound["head"], weight_sha256=bound["weight_sha256"],
        contributions_sha256=expected["contributions_sha256"],
        weight_shape=[d, m], supplied_packets=len(checked), declared_sample_count=count,
        candidate_pin_tuple_matches=True, complete_declared_head_matched=True,
        declared_sample_ids_unique_in_supplied_bundle=True,
        gram_and_yty_symmetric_within_profile=True, regularizer_added_once_per_diagonal=True,
        backward_error_limit=BACKWARD_ERROR_LIMIT, per_output_scaled_backward_error=errors,
        max_scaled_backward_error=max(errors),
        normal_equations_consistent_with_supplied_bound_statistics=consistent,
        **dict.fromkeys(FALSE_CLAIMS, False),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "contributions", "expectations", "receipt"):
        parser.add_argument(name)
    args = parser.parse_args()
    # Exclusive receipt reservation precedes numerical work. Existing evidence
    # is never overwritten; an interrupted writer can still leave a partial file.
    with Path(args.receipt).open("xb") as destination:
        observed = {}
        try:
            raw = {}
            for name, maximum in (("candidate", identity.MAX_BYTES), ("contributions", MAX_BUNDLE_BYTES),
                                  ("expectations", 8192)):
                raw[name] = identity.read_bounded(getattr(args, name), maximum)
                observed[name + "_sha256"] = identity.sha(raw[name])
            report = verify_normal_equations(raw["candidate"], raw["contributions"],
                                             identity.decode(raw["expectations"], 8192))
        except Exception as error:
            code = str(error)
            if not re.fullmatch("(?:NEQ|PFT)_[A-Z0-9_]+", code):
                code = "NEQ_INPUT_OR_NUMERIC_EXCEPTION"
            report = dict(schema=REPORT_SCHEMA, protocol_sha256=PROTOCOL_SHA256,
                          scope="normal equations consistent with supplied bound statistics only",
                          status="REFUSED_INPUT_OR_NUMERIC_RANGE", error_type=type(error).__name__,
                          error_code=code, observed_input_sha256=observed,
                          normal_equations_consistent_with_supplied_bound_statistics=False,
                          **dict.fromkeys(FALSE_CLAIMS, False))
        destination.write(identity.canonical(report) + b"\n")
        destination.flush()
    print(identity.canonical(report).decode())
    return 0 if report["normal_equations_consistent_with_supplied_bound_statistics"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
