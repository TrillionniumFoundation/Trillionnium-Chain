"""Compute XW for one pinned research candidate and supplied expanded features.

No feature extraction, native adoption, FinalUse, useful-gain or payment proof.
The caller must supply expectations retained independently of these inputs.
"""
import argparse
from pathlib import Path
import re
import struct

import pft_candidate_readback as identity
import pft_normal_equation_readback as normal

PROTOCOL_SHA256 = "276782c46caa1df62ddc73537fc6ce002108743c03fec197759ff0aa76f9e70b"
EXPECTED_SCHEMA = "trnm-pft-reference-consumption-expectations-v1"
FEATURE_SCHEMA = "pft-feature-input-v1"
REPORT_SCHEMA = "trnm-pft-reference-consumption-v1"
MAX_FEATURE_BYTES = 16777216
MAX_ROWS = 256
MAX_FEATURE_ELEMENTS = 262144
EXPECTED_FIELDS = {"schema", "protocol_sha256", "request_id", "normal_expectations_sha256", "feature_input_sha256"}
FEATURE_FIELDS = {"schema", "model_family", "request_id", "contract_sha256", "feature_program_sha256",
                  "normalization_sha256", "time_semantics_sha256", "source_sha256", "row_ids", "features"}
FALSE_CLAIMS = sorted(set(normal.FALSE_CLAIMS) | {
    "feature_program_execution_verified", "normalization_execution_verified",
    "consumer_identity_authenticated", "execution_authenticated", "native_final_use_verified",
    "cross_platform_consensus_determinism_verified", "runtime_closure_complete",
})


def consume_reference(candidate_raw, bundle_raw, normal_expected_raw, feature_raw, expected):
    identity.fields(expected, EXPECTED_FIELDS, "PFT_REFERENCE_EXPECTED_FIELDS")
    identity.require(expected["schema"] == EXPECTED_SCHEMA and expected["protocol_sha256"] == PROTOCOL_SHA256,
                     "PFT_REFERENCE_EXPECTED_PROFILE")
    request_id = identity.hex_digest(expected["request_id"])
    identity.require(type(normal_expected_raw) is bytes and len(normal_expected_raw) <= 8192
                     and identity.sha(normal_expected_raw) == identity.hex_digest(expected["normal_expectations_sha256"]),
                     "PFT_REFERENCE_NORMAL_EXPECTATIONS_PIN")
    identity.require(type(feature_raw) is bytes and len(feature_raw) <= MAX_FEATURE_BYTES,
                     "PFT_REFERENCE_FEATURE_LIMIT")
    identity.require(identity.sha(feature_raw) == identity.hex_digest(expected["feature_input_sha256"]),
                     "PFT_REFERENCE_FEATURE_PIN")
    features = identity.decode(feature_raw, MAX_FEATURE_BYTES)
    identity.fields(features, FEATURE_FIELDS, "PFT_REFERENCE_FEATURE_FIELDS")
    identity.require(features["schema"] == FEATURE_SCHEMA and features["model_family"] == identity.MODEL_FAMILY,
                     "PFT_REFERENCE_FEATURE_SCHEMA")
    identity.require(identity.hex_digest(features["request_id"]) == request_id, "PFT_REFERENCE_REQUEST")
    identity.hex_digest(features["source_sha256"])
    observation = normal.verify_normal_equations(candidate_raw, bundle_raw,
                                                 identity.decode(normal_expected_raw, 8192))
    report = dict(schema=REPORT_SCHEMA, protocol_sha256=PROTOCOL_SHA256,
                  scope="reference XW with the same pinned candidate and supplied expanded features only",
                  request_id=request_id, model_family=identity.MODEL_FAMILY,
                  candidate_sha256=observation["candidate_sha256"], contract_sha256=observation["contract_sha256"],
                  head=observation["head"], weight_sha256=observation["weight_sha256"],
                  contributions_sha256=observation["contributions_sha256"],
                  normal_expectations_sha256=expected["normal_expectations_sha256"],
                  feature_input_sha256=expected["feature_input_sha256"],
                  declared_feature_source_sha256=features["source_sha256"],
                  normal_equation_observation=observation,
                  same_candidate_reference_inference_computed=False, **dict.fromkeys(FALSE_CLAIMS, False))
    if not observation["normal_equations_consistent_with_supplied_bound_statistics"]:
        return dict(report, status="REFUSED_NORMAL_EQUATION_INCONSISTENCY",
                    error_code="PFT_REFERENCE_NORMAL_EQUATIONS")
    candidate = identity.decode(candidate_raw)
    contract = candidate["contract"]
    identity.require(features["contract_sha256"] == candidate["contract_sha256"], "PFT_REFERENCE_CONTRACT")
    for key in ("feature_program_sha256", "normalization_sha256", "time_semantics_sha256"):
        identity.require(features[key] == contract[key], "PFT_REFERENCE_FEATURE_SEMANTICS")
    d, m = candidate["weight_shape"]
    rows = features["features"]
    identity.require(type(rows) is list and 1 <= len(rows) <= MAX_ROWS
                     and len(rows) * d <= MAX_FEATURE_ELEMENTS, "PFT_REFERENCE_ROW_LIMIT")
    ids = features["row_ids"]
    identity.require(type(ids) is list and len(ids) == len(rows), "PFT_REFERENCE_ROW_IDS")
    for value in ids:
        identity.hex_digest(value)
    identity.require(len(set(ids)) == len(ids), "PFT_REFERENCE_ROW_REUSE")
    x = normal.matrix(rows, len(rows), d)
    weight = normal.matrix(candidate["weight"], d, m)
    # Inputs already include all declared expansion, normalization and bias.
    prediction = [[normal.summed([normal.multiplied(row[k], weight[k][j]) for k in range(d)])
                   for j in range(m)] for row in x]
    encoded = b"".join(struct.pack("<" + "d" * m, *row) for row in prediction)
    return dict(report, status="REFERENCE_INFERENCE_COMPUTED",
                same_candidate_reference_inference_computed=True,
                feature_input_declarations_match_contract=True,
                row_ids_sha256=identity.sha(identity.canonical(ids)),
                prediction=prediction, prediction_shape=[len(rows), m],
                prediction_encoding="float64-le-c-rowmajor", prediction_sha256=identity.sha(encoded))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("candidate", "contributions", "normal_expectations", "features", "expectations", "receipt"):
        parser.add_argument(name)
    args = parser.parse_args()
    with Path(args.receipt).open("xb") as destination:
        observed = {}
        try:
            raw = {}
            for name, maximum in (("candidate", identity.MAX_BYTES), ("contributions", normal.MAX_BUNDLE_BYTES),
                                  ("normal_expectations", 8192), ("features", MAX_FEATURE_BYTES), ("expectations", 4096)):
                raw[name] = identity.read_bounded(getattr(args, name), maximum)
                observed[name + "_sha256"] = identity.sha(raw[name])
            report = consume_reference(raw["candidate"], raw["contributions"], raw["normal_expectations"],
                                       raw["features"], identity.decode(raw["expectations"], 4096))
        except Exception as error:
            code = str(error)
            if not re.fullmatch("(?:PFT|NEQ)_[A-Z0-9_]+", code):
                code = "PFT_REFERENCE_INPUT_OR_NUMERIC_EXCEPTION"
            report = dict(schema=REPORT_SCHEMA, protocol_sha256=PROTOCOL_SHA256,
                          scope="reference XW with the same pinned candidate and supplied expanded features only",
                          status="REFUSED_INPUT_OR_NUMERIC_RANGE", error_type=type(error).__name__, error_code=code,
                          observed_input_sha256=observed, same_candidate_reference_inference_computed=False,
                          **dict.fromkeys(FALSE_CLAIMS, False))
        destination.write(identity.canonical(report) + b"\n")
        destination.flush()
    print(identity.canonical(report).decode())
    return 0 if report["same_candidate_reference_inference_computed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
