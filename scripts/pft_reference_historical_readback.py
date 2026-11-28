"""One fixed research consumption from an existing train-shard feature export.

This consumes the independent export, not the NPZ, y, DEV or final-test data.
Full outputs stay in the requested private run directory; stdout is metadata.
"""
import argparse
from pathlib import Path
import subprocess
import sys
import time

import pft_candidate_readback as identity
import pft_normal_equation_readback as normal
import pft_reference_consumption as consumer

PINS = {
    "candidate": "001f322da2ac470f83a9e502971b79e47c0dca3baa9211fc4abd10ba10b115ae",
    "contributions": "75a5cbda912db7841e70227c1f197f14163bd3be048d759d3bd67f8b22575d20",
    "normal_expectations": "55caff98a3fd6d23db730a6032bbb0b24547d37124d805041d314356dd5aee2a",
    "features": "26456299b8fc9ac79914f8ac5762280329ebf3ced28c3e2d4420f7e95d1dd9e0",
    "expectations": "997545c4162d889bfb36c509fa6581c56545a7a7b5a63ab9d7143c233c8a7541",
}


def save(path, value):
    with path.open("xb") as output:
        output.write(identity.canonical(value) + b"\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("historical_root", "feature_root", "output"):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    parent = args.historical_root / "runs/attempt-1/historical/n8-s17011"
    paths = [parent / "forward-candidate.json", parent / "CONTRIBUTIONS.json",
             args.feature_root / "NORMAL_EXPECTED.json", args.feature_root / "FEATURE_INPUT.json",
             args.feature_root / "EXPECTED_BEFORE_XW.json"]
    sources = {}
    for source in (Path(__file__), Path(identity.__file__), Path(normal.__file__), Path(consumer.__file__)):
        raw = source.read_bytes()
        sources[source.name] = identity.sha(raw)
        (args.output / source.name).write_bytes(raw)
    save(args.output / "FROZEN_RUN.json", dict(protocol_sha256=consumer.PROTOCOL_SHA256,
         input_sha256=PINS, source_sha256=sources, python=sys.version, historical_parent="n8-s17011",
         feature_array="x", shard_local_rows=[0, 1, 2, 3], raw_shard_opened_by_this_runner=False))
    summary = dict(schema="trnm-pft-reference-historical-observation-v1", protocol_sha256=consumer.PROTOCOL_SHA256,
                   scope="one fixed same-candidate XW reference computation; historical synthetic-source train features",
                   source_sha256=sources, input_sha256=PINS, same_candidate_reference_inference_computed=False,
                   raw_shard_or_labels_or_final_test_opened=False, **dict.fromkeys(consumer.FALSE_CLAIMS, False))
    began = time.perf_counter_ns()
    try:
        for (name, digest), path in zip(PINS.items(), paths):
            maximum = normal.MAX_BUNDLE_BYTES if name == "contributions" else identity.MAX_BYTES
            identity.require(identity.sha(identity.read_bounded(path, maximum)) == digest,
                             "PFT_REFERENCE_HISTORICAL_INPUT_PIN")
        receipt_path = args.output / "PRIVATE_RECEIPT.json"
        with (args.output / "PRIVATE_STDOUT.log").open("xb") as stdout, (args.output / "STDERR.log").open("xb") as stderr:
            result = subprocess.run([sys.executable, "-B", consumer.__file__, *(str(p) for p in paths), str(receipt_path)],
                                    stdout=stdout, stderr=stderr, timeout=30)
        summary["returncode"] = result.returncode
        raw = identity.read_bounded(receipt_path, identity.MAX_BYTES)
        summary["private_receipt_sha256"] = identity.sha(raw)
        receipt = identity.decode(raw)
        identity.require(all(receipt[name] is False for name in consumer.FALSE_CLAIMS), "PFT_REFERENCE_AUTHORITY")
        for name in ("status", "request_id", "candidate_sha256", "contract_sha256", "head", "weight_sha256",
                     "contributions_sha256", "normal_expectations_sha256", "feature_input_sha256",
                     "declared_feature_source_sha256", "prediction_shape", "prediction_sha256", "prediction_encoding",
                     "row_ids_sha256", "same_candidate_reference_inference_computed", "error_code"):
            if name in receipt:
                summary[name] = receipt[name]
        summary["input_and_source_unchanged_afterward"] = all(
            identity.sha(identity.read_bounded(path, normal.MAX_BUNDLE_BYTES)) == digest
            for (name, digest), path in zip(PINS.items(), paths)) and all(
            identity.sha((Path(__file__).parent / name).read_bytes()) == digest for name, digest in sources.items())
        identity.require(summary["input_and_source_unchanged_afterward"], "PFT_REFERENCE_SOURCE_CHANGED")
        identity.require(result.returncode == 0 and receipt["prediction_shape"] == [4, 3]
                         and receipt["same_candidate_reference_inference_computed"], "PFT_REFERENCE_REAL_RUN_REFUSED")
    except Exception as error:
        summary.update(error_type=type(error).__name__, error_code=str(error),
                       same_candidate_reference_inference_computed=False)
    summary["wall_ns"] = time.perf_counter_ns() - began
    save(args.output / "PUBLIC_OBSERVATION.json", summary)
    print(identity.canonical(summary).decode())
    return 0 if summary["same_candidate_reference_inference_computed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
