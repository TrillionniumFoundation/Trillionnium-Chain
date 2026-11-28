"""Read nine existing private research bundles; publish hashes/receipts only.

No training, final-test reads, sample provenance claim or native authority.
Pins predate this numerical verification and come from the #1016 readback.
"""
import argparse
from pathlib import Path
import time

import pft_candidate_readback as identity
import pft_normal_equation_readback as normal

ROOT = Path(__file__).resolve().parents[1]
OLD_REPORT = ROOT / "evidence/pft-candidate-readback-20261128/NINE_PARENT_READBACK.json"
OLD_REPORT_SHA256 = "699f5f402b8444a6eee977bc3f3cd50c6c095b54dfa07307d59428462db0b12c"
INVENTORY_SHA256 = "bae99a7791254e07a45eac9dd3f53cfcfbe397e3576150c1e44764c191f12a07"
PARENTS = {f"n{n}-s{seed}" for n in (8, 32, 64) for seed in (17011, 27011, 37011)}


def pinned(path, digest, maximum, size=None):
    raw = identity.read_bounded(path, maximum)
    identity.require(identity.sha(raw) == digest, "NEQ_HISTORICAL_SOURCE_PIN")
    identity.require(size is None or len(raw) == size, "NEQ_HISTORICAL_SOURCE_SIZE")
    return raw


def save(path, value):
    with path.open("xb") as stream:
        stream.write(identity.canonical(value) + b"\n")
        stream.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("historical_root", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    # Retain the exact first-run source before parsing private numerical inputs.
    sources = {}
    for path in (Path(__file__), Path(normal.__file__), Path(identity.__file__)):
        raw = path.read_bytes()
        sources[path.name] = identity.sha(raw)
        (args.output / path.name).write_bytes(raw)
    save(args.output / "FROZEN_SOURCE.json", dict(protocol_sha256=normal.PROTOCOL_SHA256,
         prior_readback_sha256=OLD_REPORT_SHA256, evidence_inventory_sha256=INVENTORY_SHA256,
         source_sha256=sources))
    old = identity.decode(pinned(OLD_REPORT, OLD_REPORT_SHA256, identity.MAX_BYTES))
    identity.require(old["evidence_inventory_sha256"] == INVENTORY_SHA256, "NEQ_HISTORICAL_INVENTORY_PIN")
    inventory = identity.decode(pinned(args.historical_root / "runs/attempt-1/HISTORICAL_EVIDENCE_MANIFEST.json",
                                      INVENTORY_SHA256, identity.MAX_BYTES))
    index = {row["path"]: row for row in inventory["files"]}
    identity.require(len(index) == len(inventory["files"]), "NEQ_DUPLICATE_INVENTORY_PATH")
    identity.require(len(old["reports"]) == 9 and {r["parent"] for r in old["reports"]} == PARENTS,
                     "NEQ_HISTORICAL_PARENT_SET")
    reports = []
    for row in sorted(old["reports"], key=lambda value: value["parent"]):
        parent, began = row["parent"], time.perf_counter_ns()
        record = dict(parent=parent, source_sha256=sources, observed_inputs={})
        try:
            prefix = f"runs/attempt-1/historical/{parent}/"
            candidate_meta, bundle_meta = (index[prefix + name] for name in
                                           ("forward-candidate.json", "CONTRIBUTIONS.json"))
            candidate = pinned(args.historical_root / candidate_meta["path"], candidate_meta["sha256"],
                               identity.MAX_BYTES, candidate_meta["size"])
            bundle = pinned(args.historical_root / bundle_meta["path"], bundle_meta["sha256"],
                            normal.MAX_BUNDLE_BYTES, bundle_meta["size"])
            expected = dict(schema=normal.EXPECTED_SCHEMA, protocol_sha256=normal.PROTOCOL_SHA256,
                            candidate=row["expectations"], contributions_sha256=bundle_meta["sha256"])
            record.update(expectations=expected, observed_inputs=dict(candidate_sha256=identity.sha(candidate),
                          contributions_sha256=identity.sha(bundle), contributions_bytes=len(bundle)))
            record["receipt"] = normal.verify_normal_equations(candidate, bundle, expected)
        except Exception as error:
            record.update(error_type=type(error).__name__, error_code=str(error),
                          normal_equations_consistent_with_supplied_bound_statistics=False,
                          **dict.fromkeys(normal.FALSE_CLAIMS, False))
        record["wall_ns"] = time.perf_counter_ns() - began
        save(args.output / (parent + ".json"), record)
        reports.append(record)
        print(parent, record.get("receipt", {}).get("status", "REFUSED_INPUT_OR_NUMERIC_RANGE"), flush=True)
    passed = sum(r.get("receipt", {}).get("normal_equations_consistent_with_supplied_bound_statistics") is True
                 for r in reports)
    summary = dict(schema="trnm-pft-normal-equation-historical-observations-v1", reports=reports,
                   checked_parents=len(reports), consistent_parents=passed,
                   protocol_sha256=normal.PROTOCOL_SHA256, evidence_inventory_sha256=INVENTORY_SHA256,
                   prior_readback_sha256=OLD_REPORT_SHA256,
                   scope="nine historical synthetic-source research caches; supplied-statistics consistency only",
                   **dict.fromkeys(normal.FALSE_CLAIMS, False))
    save(args.output / "NINE_PARENT_NORMAL_EQUATIONS.json", summary)
    return 0 if passed == 9 else 2


if __name__ == "__main__":
    raise SystemExit(main())
