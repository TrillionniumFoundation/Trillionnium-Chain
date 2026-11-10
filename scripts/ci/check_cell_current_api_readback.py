#!/usr/bin/env python3
"""Read one source-bound Rust compile-fail observation, never a release verdict."""
import argparse
import json
from pathlib import Path
import re

SOURCE = "trillionnium/crates/trnm-data-availability/src/cell/pq.rs"
EXAMPLE = "/// ```compile_fail,E0308\n/// use trnm_data_availability::cell::CellReleaseManifestV1;\n/// use trnm_data_availability::cell::pq::{\n///     CellPqReleaseAuthorizationV2, CellPqReleaseExpectationV2,\n/// };\n/// fn stale_time_only(\n///     authorization: &CellPqReleaseAuthorizationV2,\n///     release: &CellReleaseManifestV1,\n///     expected: &CellPqReleaseExpectationV2<'_>,\n/// ) {\n///     let proof = authorization.verify_at(release, expected).unwrap();\n///     let _ = proof.release_at(300);\n/// }\n/// ```\n"
TYPE = "pub struct VerifiedCellPqReleaseV2<'a> {"


def observe(text, source):
    bound = EXAMPLE + TYPE
    line = None
    if source.count(EXAMPLE) == 1 and source.count(bound) == 1:
        line = source[:source.index(bound)].count("\n") + 1
    case = ("test crates/trnm-data-availability/src/cell/pq.rs - "
            f"cell::pq::VerifiedCellPqReleaseV2 (line {line}) - compile fail ... ok")
    cases = re.findall(r"^test (?!result:).*?$", text, re.M)
    summaries = re.findall(r"^test result:.*?$", text, re.M)
    summary = re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; "
        r"[0-9]+ filtered out; finished in [0-9.]+s", summaries[0]) if len(summaries) == 1 else None
    errors = re.findall(r"^error\[(E[0-9]+)\]:", text, re.M)
    all_errors = re.findall(r"^error.*?$", text, re.M)
    plain_errors = re.findall(r"^error:.*?$", text, re.M)
    valid = (line is not None and cases == [case] and summary is not None
             and errors == ["E0308"] and len(all_errors) == 2
             and plain_errors == ["error: aborting due to 1 previous error"]
             and all(item in text for item in (
                 "CellPqReleaseExpectationV2", "integer", "release_at(300)")))
    return {"result": "PASS" if valid else "FAIL",
            "contract": "cell-current-view-required", "executed_tests": len(cases),
            "diagnostic_codes": errors, "scope": "compile-fail-type-boundary-observation"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--source", type=Path,
                        default=Path(__file__).resolve().parents[2] / SOURCE)
    args = parser.parse_args()
    report = observe(args.log.read_text(), args.source.read_text())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
