#!/usr/bin/env python3
"""Strict source-bound readback of the current-view compile-fail boundary.

The source recorder owns clean-tree/command-exit identity. This reader does not
turn a synthetic log or a historical observation into a new native execution.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

SOURCE = "trillionnium/crates/trnm-data-availability/src/cell/pq.rs"
BLOCK_SHA256 = "ef4ecc7461197600f25854f011ae2abd756016bc9931098af7755d619bf7be73"


def expected_case(source):
    marker = "/// ```compile_fail,E0308"
    end = "pub struct VerifiedCellPqReleaseV2<'a> {"
    # Bind the complete boundary example and its immediately attached type,
    # not an arbitrary matching line in another doc block.
    blocks = list(re.finditer(re.escape(marker) + r".*?(?=" + re.escape(end) + r")", source, re.S))
    if len(blocks) != 1 or hashlib.sha256(blocks[0].group().encode()).hexdigest() != BLOCK_SHA256:
        raise ValueError("current-view source example changed")
    line = source[:blocks[0].start()].count("\n") + 1
    return ("test crates/trnm-data-availability/src/cell/pq.rs - "
            f"cell::pq::VerifiedCellPqReleaseV2 (line {line}) - compile fail ... ok")


def check(text, source):
    try:
        expected = expected_case(source)
    except ValueError:
        expected = None
    cases = [line for line in text.splitlines() if line.startswith("test ") and not line.startswith("test result:")]
    summaries = [line for line in text.splitlines() if line.startswith("test result:")]
    summary = re.fullmatch(r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; [0-9]+ filtered out; finished in [0-9.]+s", summaries[0]) if len(summaries) == 1 else None
    errors = re.findall(r"^error\[(E[0-9]+)\]:", text, re.M)
    valid = (expected is not None and cases == [expected] and bool(summary)
             and errors == ["E0308"] and "CellPqReleaseExpectationV2" in text
             and "integer" in text and "release_at(300)" in text)
    return {"result": "PASS" if valid else "FAIL", "contract": "cell-current-view-required",
            "executed_tests": cases.count(expected), "diagnostic_codes": errors,
            "scope": "compile-fail-type-boundary-observation"}


def main():
    report = check(Path(sys.argv[1]).read_text(), Path(sys.argv[2]).read_text())
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
