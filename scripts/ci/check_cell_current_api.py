#!/usr/bin/env python3
"""Bind the current-authority compile-fail observation to its source location.

The source location can move when unrelated code is added. The test symbol,
single executed result, E0308 diagnostic and authority type remain mandatory.
This readback is a local type-boundary observation, not runtime qualification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

from pq_source_reader import read_regular

SOURCE = "trillionnium/crates/trnm-data-availability/src/cell/pq.rs"
CASE = "crates/trnm-data-availability/src/cell/pq.rs - cell::pq::VerifiedCellPqReleaseV2"


def source_line(text):
    blocks = list(re.finditer(
        r"(?P<docs>(?:///[^\n]*\n)+)pub struct VerifiedCellPqReleaseV2<'a> \{", text))
    if len(blocks) != 1:
        raise ValueError("expected one documented current-authority proof type")
    block = blocks[0]
    docs = block.group("docs")
    markers = list(re.finditer(r"^/// ```compile_fail,E0308$", docs, re.M))
    if len(markers) != 1 or docs.count("/// ```") != 2:
        raise ValueError("expected one E0308 compile-fail source example")
    example = docs[markers[0].end():]
    required = ("expected: &CellPqReleaseExpectationV2<'_>,", "authorization.verify_at(release, expected)",
                "let _ = proof.release_at(300);")
    if any(example.count(item) != 1 for item in required):
        raise ValueError("current-authority source example changed")
    return text.count("\n", 0, block.start("docs") + markers[0].start()) + 1


def inspect(text, expected_line):
    if type(expected_line) is not int or expected_line < 1:
        raise ValueError("invalid source example line")
    pattern = "^test " + re.escape(CASE) + r" \(line " + str(expected_line) + r"\) - compile fail \.\.\. ok$"
    names = re.findall(pattern, text, re.M)
    summaries = re.findall(
        r"^test result: ok\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out;",
        text, re.M)
    errors = re.findall(r"^error\[(E[0-9]+)\]:", text, re.M)
    valid = (len(names) == 1 and len(summaries) == 1
             and tuple(map(int, summaries[0][:4])) == (1, 0, 0, 0)
             and errors == ["E0308"] and "CellPqReleaseExpectationV2" in text
             and "integer" in text and "release_at(300)" in text)
    return {"result": "PASS" if valid else "FAIL", "contract": "cell-current-view-required",
            "executed_tests": len(names), "diagnostic_codes": errors,
            "scope": "compile-fail-type-boundary-observation"}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        source = read_regular(args.root, SOURCE, 1024 * 1024).decode("utf-8")
        log = read_regular(args.log.parent, args.log.name, 2 * 1024 * 1024).decode("utf-8")
        report = inspect(log, source_line(source))
    except (OSError, ValueError) as error:
        report = {"result": "FAIL", "contract": "cell-current-view-required",
                  "reason": str(error), "executed_tests": 0, "diagnostic_codes": [],
                  "scope": "compile-fail-type-boundary-observation"}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
