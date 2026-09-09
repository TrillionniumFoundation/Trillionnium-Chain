#!/usr/bin/env python3
"""Verify a generated Trillionnium Rust CodeQL candidate disposition packet."""
from __future__ import annotations

import base64
import gzip
import hashlib
import json
from pathlib import Path


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    records = []
    expected = 1
    for chunk in manifest["chunks"]:
        path = root / chunk["path"]
        encoded = path.read_bytes()
        if sha256(encoded) != chunk["base64_sha256"]:
            raise SystemExit(f"base64 digest mismatch: {path}")
        compressed = base64.b64decode(encoded.strip(), validate=True)
        if sha256(compressed) != chunk["gzip_sha256"]:
            raise SystemExit(f"gzip digest mismatch: {path}")
        raw = gzip.decompress(compressed)
        if sha256(raw) != chunk["json_sha256"]:
            raise SystemExit(f"JSON digest mismatch: {path}")
        document = json.loads(raw)
        if document["source_commit"] != manifest["source_commit"]:
            raise SystemExit(f"source commit drift: {path}")
        if document["source_tree"] != manifest["source_tree"]:
            raise SystemExit(f"source tree drift: {path}")
        if document["accepted"] is not False:
            raise SystemExit(f"unexpected acceptance: {path}")
        if document["independent_security_review_required"] is not True:
            raise SystemExit(f"missing independent-review requirement: {path}")
        if document["range"]["first_ordinal"] != expected:
            raise SystemExit(f"non-contiguous range: {path}")
        if document["range"]["count"] != len(document["findings"]):
            raise SystemExit(f"range count mismatch: {path}")
        for finding in document["findings"]:
            if finding["ordinal"] != expected:
                raise SystemExit(f"ordinal drift at {expected}: {path}")
            if finding["exact_source_sha"] != manifest["source_commit"]:
                raise SystemExit(f"finding source commit drift at {expected}")
            if finding["exact_source_tree"] != manifest["source_tree"]:
                raise SystemExit(f"finding source tree drift at {expected}")
            if finding["accepted"] is not False:
                raise SystemExit(f"finding unexpectedly accepted at {expected}")
            if finding["acceptance_state"] != "candidate-unreviewed":
                raise SystemExit(f"finding acceptance state drift at {expected}")
            if finding["independent_security_review_required"] is not True:
                raise SystemExit(f"finding lacks independent review at {expected}")
            records.append(finding)
            expected += 1

    if len(records) != manifest["result_count"]:
        raise SystemExit("result count mismatch")
    if len({record["finding_id"] for record in records}) != len(records):
        raise SystemExit("duplicate finding ID")
    if len({record["sarif_result_sha256"] for record in records}) != len(records):
        raise SystemExit("duplicate SARIF result hash")

    by_rule = {}
    by_class = {}
    by_confidence = {}
    for record in records:
        by_rule[record["rule_id"]] = by_rule.get(record["rule_id"], 0) + 1
        key = record["candidate_disposition_class"]
        by_class[key] = by_class.get(key, 0) + 1
        confidence = record["candidate_confidence"]
        by_confidence[confidence] = by_confidence.get(confidence, 0) + 1
    if by_rule != manifest["counts_by_rule"]:
        raise SystemExit("rule counts drift")
    if by_class != manifest["counts_by_candidate_class"]:
        raise SystemExit("class counts drift")
    if by_confidence != manifest["counts_by_confidence"]:
        raise SystemExit("confidence counts drift")
    if manifest["accepted"] is not False:
        raise SystemExit("manifest unexpectedly accepted")
    if manifest["official_codeql_gate_success"] is not False:
        raise SystemExit("manifest falsely claims official gate success")
    print(f"verified candidate dispositions: {len(records)}; accepted=false")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
